//! Web PKI types.

use std::time::Duration;

use rustls_pki_types::{self as webpki_types, pem::PemObject};
use serde::{Deserialize, Serialize};

use crate::connection::ServerName;

/// X.509 certificate, DER encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDer(pub Vec<u8>);

impl CertificateDer {
    /// Creates a DER-encoded certificate from a PEM-encoded certificate.
    pub fn from_pem_slice(pem: &[u8]) -> Result<Self, PemError> {
        let der = webpki_types::CertificateDer::from_pem_slice(pem).map_err(|_| PemError {})?;

        Ok(Self(der.to_vec()))
    }
}

/// Private key, DER encoded.
#[derive(Debug, Clone, zeroize::ZeroizeOnDrop, Serialize, Deserialize)]
pub struct PrivateKeyDer(pub Vec<u8>);

impl PrivateKeyDer {
    /// Creates a DER-encoded private key from a PEM-encoded private key.
    pub fn from_pem_slice(pem: &[u8]) -> Result<Self, PemError> {
        let der = webpki_types::PrivateKeyDer::from_pem_slice(pem).map_err(|_| PemError {})?;

        Ok(Self(der.secret_der().to_vec()))
    }
}

/// PEM parsing error.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse PEM object")]
pub struct PemError {}

/// Root certificate store.
///
/// This stores root certificates which are used to verify end-entity
/// certificates presented by a TLS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCertStore {
    /// Unvalidated DER-encoded X.509 root certificates.
    pub roots: Vec<CertificateDer>,
}

impl RootCertStore {
    /// Creates an empty root certificate store.
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Creates a root certificate store with Mozilla root certificates.
    ///
    /// These certificates are sourced from [`webpki-root-certs`](https://docs.rs/webpki-root-certs/latest/webpki_root_certs/). It is not recommended to use these unless the
    /// application binary can be recompiled and deployed on-demand in the case
    /// that the root certificates need to be updated.
    #[cfg(feature = "mozilla-certs")]
    pub fn mozilla() -> Self {
        Self {
            roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|cert| CertificateDer(cert.to_vec()))
                .collect(),
        }
    }
}

/// Server certificate verifier.
#[derive(Debug)]
pub struct ServerCertVerifier {
    roots: Vec<webpki_types::TrustAnchor<'static>>,
    /// [ph fork] Chains this verifier already accepted: key -> (lo, hi), the
    /// intersection of the validity windows of every presented certificate.
    /// See `verify_server_cert` for why a hit is sound.
    verified: std::sync::Mutex<std::collections::BTreeMap<[u8; 32], (u64, u64)>>,
}

/// [ph fork] Cache key: the exact presented chain and server name.
fn chain_key(end_entity: &CertificateDer, intermediates: &[CertificateDer], server_name: &ServerName) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ph/tlsn-fork/verified-chain/v1");
    let mut field = |b: &[u8]| {
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    };
    let ServerName::Dns(name) = server_name;
    field(name.as_str().as_bytes());
    field(&end_entity.0);
    field(&(intermediates.len() as u64).to_le_bytes());
    for c in intermediates {
        field(&c.0);
    }
    h.finalize().into()
}

/// [ph fork] (notBefore, notAfter) of a DER certificate in Unix seconds, or
/// None if it does not parse (then nothing is cached: fail safe).
fn validity_window(der: &[u8]) -> Option<(u64, u64)> {
    use x509_cert::der::Decode;
    let c = x509_cert::Certificate::from_der(der).ok()?;
    let v = &c.tbs_certificate.validity;
    Some((
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    ))
}

impl ServerCertVerifier {
    /// Creates a new server certificate verifier.
    pub fn new(roots: &RootCertStore) -> Result<Self, ServerCertVerifierError> {
        let roots = roots
            .roots
            .iter()
            .map(|cert| {
                webpki::anchor_from_trusted_cert(&webpki_types::CertificateDer::from(
                    cert.0.as_slice(),
                ))
                .map(|anchor| anchor.to_owned())
                .map_err(|err| ServerCertVerifierError::InvalidRootCertificate {
                    cert: cert.clone(),
                    reason: err.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            roots,
            verified: Default::default(),
        })
    }

    /// Creates a server certificate verifier with Mozilla root certificates.
    ///
    /// These certificates are sourced from [`webpki-root-certs`](https://docs.rs/webpki-root-certs/latest/webpki_root_certs/). It is not recommended to use these unless the
    /// application binary can be recompiled and deployed on-demand in the case
    /// that the root certificates need to be updated.
    #[cfg(feature = "mozilla-certs")]
    pub fn mozilla() -> Self {
        Self {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            verified: Default::default(),
        }
    }

    /// Verifies the server certificate was valid at the given time of
    /// presentation.
    ///
    /// # Arguments
    ///
    /// * `end_entity` - End-entity certificate to verify.
    /// * `intermediates` - Intermediate certificates to a trust anchor.
    /// * `server_name` - Server DNS name.
    /// * `time` - Unix time the certificate was presented.
    ///
    /// [ph fork] Verified-chain cache. Inside the zkVM one session verifies the
    /// same chain once per call (about 15 M cycles each for a P-384 intermediate,
    /// which SP1 has no precompile for). After a full verification succeeds, the
    /// exact (chain, server name) is remembered with `[lo, hi]` = the
    /// intersection of the validity windows of *every presented* certificate.
    /// A later call with the same chain and name at a time `t` in `[lo, hi]` is
    /// accepted without re-verifying. That is exactly the full result:
    /// - the path webpki accepted earlier uses only presented certificates plus
    ///   a trust anchor of this verifier;
    /// - signatures, basic constraints, key usage, name constraints and the
    ///   subject-name check do not depend on time; validity windows are the only
    ///   time-dependent check (no revocation is configured), and trust anchors
    ///   carry none;
    /// - every presented certificate is valid at `t`, so that same path is valid
    ///   at `t`, and the full verification would accept.
    /// Any miss (other chain, name or time) falls back to full verification.
    pub fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        time: u64,
    ) -> Result<(), ServerCertVerifierError> {
        let key = chain_key(end_entity, intermediates, server_name);
        if let Some(&(lo, hi)) = self.verified.lock().unwrap().get(&key) {
            if lo <= time && time <= hi {
                return Ok(());
            }
        }
        self.verify_server_cert_uncached(end_entity, intermediates, server_name, time)?;
        let window = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|c| validity_window(&c.0))
            .try_fold((0u64, u64::MAX), |(lo, hi), w| {
                w.map(|(nb, na)| (lo.max(nb), hi.min(na)))
            });
        if let Some(w) = window {
            self.verified.lock().unwrap().insert(key, w);
        }
        Ok(())
    }

    /// The upstream verification (no cache).
    pub fn verify_server_cert_uncached(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        time: u64,
    ) -> Result<(), ServerCertVerifierError> {
        let cert = webpki_types::CertificateDer::from(end_entity.0.as_slice());
        let cert = webpki::EndEntityCert::try_from(&cert).map_err(|e| {
            ServerCertVerifierError::InvalidEndEntityCertificate {
                cert: end_entity.clone(),
                reason: e.to_string(),
            }
        })?;
        let intermediates = intermediates
            .iter()
            .map(|c| webpki_types::CertificateDer::from(c.0.as_slice()))
            .collect::<Vec<_>>();
        let server_name = server_name.to_webpki();
        let time = webpki_types::UnixTime::since_unix_epoch(Duration::from_secs(time));

        cert.verify_for_usage(
            ph_webpki_algs::ALL_VERIFICATION_ALGS, // [ph fork] was ring-backed
            &self.roots,
            &intermediates,
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(|_| ServerCertVerifierError::InvalidPath)?;

        cert.verify_is_valid_for_subject_name(&server_name)
            .map_err(|_| ServerCertVerifierError::InvalidServerName)?;

        Ok(())
    }
}

/// Error for [`ServerCertVerifier`].
#[derive(Debug, thiserror::Error)]
#[error("server certificate verification failed: {0}")]
pub enum ServerCertVerifierError {
    /// Root certificate store contains invalid certificate.
    #[error("root certificate store contains invalid certificate: {reason}")]
    InvalidRootCertificate {
        /// Invalid certificate.
        cert: CertificateDer,
        /// Reason for invalidity.
        reason: String,
    },
    /// End-entity certificate is invalid.
    #[error("end-entity certificate is invalid: {reason}")]
    InvalidEndEntityCertificate {
        /// Invalid certificate.
        cert: CertificateDer,
        /// Reason for invalidity.
        reason: String,
    },
    /// Failed to verify certificate path to provided trust anchors.
    #[error("failed to verify certificate path to provided trust anchors")]
    InvalidPath,
    /// Failed to verify certificate is valid for provided server name.
    #[error("failed to verify certificate is valid for provided server name")]
    InvalidServerName,
}
