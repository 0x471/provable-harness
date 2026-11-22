//! `ph-core`: a sans-IO agent harness whose execution can be proven in a zkVM.
//!
//! The same code runs in two places:
//! - **host (live)**: backends perform real model / tool I/O and record each
//!   attested response (signature or zkTLS presentation) into a [`Witness`];
//! - **SP1 guest (replay)**: [`verify_witness`] re-runs the session from the
//!   witness, verifying every signature against digests it computes itself, and
//!   outputs a [`Claim`].
//!
//! Nothing in this crate touches the OS (no fs, net, clock, threads or randomness),
//! which is what makes it runnable inside the zkVM with plain `std`.

/// Version of the witness and eval-batch formats (and of what the guest
/// accepts). v3: action-log blinding seeds, stateful fixture banks, metered
/// scripts. Earlier formats had no version field.
pub const FORMAT_VERSION: u32 = 3;

/// Check the little-endian `u32` format version at byte `offset` of a bincode
/// encoding, so an old file fails with a clear message instead of a decode error.
pub fn check_format_prefix(bytes: &[u8], offset: usize) -> Result<(), String> {
    let v = bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or("truncated input")?;
    if v != FORMAT_VERSION {
        return Err(format!(
            "this file has format v{v} (or predates format versions); this harness reads v{FORMAT_VERSION}. \
             Use a `ph` built from the commit of the program vk the file was made for."
        ));
    }
    Ok(())
}

pub mod anthropic;
pub mod bank;
pub mod claim;
pub mod eval;
pub mod hash;
pub mod http;
pub mod native;
pub mod notary_log;
pub mod policy;
pub mod protocol;
pub mod render;
pub mod script;
pub mod session;
pub mod witness;
pub mod workspace;
pub mod zktls;

pub use claim::{Claim, Outcome};
pub use eval::{
    verify_eval, verify_guest_input, EvalBatch, EvalOutcome, EvalReport, EvalSpec, EvalSuite,
    GuestInput, GuestOutput, World,
};
pub use hash::Digest;
pub use policy::Policy;
pub use protocol::{Message, ModelQuery, ModelRequest, Role, ToolCall, ToolResult};
pub use session::{extract_script, run_session, SessionInput, SessionOutput};
pub use witness::{
    verify_witness, ModelEvidence, SignedText, SignedToolResult, ToolEvidence, Witness,
};
pub use zktls::{ModelAuth, NotaryKey, Slot, SlotKind, TlsRoots, ToolAuth, ToolTlsConfig, ZkTlsConfig};
pub use workspace::WorkspaceFile;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HarnessError {
    /// Session input is malformed (bad policy, workspace, keys).
    InvalidInput(String),
    /// A signature in the witness does not verify.
    Attestation(String),
    /// The witness has missing or extra entries.
    Witness(String),
    /// A live backend failed (network, gateway refused, ...).
    Backend(String),
}

impl core::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HarnessError::InvalidInput(e) => write!(f, "invalid input: {e}"),
            HarnessError::Attestation(e) => write!(f, "attestation failure: {e}"),
            HarnessError::Witness(e) => write!(f, "witness error: {e}"),
            HarnessError::Backend(e) => write!(f, "backend error: {e}"),
        }
    }
}

impl std::error::Error for HarnessError {}

/// Source of model replies.
pub trait ModelBackend {
    fn complete(&mut self, q: &ModelQuery<'_>) -> Result<String, HarnessError>;
    /// (min, max) notarized connection time over all replies, for zkTLS backends.
    fn attested_time_range(&self) -> Option<(u64, u64)> {
        None
    }
    /// Whether the reply just returned stopped at `max_tokens` (zkTLS backends:
    /// the attested `stop_reason`). The session runs nothing from such a reply.
    fn truncated(&self) -> bool {
        false
    }
    /// Called once after the session loop (replay checks the witness is fully used).
    fn finish(&mut self) -> Result<(), HarnessError> {
        Ok(())
    }
}

/// Executor of external (non-deterministic) tool calls.
pub trait ToolBackend {
    fn call(&mut self, call: &ToolCall) -> Result<ToolResult, HarnessError>;
    /// (min, max) notarized connection time over all results, for zkTLS backends.
    fn attested_time_range(&self) -> Option<(u64, u64)> {
        None
    }
    fn finish(&mut self) -> Result<(), HarnessError> {
        Ok(())
    }
    /// Final state of a fixture world (eval grading), for fixture backends.
    fn fixture_world(&self) -> Option<crate::eval::World> {
        None
    }
}
