//! SP1 integration: execute, prove, verify the harness guest.

use std::time::Instant;

use anyhow::{anyhow, Result};
use ph_core::{Claim, GuestInput, GuestOutput, Witness};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin};

/// The harness program. Its verifying key *is* the harness identity: a verifier
/// that trusts this program (built from reviewed source) trusts what it enforces.
pub const PH_ELF: Elf = include_elf!("ph-program");

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ProofMode {
    /// STARK shard proofs (size grows with execution length).
    Core,
    /// Recursively compressed to a single constant-size STARK.
    Compressed,
    /// The compressed STARK wrapped in a Groth16 (BN254) proof: ~260 bytes,
    /// zero-knowledge (gnark samples fresh randomness per proof; the STARK
    /// stays private), verifiable on chain. Needs `--features groth16`.
    Groth16,
}

fn stdin_for(input: &GuestInput) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input.to_bytes());
    stdin
}

fn session_claim(out: GuestOutput) -> Result<Claim> {
    match out {
        GuestOutput::Session(c) => Ok(c),
        GuestOutput::Eval(_) => Err(anyhow!("expected a session claim, got an eval report")),
    }
}

/// Execute the guest (no proof). Returns its public output and cycle count.
pub fn execute_input(input: &GuestInput) -> Result<(GuestOutput, u64)> {
    let client = ProverClient::builder().light().build();
    let (public_values, report) = client
        .execute(PH_ELF, stdin_for(input))
        .run()
        .map_err(|e| anyhow!("guest execution failed: {e}"))?;
    // A panicking guest (rejected input) still "executes"; check the exit code.
    if report.exit_code != 0 {
        return Err(anyhow!("guest rejected the input (exit code {})", report.exit_code));
    }
    let out = GuestOutput::from_bytes(public_values.as_slice()).map_err(|e| anyhow!(e))?;
    Ok((out, report.total_instruction_count()))
}

/// Execute one session. Returns the claim it commits and its cycle count.
pub fn execute(w: &Witness) -> Result<(Claim, u64)> {
    let (out, cycles) = execute_input(&GuestInput::Session(w.clone()))?;
    Ok((session_claim(out)?, cycles))
}

pub struct ProveOutcome {
    pub proof: SP1ProofWithPublicValues,
    pub vk_hash: String,
    pub seconds: f64,
}

pub fn prove(w: &Witness, mode: ProofMode) -> Result<ProveOutcome> {
    prove_input(&GuestInput::Session(w.clone()), mode)
}

pub fn prove_input(input: &GuestInput, mode: ProofMode) -> Result<ProveOutcome> {
    let client = ProverClient::builder().cpu().build();
    let pk = client
        .setup(PH_ELF)
        .map_err(|e| anyhow!("setup failed: {e}"))?;
    let start = Instant::now();
    let request = client.prove(&pk, stdin_for(input));
    let request = match mode {
        ProofMode::Core => request.core(),
        ProofMode::Compressed => request.compressed(),
        #[cfg(feature = "groth16")]
        ProofMode::Groth16 => request.groth16(),
        #[cfg(not(feature = "groth16"))]
        ProofMode::Groth16 => {
            return Err(anyhow!("Groth16 proving needs a build with `--features groth16` (Go, ~6.2 GB of circuit artifacts)"))
        }
    };
    let proof = request.run().map_err(|e| anyhow!("proving failed: {e}"))?;
    let seconds = start.elapsed().as_secs_f64();
    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| anyhow!("fresh proof does not verify: {e}"))?;
    Ok(ProveOutcome {
        proof,
        vk_hash: pk.verifying_key().bytes32(),
        seconds,
    })
}

/// Verify a single-session proof; returns its claim and the program vk hash.
pub fn verify(proof: &SP1ProofWithPublicValues) -> Result<(Claim, String)> {
    let (out, vk) = verify_output(proof)?;
    Ok((session_claim(out)?, vk))
}

/// Verify a proof against the harness program embedded in this binary.
/// Uses SP1's light verifier: real cryptographic verification, never mock.
pub fn verify_output(proof: &SP1ProofWithPublicValues) -> Result<(GuestOutput, String)> {
    let client = ProverClient::builder().light().build();
    let pk = client
        .setup(PH_ELF)
        .map_err(|e| anyhow!("setup failed: {e}"))?;
    let vk = pk.verifying_key().bytes32();
    if let sp1_sdk::SP1Proof::Groth16(_) = &proof.proof {
        // Standalone verifier (as on chain): proof bytes, public values, vk hash.
        sp1_verifier::Groth16Verifier::verify(
            &proof.bytes(),
            proof.public_values.as_slice(),
            &vk,
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|e| anyhow!("Groth16 proof verification failed: {e}"))?;
    }
    client
        .verify(proof, pk.verifying_key(), None)
        .map_err(|e| anyhow!("proof verification failed: {e}"))?;
    let out = GuestOutput::from_bytes(proof.public_values.as_slice()).map_err(|e| anyhow!(e))?;
    Ok((out, vk))
}

pub fn vk_hash() -> Result<String> {
    let client = ProverClient::builder().light().build();
    let pk = client
        .setup(PH_ELF)
        .map_err(|e| anyhow!("setup failed: {e}"))?;
    Ok(pk.verifying_key().bytes32())
}
