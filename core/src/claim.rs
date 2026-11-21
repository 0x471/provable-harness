//! The public statement proven by the zkVM (the SP1 public values).

use serde::{Deserialize, Serialize};

use crate::hash::{to_hex, Digest};

pub const CLAIM_VERSION: u32 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The model produced a final answer (a reply without a script).
    Completed,
    /// `max_steps` model turns were used without a final answer.
    StepLimit,
}

/// "Harness program H (identified by the SP1 verifying key), given these
/// commitments, executed this session and produced these results."
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub version: u32,
    pub session_id: Digest,
    pub model_id: String,
    /// Hash of the model-authentication config (gateway key, or zkTLS notary
    /// key + host + roots + model + max_tokens): see `ModelAuth::hash`.
    pub model_auth_hash: Digest,
    /// Hash of the tool-authentication config (oracle key, or zkTLS notary key
    /// + roots): see `ToolAuth::hash`.
    pub tool_auth_hash: Digest,
    /// Code mode, or the native tool definitions and bindings.
    pub tool_mode_hash: Digest,
    pub policy_hash: Digest,
    pub system_prompt_hash: Digest,
    pub task_hash: Digest,
    pub initial_workspace_root: Digest,
    pub final_workspace_root: Digest,
    /// Context-chain hash over every message (task, replies, tool results).
    pub transcript_hash: Digest,
    /// Hash chain over every tool call: name, args, allow/deny, result digest.
    pub action_log_hash: Digest,
    pub outcome: Outcome,
    /// `text_hash` of the model's final message.
    pub final_answer_hash: Digest,
    /// The final message itself, only if the session is untainted: a tainted
    /// session may have put secret data into it, and the claim is public.
    pub final_answer: Option<String>,
    pub steps: u32,
    pub scripts: u32,
    pub calls_allowed: u32,
    pub calls_denied: u32,
    pub external_calls: u32,
    /// Whether the session read secret-labelled data.
    pub tainted: bool,
    /// zkTLS only: (earliest, latest) notarized connection time over model and
    /// tool exchanges, unix seconds.
    pub tls_time_range: Option<(u64, u64)>,
    /// Eval sessions only: the in-guest grader's verdict.
    pub eval: Option<crate::eval::EvalOutcome>,
}

fn grade_str(g: Option<bool>) -> &'static str {
    match g {
        None => "-",
        Some(true) => "yes",
        Some(false) => "no",
    }
}

impl Claim {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("claim serialization cannot fail")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        bincode::deserialize(b).map_err(|e| format!("malformed claim: {e}"))
    }

    /// Human-readable, stable rendering (used by the CLI).
    pub fn pretty(&self) -> String {
        let outcome = match self.outcome {
            Outcome::Completed => "completed",
            Outcome::StepLimit => "step-limit",
        };
        format!(
            "claim v{}\n  session_id           {}\n  model_id             {}\n  model_auth_hash      {}\n  tool_auth_hash       {}\n  tool_mode_hash       {}\n  policy_hash          {}\n  system_prompt_hash   {}\n  task_hash            {}\n  workspace root       {} -> {}\n  transcript_hash      {}\n  action_log_hash      {}\n  outcome              {}\n  steps / scripts      {} / {}\n  calls allowed/denied {} / {}\n  external calls       {}\n  tainted              {}\n  tls time range       {}\n  final_answer         {}",
            self.version,
            to_hex(&self.session_id),
            self.model_id,
            to_hex(&self.model_auth_hash),
            to_hex(&self.tool_auth_hash),
            to_hex(&self.tool_mode_hash),
            to_hex(&self.policy_hash),
            to_hex(&self.system_prompt_hash),
            to_hex(&self.task_hash),
            to_hex(&self.initial_workspace_root),
            to_hex(&self.final_workspace_root),
            to_hex(&self.transcript_hash),
            to_hex(&self.action_log_hash),
            outcome,
            self.steps,
            self.scripts,
            self.calls_allowed,
            self.calls_denied,
            self.external_calls,
            self.tainted,
            match self.tls_time_range {
                Some((a, b)) => format!("{a}..={b}"),
                None => "-".to_string(),
            },
            match &self.final_answer {
                Some(a) => crate::render::quote_preview(a, 400),
                None => format!("(withheld: tainted session) hash {}", crate::hash::to_hex(&self.final_answer_hash)),
            },
        ) + match &self.eval {
            None => String::new(),
            Some(e) => format!(
                "\n  eval grade           canary attempts {} / leaks {}, canary in answer {}, task completed {}, utility {}, attack succeeded {}",
                e.canary_attempts,
                e.canary_leaks,
                e.canary_in_final_answer,
                grade_str(e.task_completed),
                grade_str(e.utility),
                grade_str(e.attack_succeeded)
            ),
        }
        .as_str()
    }
}
