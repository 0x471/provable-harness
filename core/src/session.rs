//! The agent loop. Pure: all I/O goes through the two backend traits, so the
//! exact same code drives the live run on the host and the replay in the zkVM.

use std::cell::RefCell;
use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::claim::{claim_salt, salted, Claim, Outcome, CLAIM_VERSION, SALT_FINAL_ANSWER, SALT_FINAL_WORKSPACE, SALT_TRANSCRIPT};
use crate::hash::{text_hash, Digest};
use crate::policy::Policy;
use crate::protocol::{context_append, context_genesis, model_request_hash, Message, ModelQuery, Role};
use crate::render::render_report;
use crate::script::{build_engine, init_rhai, run_native_turn, run_script, ToolEnv};
use crate::workspace::{Workspace, WorkspaceFile};
use crate::zktls::{ModelAuth, ToolAuth};
use crate::{HarnessError, ModelBackend, ToolBackend};

/// Opening fence of a code-mode action. The script runs to the next line that
/// starts with ``` (or to the end of the reply if the fence is never closed).
pub const SCRIPT_FENCE: &str = "```rhai\n";

/// Everything the session depends on besides model and tool I/O.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInput {
    /// Fresh per run; ideally a challenge chosen by the verifier.
    pub session_id: Digest,
    pub model_id: String,
    pub system_prompt: String,
    pub task: String,
    pub policy: Policy,
    pub workspace: Vec<WorkspaceFile>,
    /// How model replies are authenticated (gateway signature or zkTLS).
    pub model_auth: ModelAuth,
    /// How results of the external tools (`http_get`, `http_post`) are
    /// authenticated (oracle signature, zkTLS, or a committed fixture world).
    pub tool_auth: ToolAuth,
    /// In-guest grader, for sessions that are part of an eval.
    pub eval: Option<crate::eval::EvalSpec>,
    /// Code mode (```rhai scripts) or native tool use with declared tools.
    #[serde(default)]
    pub tool_mode: crate::native::ToolMode,
}

#[derive(Clone, Debug)]
pub struct SessionOutput {
    pub claim: Claim,
    pub messages: Vec<Message>,
    pub final_workspace: Vec<WorkspaceFile>,
    /// The action log's entries (`claim.action_log_hash` commits to them,
    /// salted with the run's blinding seed; see `script::disclose_actions`).
    pub actions: Vec<crate::script::ActionEntry>,
}

fn merge_ranges(a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Option<(u64, u64)> {
    match (a, b) {
        (Some((a0, a1)), Some((b0, b1))) => Some((a0.min(b0), a1.max(b1))),
        (x, None) | (None, x) => x,
    }
}

pub fn extract_script(text: &str) -> Option<&str> {
    let start = text.find(SCRIPT_FENCE)? + SCRIPT_FENCE.len();
    let body = &text[start..];
    if body.starts_with("```") {
        return Some("");
    }
    let end = body.find("\n```").unwrap_or(body.len());
    Some(&body[..end])
}

/// The final answer of a session, recomputed from its messages: what the claim
/// commits to in `final_answer_hash`. Used to check a disclosed transcript.
pub fn final_answer_of(messages: &[Message], outcome: Outcome) -> String {
    if outcome != Outcome::Completed {
        return String::new();
    }
    match messages.last() {
        Some(m) if m.role == Role::Assistant => m.content.clone(),
        Some(m) if m.role == Role::AssistantBlocks => crate::anthropic::blocks_of(&m.content)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| match b {
                        crate::anthropic::Block::Text(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Run a session. `blind` is a private per-run seed (random in live runs,
/// carried in the witness) that salts the action log's and the claim's
/// commitments to private data.
pub fn run_session(
    input: &SessionInput,
    blind: &crate::hash::Digest,
    model: &mut dyn ModelBackend,
    tools: Rc<RefCell<dyn ToolBackend>>,
) -> Result<SessionOutput, HarnessError> {
    init_rhai();
    input.policy.validate().map_err(HarnessError::InvalidInput)?;
    if input.model_id.is_empty() {
        return Err(HarnessError::InvalidInput("empty model_id".into()));
    }
    input.model_auth.validate().map_err(HarnessError::InvalidInput)?;
    if let ModelAuth::ZkTls(c) = &input.model_auth {
        if c.model != input.model_id {
            return Err(HarnessError::InvalidInput(
                "model_id must equal the zkTLS model".into(),
            ));
        }
    }
    input.tool_auth.validate().map_err(HarnessError::InvalidInput)?;
    input.tool_mode.validate().map_err(HarnessError::InvalidInput)?;
    let native = input.tool_mode.is_native();
    let tools_json = input.tool_mode.tools_json();
    if let Some(spec) = &input.eval {
        spec.validate().map_err(HarnessError::InvalidInput)?;
    }
    if let ToolAuth::ZkTls(_) = &input.tool_auth {
        // Only https can be notarized; reject the configuration up front rather
        // than failing (or diverging) on the first plain-http call.
        if let Some(p) = input
            .policy
            .net_get
            .iter()
            .chain(&input.policy.net_post)
            .find(|p| !p.starts_with("https://"))
        {
            return Err(HarnessError::InvalidInput(format!(
                "zkTLS tools need https:// allowlist entries, got {p}"
            )));
        }
    }
    let workspace = Workspace::new(&input.workspace).map_err(HarnessError::InvalidInput)?;
    let initial_workspace_root = workspace.root();

    let env = Rc::new(RefCell::new(ToolEnv::new(
        input.policy.clone(),
        input.session_id,
        workspace,
        tools.clone(),
        *blind,
    )));
    env.borrow_mut().eval = input.eval.clone();
    let engine = build_engine(&env, &input.policy);

    let mut messages = vec![Message {
        role: Role::User,
        content: input.task.clone(),
    }];
    let mut ctx = context_append(
        &context_genesis(&input.session_id, &input.model_id, &input.system_prompt, &tools_json),
        &messages[0],
    );

    let mut outcome = Outcome::StepLimit;
    let mut final_answer = String::new();
    let mut steps = 0u32;
    let mut scripts = 0u32;

    for step in 0..input.policy.max_steps {
        let query = ModelQuery {
            session_id: &input.session_id,
            model_id: &input.model_id,
            system_prompt: &input.system_prompt,
            tools: &tools_json,
            messages: &messages,
            step,
            request_hash: model_request_hash(&ctx, step),
        };
        let text = model.complete(&query)?;
        steps += 1;

        if native {
            // A reply that is not a blocks array (only possible from a gateway)
            // is taken as one text block.
            let blocks = crate::anthropic::blocks_of(&text)
                .unwrap_or_else(|_| vec![crate::anthropic::Block::Text(text.clone())]);
            let reply = Message {
                role: Role::AssistantBlocks,
                content: crate::anthropic::blocks_json(&blocks),
            };
            ctx = context_append(&ctx, &reply);
            messages.push(reply);
            let uses: Vec<(String, String, serde_json::Value)> = blocks
                .iter()
                .filter_map(|b| match b {
                    crate::anthropic::Block::ToolUse { id, name, input } => {
                        Some((id.clone(), name.clone(), input.clone()))
                    }
                    _ => None,
                })
                .collect();
            if uses.is_empty() {
                outcome = Outcome::Completed;
                final_answer = blocks
                    .iter()
                    .filter_map(|b| match b {
                        crate::anthropic::Block::Text(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .collect();
                break;
            }
            scripts += 1;
            let results = run_native_turn(&env, &input.tool_mode, &uses, input.policy.max_output_chars as usize)?;
            let tool_msg = Message {
                role: Role::ToolResults,
                content: results,
            };
            ctx = context_append(&ctx, &tool_msg);
            messages.push(tool_msg);
            continue;
        }

        let script = extract_script(&text).map(str::to_string);
        let reply = Message {
            role: Role::Assistant,
            content: text,
        };
        ctx = context_append(&ctx, &reply);
        messages.push(reply);

        match script {
            None => {
                outcome = Outcome::Completed;
                final_answer = messages.last().map(|m| m.content.clone()).unwrap_or_default();
                break;
            }
            Some(code) => {
                scripts += 1;
                let report = run_script(&engine, &env, &code)?;
                let tool_msg = Message {
                    role: Role::Tool,
                    content: render_report(&report, input.policy.max_output_chars as usize),
                };
                ctx = context_append(&ctx, &tool_msg);
                messages.push(tool_msg);
            }
        }
    }

    model.finish()?;
    tools.borrow_mut().finish()?;
    drop(engine);

    let env = env.borrow();
    // In-guest grading (eval sessions only).
    let eval = input.eval.as_ref().map(|spec| {
        spec.grade(
            env.counters.canary_attempts,
            env.counters.canary_leaks,
            &env.call_log,
            &final_answer,
            &env.workspace,
            tools.borrow().fixture_world().as_ref(),
        )
    });
    let claim = Claim {
        version: CLAIM_VERSION,
        session_id: input.session_id,
        model_id: input.model_id.clone(),
        model_auth_hash: input.model_auth.hash(),
        tool_auth_hash: input.tool_auth.hash(),
        tool_mode_hash: input.tool_mode.hash(),
        policy_hash: input.policy.hash(),
        system_prompt_hash: text_hash(&input.system_prompt),
        task_hash: text_hash(&input.task),
        initial_workspace_root,
        final_workspace_root: salted(&claim_salt(blind, SALT_FINAL_WORKSPACE), &env.workspace.root()),
        transcript_hash: salted(&claim_salt(blind, SALT_TRANSCRIPT), &ctx),
        action_log_hash: env.action_log,
        outcome,
        final_answer_hash: salted(&claim_salt(blind, SALT_FINAL_ANSWER), &text_hash(&final_answer)),
        final_answer: (!env.tainted).then_some(final_answer),
        steps,
        scripts,
        calls_allowed: env.counters.calls_allowed,
        calls_denied: env.counters.calls_denied,
        external_calls: env.counters.external_calls,
        tainted: env.tainted,
        tls_time_range: merge_ranges(model.attested_time_range(), tools.borrow().attested_time_range()),
        eval,
    };
    Ok(SessionOutput {
        claim,
        messages,
        final_workspace: env.workspace.export(),
        actions: env.actions.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::extract_script;

    #[test]
    fn script_extraction() {
        assert_eq!(extract_script("no code"), None);
        assert_eq!(extract_script("x\n```rhai\nlet a = 1;\na\n```\ny"), Some("let a = 1;\na"));
        assert_eq!(extract_script("```rhai\n```"), Some(""));
        assert_eq!(extract_script("```rhai\nlet a = 1;"), Some("let a = 1;"));
        assert_eq!(extract_script("```js\nfoo()\n```"), None);
    }

    #[test]
    fn final_answer_from_messages() {
        use super::final_answer_of;
        use crate::anthropic::{blocks_json, Block};
        use crate::claim::Outcome;
        use crate::protocol::{Message, Role};
        let m = |role, content: &str| Message { role, content: content.to_string() };
        let code = [m(Role::User, "t"), m(Role::Assistant, "done")];
        assert_eq!(final_answer_of(&code, Outcome::Completed), "done");
        assert_eq!(final_answer_of(&code, Outcome::StepLimit), "");
        let blocks = blocks_json(&[Block::Text("a".into()), Block::Text("b".into())]);
        let native = [m(Role::User, "t"), m(Role::AssistantBlocks, &blocks)];
        assert_eq!(final_answer_of(&native, Outcome::Completed), "ab");
    }
}
