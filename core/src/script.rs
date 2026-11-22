//! Code-mode execution: the model replies with a Rhai script; the script calls
//! tools; every call goes through the policy with its concrete runtime arguments.
//!
//! File tools execute here, inside the proof. Network tools go to the
//! [`ToolBackend`]: live HTTP on the host, signed witness entries in the zkVM.
//!
//! Soundness note: a backend failure (e.g. a forged attestation in the witness)
//! must abort the whole session. Rhai lets scripts `try { } catch { }` errors, and
//! errors raised inside script-defined functions are re-wrapped into a catchable
//! kind, so we cannot rely on the error type alone. Instead the failure is stored
//! in `ToolEnv::fatal`, every later call fails immediately, and `run_script`
//! returns the fatal error regardless of what the script did with it.

use std::cell::RefCell;
use std::rc::Rc;

use rhai::{Array, Dynamic, Engine, EvalAltResult, Position};

use crate::hash::{domain, text_hash, Digest, Hasher};
use crate::policy::{NetMethod, Policy};
use crate::protocol::ToolCall;
use crate::render;
use crate::workspace::Workspace;
use crate::{HarnessError, ToolBackend};

/// Stdout kept per script; the rendered tool message is capped separately.
const MAX_STDOUT_CHARS: usize = 64 * 1024;

/// Denied calls allowed per script before the script is terminated. Denied
/// calls do not consume the tool budget, so without this cap a
/// `loop { try { write_file(bad, big) } catch {} }` costs unbounded proving
/// work (each denial is hashed into the action log).
pub const MAX_DENIED_PER_SCRIPT: u32 = 16;

/// Fixed Rhai hashing seed so hashing never depends on process randomness.
const RHAI_HASHING_SEED: [u64; 4] = [0x7068_2d76_3100_0001, 2, 3, 4];

pub(crate) fn init_rhai() {
    // Errors only if already set, which is fine as long as it is our seed.
    let _ = rhai::config::hashing::set_hashing_seed(Some(RHAI_HASHING_SEED));
    assert_eq!(
        *rhai::config::hashing::get_hashing_seed(),
        Some(RHAI_HASHING_SEED),
        "rhai hashing seed must be fixed before any engine is built"
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallOutcome {
    Ok { chars: usize },
    Failed(String),
    Denied(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallRecord {
    pub tool: &'static str,
    pub args: Vec<String>,
    pub outcome: CallOutcome,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScriptReport {
    pub calls: Vec<CallRecord>,
    pub stdout: String,
    pub stdout_truncated: bool,
    pub value: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub calls_allowed: u32,
    pub calls_denied: u32,
    pub external_calls: u32,
    /// Eval grading: external calls whose arguments carry a canary.
    pub canary_attempts: u32,
    /// Eval grading: of those, the ones the policy allowed out.
    pub canary_leaks: u32,
}

pub const ACTION_OK: u8 = 1;
pub const ACTION_FAILED: u8 = 2;
pub const ACTION_DENIED: u8 = 3;

/// One tool call in the action log (OK, failed, or denied by the policy).
/// `detail` is the digest of the result, of the error, or of the denial reason.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActionEntry {
    pub tool: String,
    pub args: Vec<String>,
    pub kind: u8,
    pub detail: Digest,
}

/// Salt of field `j` of action `i` (`j = u64::MAX`: the detail). Derived from
/// the run's private blinding seed, so hidden fields cannot be brute-forced
/// from their commitments.
pub fn action_salt(blind: &Digest, i: u64, j: u64) -> Digest {
    let mut h = Hasher::new(domain::ACTION_SALT);
    h.digest(blind).u64(i).u64(j);
    h.finish()
}

pub fn action_field_commitment(salt: &Digest, text: &str) -> Digest {
    let mut h = Hasher::new(domain::ACTION_FIELD);
    h.digest(salt).str(text);
    h.finish()
}

/// One link of the action-log hash chain, over field commitments only, so a
/// log can be disclosed with any field hidden (see `disclose_actions`).
pub fn action_link(prev: &Digest, tool: &str, fields: &[Digest], kind: u8, detail: &Digest) -> Digest {
    let mut h = Hasher::new(domain::ACTION);
    h.digest(prev).str(tool).u64(fields.len() as u64);
    for f in fields {
        h.digest(f);
    }
    h.u8(kind).digest(detail);
    h.finish()
}

pub fn action_genesis(session_id: &Digest) -> Digest {
    let mut h = Hasher::new(domain::ACTION_GENESIS);
    h.digest(session_id);
    h.finish()
}

/// A field of a disclosed action: its text and salt, or only its commitment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Open { text: String, salt: String },
    Hidden { commitment: String },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DisclosedAction {
    pub tool: String,
    /// "ok", "failed" or "denied".
    pub outcome: String,
    pub args: Vec<Field>,
    /// The result digest (hex), as a field.
    pub detail: Field,
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        ACTION_OK => "ok",
        ACTION_FAILED => "failed",
        _ => "denied",
    }
}

/// Disclose a session's action log. `open(i, j)` decides whether field `j` of
/// action `i` is shown (`j = None`: the detail); hidden fields keep only their
/// salted commitment.
pub fn disclose_actions(
    blind: &Digest,
    actions: &[ActionEntry],
    open: impl Fn(usize, Option<usize>) -> bool,
) -> Vec<DisclosedAction> {
    let field = |i: usize, j: Option<usize>, text: &str| {
        let salt = action_salt(blind, i as u64, j.map_or(u64::MAX, |j| j as u64));
        if open(i, j) {
            Field::Open { text: text.to_string(), salt: crate::hash::to_hex(&salt) }
        } else {
            Field::Hidden { commitment: crate::hash::to_hex(&action_field_commitment(&salt, text)) }
        }
    };
    actions
        .iter()
        .enumerate()
        .map(|(i, a)| DisclosedAction {
            tool: a.tool.clone(),
            outcome: kind_name(a.kind).to_string(),
            args: a.args.iter().enumerate().map(|(j, x)| field(i, Some(j), x)).collect(),
            detail: field(i, None, &crate::hash::to_hex(&a.detail)),
        })
        .collect()
}

/// Recompute the action-log hash from a disclosure (what `ph verify` does).
pub fn action_log_of(session_id: &Digest, disclosed: &[DisclosedAction]) -> Result<Digest, String> {
    let commit = |f: &Field| -> Result<Digest, String> {
        match f {
            Field::Open { text, salt } => {
                let salt = crate::hash::from_hex32(salt).ok_or("bad salt")?;
                Ok(action_field_commitment(&salt, text))
            }
            Field::Hidden { commitment } => crate::hash::from_hex32(commitment).ok_or_else(|| "bad commitment".into()),
        }
    };
    let mut log = action_genesis(session_id);
    for a in disclosed {
        let kind = match a.outcome.as_str() {
            "ok" => ACTION_OK,
            "failed" => ACTION_FAILED,
            "denied" => ACTION_DENIED,
            _ => return Err(format!("unknown outcome {}", a.outcome)),
        };
        let fields = a.args.iter().map(commit).collect::<Result<Vec<_>, _>>()?;
        log = action_link(&log, &a.tool, &fields, kind, &commit(&a.detail)?);
    }
    Ok(log)
}

pub(crate) struct ToolEnv {
    pub policy: Policy,
    pub session_id: Digest,
    pub workspace: Workspace,
    pub tools: Rc<RefCell<dyn ToolBackend>>,
    pub next_seq: u64,
    pub tainted: bool,
    pub counters: Counters,
    /// Eval grader, if this session is part of an eval.
    pub eval: Option<crate::eval::EvalSpec>,
    /// Eval grading: allowed external calls that returned ok, as (tool, args).
    /// Recorded only when the grader has call checks.
    pub call_log: Vec<(String, Vec<String>)>,
    pub action_log: Digest,
    /// The log's entries (disclosed by the host, see `disclose_actions`).
    pub actions: Vec<ActionEntry>,
    /// Private blinding seed for the action log's field commitments.
    blind: Digest,
    pub fatal: Option<HarnessError>,
    report: ScriptReport,
    /// Characters in `report.stdout` (kept to avoid recounting on every print).
    stdout_chars: usize,
    /// Denied calls in the current script.
    script_denied: u32,
    /// Set when the current script must stop (checked by `on_progress`, which
    /// cannot be caught by the script).
    abort: Rc<core::cell::Cell<bool>>,
    /// Session-wide operation budget (checked by `on_progress`).
    ops: Rc<OpsMeter>,
}

/// Rhai operations used by finished scripts and by the running one, and the
/// session's data volume (see `Policy::max_session_data`).
pub(crate) struct OpsMeter {
    cap: u64,
    script_cap: u64,
    used: core::cell::Cell<u64>,
    current: core::cell::Cell<u64>,
    exhausted: core::cell::Cell<bool>,
    script_exhausted: core::cell::Cell<bool>,
    data_cap: u64,
    data_used: core::cell::Cell<u64>,
    data_exhausted: core::cell::Cell<bool>,
}

impl OpsMeter {
    /// Charge data-volume units; false once the session's budget is gone.
    fn charge(&self, units: u64) -> bool {
        let used = self.data_used.get().saturating_add(units);
        self.data_used.set(used);
        if used > self.data_cap {
            self.data_exhausted.set(true);
        }
        !self.data_exhausted.get()
    }

    fn charge_or_stop(&self, units: u64) -> Result<(), Box<EvalAltResult>> {
        if self.charge(units) {
            Ok(())
        } else {
            Err(terminated())
        }
    }
}

impl ToolEnv {
    pub fn new(
        policy: Policy,
        session_id: Digest,
        workspace: Workspace,
        tools: Rc<RefCell<dyn ToolBackend>>,
        blind: Digest,
    ) -> Self {
        let policy_session_ops = policy.max_session_operations;
        let policy_script_ops = policy.max_script_operations;
        let policy_session_data = policy.max_session_data;
        Self {
            policy,
            session_id,
            workspace,
            tools,
            next_seq: 0,
            tainted: false,
            counters: Counters::default(),
            eval: None,
            call_log: Vec::new(),
            action_log: action_genesis(&session_id),
            actions: Vec::new(),
            blind,
            fatal: None,
            report: ScriptReport::default(),
            stdout_chars: 0,
            script_denied: 0,
            abort: Rc::new(core::cell::Cell::new(false)),
            ops: Rc::new(OpsMeter {
                cap: policy_session_ops,
                script_cap: policy_script_ops,
                used: Default::default(),
                current: Default::default(),
                exhausted: Default::default(),
                script_exhausted: Default::default(),
                data_cap: policy_session_data,
                data_used: Default::default(),
                data_exhausted: Default::default(),
            }),
        }
    }

    fn log_action(&mut self, tool: &str, args: &[String], kind: u8, detail: &Digest) {
        let i = self.actions.len() as u64;
        let fields: Vec<Digest> = args
            .iter()
            .enumerate()
            .map(|(j, a)| action_field_commitment(&action_salt(&self.blind, i, j as u64), a))
            .collect();
        let detail_c = action_field_commitment(&action_salt(&self.blind, i, u64::MAX), &crate::hash::to_hex(detail));
        self.action_log = action_link(&self.action_log, tool, &fields, kind, &detail_c);
        self.actions.push(ActionEntry {
            tool: tool.to_string(),
            args: args.to_vec(),
            kind,
            detail: *detail,
        });
    }

    fn push_stdout(&mut self, s: &str) {
        if self.stdout_chars >= MAX_STDOUT_CHARS {
            self.report.stdout_truncated = true;
            return;
        }
        let room = MAX_STDOUT_CHARS - self.stdout_chars;
        let mut taken = 0;
        for c in s.chars().take(room) {
            self.report.stdout.push(c);
            taken += 1;
        }
        if taken < s.chars().count() {
            self.report.stdout_truncated = true;
        }
        self.report.stdout.push('\n');
        self.stdout_chars += taken + 1;
    }
}

fn runtime_error(msg: String) -> Box<EvalAltResult> {
    EvalAltResult::ErrorRuntime(msg.into(), Position::NONE).into()
}

/// Not catchable by `try/catch` at top level; see module docs for why we do not
/// rely on that alone.
fn terminated() -> Box<EvalAltResult> {
    EvalAltResult::ErrorTerminated(Dynamic::UNIT, Position::NONE).into()
}

/// Longest script the harness compiles. Parsing is not metered, so its cost is
/// bounded by the length.
pub const MAX_SCRIPT_BYTES: usize = 32 * 1024;

/// Meter units per input byte of `parse_json`, on top of the call's own charge.
const JSON_WEIGHT: u64 = 32;

/// Meter units per non-ASCII byte of a case mapping (`to_upper`, ...), on top of
/// the call's own charge: Unicode case tables cost far more than ASCII.
const CASE_WEIGHT: u64 = 32;

/// Meter units per match of `replace`: each costs a search restart and a copy.
const MATCH_WEIGHT: u64 = 16;

/// Meter units per Rhai operation. One operation costs up to ~4.6 K zkVM cycles
/// (comparing array elements in `in` or `==` calls back into Rhai). Charging
/// operations to the data meter too makes one budget bound both kinds of work:
/// with two separate budgets a script could spend both in full.
const OP_WEIGHT: u64 = 256;

fn data_too_large() -> Box<EvalAltResult> {
    EvalAltResult::ErrorDataTooLarge("Length of string".into(), Position::NONE).into()
}

/// `replace` as in Rhai's string package, but the result's length is checked
/// and charged before it is built: Rhai builds it first (512 MiB from a 64 KiB
/// string) and checks afterwards.
fn replace_checked(
    meter: &OpsMeter,
    max: usize,
    s: &mut rhai::ImmutableString,
    find: &str,
    sub: &str,
) -> Result<(), Box<EvalAltResult>> {
    if s.is_empty() {
        return Ok(());
    }
    let n = s.matches(find).count();
    let len = (s.len() - n * find.len()).saturating_add(n.saturating_mul(sub.len()));
    if len > max {
        return Err(data_too_large());
    }
    meter.charge_or_stop(1 + len as u64 + MATCH_WEIGHT * n as u64)?;
    *s = s.replace(find, sub).into();
    Ok(())
}

fn charge_case(meter: &OpsMeter, s: &str) -> Result<(), Box<EvalAltResult>> {
    let wide = s.bytes().filter(|b| !b.is_ascii()).count() as u64;
    meter.charge_or_stop(CASE_WEIGHT * wide)
}

/// Metered replacements for string functions whose cost Rhai's meter misses.
/// Behaviour is Rhai's own (same early returns), except that an oversized
/// `replace` fails before it changes the string.
fn register_metered_strings(engine: &mut Engine, meter: &Rc<OpsMeter>, max: usize) {
    use rhai::ImmutableString as S;
    let m = meter.clone();
    engine.register_fn("replace", move |s: &mut S, f: &str, r: &str| replace_checked(&m, max, s, f, r));
    let m = meter.clone();
    engine.register_fn("replace", move |s: &mut S, f: &str, r: char| {
        replace_checked(&m, max, s, f, &r.to_string())
    });
    let m = meter.clone();
    engine.register_fn("replace", move |s: &mut S, f: char, r: &str| {
        replace_checked(&m, max, s, &f.to_string(), r)
    });
    let m = meter.clone();
    engine.register_fn("replace", move |s: &mut S, f: char, r: char| {
        replace_checked(&m, max, s, &f.to_string(), &r.to_string())
    });
    let m = meter.clone();
    engine.register_fn("to_upper", move |s: S| -> Result<S, Box<EvalAltResult>> {
        charge_case(&m, &s)?;
        if s.chars().all(char::is_uppercase) {
            return Ok(s);
        }
        Ok(s.to_uppercase().into())
    });
    let m = meter.clone();
    engine.register_fn("make_upper", move |s: &mut S| -> Result<(), Box<EvalAltResult>> {
        charge_case(&m, s)?;
        if s.is_empty() || s.chars().all(char::is_uppercase) {
            return Ok(());
        }
        *s = s.to_uppercase().into();
        Ok(())
    });
    let m = meter.clone();
    engine.register_fn("to_lower", move |s: S| -> Result<S, Box<EvalAltResult>> {
        charge_case(&m, &s)?;
        if s.is_empty() || s.chars().all(char::is_lowercase) {
            return Ok(s);
        }
        Ok(s.to_lowercase().into())
    });
    let m = meter.clone();
    engine.register_fn("make_lower", move |s: &mut S| -> Result<(), Box<EvalAltResult>> {
        charge_case(&m, s)?;
        if s.is_empty() || s.chars().all(char::is_lowercase) {
            return Ok(());
        }
        *s = s.to_lowercase().into();
        Ok(())
    });
}

pub(crate) fn invoke(
    env: &Rc<RefCell<ToolEnv>>,
    tool: &'static str,
    args: Vec<String>,
) -> Result<Dynamic, Box<EvalAltResult>> {
    let mut guard = env.borrow_mut();
    let e = &mut *guard;
    if e.fatal.is_some() || e.abort.get() {
        return Err(terminated());
    }

    // Grading sees every attempted external call, before the policy decides.
    let carries_canary = matches!(tool, "http_get" | "http_post")
        && e.eval.as_ref().is_some_and(|spec| spec.carries_canary(&args));
    if carries_canary {
        e.counters.canary_attempts += 1;
    }

    let decision = if e.counters.calls_allowed >= e.policy.max_tool_calls {
        Err(format!(
            "tool call budget of {} exhausted",
            e.policy.max_tool_calls
        ))
    } else {
        match tool {
            "read_file" => e.policy.check_read(&args[0]),
            "list_files" => e.policy.check_list(&args[0]),
            "write_file" => e.policy.check_write(&args[0]),
            "http_get" => e.policy.check_net(NetMethod::Get, &args[0], e.tainted),
            "http_post" => e.policy.check_net(NetMethod::Post, &args[0], e.tainted),
            _ => Err("unknown tool".to_string()),
        }
    };
    if let Err(reason) = decision {
        e.counters.calls_denied += 1;
        e.script_denied += 1;
        if e.script_denied >= MAX_DENIED_PER_SCRIPT {
            e.abort.set(true);
        }
        e.log_action(tool, &args, ACTION_DENIED, &text_hash(&reason));
        let msg = format!("{tool}: denied by policy: {reason}");
        e.report.calls.push(CallRecord {
            tool,
            args,
            outcome: CallOutcome::Denied(reason),
        });
        return Err(runtime_error(msg));
    }
    e.counters.calls_allowed += 1;
    if carries_canary {
        e.counters.canary_leaks += 1;
    }

    // (value, detail digest for the action log) or error message.
    let result: Result<(Dynamic, usize, Digest), String> = match tool {
        "read_file" => {
            let found = e
                .workspace
                .read(&args[0])
                .map(|(c, secret)| (c.to_string(), secret));
            match found {
                Some((content, secret)) => {
                    if secret || e.policy.is_secret(&args[0]) {
                        e.tainted = true;
                    }
                    let n = content.chars().count();
                    let d = text_hash(&content);
                    Ok((Dynamic::from(content), n, d))
                }
                None => Err(format!("no such file: {}", args[0])),
            }
        }
        "list_files" => {
            let policy = &e.policy;
            let paths = e
                .workspace
                .list(&args[0], |p| policy.check_read(p).is_ok());
            // Names of secret files can carry secret data (a tainted script may
            // have written `/out/<secret>`), so listing one taints the session.
            if paths
                .iter()
                .any(|p| e.workspace.read(p).is_some_and(|(_, secret)| secret) || policy.is_secret(p))
            {
                e.tainted = true;
            }
            let joined = paths.join("\n");
            let arr: Array = paths.into_iter().map(Dynamic::from).collect();
            Ok((Dynamic::from(arr), joined.chars().count(), text_hash(&joined)))
        }
        "write_file" => {
            let tainted = e.tainted;
            e.workspace
                .write(&args[0], &args[1], tainted)
                .map(|()| (Dynamic::UNIT, args[1].chars().count(), text_hash(&args[1])))
        }
        "http_get" | "http_post" => {
            let call = ToolCall {
                session_id: e.session_id,
                seq: e.next_seq,
                tool: tool.to_string(),
                args: args.clone(),
            };
            e.next_seq += 1;
            e.counters.external_calls += 1;
            let res = e.tools.borrow_mut().call(&call);
            match res {
                Err(fatal) => {
                    e.fatal = Some(fatal);
                    return Err(terminated());
                }
                Ok(r) if r.ok => {
                    if e.eval.as_ref().is_some_and(|s| s.needs_call_log()) {
                        e.call_log.push((tool.to_string(), args.clone()));
                    }
                    let d = r.hash();
                    let n = r.output.chars().count();
                    Ok((Dynamic::from(r.output), n, d))
                }
                Ok(r) => {
                    // Log the attested result itself, then surface it as an error.
                    e.log_action(tool, &args, ACTION_FAILED, &r.hash());
                    let msg = format!("{tool} failed: {}", r.output);
                    e.report.calls.push(CallRecord {
                        tool,
                        args,
                        outcome: CallOutcome::Failed(r.output),
                    });
                    return Err(runtime_error(msg));
                }
            }
        }
        _ => unreachable!("decision rejects unknown tools"),
    };

    match result {
        Ok((value, chars, detail)) => {
            e.log_action(tool, &args, ACTION_OK, &detail);
            e.report.calls.push(CallRecord {
                tool,
                args,
                outcome: CallOutcome::Ok { chars },
            });
            Ok(value)
        }
        Err(err) => {
            e.log_action(tool, &args, ACTION_FAILED, &text_hash(&err));
            let msg = format!("{tool} failed: {err}");
            e.report.calls.push(CallRecord {
                tool,
                args,
                outcome: CallOutcome::Failed(err),
            });
            Err(runtime_error(msg))
        }
    }
}

pub(crate) fn build_engine(env: &Rc<RefCell<ToolEnv>>, policy: &Policy) -> Engine {
    let mut engine = Engine::new();
    engine
        // The harness counts operations itself (`on_progress` below); Rhai's
        // own limit, one past it, is only a backstop.
        .set_max_operations(policy.max_script_operations.saturating_add(1))
        .set_max_string_size(policy.max_string_bytes as usize)
        .set_max_array_size(4096)
        .set_max_map_size(4096)
        .set_max_call_levels(32)
        .set_max_expr_depths(64, 32);
    // The optimizer folds constants at compile time, where no meter runs: a few
    // nested `const` arrays built 10^6 elements before the script started.
    engine.set_optimization_level(rhai::OptimizationLevel::None);
    engine.disable_symbol("eval");
    // Rhai's core package ships `sleep`, which would block the live host and
    // panic inside the zkVM (no threads). The harness must never touch the OS.
    engine.register_fn("sleep", |_: rhai::INT| -> Result<(), Box<EvalAltResult>> {
        Err(runtime_error("sleep is not available".into()))
    });
    // Operators must be native calls so the data-volume meter sees them.
    engine.set_fast_operators(false);
    let meter = env.borrow().ops.clone();
    engine.on_data_volume(move |units| (!meter.charge(units)).then_some(Dynamic::UNIT));
    let abort = env.borrow().abort.clone();
    let ops = env.borrow().ops.clone();
    engine.on_progress(move |_| {
        // Rhai's own count restarts in every callback a native function makes
        // (`map`, `sort`, ...: each gets a copy of the runtime state), so the
        // harness counts the calls of this hook. Exhaustion is sticky: if a
        // native function swallows the error, the next operation stops again.
        let n = ops.current.get() + 1;
        ops.current.set(n);
        ops.charge(OP_WEIGHT);
        if n > ops.script_cap {
            ops.script_exhausted.set(true);
        }
        if ops.used.get().saturating_add(n) > ops.cap {
            ops.exhausted.set(true);
        }
        let stop = ops.data_exhausted.get() || ops.exhausted.get() || ops.script_exhausted.get();
        (stop || abort.get()).then_some(Dynamic::UNIT)
    });

    // Deterministic, JSON-valued rendering (see render.rs): override Rhai's
    // `{:?}`-based formatting of arrays, maps, and debug strings. Functions
    // registered on the engine take precedence over the standard packages, and
    // `print`, `+`, string interpolation all resolve `to_string` by name.
    for name in ["to_string", "print", "to_debug", "debug", "to_json"] {
        engine.register_fn(name, |a: &mut Array| render::value_json(&Dynamic::from_array(a.clone())));
        engine.register_fn(name, |m: &mut rhai::Map| render::value_json(&Dynamic::from_map(m.clone())));
    }
    for name in ["to_debug", "debug"] {
        engine.register_fn(name, |s: &str| render::json_quote(s));
        engine.register_fn(name, |c: char| render::json_quote(c.encode_utf8(&mut [0u8; 4])));
    }
    let m = env.borrow().ops.clone();
    engine.register_fn("parse_json", move |s: &str| -> Result<Dynamic, Box<EvalAltResult>> {
        m.charge_or_stop(JSON_WEIGHT * s.len() as u64)?;
        render::parse_json(s).map_err(runtime_error)
    });
    register_metered_strings(&mut engine, &env.borrow().ops, policy.max_string_bytes as usize);

    let e = env.clone();
    engine.on_print(move |s| e.borrow_mut().push_stdout(s));
    let e = env.clone();
    engine.on_debug(move |s, _, _| e.borrow_mut().push_stdout(s));

    let e = env.clone();
    engine.register_fn("read_file", move |path: &str| {
        invoke(&e, "read_file", vec![path.to_string()])
    });
    let e = env.clone();
    engine.register_fn("list_files", move |dir: &str| {
        invoke(&e, "list_files", vec![dir.to_string()])
    });
    let e = env.clone();
    engine.register_fn("write_file", move |path: &str, content: Dynamic| {
        invoke(&e, "write_file", vec![path.to_string(), render::value_text(&content)])
    });
    let e = env.clone();
    engine.register_fn("http_get", move |url: &str| {
        invoke(&e, "http_get", vec![url.to_string()])
    });
    let e = env.clone();
    engine.register_fn("http_post", move |url: &str, body: Dynamic| {
        invoke(&e, "http_post", vec![url.to_string(), render::value_text(&body)])
    });
    engine
}

/// Native tool use: run one assistant turn's `tool_use` blocks, in order, and
/// return the canonical `tool_result` array. Every call goes through `invoke`
/// (policy, budgets, taint, action log, backends), exactly like a script call.
pub(crate) fn run_native_turn(
    env: &Rc<RefCell<ToolEnv>>,
    mode: &crate::native::ToolMode,
    uses: &[(String, String, serde_json::Value)],
    max_chars: usize,
) -> Result<String, HarnessError> {
    {
        let mut e = env.borrow_mut();
        e.report = ScriptReport::default();
        e.script_denied = 0;
        e.abort.set(false);
    }
    let mut out = String::from("[");
    for (i, (id, name, input)) in uses.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let (text, is_error) = match mode.tool(name) {
            None => (format!("unknown tool {name}"), true),
            Some(t) => match crate::native::harness_call(&t.binding, input) {
                Err(m) => (format!("invalid input: {m}"), true),
                Ok((tool, args)) => match invoke(env, tool, args) {
                    Ok(v) if v.is_unit() => ("ok".to_string(), false),
                    Ok(v) => (render::value_text(&v), false),
                    Err(err) => {
                        if let Some(fatal) = env.borrow_mut().fatal.take() {
                            return Err(fatal);
                        }
                        let msg = match *err {
                            EvalAltResult::ErrorRuntime(d, _) => render::value_text(&d),
                            _ => format!(
                                "not executed: this turn made {MAX_DENIED_PER_SCRIPT} denied tool calls"
                            ),
                        };
                        (msg, true)
                    }
                },
            },
        };
        crate::anthropic::tool_result_block(&mut out, id, &render::truncate_chars(&text, max_chars), is_error);
    }
    out.push(']');
    Ok(out)
}

pub(crate) fn run_script(
    engine: &Engine,
    env: &Rc<RefCell<ToolEnv>>,
    code: &str,
) -> Result<ScriptReport, HarnessError> {
    {
        let mut e = env.borrow_mut();
        e.report = ScriptReport::default();
        e.stdout_chars = 0;
        e.script_denied = 0;
        e.abort.set(false);
        e.ops.current.set(0);
        e.ops.script_exhausted.set(false);
    }
    if code.len() > MAX_SCRIPT_BYTES {
        return Ok(ScriptReport {
            error: Some(format!(
                "script not run: it has {} bytes, the limit is {MAX_SCRIPT_BYTES}",
                code.len()
            )),
            ..ScriptReport::default()
        });
    }
    let res = engine.eval::<Dynamic>(code);
    let mut e = env.borrow_mut();
    let used = e.ops.used.get().saturating_add(e.ops.current.get());
    e.ops.used.set(used);
    if let Some(fatal) = e.fatal.take() {
        return Err(fatal);
    }
    let mut report = core::mem::take(&mut e.report);
    if e.abort.get() {
        report.error = Some(format!(
            "script terminated after {MAX_DENIED_PER_SCRIPT} denied tool calls"
        ));
        return Ok(report);
    }
    if e.ops.data_exhausted.get() {
        report.error = Some(format!(
            "script terminated: the session's data budget of {} units is exhausted",
            e.ops.data_cap
        ));
        return Ok(report);
    }
    if e.ops.exhausted.get() {
        report.error = Some(format!(
            "script terminated: the session's budget of {} operations is exhausted",
            e.ops.cap
        ));
        return Ok(report);
    }
    if e.ops.script_exhausted.get() {
        report.error = Some(format!(
            "script terminated: it used more than {} operations",
            e.ops.script_cap
        ));
        return Ok(report);
    }
    match res {
        Ok(v) => report.value = Some(render::value_text(&v)),
        Err(err) => report.error = Some(render::error_text(&err)),
    }
    Ok(report)
}
