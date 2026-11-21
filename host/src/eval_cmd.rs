//! `ph eval`: provable evaluations.
//!
//!   ph eval seed                                   (verifier: a fresh challenge)
//!   ph eval run    --suite DIR --seed HEX --out DIR --zktls-config C --zktls-proxy URL
//!                  [--prove none|compressed]       (operator)
//!   ph eval verify --suite DIR --seed HEX --dir DIR --zktls-config C
//!                  [--tls-max-age-secs N]          (verifier)
//!
//! A suite directory holds `scenario.json` (task, system prompt), `policy.json`,
//! `workspace/`, and `suite.json` (name, repeats, grader spec, cases with one
//! fixture world each).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ph_core::eval::{Check, EvalCase, EvalReport, RunEvidence, EVAL_REPORT_VERSION};
use ph_core::hash::{from_hex32, to_hex, Digest};
use ph_core::{
    EvalBatch, EvalSpec, EvalSuite, GuestInput, GuestOutput, ModelAuth, World, WorkspaceFile, ZkTlsConfig,
};
use serde::Deserialize;
use sp1_sdk::SP1ProofWithPublicValues;

use crate::prover::{self, ProofMode};
use crate::scenario::Scenario;

#[derive(Deserialize)]
struct SuiteFile {
    name: String,
    repeats: u32,
    spec: EvalSpec,
    cases: Vec<CaseFile>,
}

#[derive(Deserialize)]
struct CaseFile {
    name: String,
    world: PathBuf,
    /// Overrides the suite task for this case.
    #[serde(default)]
    task: Option<String>,
    /// Workspace files added for this case (same path: replaced).
    #[serde(default)]
    files: Vec<WorkspaceFile>,
    #[serde(default)]
    utility: Vec<Check>,
    #[serde(default)]
    attack: Vec<Check>,
}

pub fn load_suite(dir: &Path) -> Result<EvalSuite> {
    let base = Scenario::load(dir)?;
    let sf: SuiteFile = serde_json::from_str(
        &fs::read_to_string(dir.join("suite.json")).context("reading suite.json")?,
    )
    .context("parsing suite.json")?;
    let cases = sf
        .cases
        .into_iter()
        .map(|c| {
            let p = dir.join(&c.world);
            let world: World = serde_json::from_str(
                &fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?,
            )
            .with_context(|| format!("parsing {}", p.display()))?;
            Ok(EvalCase {
                name: c.name,
                world,
                task: c.task,
                files: c.files,
                utility: c.utility,
                attack: c.attack,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let suite = EvalSuite {
        name: sf.name,
        system_prompt: base.system_prompt,
        task: base.task,
        policy: base.policy,
        workspace: base.workspace,
        spec: sf.spec,
        cases,
        repeats: sf.repeats,
        tool_mode: base.tool_mode,
    };
    suite.validate().map_err(|e| anyhow!("suite: {e}"))?;
    Ok(suite)
}

fn parse_seed(s: &str) -> Result<Digest> {
    from_hex32(s).ok_or_else(|| anyhow!("--seed must be 32 bytes of hex"))
}

pub fn fresh_seed() -> Result<String> {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s)?;
    Ok(to_hex(&s))
}

/// Operator: run every case of the suite against the live (zkTLS) model.
pub fn run(
    suite_dir: &Path,
    seed: &str,
    out: &Path,
    config: ZkTlsConfig,
    proxy: &str,
    prove: &str,
) -> Result<()> {
    let suite = load_suite(suite_dir)?;
    let seed = parse_seed(seed)?;
    let model_auth = ModelAuth::ZkTls(config.clone());
    let model_id = config.model.clone();
    fs::create_dir_all(out)?;
    println!(
        "eval {} ({} cases x {} repeats), suite hash {}, seed {}",
        suite.name,
        suite.cases.len(),
        suite.repeats,
        to_hex(&suite.hash()),
        to_hex(&seed)
    );
    let mut runs = vec![];
    for (case, repeat) in suite.runs() {
        let input = suite.session_input(&seed, case, repeat, &model_id, &model_auth);
        let label = format!("{} #{repeat}", suite.cases[case].name);
        match crate::live::run_live(&input, "", Some(proxy), None) {
            Ok((output, witness)) => {
                let c = &output.claim;
                let e = c.eval.as_ref().expect("eval session has a grade");
                println!(
                    "  {label:<28} {:?} steps {} secret {} attempts {} leaks {} task {} utility {} attack {}",
                    c.outcome,
                    c.steps,
                    c.tainted,
                    e.canary_attempts,
                    e.canary_leaks,
                    g(e.task_completed),
                    g(e.utility),
                    g(e.attack_succeeded)
                );
                let dir = out.join(format!("run-{case:02}-{repeat:02}"));
                fs::create_dir_all(&dir)?;
                fs::write(
                    dir.join("transcript.json"),
                    serde_json::to_string_pretty(&serde_json::json!({
                        "session_id": to_hex(&input.session_id),
                        "case": suite.cases[case].name,
                        "repeat": repeat,
                        "messages": output.messages,
                    }))?,
                )?;
                fs::write(dir.join("final_workspace.json"), serde_json::to_string_pretty(&output.final_workspace)?)?;
                crate::write_actions(&dir, &output, &witness.blind)?;
                runs.push(Some(RunEvidence {
                    blind: witness.blind,
                    model_responses: witness.model_responses,
                }));
            }
            Err(e) => {
                // The slot is burned; the run is reported as missing, not retried.
                println!("  {label:<24} MISSING: {e:#}");
                runs.push(None);
            }
        }
    }
    let batch = EvalBatch {
        version: ph_core::FORMAT_VERSION,
        suite,
        seed,
        model_id,
        model_auth,
        runs,
    };
    let input = GuestInput::Eval(batch);
    fs::write(out.join("eval-input.bin"), input.to_bytes())?;

    // Fail fast with the exact guest logic, natively.
    let native = ph_core::verify_guest_input(&input).map_err(|e| anyhow!("native replay: {e}"))?;
    let GuestOutput::Eval(report) = &native else { bail!("unexpected output") };
    print_report_named(report, None, Some(&batch_suite_for_names(&input)));
    fs::write(out.join("report.json"), report_json(report)?)?;

    println!("executing the eval in SP1 ...");
    let (guest, cycles) = prover::execute_input(&input)?;
    if guest != native {
        bail!("zkVM report differs from the native replay");
    }
    println!("zkVM execution OK: {cycles} cycles, report matches native replay");
    match prove {
        "none" => {}
        "compressed" | "core" => {
            let mode = if prove == "core" { ProofMode::Core } else { ProofMode::Compressed };
            println!("proving ({mode:?}) ... this takes a while on CPU");
            let o = prover::prove_input(&input, mode)?;
            if GuestOutput::from_bytes(o.proof.public_values.as_slice()).map_err(|e| anyhow!(e))? != native {
                bail!("proven report differs from the native replay");
            }
            o.proof.save(out.join("proof.bin"))?;
            println!("proof written to {} ({:.1}s, vk {})", out.join("proof.bin").display(), o.seconds, o.vk_hash);
        }
        other => bail!("--prove must be none|core|compressed, got {other}"),
    }
    Ok(())
}

/// Operator: prove a recorded eval (no model calls: the notary would refuse them,
/// every slot is already used).
pub fn prove(dir: &Path, mode: ProofMode) -> Result<()> {
    let input = GuestInput::from_bytes(&fs::read(dir.join("eval-input.bin"))?).map_err(|e| anyhow!(e))?;
    let native = ph_core::verify_guest_input(&input).map_err(|e| anyhow!("native replay: {e}"))?;
    println!("proving ({mode:?}) ... this takes a while on CPU");
    let o = prover::prove_input(&input, mode)?;
    if GuestOutput::from_bytes(o.proof.public_values.as_slice()).map_err(|e| anyhow!(e))? != native {
        bail!("proven report differs from the native replay");
    }
    o.proof.save(dir.join("proof.bin"))?;
    println!("proof written to {} ({:.1}s, vk {})", dir.join("proof.bin").display(), o.seconds, o.vk_hash);
    Ok(())
}

/// Verifier: check the proof and every field of the report against the verifier's
/// own suite, seed and pinned model config.
/// Where the verifier's seed comes from.
pub enum SeedSource {
    /// Chosen by the verifier (hex).
    Given(String),
    /// Derived from a pre-registered drand round.
    Beacon { prereg: crate::beacon::Prereg, beacon: crate::beacon::Beacon },
}

pub fn verify(
    suite_dir: &Path,
    seed_source: &SeedSource,
    dir: &Path,
    config: &ZkTlsConfig,
    tls_max_age_secs: Option<u64>,
    notary_log: Option<&Path>,
) -> Result<EvalReport> {
    let suite = load_suite(suite_dir)?;
    let seed = match seed_source {
        SeedSource::Given(s) => parse_seed(s)?,
        SeedSource::Beacon { prereg, beacon } => crate::beacon::seed_from(prereg, beacon)?,
    };
    let proof = SP1ProofWithPublicValues::load(dir.join("proof.bin"))
        .with_context(|| format!("loading {}", dir.join("proof.bin").display()))?;
    let (out, vk) = prover::verify_output(&proof)?;
    println!("SP1 proof valid for harness program vk {vk}");
    let GuestOutput::Eval(report) = out else { bail!("proof is for a single session, not an eval") };

    let model_auth = ModelAuth::ZkTls(config.clone());
    let mut fails = vec![];
    let mut check = |ok: bool, what: String| {
        println!("  [{}] {what}", if ok { "ok" } else { "FAIL" });
        if !ok {
            fails.push(what);
        }
    };
    check(report.version == EVAL_REPORT_VERSION, format!("report version {}", report.version));
    check(report.suite_hash == suite.hash(), format!("suite {} hash {}", suite.name, to_hex(&suite.hash())));
    check(report.seed == seed, format!("seed (the verifier's challenge) {}", to_hex(&seed)));
    check(report.model_auth_hash == model_auth.hash(), format!("zkTLS config pinned (notary {}, model {})", to_hex(&config.notary.key), config.model));
    check(report.model_id == config.model, format!("model id {}", report.model_id));
    let plan = suite.runs();
    let ids_ok = report.runs.len() == plan.len()
        && report.runs.iter().zip(&plan).all(|(r, &(c, k))| {
            r.case as usize == c && r.repeat == k && r.session_id == suite.session_id(&seed, c, k)
        });
    check(ids_ok, format!("all {} runs present in order, session ids derived from the seed", plan.len()));
    let times: Vec<(u64, u64)> = report
        .runs
        .iter()
        .filter_map(|r| r.claim.as_ref().and_then(|c| c.tls_time_range))
        .collect();
    if let (Some(lo), Some(hi)) = (times.iter().map(|t| t.0).min(), times.iter().map(|t| t.1).max()) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let fresh = tls_max_age_secs.is_none_or(|m| now.saturating_sub(lo) <= m) && hi <= now + 300;
        check(fresh, format!("notarized times {lo}..={hi} (now {now})"));
    }
    if let SeedSource::Beacon { prereg, beacon } = seed_source {
        println!("  seed from drand quicknet round {} (BLS signature verified), pre-registration {}", beacon.round, to_hex(&prereg.hash()));
        check(prereg.suite_hash == to_hex(&suite.hash()), "pre-registered suite".into());
        check(prereg.model_auth_hash == to_hex(&model_auth.hash()) && prereg.model_id == report.model_id, "pre-registered model and notary".into());
        check(prereg.program_vk == vk, format!("pre-registered program vk {}", prereg.program_vk));
        let first = times.iter().map(|t| t.0).min();
        check(
            first.is_some_and(|t| t >= prereg.beacon_time),
            format!("every run notarized after the beacon round (round at {}, first run at {:?})", prereg.beacon_time, first),
        );
    }
    if let Some(path) = notary_log {
        let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let log: ph_core::notary_log::SessionLog = serde_json::from_str(&text)?;
        let sig = log.verify(&config.notary);
        check(sig.is_ok(), format!("notary session log signed by the pinned notary{}", sig.err().map(|e| format!(": {e}")).unwrap_or_default()));
        let all: Vec<String> = report.runs.iter().map(|r| to_hex(&r.session_id)).collect();
        check(all.iter().all(|s| log.sessions.contains(s)), format!("log covers all {} sessions of this eval", all.len()));
        let last = times.iter().map(|t| t.1).max().unwrap_or(0);
        check(log.generated_at >= last, format!("log generated at {} (after the last notarized time {last})", log.generated_at));
        let names = |r: &ph_core::eval::RunReport| format!("{}#{}", suite.cases[r.case as usize].name, r.repeat);
        let (mut never, mut aborted, mut withheld) = (vec![], vec![], vec![]);
        let mut inconsistent = vec![];
        for r in &report.runs {
            use ph_core::notary_log::{reconcile, RunVerdict};
            match reconcile(&log, &to_hex(&r.session_id), r.claim.as_ref().map(|c| c.steps), false) {
                RunVerdict::Consistent => {}
                RunVerdict::Inconsistent(why) => inconsistent.push(format!("{}: {why}", names(r))),
                RunVerdict::NeverStarted => never.push(names(r)),
                RunVerdict::Aborted { slot } => aborted.push(format!("{} (during {})", names(r), short_slot(&slot))),
                RunVerdict::Withheld { signed } => withheld.push(format!("{} ({signed} signed model replies)", names(r))),
            }
        }
        check(inconsistent.is_empty(), format!("delivered runs match the notary log{}", if inconsistent.is_empty() { String::new() } else { format!(": {}", inconsistent.join("; ")) }));
        let missing = report.runs.iter().filter(|r| r.claim.is_none()).count();
        println!("  missing runs per the notary log: {missing} total, {} never started, {} aborted, {} WITHHELD", never.len(), aborted.len(), withheld.len());
        for (label, v) in [("never started", &never), ("aborted", &aborted), ("WITHHELD (completed, not delivered)", &withheld)] {
            for x in v.iter() {
                println!("    {label}: {x}");
            }
        }
    }
    print_report_named(&report, Some(&vk), Some(&suite));
    if !fails.is_empty() {
        bail!("eval verification FAILED: {}", fails.join("; "));
    }
    println!(
        "VERIFIED: every delivered run of suite {} ran under the published configuration for seed {}, with genuine model replies; grades were computed in the proof.",
        suite.name,
        to_hex(&seed)
    );
    Ok(report)
}

/// "model 1f2e...9a 3" for display.
fn short_slot(text: &str) -> String {
    let mut it = text.split(' ');
    match (it.next(), it.next(), it.next()) {
        (Some(k), Some(s), Some(n)) if s.len() == 64 => format!("{k} {}...{} step {n}", &s[..4], &s[60..]),
        _ => text.to_string(),
    }
}

fn g(v: Option<bool>) -> &'static str {
    match v {
        None => "-",
        Some(true) => "yes",
        Some(false) => "no",
    }
}

fn batch_suite_for_names(input: &GuestInput) -> EvalSuite {
    match input {
        GuestInput::Eval(b) => b.suite.clone(),
        GuestInput::Session(_) => unreachable!("eval input"),
    }
}

fn print_report_named(r: &EvalReport, vk: Option<&str>, suite: Option<&EvalSuite>) {
    println!(
        "\neval report: {} ({} runs){}",
        r.suite_name,
        r.totals.runs,
        vk.map(|v| format!(", vk {v}")).unwrap_or_default()
    );
    println!(
        "  {:<34} {:>9} {:>7} {:>9} {:>6} {:>5} {:>8} {:>7}",
        "run", "outcome", "secret", "attempts", "leaks", "task", "utility", "attack"
    );
    for run in &r.runs {
        let case = suite
            .and_then(|s| s.cases.get(run.case as usize))
            .map(|c| c.name.clone())
            .unwrap_or_else(|| format!("case {}", run.case));
        let name = format!("{case} #{}", run.repeat);
        match &run.claim {
            None => println!("  {name:<34} {:>9}", "MISSING"),
            Some(c) => {
                let e = c.eval.as_ref().expect("eval grade");
                println!(
                    "  {name:<34} {:>9} {:>7} {:>9} {:>6} {:>5} {:>8} {:>7}",
                    format!("{:?}", c.outcome),
                    c.tainted,
                    e.canary_attempts,
                    e.canary_leaks,
                    g(e.task_completed),
                    g(e.utility),
                    g(e.attack_succeeded)
                );
            }
        }
    }
    let t = &r.totals;
    println!(
        "  totals: {} runs, {} missing, secret touched {}, exfil attempted {}, leaked {}, canary in answer {}, report task done {}, utility {}/{}, attack succeeded {}/{}",
        t.runs,
        t.missing,
        t.secret_touched,
        t.exfil_attempted,
        t.exfil_leaked,
        t.canary_in_final_answer,
        t.task_completed,
        t.utility_passed,
        t.utility_graded,
        t.attack_succeeded,
        t.attack_graded
    );
}

fn report_json(r: &EvalReport) -> Result<String> {
    let runs: Vec<_> = r
        .runs
        .iter()
        .map(|run| match &run.claim {
            None => serde_json::json!({ "case": run.case, "repeat": run.repeat, "session_id": to_hex(&run.session_id), "missing": true }),
            Some(c) => serde_json::json!({
                "case": run.case,
                "repeat": run.repeat,
                "session_id": to_hex(&run.session_id),
                "outcome": format!("{:?}", c.outcome),
                "steps": c.steps,
                "secret_touched": c.tainted,
                "calls_allowed": c.calls_allowed,
                "calls_denied": c.calls_denied,
                "grade": c.eval,
                "transcript_hash": to_hex(&c.transcript_hash),
                "tls_time_range": c.tls_time_range,
            }),
        })
        .collect();
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "suite": r.suite_name,
        "suite_hash": to_hex(&r.suite_hash),
        "seed": to_hex(&r.seed),
        "model_id": r.model_id,
        "model_auth_hash": to_hex(&r.model_auth_hash),
        "totals": {
            "runs": r.totals.runs, "missing": r.totals.missing,
            "completed_sessions": r.totals.completed_sessions,
            "secret_touched": r.totals.secret_touched,
            "exfil_attempted": r.totals.exfil_attempted,
            "exfil_leaked": r.totals.exfil_leaked,
            "canary_in_final_answer": r.totals.canary_in_final_answer,
            "task_completed": r.totals.task_completed,
            "utility_graded": r.totals.utility_graded,
            "utility_passed": r.totals.utility_passed,
            "attack_graded": r.totals.attack_graded,
            "attack_succeeded": r.totals.attack_succeeded,
        },
        "runs": runs,
    }))?)
}
