//! `ph`: provable-harness CLI.
//!
//! Roles:
//! - trusted services (`ph serve`): model gateway + tool oracle with signing keys
//! - operator (`ph run`, `ph prove`): runs the agent live, then proves the run
//! - verifier (`ph verify`): checks the proof against the harness program and
//!   its own expectations (policy, keys, task, prompt, initial workspace)

mod beacon;
mod eval_cmd;
mod live;
mod prover;
mod scenario;
mod services;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ph_core::hash::{from_hex32, to_hex, Digest};
use ph_core::{
    Claim, ModelAuth, Outcome, Role, SessionInput, TlsRoots, ToolAuth, ToolTlsConfig, Witness,
    ZkTlsConfig,
};
use sha2::{Digest as _, Sha256};
use sp1_sdk::SP1ProofWithPublicValues;

use crate::prover::ProofMode;
use crate::scenario::{load_public_key, load_signing_key, FinalWorkspace, RunDir, Scenario, Transcript};
use crate::services::{ModelProvider, Services};

#[derive(Parser)]
#[command(name = "ph", about = "Provable agent harness (SP1 zkVM PoC)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum EvalCmd {
    /// Verifier: print a fresh random seed (the eval's challenge). With
    /// `--prereg`: fetch the pre-registered drand round, verify it, write it to
    /// `--out`, and print the seed derived from it.
    Seed {
        #[arg(long)]
        prereg: Option<PathBuf>,
        #[arg(long, requires = "prereg")]
        out: Option<PathBuf>,
    },
    /// Operator: pre-register an eval (suite, pinned model and notary, program
    /// vk) against a future drand round; publish the file before that round.
    Prereg {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        zktls_config: PathBuf,
        /// How far in the future the beacon round is.
        #[arg(long, default_value_t = 600)]
        delay_secs: u64,
        /// Address of the pinned notary, which time-stamps the pre-registration.
        #[arg(long)]
        notary: String,
        /// Environment variable holding the notary operator token, if it needs one.
        #[arg(long)]
        notary_token_env: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Operator: run all cases against the live zkTLS model, execute (and prove) the batch.
    Run {
        #[arg(long)]
        suite: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        zktls_config: PathBuf,
        #[arg(long)]
        zktls_proxy: String,
        /// `none` executes in the zkVM without proving.
        #[arg(long, default_value = "none")]
        prove: String,
    },
    /// Operator: prove an eval recorded earlier by `ph eval run` (from eval-input.bin).
    Prove {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, value_enum, default_value = "compressed")]
        mode: ProofMode,
    },
    /// Verifier: check the eval proof against the suite, seed and pinned model.
    Verify {
        #[arg(long)]
        suite: PathBuf,
        /// The seed the verifier chose (else `--prereg` + `--beacon`).
        #[arg(long, required_unless_present = "prereg", conflicts_with = "prereg")]
        seed: Option<String>,
        /// Pre-registration (`ph eval prereg`) whose beacon round fixes the seed.
        #[arg(long, requires = "beacon")]
        prereg: Option<PathBuf>,
        /// The drand round (`ph eval seed --prereg ... --out`).
        #[arg(long)]
        beacon: Option<PathBuf>,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        zktls_config: PathBuf,
        #[arg(long)]
        tls_max_age_secs: Option<u64>,
        /// The notary's signed log for this eval's sessions (`ph-zktls session-log`).
        /// Shows whether missing runs were never started, aborted, or withheld.
        #[arg(long)]
        notary_log: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the harness program's vk (what verifiers pin; rebuild with
    /// tools/repro-guest-build.sh to check it matches the source).
    Vk,
    /// Generate gateway and oracle signing keys.
    Keygen {
        #[arg(long)]
        keys: PathBuf,
    },
    /// Run the trusted services (model gateway + tool oracle).
    Serve {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        scenario: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7878")]
        addr: String,
        /// Use a real model via the `claude` CLI (e.g. `sonnet`) instead of model.json.
        #[arg(long)]
        claude: Option<String>,
    },
    /// Operator: run the agent live against the services and record the witness.
    Run {
        #[arg(long)]
        scenario: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:7878")]
        services: String,
        /// Directory with gateway.pub / oracle.pub.
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Session id (hex), e.g. a challenge chosen by the verifier. Random if omitted.
        #[arg(long)]
        session: Option<String>,
        /// zkTLS model mode: ZkTlsConfig JSON to pin (notary key, host, roots, model).
        #[arg(long, requires = "zktls_proxy")]
        zktls_config: Option<PathBuf>,
        /// zkTLS model mode: URL of the operator's MPC-TLS proxy (`ph-zktls proxy`).
        #[arg(long, requires = "zktls_config")]
        zktls_proxy: Option<String>,
        /// zkTLS tool mode: ToolTlsConfig JSON to pin (notary key, roots) for
        /// http_get / http_post (else the oracle in keys/ signs tool results).
        #[arg(long, requires = "zktls_tool_proxy")]
        zktls_tools: Option<PathBuf>,
        /// zkTLS tool mode: URL of the MPC-TLS proxy serving /v1/fetch.
        #[arg(long, requires = "zktls_tools")]
        zktls_tool_proxy: Option<String>,
    },
    /// Operator: execute the guest in SP1 and (optionally) generate a proof.
    Prove {
        #[arg(long)]
        run: PathBuf,
        #[arg(long, value_enum, default_value = "compressed")]
        mode: ProofMode,
        /// Only execute in the zkVM (cycle count + claim), no proof.
        #[arg(long)]
        execute_only: bool,
    },
    /// Verifier: check a proof against the harness program and expectations.
    Verify {
        #[arg(long)]
        run: PathBuf,
        #[arg(long)]
        scenario: PathBuf,
        #[arg(long)]
        keys: PathBuf,
        /// The session id (hex) this verifier issued as a fresh challenge. Required:
        /// without it the operator may run many sessions and publish the one it
        /// likes, so neither the gateway nor the notary rule prevents re-rolls.
        #[arg(long, required_unless_present = "unchallenged")]
        session: Option<String>,
        /// Accept any session id. The result is NOT re-roll protected.
        #[arg(long, conflicts_with = "session")]
        unchallenged: bool,
        /// Also check the disclosed transcript.json against the proven transcript hash.
        #[arg(long)]
        check_transcript: bool,
        /// Accept step-limit outcomes (default: require a completed session).
        #[arg(long)]
        allow_incomplete: bool,
        /// Expected model id (as attested by the gateway).
        #[arg(long)]
        expect_model: Option<String>,
        /// zkTLS model mode: the ZkTlsConfig the verifier trusts (else gateway.pub is pinned).
        #[arg(long)]
        zktls_config: Option<PathBuf>,
        /// zkTLS: reject sessions notarized more than this many seconds ago.
        #[arg(long)]
        tls_max_age_secs: Option<u64>,
        /// zkTLS tool mode: the ToolTlsConfig the verifier trusts (else oracle.pub is pinned).
        #[arg(long)]
        zktls_tools: Option<PathBuf>,
    },
    /// Everything in one process: keys, services, live run, execute, prove, verify.
    Demo {
        #[arg(long)]
        scenario: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// `none` executes in the zkVM without proving.
        #[arg(long, default_value = "compressed")]
        prove: String,
        #[arg(long)]
        claude: Option<String>,
        #[arg(long, requires = "zktls_proxy")]
        zktls_config: Option<PathBuf>,
        #[arg(long, requires = "zktls_config")]
        zktls_proxy: Option<String>,
        /// zkTLS tool mode: ToolTlsConfig JSON to pin (notary key, roots) for
        /// http_get / http_post (else the oracle in keys/ signs tool results).
        #[arg(long, requires = "zktls_tool_proxy")]
        zktls_tools: Option<PathBuf>,
        /// zkTLS tool mode: URL of the MPC-TLS proxy serving /v1/fetch.
        #[arg(long, requires = "zktls_tools")]
        zktls_tool_proxy: Option<String>,
    },
    /// Print the transcript of a run.
    Show {
        #[arg(long)]
        run: PathBuf,
    },
    /// Provable evaluations: run every case of a suite for a verifier's seed,
    /// prove the whole eval in one SP1 proof, verify the report.
    Eval {
        #[command(subcommand)]
        cmd: EvalCmd,
    },
    /// Print the verifying-key hash of the embedded harness program.
    Vkey,
}

fn parse_session(s: Option<&str>) -> Result<Digest> {
    match s {
        Some(h) => from_hex32(h).ok_or_else(|| anyhow!("--session must be 32 hex bytes")),
        None => {
            let mut sid = [0u8; 32];
            getrandom::getrandom(&mut sid)?;
            Ok(sid)
        }
    }
}

fn provider_for(scenario: &Scenario, claude: Option<String>) -> Result<ModelProvider> {
    match claude {
        Some(model) => Ok(ModelProvider::ClaudeCli {
            model_id: format!("claude-cli/{model}"),
            model,
        }),
        None => scenario.scripted_provider(),
    }
}

fn start_services(
    keys: &Path,
    scenario: &Scenario,
    claude: Option<String>,
    addr: &str,
) -> Result<(String, std::thread::JoinHandle<()>)> {
    let services = Services::new(
        load_signing_key(keys, "gateway")?,
        load_signing_key(keys, "oracle")?,
        provider_for(scenario, claude)?,
        scenario.world()?,
        true,
    );
    services::spawn(Arc::new(services), addr)
}

fn print_transcript(messages: &[ph_core::Message]) {
    for (i, m) in messages.iter().enumerate() {
        let who = match m.role {
            Role::User => "USER",
            Role::Assistant | Role::AssistantBlocks => "MODEL",
            Role::Tool | Role::ToolResults => "HARNESS",
        };
        println!("---- [{i}] {who} ----\n{}", m.content.trim_end());
    }
    println!("----");
}

fn load_tool_config(p: &Path) -> Result<ToolTlsConfig> {
    serde_json::from_str(&fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
        .with_context(|| format!("parsing {}", p.display()))
}

fn load_zktls_config(p: &Path) -> Result<ZkTlsConfig> {
    serde_json::from_str(&fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
        .with_context(|| format!("parsing {}", p.display()))
}

fn cmd_run(
    scenario: &Scenario,
    services_url: &str,
    keys: &Path,
    out: &Path,
    session: Option<&str>,
    zktls: Option<(ZkTlsConfig, String)>,
    zktls_tools: Option<(ToolTlsConfig, String)>,
) -> Result<Witness> {
    let (model_id, model_auth, proxy) = match zktls {
        Some((config, proxy)) => (
            config.model.clone(),
            ModelAuth::ZkTls(config),
            Some(proxy),
        ),
        None => {
            let info: serde_json::Value = ureq::get(&format!("{services_url}/v1/info"))
                .call()
                .context("contacting services")?
                .into_json()?;
            let model_id = info["model_id"]
                .as_str()
                .ok_or_else(|| anyhow!("services did not report a model_id"))?
                .to_string();
            // Pinned from the keys directory, not from the services' self-report.
            let key = load_public_key(keys, "gateway")?;
            (model_id, ModelAuth::Gateway { key }, None)
        }
    };
    let input = SessionInput {
        session_id: parse_session(session)?,
        model_id,
        system_prompt: scenario.system_prompt.clone(),
        task: scenario.task.clone(),
        policy: scenario.policy.clone(),
        workspace: scenario.workspace.clone(),
        model_auth,
        tool_auth: match &zktls_tools {
            Some((c, _)) => ToolAuth::ZkTls(c.clone()),
            None => ToolAuth::Oracle {
                key: load_public_key(keys, "oracle")?,
            },
        },
        eval: None,
        tool_mode: scenario.tool_mode.clone(),
    };
    let tool_proxy = zktls_tools.as_ref().map(|(_, p)| p.as_str());
    let (output, witness) = live::run_live(&input, services_url, proxy.as_deref(), tool_proxy)?;

    // Fail fast: the native replay runs the exact guest logic (host build).
    let replay = ph_core::verify_witness(&witness).map_err(|e| anyhow!("native replay: {e}"))?;
    if replay.claim != output.claim {
        bail!("native replay diverged from the live run");
    }

    fs::create_dir_all(out)?;
    let rd = RunDir(out.to_path_buf());
    fs::write(rd.witness(), witness.to_bytes())?;
    fs::write(rd.claim(), output.claim.pretty())?;
    fs::write(
        rd.transcript(),
        serde_json::to_string_pretty(&Transcript::new(&input, &output, &witness.blind))?,
    )?;
    fs::write(
        rd.final_workspace(),
        serde_json::to_string_pretty(&FinalWorkspace::new(&output, &witness.blind))?,
    )?;
    write_actions(out, &output, &witness.blind)?;
    print_transcript(&output.messages);
    println!("{}", output.claim.pretty());
    println!("run recorded in {}", out.display());
    Ok(witness)
}

fn cmd_prove(run: &Path, mode: ProofMode, execute_only: bool) -> Result<()> {
    let rd = RunDir(run.to_path_buf());
    let witness = Witness::from_bytes(&fs::read(rd.witness())?).map_err(|e| anyhow!(e))?;
    let native = ph_core::verify_witness(&witness)
        .map_err(|e| anyhow!("native replay: {e}"))?
        .claim;

    println!("executing harness guest in SP1 ...");
    let (guest_claim, cycles) = prover::execute(&witness)?;
    if guest_claim != native {
        bail!("zkVM execution diverged from native replay:\nnative: {}\nguest: {}", native.pretty(), guest_claim.pretty());
    }
    println!("zkVM execution OK: {cycles} cycles, claim matches native replay");
    if execute_only {
        return Ok(());
    }

    println!("proving ({mode:?}) ... this takes a while on CPU");
    let outcome = prover::prove(&witness, mode)?;
    outcome.proof.save(rd.proof())?;
    fs::write(
        rd.proof_info(),
        serde_json::to_string_pretty(&serde_json::json!({
            "mode": format!("{mode:?}"),
            "vk_hash": outcome.vk_hash,
            "cycles": cycles,
            "prove_seconds": outcome.seconds,
            "proof_bytes": fs::metadata(rd.proof())?.len(),
        }))?,
    )?;
    println!(
        "proof written to {} ({:.1}s, vk {})",
        rd.proof().display(),
        outcome.seconds,
        outcome.vk_hash
    );
    Ok(())
}

struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn eq_check(name: &'static str, got: &[u8], want: &[u8]) -> Check {
    Check {
        name,
        ok: got == want,
        detail: if got == want {
            to_hex(got)
        } else {
            format!("got {} want {}", to_hex(got), to_hex(want))
        },
    }
}

/// What the verifier expects beyond the scenario and the pinned keys.
#[derive(Default)]
struct Expect<'a> {
    session: Option<&'a str>,
    check_transcript: bool,
    allow_incomplete: bool,
    model: Option<&'a str>,
    zktls: Option<&'a ZkTlsConfig>,
    tls_max_age_secs: Option<u64>,
    tools: Option<&'a ToolTlsConfig>,
}

fn cmd_verify(run: &Path, scenario: &Scenario, keys: &Path, x: &Expect<'_>) -> Result<Claim> {
    let Expect {
        session,
        check_transcript,
        allow_incomplete,
        model: expect_model,
        zktls,
        tls_max_age_secs,
        tools,
    } = *x;
    let rd = RunDir(run.to_path_buf());
    let proof = SP1ProofWithPublicValues::load(rd.proof())
        .with_context(|| format!("loading {}", rd.proof().display()))?;
    let (claim, vk_hash) = prover::verify(&proof)?;
    println!("SP1 proof valid for harness program vk {vk_hash}");

    let expected_auth = match zktls {
        Some(c) => ModelAuth::ZkTls(c.clone()),
        None => ModelAuth::Gateway {
            key: load_public_key(keys, "gateway")?,
        },
    };
    let expected_tools = match tools {
        Some(c) => ToolAuth::ZkTls(c.clone()),
        None => ToolAuth::Oracle {
            key: load_public_key(keys, "oracle")?,
        },
    };
    // Everything below is only as good as these anchors. They must come from the
    // verifier's own trusted source, never from the operator's run directory.
    println!("trust anchors (must be obtained independently of the operator):");
    let mut warnings: Vec<String> = Vec::new();
    let custom_roots_warning = |what: &str| {
        format!("custom TLS roots for {what}: whoever picked them can impersonate those servers; check each fingerprint")
    };
    match &expected_tools {
        ToolAuth::Oracle { key } => println!("  tool oracle    {}", to_hex(key)),
        ToolAuth::Fixture(_) => println!("  tools          fixture world (committed in the claim)"),
        ToolAuth::ZkTls(c) => {
            println!("  tools (zkTLS)  notary {} {}", c.notary.alg, to_hex(&c.notary.key));
            match &c.roots {
                TlsRoots::Mozilla => println!("  tool roots     Mozilla root store (compiled into the program)"),
                TlsRoots::Custom(roots) => {
                    for r in roots {
                        println!("  tool root      sha256 {}", to_hex(&Sha256::digest(r)));
                    }
                    warnings.push(custom_roots_warning("tool calls"));
                }
            }
        }
    }
    match zktls {
        None => println!("  gateway key    {}", to_hex(&load_public_key(keys, "gateway")?)),
        Some(c) => {
            println!("  notary key     {} {}", c.notary.alg, to_hex(&c.notary.key));
            println!("  server name    {}", c.host);
            match &c.roots {
                TlsRoots::Mozilla => println!("  TLS roots      Mozilla root store (compiled into the program)"),
                TlsRoots::Custom(roots) => {
                    for r in roots {
                        println!("  TLS root       sha256 {}", to_hex(&Sha256::digest(r)));
                    }
                    warnings.push(custom_roots_warning("model calls"));
                }
            }
            println!("  model          {} (max_tokens {})", c.model, c.max_tokens);
        }
    }
    if session.is_none() {
        warnings.push(
            "no session challenge: the operator may have run many sessions and kept this one (NOT re-roll protected)".into(),
        );
    }
    let mut checks = vec![
        Check {
            name: "claim version",
            ok: claim.version == ph_core::claim::CLAIM_VERSION,
            detail: claim.version.to_string(),
        },
        eq_check(
            if zktls.is_some() { "zkTLS config pinned" } else { "gateway key pinned" },
            &claim.model_auth_hash,
            &expected_auth.hash(),
        ),
        eq_check(
            if tools.is_some() { "zkTLS tools pinned" } else { "tool oracle pinned" },
            &claim.tool_auth_hash,
            &expected_tools.hash(),
        ),
        eq_check("policy", &claim.policy_hash, &scenario.policy.hash()),
        eq_check("tool mode", &claim.tool_mode_hash, &scenario.tool_mode.hash()),
        eq_check("system prompt", &claim.system_prompt_hash, &scenario.system_prompt_hash()),
        eq_check("task", &claim.task_hash, &scenario.task_hash()),
        eq_check(
            "initial workspace",
            &claim.initial_workspace_root,
            &scenario.initial_workspace_root(),
        ),
        Check {
            name: "outcome",
            ok: allow_incomplete || claim.outcome == Outcome::Completed,
            detail: format!("{:?}", claim.outcome),
        },
        Check {
            name: "no eval grade",
            ok: claim.eval.is_none(),
            detail: match claim.eval {
                None => "single session".into(),
                Some(_) => "the claim carries a grade from a grader nobody pinned; use ph eval verify".into(),
            },
        },
    ];
    if let Some(s) = session {
        let want = from_hex32(s).ok_or_else(|| anyhow!("--session must be 32 hex bytes"))?;
        checks.push(eq_check("session challenge", &claim.session_id, &want));
    }
    if zktls.is_some() || tools.is_some() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let (ok, detail) = match (claim.tls_time_range, tls_max_age_secs) {
            // zkTLS tools with a gateway model: nothing is notarized if the
            // session made no external call.
            (None, _) if zktls.is_none() && claim.external_calls == 0 => {
                (true, "none (no external call)".to_string())
            }
            (None, _) => (false, "no notarized time in claim".to_string()),
            (Some((a, b)), max_age) => {
                let fresh = max_age.is_none_or(|m| now.saturating_sub(a) <= m);
                let not_future = b <= now + 300;
                (fresh && not_future, format!("{a}..={b} (now {now})"))
            }
        };
        checks.push(Check {
            name: "notarized time",
            ok,
            detail,
        });
    }
    if let Some(m) = expect_model {
        checks.push(Check {
            name: "model id",
            ok: claim.model_id == m,
            detail: if claim.model_id == m {
                m.to_string()
            } else {
                format!("got {} want {m}", claim.model_id)
            },
        });
    }
    match fs::read_to_string(rd.final_workspace()) {
        Ok(text) => {
            let fw: FinalWorkspace = serde_json::from_str(&text)?;
            checks.push(eq_check("disclosed final workspace", &fw.commitment()?, &claim.final_workspace_root));
        }
        Err(_) => warnings.push("no final_workspace.json disclosed; only its root is proven".into()),
    }
    match fs::read_to_string(rd.0.join("actions.json")) {
        Ok(text) => {
            let d: ActionsFile = serde_json::from_str(&text)?;
            let h = ph_core::script::action_log_of(&claim.session_id, &d.actions).map_err(|e| anyhow!("actions.json: {e}"))?;
            let hidden = d
                .actions
                .iter()
                .flat_map(|a| a.args.iter().chain(core::iter::once(&a.detail)))
                .filter(|f| matches!(f, ph_core::script::Field::Hidden { .. }))
                .count();
            checks.push(eq_check("disclosed action log", &h, &claim.action_log_hash));
            println!("  action log: {} calls disclosed ({hidden} fields hidden as salted commitments)", d.actions.len());
        }
        Err(_) => warnings.push("no actions.json disclosed; only the action log hash is proven".into()),
    }
    if check_transcript {
        let t: Transcript = serde_json::from_str(&fs::read_to_string(rd.transcript())?)?;
        for (name, ok, detail) in t.check(&claim)? {
            checks.push(Check { name, ok, detail });
        }
    }

    let mut all_ok = true;
    for c in &checks {
        all_ok &= c.ok;
        println!("  [{}] {:<22} {}", if c.ok { "ok" } else { "FAIL" }, c.name, c.detail);
    }
    for w in &warnings {
        println!("  [WARN] {w}");
    }
    println!("{}", claim.pretty());
    if !all_ok {
        bail!("verification FAILED");
    }
    println!("VERIFIED: the harness program with vk {vk_hash} executed this session under the expected policy, keys, task, prompt and workspace; every field of the claim above is proven.");
    Ok(claim)
}

fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();

    match Cli::parse().cmd {
        Cmd::Vk => {
            println!("program vk     {}", prover::vk_hash()?);
            println!("format version {}", ph_core::FORMAT_VERSION);
            println!("claim version  {}", ph_core::claim::CLAIM_VERSION);
        }
        Cmd::Keygen { keys } => {
            scenario::keygen(&keys)?;
            println!("keys written to {}", keys.display());
        }
        Cmd::Serve {
            keys,
            scenario,
            addr,
            claude,
        } => {
            let scenario = Scenario::load(&scenario)?;
            let (url, handle) = start_services(&keys, &scenario, claude, &addr)?;
            println!("services listening on {url}");
            handle.join().map_err(|_| anyhow!("server thread panicked"))?;
        }
        Cmd::Run {
            scenario,
            services,
            keys,
            out,
            session,
            zktls_config,
            zktls_proxy,
            zktls_tools,
            zktls_tool_proxy,
        } => {
            let scenario = Scenario::load(&scenario)?;
            let zk = match (zktls_config, zktls_proxy) {
                (Some(c), Some(p)) => Some((load_zktls_config(&c)?, p)),
                _ => None,
            };
            let zt = match (zktls_tools, zktls_tool_proxy) {
                (Some(c), Some(p)) => Some((load_tool_config(&c)?, p)),
                _ => None,
            };
            cmd_run(&scenario, &services, &keys, &out, session.as_deref(), zk, zt)?;
        }
        Cmd::Prove {
            run,
            mode,
            execute_only,
        } => cmd_prove(&run, mode, execute_only)?,
        Cmd::Verify {
            run,
            scenario,
            keys,
            session,
            unchallenged: _,
            check_transcript,
            allow_incomplete,
            expect_model,
            zktls_config,
            tls_max_age_secs,
            zktls_tools,
        } => {
            let scenario = Scenario::load(&scenario)?;
            let zk = zktls_config.as_deref().map(load_zktls_config).transpose()?;
            let zt = zktls_tools.as_deref().map(load_tool_config).transpose()?;
            cmd_verify(
                &run,
                &scenario,
                &keys,
                &Expect {
                    session: session.as_deref(),
                    check_transcript,
                    allow_incomplete,
                    model: expect_model.as_deref(),
                    zktls: zk.as_ref(),
                    tls_max_age_secs,
                    tools: zt.as_ref(),
                },
            )?;
        }
        Cmd::Demo {
            scenario,
            out,
            prove,
            claude,
            zktls_config,
            zktls_proxy,
            zktls_tools,
            zktls_tool_proxy,
        } => {
            let scenario = Scenario::load(&scenario)?;
            let zk = match (zktls_config, zktls_proxy) {
                (Some(c), Some(p)) => Some((load_zktls_config(&c)?, p)),
                _ => None,
            };
            let zk_cfg = zk.as_ref().map(|(c, _)| c.clone());
            let zt = match (zktls_tools, zktls_tool_proxy) {
                (Some(c), Some(p)) => Some((load_tool_config(&c)?, p)),
                _ => None,
            };
            let zt_cfg = zt.as_ref().map(|(c, _)| c.clone());
            let keys = out.join("keys");
            if !keys.join("gateway.key").exists() {
                scenario::keygen(&keys)?;
            }
            let (url, _handle) = start_services(&keys, &scenario, claude, "127.0.0.1:0")?;
            let challenge = to_hex(&parse_session(None)?);
            println!("verifier challenge (session id): {challenge}");
            cmd_run(&scenario, &url, &keys, &out, Some(&challenge), zk, zt)?;
            match prove.as_str() {
                "none" => cmd_prove(&out, ProofMode::Compressed, true)?,
                "core" => cmd_prove(&out, ProofMode::Core, false)?,
                "compressed" => cmd_prove(&out, ProofMode::Compressed, false)?,
                other => bail!("--prove must be none|core|compressed, got {other}"),
            }
            if prove != "none" {
                cmd_verify(
                    &out,
                    &scenario,
                    &keys,
                    &Expect {
                        session: Some(&challenge),
                        check_transcript: true,
                        zktls: zk_cfg.as_ref(),
                        tools: zt_cfg.as_ref(),
                        tls_max_age_secs: (zk_cfg.is_some() || zt_cfg.is_some()).then_some(3600),
                        ..Default::default()
                    },
                )?;
            }
        }
        Cmd::Show { run } => {
            let t: Transcript =
                serde_json::from_str(&fs::read_to_string(RunDir(run).transcript())?)?;
            print_transcript(&t.messages);
        }
        Cmd::Vkey => println!("{}", prover::vk_hash()?),
        Cmd::Eval { cmd } => match cmd {
            EvalCmd::Seed { prereg: None, .. } => println!("{}", eval_cmd::fresh_seed()?),
            EvalCmd::Seed { prereg: Some(p), out } => {
                let prereg: beacon::Prereg = serde_json::from_str(&fs::read_to_string(&p)?)?;
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                if now < prereg.beacon_time {
                    bail!("drand round {} is not out yet (in {} s)", prereg.beacon_round, prereg.beacon_time - now);
                }
                let b = beacon::fetch_beacon(prereg.beacon_round)?;
                let seed = beacon::seed_from(&prereg, &b)?;
                if let Some(out) = out {
                    fs::write(&out, serde_json::to_string_pretty(&b)?)?;
                    eprintln!("drand round {} verified, saved to {}", b.round, out.display());
                }
                println!("{}", to_hex(&seed));
            }
            EvalCmd::Prereg { suite, zktls_config, delay_secs, notary, notary_token_env, out } => {
                let s = eval_cmd::load_suite(&suite)?;
                let config = load_zktls_config(&zktls_config)?;
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                let round = beacon::round_at(now + delay_secs) + 1;
                let mut p = beacon::Prereg {
                    suite_name: s.name.clone(),
                    suite_hash: to_hex(&s.hash()),
                    model_id: config.model.clone(),
                    model_auth_hash: to_hex(&ModelAuth::ZkTls(config.clone()).hash()),
                    program_vk: prover::vk_hash()?,
                    beacon_chain: beacon::QUICKNET_CHAIN.into(),
                    beacon_round: round,
                    beacon_time: beacon::round_time(round),
                    receipt: None,
                };
                let token = match &notary_token_env {
                    Some(var) => Some(std::env::var(var).with_context(|| format!("${var} is not set"))?),
                    None => None,
                };
                let receipt = beacon::notarize_prereg(&notary, token.as_deref(), &p)?;
                receipt.verify(&p, &config.notary).context("the notary's receipt")?;
                if receipt.time >= p.beacon_time {
                    bail!("the notary time-stamped it at {}, not before round {round} (at {})", receipt.time, p.beacon_time);
                }
                p.receipt = Some(receipt);
                fs::write(&out, serde_json::to_string_pretty(&p)?)?;
                println!(
                    "pre-registration {} time-stamped by the notary, written to {}: drand quicknet round {round} (at unix {}).",
                    to_hex(&p.hash()),
                    out.display(),
                    p.beacon_time
                );
            }
            EvalCmd::Run {
                suite,
                seed,
                out,
                zktls_config,
                zktls_proxy,
                prove,
            } => eval_cmd::run(&suite, &seed, &out, load_zktls_config(&zktls_config)?, &zktls_proxy, &prove)?,
            EvalCmd::Prove { dir, mode } => eval_cmd::prove(&dir, mode)?,
            EvalCmd::Verify {
                suite,
                seed,
                prereg,
                beacon,
                dir,
                zktls_config,
                tls_max_age_secs,
                notary_log,
            } => {
                let seed = match (seed, prereg, beacon) {
                    (Some(s), _, _) => eval_cmd::SeedSource::Given(s),
                    (None, Some(p), Some(b)) => eval_cmd::SeedSource::Beacon {
                        prereg: serde_json::from_str(&fs::read_to_string(&p)?)?,
                        beacon: serde_json::from_str(&fs::read_to_string(&b)?)?,
                    },
                    _ => bail!("give --seed, or --prereg and --beacon"),
                };
                eval_cmd::verify(
                    &suite,
                    &seed,
                    &dir,
                    &load_zktls_config(&zktls_config)?,
                    tls_max_age_secs,
                    notary_log.as_deref(),
                )?;
            }
        },
    }
    Ok(())
}

/// `actions.json`: the action log, disclosed so `ph verify` can recompute
/// `claim.action_log_hash`. Untainted sessions open every field; tainted ones
/// hide all arguments and result digests (salted commitments: the tool names
/// and outcomes stay visible, the values cannot be brute-forced).
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ActionsFile {
    session_id: String,
    disclosure: String,
    actions: Vec<ph_core::script::DisclosedAction>,
}

pub(crate) fn write_actions(dir: &std::path::Path, output: &ph_core::SessionOutput, blind: &[u8; 32]) -> Result<()> {
    let tainted = output.claim.tainted;
    let actions = ph_core::script::disclose_actions(blind, &output.actions, |_, _| !tainted);
    let file = ActionsFile {
        session_id: to_hex(&output.claim.session_id),
        disclosure: if tainted { "redacted (tainted session)" } else { "full" }.into(),
        actions,
    };
    fs::write(dir.join("actions.json"), serde_json::to_string_pretty(&file)?)?;
    Ok(())
}
