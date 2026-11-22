//! Scenario directories and run directories on disk.
//!
//! A scenario has two halves:
//! - what the **verifier** knows in advance: `scenario.json` (task, system prompt
//!   file), `policy.json`, `workspace/` (initial files);
//! - what only the **trusted services** know: `model.json` (scripted replies),
//!   `world.json` (fixture internet).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use ph_core::hash::{from_hex32, text_hash, to_hex, Digest};
use ph_core::workspace::Workspace;
use ph_core::{Message, Policy, WorkspaceFile};
use serde::{Deserialize, Serialize};

use crate::services::{ModelProvider, World};

#[derive(Deserialize)]
struct ScenarioFile {
    task: String,
    /// Path relative to the scenario directory.
    system_prompt: String,
    /// Native tool use: path (relative) of a JSON list of `NativeTool`s whose
    /// `input_schema` may be any JSON object (it is canonicalized on load).
    /// Absent: code mode.
    #[serde(default)]
    tools: Option<String>,
}

/// A `NativeTool` as written in a tools file (schema as a JSON value).
#[derive(Deserialize)]
struct ToolFile {
    name: String,
    description: String,
    input_schema: serde_json::Value,
    binding: ph_core::native::Binding,
}

pub fn load_tools(path: &Path) -> Result<ph_core::native::ToolMode> {
    let tools: Vec<ToolFile> = read_json(path)?;
    let mode = ph_core::native::ToolMode::Native(
        tools
            .into_iter()
            .map(|t| {
                let mut schema = String::new();
                ph_core::anthropic::json_value(&mut schema, &t.input_schema);
                ph_core::native::NativeTool {
                    name: t.name,
                    description: t.description,
                    input_schema: schema,
                    binding: t.binding,
                }
            })
            .collect(),
    );
    mode.validate().map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    Ok(mode)
}

#[derive(Deserialize)]
struct ModelFile {
    model_id: String,
    replies: Vec<String>,
}

pub struct Scenario {
    pub dir: PathBuf,
    pub task: String,
    pub system_prompt: String,
    pub policy: Policy,
    pub workspace: Vec<WorkspaceFile>,
    pub tool_mode: ph_core::native::ToolMode,
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if e.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if p.is_dir() {
            walk(root, &p, out)?;
        } else {
            out.push(p.strip_prefix(root)?.to_path_buf());
        }
    }
    Ok(())
}

impl Scenario {
    pub fn load(dir: &Path) -> Result<Self> {
        let sf: ScenarioFile = read_json(&dir.join("scenario.json"))?;
        let policy: Policy = read_json(&dir.join("policy.json"))?;
        policy
            .validate()
            .map_err(|e| anyhow::anyhow!("policy.json: {e}"))?;
        let system_prompt = fs::read_to_string(dir.join(&sf.system_prompt))
            .with_context(|| format!("reading system prompt {}", sf.system_prompt))?;

        let ws_root = dir.join("workspace");
        let mut rel = vec![];
        if ws_root.is_dir() {
            walk(&ws_root, &ws_root, &mut rel)?;
        }
        let mut workspace = vec![];
        for r in rel {
            let path = format!(
                "/{}",
                r.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            );
            let content = fs::read_to_string(ws_root.join(&r))
                .with_context(|| format!("workspace file {path} must be UTF-8"))?;
            let secret = policy.is_secret(&path);
            workspace.push(WorkspaceFile {
                path,
                content,
                secret,
            });
        }
        Workspace::new(&workspace).map_err(|e| anyhow::anyhow!("workspace: {e}"))?;
        let tool_mode = match &sf.tools {
            Some(p) => load_tools(&dir.join(p))?,
            None => ph_core::native::ToolMode::Code,
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            task: sf.task,
            system_prompt,
            policy,
            workspace,
            tool_mode,
        })
    }

    pub fn initial_workspace_root(&self) -> Digest {
        Workspace::new(&self.workspace)
            .expect("validated at load")
            .root()
    }

    pub fn task_hash(&self) -> Digest {
        text_hash(&self.task)
    }

    pub fn system_prompt_hash(&self) -> Digest {
        text_hash(&self.system_prompt)
    }

    pub fn scripted_provider(&self) -> Result<ModelProvider> {
        let m: ModelFile = read_json(&self.dir.join("model.json"))?;
        Ok(ModelProvider::Scripted {
            model_id: m.model_id,
            replies: m.replies,
        })
    }

    pub fn world(&self) -> Result<World> {
        let p = self.dir.join("world.json");
        if p.exists() {
            read_json(&p)
        } else {
            Ok(World::default())
        }
    }
}

// ---- keys -----------------------------------------------------------------

/// Create a file readable by its owner only.
pub fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

pub fn keygen(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    for name in ["gateway", "oracle"] {
        let sk_path = dir.join(format!("{name}.key"));
        if sk_path.exists() {
            bail!("{} exists; refusing to overwrite", sk_path.display());
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)?;
        let sk = SigningKey::from_bytes(&seed);
        write_secret(&sk_path, to_hex(&seed).as_bytes())?;
        fs::write(
            dir.join(format!("{name}.pub")),
            to_hex(sk.verifying_key().as_bytes()),
        )?;
    }
    Ok(())
}

fn read_hex32(path: &Path) -> Result<[u8; 32]> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    from_hex32(&s).with_context(|| format!("{} is not 32 hex bytes", path.display()))
}

pub fn load_signing_key(dir: &Path, name: &str) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&read_hex32(&dir.join(format!("{name}.key")))?))
}

pub fn load_public_key(dir: &Path, name: &str) -> Result<[u8; 32]> {
    read_hex32(&dir.join(format!("{name}.pub")))
}

// ---- run directory ----------------------------------------------------------

/// Selective-disclosure file: everything needed to recompute `transcript_hash`.
#[derive(Serialize, Deserialize)]
pub struct Transcript {
    pub session_id: String,
    pub model_id: String,
    pub system_prompt: String,
    /// Canonical native tool definitions ("" in code mode).
    #[serde(default)]
    pub tools: String,
    pub messages: Vec<Message>,
    /// Opens the claim's `transcript_hash` (see `ph_core::claim::claim_salt`).
    pub salt: String,
    /// Opens the claim's `final_answer_hash`.
    pub answer_salt: String,
}

impl Transcript {
    pub fn new(input: &ph_core::SessionInput, output: &ph_core::SessionOutput, blind: &Digest) -> Self {
        use ph_core::claim::{claim_salt, SALT_FINAL_ANSWER, SALT_TRANSCRIPT};
        Self {
            session_id: to_hex(&input.session_id),
            model_id: input.model_id.clone(),
            system_prompt: input.system_prompt.clone(),
            tools: input.tool_mode.tools_json(),
            messages: output.messages.clone(),
            salt: to_hex(&claim_salt(blind, SALT_TRANSCRIPT)),
            answer_salt: to_hex(&claim_salt(blind, SALT_FINAL_ANSWER)),
        }
    }

    /// The transcript's checks against a claim: (name, ok, detail).
    pub fn check(&self, claim: &ph_core::Claim) -> Result<Vec<(&'static str, bool, String)>> {
        use ph_core::claim::salted;
        let sid = from_hex32(&self.session_id).context("bad session id in transcript")?;
        let salt = from_hex32(&self.salt).context("bad salt in transcript")?;
        let answer_salt = from_hex32(&self.answer_salt).context("bad answer_salt in transcript")?;
        let ctx = ph_core::protocol::context_hash(&sid, &self.model_id, &self.system_prompt, &self.tools, &self.messages);
        let answer = ph_core::session::final_answer_of(&self.messages, claim.outcome);
        let t = salted(&salt, &ctx);
        let a = salted(&answer_salt, &text_hash(&answer));
        Ok(vec![
            ("disclosed transcript", t == claim.transcript_hash, to_hex(&t)),
            ("disclosed final answer", a == claim.final_answer_hash, to_hex(&a)),
        ])
    }
}

/// Selective-disclosure file for the final workspace: opens the claim's
/// `final_workspace_root`.
#[derive(Serialize, Deserialize)]
pub struct FinalWorkspace {
    pub salt: String,
    pub files: Vec<WorkspaceFile>,
}

impl FinalWorkspace {
    pub fn new(output: &ph_core::SessionOutput, blind: &Digest) -> Self {
        use ph_core::claim::{claim_salt, SALT_FINAL_WORKSPACE};
        Self {
            salt: to_hex(&claim_salt(blind, SALT_FINAL_WORKSPACE)),
            files: output.final_workspace.clone(),
        }
    }

    /// The salted root, to compare with the claim's `final_workspace_root`.
    pub fn commitment(&self) -> Result<Digest> {
        let salt = from_hex32(&self.salt).context("bad salt in final_workspace.json")?;
        let root = Workspace::new(&self.files).map_err(|e| anyhow::anyhow!("final_workspace.json: {e}"))?.root();
        Ok(ph_core::claim::salted(&salt, &root))
    }
}

pub struct RunDir(pub PathBuf);

impl RunDir {
    pub fn witness(&self) -> PathBuf {
        self.0.join("witness.bin")
    }
    pub fn claim(&self) -> PathBuf {
        self.0.join("claim.txt")
    }
    pub fn transcript(&self) -> PathBuf {
        self.0.join("transcript.json")
    }
    pub fn final_workspace(&self) -> PathBuf {
        self.0.join("final_workspace.json")
    }
    pub fn proof(&self) -> PathBuf {
        self.0.join("proof.bin")
    }
    pub fn proof_info(&self) -> PathBuf {
        self.0.join("proof_info.json")
    }
}
