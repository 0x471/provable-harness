//! `ph-zktls`: notary, operator-side MPC-TLS proxy, and mock servers.
//!
//!   ph-zktls keygen --out notary.key
//!   ph-zktls notary --key notary.key --state notary-slots.log
//!                   [--addr 127.0.0.1:7047] [--ca test-ca.der]
//!   ph-zktls proxy  --notary 127.0.0.1:7047 [--addr 127.0.0.1:7050]
//!                   model route  POST /v1/notarize: enabled iff $ANTHROPIC_API_KEY
//!                                (or --api-key-env) is set
//!                   [--server api.anthropic.com:443 --server-name api.anthropic.com --ca ...]
//!                   tool route   POST /v1/fetch: always on
//!                   [--tool-ca ca.der] [--resolve host=ip:port ...]
//!   ph-zktls config      --notary-pub HEX --model M [--root der ...] --out zktls.json
//!   ph-zktls tool-config --notary-pub HEX [--root der ...] --out tools.json
//!   ph-zktls mock   --replies replies.json [--addr 127.0.0.1:7443]
//!   ph-zktls dev    --replies replies.json --config-out zktls.json --model M
//!                   [--web-world world.json --tool-config-out tools.json]
//!                   [--key notary.key] [--state slots.log]
//!                   (mock API + mock websites + notary + proxy in one process)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ph_core::{Slot, ToolCall};
use ph_zktls::{
    dev_web_pki, mock_server, mock_web_server, notarize, notarize_tool, notary_public_key,
    notary_session, signed_session_log, MockWorld, NotaryAccess, NotaryState, Roots, Target,
};

#[derive(Parser)]
#[command(name = "ph-zktls")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Notary {
        #[arg(long)]
        key: PathBuf,
        /// Append-only journal of consumed slots. Must persist across restarts:
        /// losing it lets operators re-roll model replies and tool results.
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7047")]
        addr: String,
        /// Trust only this CA (DER) instead of the Mozilla roots (tests).
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Only operators presenting one of these tokens (one per line, >= 16
        /// bytes) may request notarizations. Without it, anyone who can reach
        /// the notary can burn slots of a session whose id they know.
        #[arg(long)]
        operator_tokens: Option<PathBuf>,
        /// Serve without --operator-tokens on a non-loopback address.
        #[arg(long)]
        open: bool,
        /// Concurrent MPC-TLS sessions (more are refused with REFUSED busy).
        #[arg(long, default_value_t = 8)]
        max_sessions: usize,
    },
    /// Notary operator: export a signed log of what the notary saw for sessions.
    SessionLog {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        state: PathBuf,
        /// Session ids (hex); repeat, or give a file with one per line via --sessions-file.
        #[arg(long)]
        session: Vec<String>,
        #[arg(long)]
        sessions_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    Proxy {
        #[arg(long, default_value = "127.0.0.1:7047")]
        notary: String,
        #[arg(long, default_value = "127.0.0.1:7050")]
        addr: String,
        /// Model API endpoint (model route).
        #[arg(long, default_value = "api.anthropic.com:443")]
        server: String,
        #[arg(long, default_value = "api.anthropic.com")]
        server_name: String,
        /// Model API: trust only this CA (DER) instead of Mozilla (tests).
        #[arg(long)]
        ca: Option<PathBuf>,
        /// Environment variable holding the model API key. If unset, the model
        /// route is disabled and only tool fetches are served.
        #[arg(long, default_value = "ANTHROPIC_API_KEY")]
        api_key_env: String,
        /// Tool fetches: trust only this CA (DER) instead of Mozilla (tests).
        #[arg(long)]
        tool_ca: Option<PathBuf>,
        /// Tool fetches: connect to ADDR for HOST (`host=ip:port`), like curl's
        /// --resolve. TLS identity is still checked against HOST.
        #[arg(long)]
        resolve: Vec<String>,
    },
    Mock {
        #[arg(long)]
        replies: PathBuf,
        #[arg(long, default_value = "127.0.0.1:7443")]
        addr: String,
    },
    /// Write the ZkTlsConfig a verifier pins for model calls, e.g. the real API.
    Config {
        /// Notary public key (k256, compressed SEC1 hex) as printed by `keygen`/`notary`.
        #[arg(long)]
        notary_pub: String,
        #[arg(long, default_value = "api.anthropic.com")]
        host: String,
        /// Pin these DER root certificates instead of the Mozilla set.
        #[arg(long)]
        root: Vec<PathBuf>,
        #[arg(long)]
        model: String,
        #[arg(long, default_value_t = 1024)]
        max_tokens: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the ToolTlsConfig a verifier pins for zkTLS http_get / http_post.
    ToolConfig {
        #[arg(long)]
        notary_pub: String,
        /// Pin these DER root certificates instead of the Mozilla set.
        #[arg(long)]
        root: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    Dev {
        #[arg(long)]
        replies: PathBuf,
        /// Where to write the ZkTlsConfig the harness must pin.
        #[arg(long)]
        config_out: PathBuf,
        #[arg(long, default_value = "claude-mock-1")]
        model: String,
        #[arg(long, default_value_t = 1024)]
        max_tokens: u32,
        #[arg(long, default_value = "127.0.0.1:7050")]
        proxy_addr: String,
        /// Notary secret key file (default: a fresh random key).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Notary slot journal (default: in memory).
        #[arg(long)]
        state: Option<PathBuf>,
        /// Also serve mock websites for every URL in this world.json (fresh dev
        /// CA), so http_get / http_post can run in zkTLS mode offline.
        #[arg(long, requires = "tool_config_out")]
        web_world: Option<PathBuf>,
        /// Where to write the ToolTlsConfig (pins the dev CA).
        #[arg(long, requires = "web_world")]
        tool_config_out: Option<PathBuf>,
    },
}

fn read_key(path: &PathBuf) -> Result<[u8; 32]> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    hex::decode(s.trim())?
        .try_into()
        .map_err(|_| anyhow!("notary key must be 32 bytes hex"))
}

fn roots(ca: &Option<PathBuf>) -> Result<Roots> {
    Ok(match ca {
        Some(p) => Roots::Ca(std::fs::read(p)?),
        None => Roots::Mozilla,
    })
}

fn notary_key_arg(notary_pub: &str) -> Result<ph_core::NotaryKey> {
    let key = hex::decode(notary_pub.trim())?;
    let k = ph_core::NotaryKey { alg: "k256".into(), key };
    k.validate().map_err(|e| anyhow!(e))?;
    Ok(k)
}

fn root_list(root: &[PathBuf]) -> Result<ph_core::TlsRoots> {
    Ok(if root.is_empty() {
        ph_core::TlsRoots::Mozilla
    } else {
        ph_core::TlsRoots::Custom(root.iter().map(std::fs::read).collect::<std::io::Result<Vec<_>>>()?)
    })
}

async fn run_notary(
    addr: String,
    secret: [u8; 32],
    roots: Roots,
    state: NotaryState,
    access: NotaryAccess,
    max_sessions: usize,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!(
        "[notary] listening on {addr}, public key (k256) {}",
        hex::encode(notary_public_key(&secret)?)
    );
    let (state, access) = (Arc::new(state), Arc::new(access));
    let permits = Arc::new(tokio::sync::Semaphore::new(max_sessions.max(1)));
    loop {
        let (mut sock, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            let _ = sock.write_all(b"REFUSED busy\n").await;
            continue;
        };
        let (state, access, store) = (state.clone(), access.clone(), roots.store());
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = notary_session(sock, secret, store, state, access).await {
                eprintln!("[notary] refused: {e:#}");
            }
        });
    }
}

/// The model route: where the API lives and the key the prover sends.
struct ModelRoute {
    target: Target,
    api_key: String,
}

/// The tool route: roots for arbitrary https hosts, and address overrides.
struct ToolRoute {
    roots: Roots,
    resolve: BTreeMap<String, String>,
}

fn parse_resolve(entries: &[String]) -> Result<BTreeMap<String, String>> {
    entries
        .iter()
        .map(|e| {
            let (h, a) = e
                .split_once('=')
                .ok_or_else(|| anyhow!("--resolve expects host=ip:port, got {e}"))?;
            Ok((h.to_string(), a.to_string()))
        })
        .collect()
}

/// Blocking HTTP front-end:
///   POST /v1/notarize {"body": "..."}  -> {"presentation": hex}   (model call)
///   POST /v1/fetch    <ToolCall JSON>  -> {"presentation": hex}   (tool call)
fn run_proxy(
    rt: tokio::runtime::Handle,
    addr: &str,
    notary: String,
    model: Option<ModelRoute>,
    tools: ToolRoute,
) -> Result<()> {
    let server = tiny_http::Server::http(addr).map_err(|e| anyhow!("binding {addr}: {e}"))?;
    match &model {
        Some(m) => eprintln!(
            "[proxy] listening on http://{addr}: model route -> {} ({}); tool route on",
            m.target.addr, m.target.server_name
        ),
        None => eprintln!("[proxy] listening on http://{addr}: tool route only (no model API key)"),
    }
    for mut req in server.incoming_requests() {
        // The proxy spends the API key on behalf of whoever reaches it, so refuse
        // anything a web page could send: browsers attach `Origin` to cross-site
        // POSTs and cannot send `application/json` cross-origin without a CORS
        // preflight (which this server never approves). The harness sends JSON
        // via ureq, without `Origin`. Local processes are not stopped by this;
        // keep the proxy on 127.0.0.1 and stop it when idle.
        let from_browser = req.headers().iter().any(|h| h.field.equiv("Origin"));
        let json = req.headers().iter().any(|h| {
            h.field.equiv("Content-Type")
                && h.value.as_str().to_ascii_lowercase().starts_with("application/json")
        });
        if from_browser || !json {
            eprintln!("[proxy] refused {} {}: not a JSON request from the harness", req.method(), req.url());
            let _ = req.respond(tiny_http::Response::from_string("refused").with_status_code(403));
            continue;
        }
        let mut body = String::new();
        let result: Result<String> = (|| {
            req.as_reader().read_to_string(&mut body)?;
            let t0 = std::time::Instant::now();
            let (what, presentation) = match req.url() {
                "/v1/notarize" => {
                    let m = model
                        .as_ref()
                        .ok_or_else(|| anyhow!("model route disabled: no API key configured"))?;
                    let v: serde_json::Value = serde_json::from_str(&body)?;
                    let api_body = v["body"].as_str().ok_or_else(|| anyhow!("missing body"))?;
                    let request =
                        ph_core::anthropic::http_request(&m.target.server_name, &m.api_key, api_body)
                            .map_err(|e| anyhow!(e))?;
                    let p = rt.block_on(notarize(&notary, &m.target, request))?;
                    (format!("model call ({} body bytes)", api_body.len()), p)
                }
                "/v1/fetch" => {
                    let call: ToolCall = serde_json::from_str(&body)?;
                    let (url, request) =
                        ph_core::http::tool_request(&call).map_err(|e| anyhow!(e))?;
                    let target = Target {
                        addr: tools
                            .resolve
                            .get(&url.host)
                            .cloned()
                            .unwrap_or_else(|| format!("{}:{}", url.host, url.port)),
                        server_name: url.host.clone(),
                        roots: tools.roots.clone(),
                    };
                    let slot = Slot::tool(&call.session_id, call.seq);
                    let p = rt.block_on(notarize_tool(&notary, &target, request, slot))?;
                    (format!("{} #{} -> {}", call.tool, call.seq, url.host), p)
                }
                other => bail!("no route {other}"),
            };
            eprintln!(
                "[proxy] notarized {what} in {:.2}s, presentation {} bytes",
                t0.elapsed().as_secs_f64(),
                presentation.len()
            );
            Ok(serde_json::json!({ "presentation": hex::encode(presentation) }).to_string())
        })();
        let (code, json) = match result {
            Ok(j) => (200, j),
            Err(e) => {
                eprintln!("[proxy] error: {e:#}");
                (400, serde_json::json!({ "error": format!("{e:#}") }).to_string())
            }
        };
        let _ = req.respond(
            tiny_http::Response::from_string(json)
                .with_status_code(code)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .unwrap(),
                ),
        );
    }
    Ok(())
}

/// The API key from `env`, or None if the variable is unset.
fn api_key(env: &str) -> Result<Option<String>> {
    let Ok(k) = std::env::var(env) else {
        return Ok(None);
    };
    if !ph_core::anthropic::valid_api_key(k.as_bytes()) {
        bail!("${env} does not look like an API key");
    }
    Ok(Some(k))
}

fn read_replies(p: &PathBuf) -> Result<Arc<Vec<String>>> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
    let replies = v["replies"]
        .as_array()
        .ok_or_else(|| anyhow!("{}: expected {{\"replies\": [...]}}", p.display()))?
        .iter()
        .map(|r| r.as_str().map(str::to_string).ok_or_else(|| anyhow!("reply must be a string")))
        .collect::<Result<Vec<_>>>()?;
    Ok(Arc::new(replies))
}

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let mut secret = [0u8; 32];
            getrandom::getrandom(&mut secret)?;
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                // Owner-only, and never over an existing key.
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&out)
                    .with_context(|| format!("creating {}", out.display()))?
                    .write_all(hex::encode(secret).as_bytes())?;
            }
            println!("{}", hex::encode(notary_public_key(&secret)?));
        }
        Cmd::Config {
            notary_pub,
            host,
            root,
            model,
            max_tokens,
            out,
        } => {
            let config = ph_core::ZkTlsConfig {
                notary: notary_key_arg(&notary_pub)?,
                host,
                roots: root_list(&root)?,
                model,
                max_tokens,
            };
            ph_core::ModelAuth::ZkTls(config.clone())
                .validate()
                .map_err(|e| anyhow!(e))?;
            std::fs::write(&out, serde_json::to_string_pretty(&config)?)?;
            println!("wrote {}", out.display());
        }
        Cmd::ToolConfig { notary_pub, root, out } => {
            let config = ph_core::ToolTlsConfig {
                notary: notary_key_arg(&notary_pub)?,
                roots: root_list(&root)?,
            };
            ph_core::ToolAuth::ZkTls(config.clone())
                .validate()
                .map_err(|e| anyhow!(e))?;
            std::fs::write(&out, serde_json::to_string_pretty(&config)?)?;
            println!("wrote {}", out.display());
        }
        Cmd::Notary {
            key,
            state,
            addr,
            ca,
            operator_tokens,
            open,
            max_sessions,
        } => {
            let secret = read_key(&key)?;
            let access = match &operator_tokens {
                Some(p) => NotaryAccess::from_file(p)?,
                None => {
                    let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
                    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]");
                    if !loopback && !open {
                        bail!("{addr} is not a loopback address: give --operator-tokens (or --open to let anyone burn slots)");
                    }
                    eprintln!("[notary] WARNING: no --operator-tokens; anyone who can connect may request slots");
                    NotaryAccess::open()
                }
            };
            let state = NotaryState::open(&state, &notary_public_key(&secret)?)?;
            rt.block_on(run_notary(addr, secret, roots(&ca)?, state, access, max_sessions))?;
        }
        Cmd::SessionLog {
            key,
            state,
            mut session,
            sessions_file,
            out,
        } => {
            let secret = read_key(&key)?;
            if let Some(f) = sessions_file {
                session.extend(
                    std::fs::read_to_string(&f)?
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string),
                );
            }
            if session.is_empty() {
                bail!("give at least one --session or --sessions-file");
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let log = signed_session_log(&state, &secret, &session, now)?;
            std::fs::write(&out, serde_json::to_string_pretty(&log)?)?;
            println!("wrote signed log for {} sessions, {} slots, to {}", log.sessions.len(), log.slots.len(), out.display());
        }
        Cmd::Proxy {
            notary,
            addr,
            server,
            server_name,
            ca,
            api_key_env,
            tool_ca,
            resolve,
        } => {
            let model = match api_key(&api_key_env)? {
                Some(api_key) => Some(ModelRoute {
                    target: Target {
                        addr: server,
                        server_name,
                        roots: roots(&ca)?,
                    },
                    api_key,
                }),
                None => {
                    eprintln!("[proxy] ${api_key_env} is not set: model route disabled");
                    None
                }
            };
            let tools = ToolRoute {
                roots: roots(&tool_ca)?,
                resolve: parse_resolve(&resolve)?,
            };
            run_proxy(rt.handle().clone(), &addr, notary, model, tools)?;
        }
        Cmd::Mock { replies, addr } => {
            let replies = read_replies(&replies)?;
            rt.block_on(async {
                let l = tokio::net::TcpListener::bind(&addr).await?;
                eprintln!("[mock] serving test-server.io on {addr}");
                mock_server(l, replies).await
            })?;
        }
        Cmd::Dev {
            replies,
            config_out,
            model,
            max_tokens,
            proxy_addr,
            key,
            state,
            web_world,
            tool_config_out,
        } => {
            let replies = read_replies(&replies)?;
            let secret = match &key {
                Some(k) => read_key(k)?,
                None => {
                    let mut s = [0u8; 32];
                    getrandom::getrandom(&mut s)?;
                    s
                }
            };
            let notary_key = ph_core::NotaryKey {
                alg: "k256".into(),
                key: notary_public_key(&secret)?,
            };
            let state = match &state {
                Some(p) => NotaryState::open(p, &notary_key.key)?,
                None => NotaryState::default(),
            };
            let web = match &web_world {
                Some(p) => {
                    let world: MockWorld = serde_json::from_str(
                        &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
                    )?;
                    let pki = dev_web_pki(&world.hosts()?)?;
                    Some((Arc::new(world), Arc::new(pki)))
                }
                None => None,
            };
            let ca = tlsn_server_fixture_certs::CA_CERT_DER.to_vec();
            let (mock_addr, notary_addr, web_addr) = rt.block_on(async {
                let m = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let n = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let (ma, na) = (m.local_addr()?, n.local_addr()?);
                tokio::spawn(async move {
                    if let Err(e) = mock_server(m, replies).await {
                        eprintln!("[mock] stopped: {e:#}");
                    }
                });
                let web_addr = match &web {
                    Some((world, pki)) => {
                        let w = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                        let wa = w.local_addr()?;
                        let (world, pki) = (world.clone(), pki.clone());
                        tokio::spawn(async move {
                            if let Err(e) = mock_web_server(w, pki, world).await {
                                eprintln!("[web] stopped: {e:#}");
                            }
                        });
                        Some(wa.to_string())
                    }
                    None => None,
                };
                let state = Arc::new(state);
                let store = Roots::Ca(ca.clone());
                tokio::spawn(async move {
                    loop {
                        let Ok((sock, _)) = n.accept().await else { break };
                        let (state, store) = (state.clone(), store.store());
                        tokio::spawn(async move {
                            if let Err(e) = notary_session(sock, secret, store, state, Arc::new(NotaryAccess::open())).await {
                                eprintln!("[notary] refused: {e:#}");
                            }
                        });
                    }
                });
                anyhow::Ok((ma.to_string(), na.to_string(), web_addr))
            })?;
            let config = ph_core::ZkTlsConfig {
                notary: notary_key.clone(),
                host: tlsn_server_fixture_certs::SERVER_DOMAIN.to_string(),
                roots: Roots::Ca(ca.clone()).to_ph(),
                model,
                max_tokens,
            };
            std::fs::write(&config_out, serde_json::to_string_pretty(&config)?)?;
            let mut tools = ToolRoute {
                roots: Roots::Mozilla,
                resolve: BTreeMap::new(),
            };
            if let (Some((_, pki)), Some(web_addr), Some(out)) = (&web, &web_addr, &tool_config_out) {
                let tool_config = ph_core::ToolTlsConfig {
                    notary: notary_key.clone(),
                    roots: ph_core::TlsRoots::Custom(vec![pki.ca_der.clone()]),
                };
                std::fs::write(out, serde_json::to_string_pretty(&tool_config)?)?;
                tools.roots = Roots::Ca(pki.ca_der.clone());
                for h in &pki.hosts {
                    tools.resolve.insert(h.clone(), web_addr.clone());
                }
                eprintln!(
                    "[dev] mock websites {web_addr} for {:?}, tool config -> {}",
                    pki.hosts,
                    out.display()
                );
            }
            eprintln!(
                "[dev] mock API {mock_addr}, notary {notary_addr}, config -> {}",
                config_out.display()
            );
            let model = ModelRoute {
                target: Target {
                    addr: mock_addr,
                    server_name: tlsn_server_fixture_certs::SERVER_DOMAIN.to_string(),
                    roots: Roots::Ca(ca),
                },
                api_key: "mock-api-key-0000".into(),
            };
            run_proxy(rt.handle().clone(), &proxy_addr, notary_addr, Some(model), tools)?;
        }
    }
    Ok(())
}
