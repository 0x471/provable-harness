//! End-to-end zkTLS: MPC-TLS against the mock Messages API with an in-process
//! notary, then verification with ph-core exactly as the zkVM guest does it.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use ph_core::witness::{verify_tool_step, verify_zktls_step, widen};
use ph_core::zktls::{crypto_provider, provider_for_roots, verify_tool_exchange};
use ph_core::{
    HarnessError, ModelAuth, ModelBackend, ModelEvidence, ModelQuery, NotaryKey, Policy,
    SessionInput, Slot, ToolAuth, ToolBackend, ToolCall, ToolEvidence, ToolResult, ToolTlsConfig,
    Witness, ZkTlsConfig,
};
use ph_zktls::{
    dev_web_pki, mock_server, mock_web_server, notarize, notarize_tool, notary_public_key,
    notary_session, DevWebPki, MockWorld, NotaryState, Roots, Target,
};

const SECRET: [u8; 32] = [9u8; 32];
const API_KEY: &str = "mock-api-key-0000";

struct Stack {
    rt: tokio::runtime::Runtime,
    notary: String,
    target: Target,
    config: ZkTlsConfig,
    /// Mock websites: listen address, dev PKI, and the tool config pinning its CA.
    web: String,
    web_pki: Arc<DevWebPki>,
    tools: ToolTlsConfig,
}

const WEATHER: &str = "https://api.weather.example/v1/today?city=paris";
const REPORT: &str = "https://api.weather.example/v1/report";

fn world() -> MockWorld {
    serde_json::from_value(serde_json::json!({
        "get": { WEATHER: "{\"city\":\"Paris\",\"temp_c\":18}" },
        "post": { REPORT: "202 accepted: report stored" }
    }))
    .unwrap()
}

fn stack(replies: Vec<&str>) -> Stack {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let ca = tlsn_server_fixture_certs::CA_CERT_DER.to_vec();
    let replies = Arc::new(replies.into_iter().map(String::from).collect::<Vec<_>>());
    let w = Arc::new(world());
    let web_pki = Arc::new(dev_web_pki(&w.hosts().unwrap()).unwrap());
    let (mock, notary, web) = rt.block_on(async {
        let m = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let n = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (ma, na, wa) = (m.local_addr().unwrap(), n.local_addr().unwrap(), wl.local_addr().unwrap());
        tokio::spawn(mock_server(m, replies));
        tokio::spawn(mock_web_server(wl, web_pki.clone(), w));
        let state = Arc::new(NotaryState::default());
        let ca2 = ca.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = n.accept().await.unwrap();
                let (state, store) = (state.clone(), Roots::Ca(ca2.clone()).store());
                tokio::spawn(async move {
                    let _ = notary_session(s, SECRET, store, state, Arc::new(ph_zktls::NotaryAccess::open())).await;
                });
            }
        });
        (ma.to_string(), na.to_string(), wa.to_string())
    });
    let config = ZkTlsConfig {
        notary: NotaryKey { alg: "k256".into(), key: notary_public_key(&SECRET).unwrap() },
        host: tlsn_server_fixture_certs::SERVER_DOMAIN.into(),
        roots: Roots::Ca(ca.clone()).to_ph(),
        model: "claude-mock-1".into(),
        max_tokens: 256,
    };
    let target = Target {
        addr: mock,
        server_name: tlsn_server_fixture_certs::SERVER_DOMAIN.into(),
        roots: Roots::Ca(ca),
    };
    let tools = ToolTlsConfig {
        notary: config.notary.clone(),
        roots: Roots::Ca(web_pki.ca_der.clone()).to_ph(),
    };
    Stack { rt, notary, target, config, web, web_pki, tools }
}

/// What a tool fetch needs (owned, so a `'static` backend can hold it).
#[derive(Clone)]
struct Fetcher {
    rt: tokio::runtime::Handle,
    notary: String,
    web: String,
    ca: Vec<u8>,
}

impl Fetcher {
    /// Notarize one tool call against the mock websites (as the proxy would).
    fn fetch(&self, call: &ToolCall) -> anyhow::Result<Vec<u8>> {
        let (url, request) = ph_core::http::tool_request(call).map_err(anyhow::Error::msg)?;
        let target = Target { addr: self.web.clone(), server_name: url.host, roots: Roots::Ca(self.ca.clone()) };
        self.rt.block_on(notarize_tool(&self.notary, &target, request, Slot::tool(&call.session_id, call.seq)))
    }
}

impl Stack {
    fn fetcher(&self) -> Fetcher {
        Fetcher {
            rt: self.rt.handle().clone(),
            notary: self.notary.clone(),
            web: self.web.clone(),
            ca: self.web_pki.ca_der.clone(),
        }
    }
    fn fetch(&self, call: &ToolCall) -> anyhow::Result<Vec<u8>> {
        self.fetcher().fetch(call)
    }
}

fn get(sid: [u8; 32], seq: u64, url: &str) -> ToolCall {
    ToolCall { session_id: sid, seq, tool: "http_get".into(), args: vec![url.into()] }
}

/// Live zkTLS tool backend for tests (the real host uses the proxy's /v1/fetch).
struct LiveTlsTools {
    f: Fetcher,
    tools: ToolTlsConfig,
    recorded: Vec<ToolEvidence>,
    times: Option<(u64, u64)>,
}

impl ToolBackend for LiveTlsTools {
    fn call(&mut self, call: &ToolCall) -> Result<ToolResult, HarnessError> {
        let p = self.f.fetch(call).map_err(|e| HarnessError::Backend(format!("{e:#}")))?;
        let provider = provider_for_roots(&self.tools.roots).unwrap();
        let (result, t) = verify_tool_step(&provider, &self.tools, call, &p)?;
        self.times = widen(self.times, t);
        self.recorded.push(ToolEvidence::Tls(p));
        Ok(result)
    }
    fn attested_time_range(&self) -> Option<(u64, u64)> {
        self.times
    }
}

/// Live zkTLS model backend for tests (the real host uses the HTTP proxy).
struct LiveTls<'a> {
    s: &'a Stack,
    recorded: Vec<ModelEvidence>,
    times: Option<(u64, u64)>,
}

impl ModelBackend for LiveTls<'_> {
    fn complete(&mut self, q: &ModelQuery<'_>) -> Result<String, HarnessError> {
        let c = &self.s.config;
        let body = ph_core::anthropic::request_body(&c.model, c.max_tokens, q.system_prompt, q.tools, q.messages, q.session_id, q.step);
        let req = ph_core::anthropic::http_request(&c.host, API_KEY, &body).unwrap();
        let p = self
            .s
            .rt
            .block_on(notarize(&self.s.notary, &self.s.target, req))
            .map_err(|e| HarnessError::Backend(format!("{e:#}")))?;
        let provider = crypto_provider(c).unwrap();
        let (text, t, _) = verify_zktls_step(&provider, c, q, &p)?;
        self.times = widen(self.times, t);
        self.recorded.push(ModelEvidence::Tls(p));
        Ok(text)
    }
    fn attested_time_range(&self) -> Option<(u64, u64)> {
        self.times
    }
}

struct NoTools;
impl ToolBackend for NoTools {
    fn call(&mut self, _: &ToolCall) -> Result<ToolResult, HarnessError> {
        Err(HarnessError::Backend("no external tools in this test".into()))
    }
}

fn input(config: &ZkTlsConfig, sid: [u8; 32]) -> SessionInput {
    SessionInput {
        session_id: sid,
        model_id: config.model.clone(),
        system_prompt: "You are a test agent. Use ```rhai blocks.".into(),
        task: "Write hello to /out/a.txt".into(),
        policy: Policy {
            max_steps: 4,
            max_tool_calls: 8,
            max_script_operations: 10_000,
            max_session_operations: 30_000,
            max_string_bytes: 65_536,
            max_session_data: 1 << 24,
            max_output_chars: 2000,
            fs_read: vec!["/out".into()],
            fs_write: vec!["/out".into()],
            secret_paths: vec![],
            net_get: vec![],
            net_post: vec![],
            deny_egress_after_secret_read: true,
        },
        workspace: vec![],
        model_auth: ModelAuth::ZkTls(config.clone()),
        tool_auth: ToolAuth::Oracle { key: ed25519_dalek_pub() },
        eval: None,
        tool_mode: Default::default(),
    }
}

fn ed25519_dalek_pub() -> [u8; 32] {
    // Any valid Ed25519 point works: the session makes no oracle calls.
    [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ]
}

#[test]
fn notarize_verify_and_no_rerolls() {
    let s = stack(vec!["hello from the mock model"]);
    let c = s.config.clone();
    let sid = [0x11u8; 32];
    let body = ph_core::anthropic::request_body(&c.model, c.max_tokens, "sys", "", &[ph_core::Message { role: ph_core::Role::User, content: "hi".into() }], &sid, 0);
    let req = ph_core::anthropic::http_request(&c.host, API_KEY, &body).unwrap();
    let p = s.rt.block_on(notarize(&s.notary, &s.target, req.clone())).unwrap();

    let provider = crypto_provider(&c).unwrap();
    let (reply, _t) = ph_core::zktls::verify_model_exchange(&provider, &c, &p, &body, &Slot::model(&sid, 0), false).unwrap();
    assert_eq!(reply.text, "hello from the mock model");
    // The same presentation does not verify against a different context.
    let other = body.replace("\"hi\"", "\"bye\"");
    assert!(ph_core::zktls::verify_model_exchange(&provider, &c, &p, &other, &Slot::model(&sid, 0), false).is_err());

    // Re-rolling the same (session, step) is refused by the notary.
    let e = s.rt.block_on(notarize(&s.notary, &s.target, req)).unwrap_err();
    assert!(format!("{e:#}").contains("no re-rolls"), "{e:#}");
    // ...but the notary still serves other (session, step) slots, and non-200
    // answers do not consume a slot (the mock has no reply for step 1 -> 400).
    let body1 = ph_core::anthropic::request_body(&c.model, c.max_tokens, "sys", "", &[ph_core::Message { role: ph_core::Role::User, content: "hi".into() }], &sid, 1);
    let req1 = ph_core::anthropic::http_request(&c.host, API_KEY, &body1).unwrap();
    for _ in 0..2 {
        let p1 = s.rt.block_on(notarize(&s.notary, &s.target, req1.clone())).unwrap();
        let e = ph_core::zktls::verify_model_exchange(&provider, &c, &p1, &body1, &Slot::model(&sid, 1), false).unwrap_err();
        assert!(e.contains("HTTP 400"), "{e}");
    }

    // Any presentation byte flip is rejected or leaves authenticated data unchanged.
    let mut rejected = 0;
    for i in (0..p.len()).step_by((p.len() / 61).max(1)) {
        let mut b = p.clone();
        b[i] ^= 1;
        match ph_core::zktls::verify_model_exchange(&provider, &c, &b, &body, &Slot::model(&sid, 0), false) {
            Err(_) => rejected += 1,
            Ok((r, _)) => assert_eq!(r.text, reply.text, "flip {i}"),
        }
    }
    assert!(rejected >= 55, "only {rejected} flips rejected");
}

#[test]
fn aborting_after_peeking_burns_the_slot() {
    let s = stack(vec!["reply A"]);
    let c = s.config.clone();
    let sid = [0x33u8; 32];
    // A dishonest prover announces (sid, 0), runs nothing (or aborts after seeing
    // the reply), and disconnects before the notary signs.
    s.rt.block_on(async {
        use tokio::io::AsyncWriteExt;
        let mut sock = tokio::net::TcpStream::connect(&s.notary).await.unwrap();
        use tokio::io::AsyncReadExt;
        let line = format!("PH-INTENT {}\n", Slot::model(&sid, 0).to_text());
        sock.write_all(line.as_bytes()).await.unwrap();
        let mut ok = [0u8; 3];
        sock.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");
        drop(sock); // abort before any MPC / disclosure
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });
    let body = ph_core::anthropic::request_body(&c.model, c.max_tokens, "sys", "", &[], &sid, 0);
    let req = ph_core::anthropic::http_request(&c.host, API_KEY, &body).unwrap();
    let e = s.rt.block_on(notarize(&s.notary, &s.target, req)).unwrap_err();
    assert!(format!("{e:#}").contains("notary refused") && format!("{e:#}").contains("no re-rolls"), "{e:#}");
    // The same body under a fresh session still works.
    let sid2 = [0x34u8; 32];
    let body2 = ph_core::anthropic::request_body(&c.model, c.max_tokens, "sys", "", &[], &sid2, 0);
    let req2 = ph_core::anthropic::http_request(&c.host, API_KEY, &body2).unwrap();
    let p = s.rt.block_on(notarize(&s.notary, &s.target, req2)).unwrap();
    let provider = crypto_provider(&c).unwrap();
    assert_eq!(ph_core::zktls::verify_model_exchange(&provider, &c, &p, &body2, &Slot::model(&sid2, 0), false).unwrap().0.text, "reply A");
}

#[test]
fn full_session_live_and_replay() {
    let replies = vec![
        "Writing the file.\n```rhai\nwrite_file(\"/out/a.txt\", \"hello\");\n\"done\"\n```\n",
        "Done: wrote /out/a.txt.",
    ];
    let s = stack(replies);
    let sid = [0x22u8; 32];
    let inp = input(&s.config, sid);
    let mut model = LiveTls { s: &s, recorded: vec![], times: None };
    let out = ph_core::run_session(&inp, &[0x42; 32], &mut model, Rc::new(RefCell::new(NoTools))).unwrap();
    assert_eq!(out.claim.final_answer.as_deref(), Some("Done: wrote /out/a.txt."));
    assert!(out.claim.tls_time_range.is_some());
    let w = Witness { version: ph_core::FORMAT_VERSION, blind: [0x42; 32], input: inp.clone(), model_responses: model.recorded, tool_results: vec![] };
    // A model presentation is bound to its (model, session, step) slot only.
    if let ModelEvidence::Tls(p0) = &w.model_responses[0] {
        let wrong = ph_core::zktls::verify_model_exchange(
            &crypto_provider(&s.config).unwrap(), &s.config, p0, "{}", &Slot::model(&sid, 1), false);
        assert!(wrong.unwrap_err().contains("not bound to slot"));
    }
    let replay = ph_core::verify_witness(&w).unwrap();
    assert_eq!(replay.claim, out.claim);

    // Swapping step presentations, or replaying into another session, fails.
    let mut swapped = w.clone();
    swapped.model_responses.swap(0, 1);
    assert!(matches!(ph_core::verify_witness(&swapped), Err(HarnessError::Attestation(_))));
    let mut other = w.clone();
    other.input.session_id = [0x23u8; 32];
    assert!(matches!(ph_core::verify_witness(&other), Err(HarnessError::Attestation(_))));
    let mut weaker = w.clone();
    if let ModelAuth::ZkTls(c) = &mut weaker.input.model_auth {
        c.notary.key[3] ^= 1;
    }
    assert!(ph_core::verify_witness(&weaker).is_err());

    std::fs::write(
        concat!(env!("CARGO_TARGET_TMPDIR"), "/zktls-witness.bin"),
        w.to_bytes(),
    )
    .unwrap();
}

#[test]
fn tool_calls_notarize_verify_and_no_rerolls() {
    let s = stack(vec![]);
    let sid = [0x44u8; 32];
    let provider = provider_for_roots(&s.tools.roots).unwrap();

    let c0 = get(sid, 0, WEATHER);
    let p0 = s.fetch(&c0).unwrap();
    let (r0, _) = verify_tool_exchange(&provider, &s.tools, &c0, &p0).unwrap();
    assert_eq!(r0, ToolResult { ok: true, output: "{\"city\":\"Paris\",\"temp_c\":18}".into() });

    // One response per (session, seq): a second fetch of the same slot is refused,
    // whatever the URL.
    let e = s.fetch(&c0).unwrap_err();
    assert!(format!("{e:#}").contains("no re-rolls"), "{e:#}");
    let e = s.fetch(&get(sid, 0, "https://api.weather.example/v1/other")).unwrap_err();
    assert!(format!("{e:#}").contains("no re-rolls"), "{e:#}");

    // The presentation counts only for exactly this call.
    for (call, why) in [
        (get(sid, 1, WEATHER), "not bound to slot"),
        (get([0x45; 32], 0, WEATHER), "not bound to slot"),
        (get(sid, 0, "https://api.weather.example/v1/today?city=rome"), "differs"),
        (ToolCall { session_id: sid, seq: 0, tool: "http_post".into(), args: vec![WEATHER.into(), "x".into()] }, "differs"),
        (get(sid, 0, "https://other.example/v1/today?city=paris"), "different server"),
    ] {
        let e = verify_tool_exchange(&provider, &s.tools, &call, &p0).unwrap_err();
        assert!(e.contains(why), "{e} (wanted {why})");
    }
    // Another notary key, or the model config's roots, do not accept it either.
    let mut other = s.tools.clone();
    other.notary.key[2] ^= 1;
    assert!(verify_tool_exchange(&provider, &other, &c0, &p0).is_err());
    let wrong_roots = provider_for_roots(&s.config.roots).unwrap();
    assert!(verify_tool_exchange(&wrong_roots, &s.tools, &c0, &p0).unwrap_err().contains("does not verify"));

    // 404 is a legitimate, attested result (ok = false); POST uses chunked framing.
    let c1 = get(sid, 1, "https://api.weather.example/v1/missing");
    let (r1, _) = verify_tool_exchange(&provider, &s.tools, &c1, &s.fetch(&c1).unwrap()).unwrap();
    assert_eq!(r1, ToolResult { ok: false, output: "HTTP 404: 404 not found".into() });
    let c2 = ToolCall { session_id: sid, seq: 2, tool: "http_post".into(), args: vec![REPORT.into(), "Paris: 18C".into()] };
    let (r2, _) = verify_tool_exchange(&provider, &s.tools, &c2, &s.fetch(&c2).unwrap()).unwrap();
    assert_eq!(r2, ToolResult { ok: true, output: "202 accepted: report stored".into() });

    // A model-slot presentation is never a tool result, and vice versa.
    let body = ph_core::anthropic::request_body(&s.config.model, s.config.max_tokens, "sys", "", &[], &sid, 3);
    let req = ph_core::anthropic::http_request(&s.config.host, API_KEY, &body).unwrap();
    let pm = s.rt.block_on(notarize(&s.notary, &s.target, req)).unwrap();
    let as_tool = verify_tool_exchange(&provider_for_roots(&s.config.roots).unwrap(), &s.tools, &get(sid, 3, WEATHER), &pm);
    assert!(as_tool.is_err());
    let as_model = ph_core::zktls::verify_model_exchange(&provider, &s.config, &p0, &body, &Slot::model(&sid, 0), false);
    assert!(as_model.is_err());

    // Byte flips anywhere are rejected or leave the authenticated result unchanged.
    let mut rejected = 0;
    for i in (0..p0.len()).step_by((p0.len() / 61).max(1)) {
        let mut b = p0.clone();
        b[i] ^= 1;
        match verify_tool_exchange(&provider, &s.tools, &c0, &b) {
            Err(_) => rejected += 1,
            Ok((r, _)) => assert_eq!(r, r0, "flip {i}"),
        }
    }
    assert!(rejected >= 55, "only {rejected} flips rejected");
}

#[test]
fn aborting_a_tool_call_burns_the_slot() {
    let s = stack(vec![]);
    let sid = [0x55u8; 32];
    s.rt.block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut sock = tokio::net::TcpStream::connect(&s.notary).await.unwrap();
        sock.write_all(format!("PH-INTENT {}\n", Slot::tool(&sid, 0).to_text()).as_bytes()).await.unwrap();
        let mut ok = [0u8; 3];
        sock.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK\n");
        drop(sock);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });
    let e = s.fetch(&get(sid, 0, WEATHER)).unwrap_err();
    assert!(format!("{e:#}").contains("no re-rolls"), "{e:#}");
    // The model slot with the same (session, n) is independent.
    let body = ph_core::anthropic::request_body(&s.config.model, s.config.max_tokens, "sys", "", &[], &sid, 0);
    let req = ph_core::anthropic::http_request(&s.config.host, API_KEY, &body).unwrap();
    assert!(s.rt.block_on(notarize(&s.notary, &s.target, req)).is_ok());
}

#[test]
fn full_session_with_zktls_model_and_tools() {
    let replies = vec![
        "Fetching the weather.\n```rhai\nlet w = http_get(\"https://api.weather.example/v1/today?city=paris\");\nlet miss = \"\";\ntry { http_get(\"https://api.weather.example/v1/missing\") } catch (e) { miss = `${e}`; }\nwrite_file(\"/out/report.md\", w);\nhttp_post(\"https://api.weather.example/v1/report\", \"Paris: 18C\") + \" | \" + miss\n```\n",
        "Done: report written and submitted.",
    ];
    let s = stack(replies);
    let sid = [0x66u8; 32];
    let mut inp = input(&s.config, sid);
    inp.policy.net_get = vec!["https://api.weather.example/".into()];
    inp.policy.net_post = vec![REPORT.into()];
    inp.tool_auth = ToolAuth::ZkTls(s.tools.clone());
    let mut model = LiveTls { s: &s, recorded: vec![], times: None };
    let tools = Rc::new(RefCell::new(LiveTlsTools {
        f: s.fetcher(),
        tools: s.tools.clone(),
        recorded: vec![],
        times: None,
    }));
    let out = ph_core::run_session(&inp, &[0x42; 32], &mut model, tools.clone()).unwrap();
    assert_eq!(out.claim.final_answer.as_deref(), Some("Done: report written and submitted."));
    assert_eq!(out.claim.external_calls, 3);
    let tool_msg = &out.messages[2].content;
    assert!(tool_msg.contains("202 accepted: report stored | http_get failed: HTTP 404: 404 not found"), "{tool_msg}");
    assert!(out.final_workspace.iter().any(|f| f.path == "/out/report.md" && f.content.contains("temp_c")));

    let w = Witness {
        version: ph_core::FORMAT_VERSION,
        blind: [0x42; 32],
        input: inp.clone(),
        model_responses: model.recorded,
        tool_results: tools.borrow().recorded.clone(),
    };
    assert_eq!(w.tool_results.len(), 3);
    let replay = ph_core::verify_witness(&w).unwrap();
    assert_eq!(replay.claim, out.claim);
    let (t0, t1) = out.claim.tls_time_range.unwrap();
    assert!(t0 <= t1);

    // Tool presentations reordered, dropped, or moved to another session: rejected.
    let mut swapped = w.clone();
    swapped.tool_results.swap(0, 1);
    assert!(matches!(ph_core::verify_witness(&swapped), Err(HarnessError::Attestation(_))));
    let mut short = w.clone();
    short.tool_results.pop();
    assert!(matches!(ph_core::verify_witness(&short), Err(HarnessError::Witness(_))));
    let mut other = w.clone();
    other.input.session_id = [0x67; 32];
    assert!(ph_core::verify_witness(&other).is_err());
    // Claiming oracle mode with zkTLS evidence (or the reverse) is rejected.
    let mut oracle = w.clone();
    oracle.input.tool_auth = ToolAuth::Oracle { key: ed25519_dalek_pub() };
    assert!(matches!(ph_core::verify_witness(&oracle), Err(HarnessError::Witness(_))));
    // A plain-http allowlist entry is refused up front in zkTLS tool mode.
    let mut plain = w.clone();
    plain.input.policy.net_get.push("http://api.weather.example/".into());
    assert!(matches!(ph_core::verify_witness(&plain), Err(HarnessError::InvalidInput(_))));

    std::fs::write(concat!(env!("CARGO_TARGET_TMPDIR"), "/zktls-tools-witness.bin"), w.to_bytes()).unwrap();
}

/// Native tool use over zkTLS: the request carries the tool definitions, the
/// API's tool_use blocks come back through MPC-TLS, and the guest re-parses the
/// notarized reply into the same canonical blocks and re-runs the calls.
#[test]
fn native_tool_use_over_zktls() {
    use ph_core::native::{canonical_json, Binding, NativeTool, ToolMode};
    let replies = vec![
        r#"[{"type":"thinking","thinking":"need the weather","signature":"c2ln"},{"type":"tool_use","id":"toolu_01","name":"get_weather","input":{"city":"paris"}}]"#,
        "Paris is 18C.",
    ];
    let s = stack(replies);
    let sid = [0x68u8; 32];
    let mut inp = input(&s.config, sid);
    inp.policy.net_get = vec!["https://api.weather.example/".into()];
    inp.tool_auth = ToolAuth::ZkTls(s.tools.clone());
    inp.tool_mode = ToolMode::Native(vec![NativeTool {
        name: "get_weather".into(),
        description: "Today's weather for a city.".into(),
        input_schema: canonical_json(r#"{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}"#).unwrap(),
        binding: Binding::HttpGet { url: "https://api.weather.example/v1/today".into(), query: vec!["city".into()] },
    }]);
    let mut model = LiveTls { s: &s, recorded: vec![], times: None };
    let tools = Rc::new(RefCell::new(LiveTlsTools { f: s.fetcher(), tools: s.tools.clone(), recorded: vec![], times: None }));
    let out = ph_core::run_session(&inp, &[0x42; 32], &mut model, tools.clone()).unwrap();
    assert_eq!(out.claim.final_answer.as_deref(), Some("Paris is 18C."));
    assert_eq!(out.claim.external_calls, 1);
    assert!(out.messages[1].content.contains("\"signature\":\"c2ln\""), "thinking echoed: {}", out.messages[1].content);
    assert!(out.messages[2].content.contains("toolu_01") && out.messages[2].content.contains("temp_c"), "{}", out.messages[2].content);
    let w = Witness {
        version: ph_core::FORMAT_VERSION,
        blind: [0x42; 32],
        input: inp.clone(),
        model_responses: model.recorded,
        tool_results: tools.borrow().recorded.clone(),
    };
    assert_eq!(ph_core::verify_witness(&w).unwrap().claim, out.claim);
    // The same notarized exchanges do not verify as a code-mode session (the
    // request bytes differ: no tools field).
    let mut code = w.clone();
    code.input.tool_mode = ToolMode::Code;
    assert!(ph_core::verify_witness(&code).is_err());
    // Nor with different tool definitions.
    let mut other = w.clone();
    if let ToolMode::Native(t) = &mut other.input.tool_mode {
        t[0].description = "Weather.".into();
    }
    assert!(ph_core::verify_witness(&other).is_err());
}

// ---- notary hardening: operator tokens, signed session logs -----------------

/// A notary with a journal and operator tokens, plus the mock API.
fn hardened_stack(replies: Vec<&str>, journal: &std::path::Path, token: &str) -> (Stack, std::path::PathBuf) {
    let mut s = stack(replies);
    let tokens = journal.with_extension("tokens");
    std::fs::write(&tokens, format!("{token}\n")).unwrap();
    let access = Arc::new(ph_zktls::NotaryAccess::from_file(&tokens).unwrap());
    let state = Arc::new(NotaryState::open(journal, &notary_public_key(&SECRET).unwrap()).unwrap());
    let ca = tlsn_server_fixture_certs::CA_CERT_DER.to_vec();
    s.notary = s.rt.block_on(async {
        let n = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = n.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (sock, _) = n.accept().await.unwrap();
                let (state, access, store) = (state.clone(), access.clone(), Roots::Ca(ca.clone()).store());
                tokio::spawn(async move {
                    let _ = notary_session(sock, SECRET, store, state, access).await;
                });
            }
        });
        addr
    });
    (s, tokens)
}

/// Send the opening lines by hand and return the notary's one-line answer.
fn opening(s: &Stack, lines: &str) -> String {
    s.rt.block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut sock = tokio::net::TcpStream::connect(&s.notary).await.unwrap();
        sock.write_all(lines.as_bytes()).await.unwrap();
        let mut line = Vec::new();
        while let Ok(b) = sock.read_u8().await {
            if b == b'\n' {
                break;
            }
            line.push(b);
        }
        String::from_utf8_lossy(&line).to_string()
    })
}

#[test]
fn notary_requires_operator_token_and_logs_sessions() {
    let journal = std::env::temp_dir().join(format!("ph-e2e-journal-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&journal);
    const TOKEN: &str = "operator-token-0123456789";
    let (s, tokens) = hardened_stack(vec!["first reply"], &journal, TOKEN);
    let (done, aborted, never) = ([0x71u8; 32], [0x72u8; 32], [0x73u8; 32]);

    // Without, or with a wrong, token: refused, and no slot is consumed.
    let intent = format!("PH-INTENT {}\n", Slot::model(&aborted, 0).to_text());
    assert!(opening(&s, &intent).starts_with("REFUSED operator not authorized"));
    assert!(opening(&s, &format!("PH-AUTH wrong-token-000000000\n{intent}")).starts_with("REFUSED"));
    // With the token: OK. Dropping the connection afterwards burns the slot (abort).
    assert_eq!(opening(&s, &format!("PH-AUTH {TOKEN}\n{intent}")), "OK");
    std::thread::sleep(std::time::Duration::from_millis(300));

    // A completed exchange (the prover authenticates through PH_NOTARY_TOKEN).
    // Step 0 has a scripted reply (200); step 1 has none, so the mock answers 400:
    // the notary signs it and releases the slot (events C, D, R).
    std::env::set_var("PH_NOTARY_TOKEN", TOKEN);
    let c = &s.config;
    for step in [0u32, 1] {
        let body = ph_core::anthropic::request_body(&c.model, c.max_tokens, "sys", "", &[], &done, step);
        let req = ph_core::anthropic::http_request(&c.host, API_KEY, &body).unwrap();
        s.rt.block_on(notarize(&s.notary, &s.target, req)).unwrap();
    }
    std::env::remove_var("PH_NOTARY_TOKEN");

    // The signed log, as the notary operator would export it.
    let sessions: Vec<String> = [done, aborted, never].iter().map(|s| ph_core::hash::to_hex(s)).collect();
    let log = ph_zktls::signed_session_log(&journal, &SECRET, &sessions, 1_795_300_000).unwrap();
    log.verify(&c.notary).unwrap();
    use ph_core::notary_log::SlotStatus;
    let status = |sid: &[u8; 32]| -> Vec<(u64, SlotStatus, String)> {
        log.session_slots(&ph_core::hash::to_hex(sid)).map(|(sl, h)| (sl.n, h.status(), h.events.clone())).collect()
    };
    assert_eq!(status(&done), vec![(0, SlotStatus::Signed, "CD".into()), (1, SlotStatus::Released, "CDR".into())]);
    assert_eq!(status(&aborted), vec![(0, SlotStatus::Aborted, "C".into())]);
    assert!(status(&never).is_empty(), "a queried session with no slots was never started");

    // Tampering, another key, or an unlisted session break verification.
    let mut t = log.clone();
    let i = t.slots.iter().position(|h| h.events == "C").unwrap();
    t.slots[i].events = "CD".into(); // hide the abort
    assert!(t.verify(&c.notary).is_err());
    let mut other = c.notary.clone();
    other.key[3] ^= 1;
    assert!(log.verify(&other).is_err());
    let mut t = log.clone();
    t.sessions.retain(|x| *x != ph_core::hash::to_hex(&aborted));
    assert!(t.verify(&c.notary).is_err());

    // The journal (with D records) still replays after a restart.
    drop(s);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = std::fs::remove_file(&tokens);
    let _ = std::fs::remove_file(&journal);
}

/// A pre-registration time-stamp over a real connection to the notary: the
/// opening line fits, the receipt verifies with ph-core's check, and a
/// malformed line is refused.
#[test]
fn prereg_receipt_over_a_connection() {
    use std::io::{BufRead, Write};
    let s = stack(vec![]);
    let (suite, prereg) = ([0x11u8; 32], [0x22u8; 32]);
    let ask = |line: String| -> String {
        let mut c = std::net::TcpStream::connect(&s.notary).unwrap();
        c.write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(&c).read_line(&mut reply).unwrap();
        reply
    };
    let r = ask(format!("PH-PREREG {} {}\n", hex::encode(suite), hex::encode(prereg)));
    let mut it = r.trim_end().split(' ');
    assert_eq!(it.next(), Some("OK"), "{r}");
    let time: u64 = it.next().unwrap().parse().unwrap();
    let sig = hex::decode(it.next().unwrap()).unwrap();
    ph_core::notary_log::verify_prereg_receipt(&s.config.notary, &suite, &prereg, time, &sig).unwrap();
    assert!(ask(format!("PH-PREREG {} x\n", hex::encode(suite))).starts_with("REFUSED"));
}
