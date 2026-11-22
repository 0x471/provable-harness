# zkTLS: model calls and tool calls verified inside the zkVM

zkTLS replaces a trusted signer with a **TLSNotary presentation** of an HTTPS exchange, verified by the harness guest inside SP1. It is used in two independent places:

- **Model calls** (`ModelAuth::ZkTls`): replaces the trusted model gateway (sections 3 and 4).
- **Tool calls** (`ToolAuth::ZkTls`): replaces the trusted tool oracle for `http_get` / `http_post` (section 4a).

The claim then says: the server holding a WebPKI certificate for `api.anthropic.com` received **exactly** the request the harness built from its own state, and answered **exactly** this reply.

Select them with `SessionInput.model_auth = ModelAuth::ZkTls(ZkTlsConfig { notary, host, roots, model, max_tokens })` and `SessionInput.tool_auth = ToolAuth::ZkTls(ToolTlsConfig { notary, roots })`. Their hashes are in the claim as `model_auth_hash` and `tool_auth_hash`.

## 1. Pieces

```
operator machine                                           independent notary
+------------------------------+   PH-INTENT <sid> <step>  +--------------------+
| ph (harness, live run)       | -----------------------> | ph-zktls notary     |
|  +- POST body -> ph-zktls    |      MPC-TLS (2PC)        |  - MPC-TLS verifier |
|                  proxy ------+-------------------------->|  - sees only: tail  |
|                  (prover,    |                           |    + status line    |
|                   API key)   | <-- signed attestation -- |  - signs (k256)     |
|                     | TLS 1.2|                           +--------------------+
|                     v        |
|            api.anthropic.com |
+------------------------------+
witness.bin = session input + presentations + oracle receipts   (private)
SP1 guest   = ph-core::verify_witness  ->  Claim (public)
```

| Component | Where | Notes |
|---|---|---|
| `core/src/anthropic.rs` | host, guest, proxy | Canonical request body, exact HTTP template, strict response parser |
| `core/src/zktls.rs` | host, guest | Presentation verification and all binding checks |
| `vendor/tlsn/` | host, guest | **Verify-only fork** of TLSNotary v0.1.0-beta.1. `ring` is replaced by RustCrypto (see `vendor/tlsn/PATCHES.md`) |
| `webpki-algs/` | host, guest | RustCrypto signature algorithms for `rustls-webpki`, **differentially tested against ring** |
| `zktls/` (`ph-zktls`) | operator and notary | Upstream TLSNotary MPC-TLS prover proxy, notary, mock API. Rust 1.95 |

## 2. Why it works inside the zkVM

Upstream TLSNotary verification depends on `ring` (C and assembly), which does not build for `riscv64im-succinct-zkvm-elf`.

The fork keeps every TLSNotary type and serialization unchanged and swaps only the signature-verification backend:
- Our `ph-webpki-algs` provides ECDSA P-256/P-384 with SHA-256/384, RSA PKCS#1 with SHA-256/384/512 (including absent-params), and RSA-PSS.
- It also removes client-only code that needs `ring` (CT/SCT, the TLS 1.3 HKDF glue).

Evidence that the fork is faithful:
- **Same decisions as `ring` on these tests.** `webpki-algs/tests/differential.rs` compares the fork's accept/reject decision with ring's on:
  - random ECDSA and RSA vectors, tampered messages/signatures/keys, and encoding edge cases;
  - 9 live certificate chains, including tampered certificates and wrong host names.
- **Reads TLSNotary output.** Presentations made by the upstream prover and an upstream-based notary (the `zktls/` workspace) verify with the fork, and so did one of a real `api.anthropic.com` exchange during development. `core/tests/zktls.rs` keeps a presentation recorded against the mock API and rejects byte flips across it.

In the guest, SHA-256, P-256, secp256k1 (notary key) and RSA are accelerated by SP1 precompile patches. P-384 is not, because SP1 has no precompile for it.

## 3. What the guest checks for every model step (`zktls::verify_model_exchange`)

1. The attestation is signed by the **pinned notary key** under the **pinned signature scheme**. TLSNotary's own verify only checks the signature against whatever key is embedded, so pinning is our responsibility.
   - Pinning the key alone is not enough. TLSNotary accepts both `secp256k1` and the Keccak-prehashed `secp256k1eth` for one k256 key. Also, *any* TLSNotary notary holding that key (e.g. a stock notary server, or a second process with its own slot journal) would sign without enforcing the one-reply-per-slot rule.
   - So the ph notary uses its own scheme: TLSNotary private-use signature id `0xA1`, ECDSA secp256k1/SHA-256 over `"provable-harness/notary-attestation/v1\0" || header`. The guest accepts only that scheme.
   - Test `only_the_ph_notary_scheme_is_accepted`: `secp256k1` and `secp256k1eth` re-signatures of the fixture (valid under upstream rules), another key, and the scheme without the domain are all rejected. The e2e tests show an upstream-tlsn notary with this signer verifies in the forked guest.
   - Attestations carrying extensions are rejected (the notary's default config already refuses them).
2. The **server identity proof** is present, names `host`, and its certificate chain is valid at the notarized time under the configured roots (`Mozilla` compiled into the guest, or a pinned list).
3. The protocol is TLS 1.2, and the transcript is present and **complete**: not a single byte redacted, in either direction (see section 5.1).
4. The attestation carries exactly one extension, written by the notary itself: the slot `model <session> <step>` it consumed (section 4). It must equal the guest's own (session, step).
5. The request equals `anthropic::http_request(host, key, body)` byte for byte.
   - `body` is rebuilt by the guest from its own context: model, max_tokens, system prompt, every message, and `metadata.user_id = "ph-<session>-<step>"`.
   - The key must match `[A-Za-z0-9_-]{8,256}`.
6. The response is exactly one `HTTP/1.1 200` message with unambiguous framing:
   - Content-Length XOR chunked;
   - no duplicates, no chunk extensions, no trailers, no trailing bytes.
7. The body is a Messages-API `message` from `assistant`, and comes from the requested model (or a dated snapshot of it). `text` blocks form the reply; `thinking` / `redacted_thinking` blocks are skipped (current models think by default); any other block type is rejected.
8. The notarized time is included in the claim (`tls_time_range`). `ph verify --tls-max-age-secs` enforces freshness.

## 4. Re-roll protection: the notary's role

Model outputs are samples. If an operator could sample several times and keep the reply they like, the proof would certify a cherry-picked transcript. The gateway design prevented this with "one reply per (session, step)". With zkTLS, the notary enforces it:

- **Announce before seeing anything.** Before MPC-TLS starts, the prover announces `PH-INTENT <session> <step>`, and the notary marks that slot consumed **immediately**.
  - This is necessary because the prover learns the reply plaintext *before* the notary signs. If the notary recorded the slot only at signing time, the prover could abort and retry.
- **Minimal disclosure, checked against the announcement.** The prover discloses to the notary only:
  - the request tail `,"metadata":{"user_id":"ph-<session>-<step>"}}`, which must end exactly at the end of the sent data;
  - the first 12 response bytes (`HTTP/1.1 NNN`).

  The notary checks the tail equals the announced intent.
- **When the slot is released.** Only after a completed protocol with an authenticated non-200 status (e.g. 529 overloaded). An aborted session burns the slot, and the verifier sees that the challenged session never completed.
- **Why the binding holds.** The notary writes the consumed slot into the attestation as an extension (`provable-harness/slot` = `ph-slot-v1 model <session> <step>`), and the guest requires exactly that extension for its own (session, step). Prover-requested extensions are refused by the notary. So the slot the notary rationed is exactly the slot the proof is about. (The guest also requires the request's `user_id` to name the same slot.)

### 4.1 Notary hardening and signed session logs

- **Operator authentication.** `ph-zktls notary --operator-tokens <file>`: the prover must open with `PH-AUTH <token>` (set `PH_NOTARY_TOKEN` for the proxy). Without it, anyone who can reach the notary and knows a session id could burn that session's slots. Unauthorized openings are refused before any slot is touched.
- **Timeouts and load.** The notary allows 10 s for the opening lines and 180 s for the whole MPC-TLS session (a timeout burns the slot, like any abort). At most `--max-sessions` (default 8) sessions run concurrently; more get `REFUSED busy`.
- **Journal v3.** The journal records `C` (consumed), `R` (released after an authenticated non-200 model reply), and `D` (attestation signed). The `D` record is fsynced *before* the attestation is sent. A crash in between therefore shows as "signed", which is a visible missing run, never as an unrecorded attestation. v2 journals cannot tell signed slots from aborted ones, so they are refused: start a new journal with a new key, because a fresh journal under the old key would allow re-rolls.
- **Signed session logs.** A proof shows the runs the operator *delivered*. The notary saw every slot it handed out. `ph-zktls session-log --key --state --sessions-file <ids> --out log.json` signs each listed session's slot histories (`core/src/notary_log.rs`; domain `ph/v1/notary-session-log`).

  `ph eval verify --notary-log log.json` checks:
  - the log is signed by the pinned notary;
  - it covers every session of the eval;
  - it was produced after the last notarized time;
  - every delivered run's model slots `0..steps` are exactly the ones the notary signed (`notary_log::reconcile`).

  For missing runs, the verifier then sees whether each one was **never started**, **aborted** (and at which step), or **withheld**: completed, with signed replies, but not delivered. That turns selective reporting from invisible into visible.

### 4.2 Native tool use over zkTLS

In native mode (DESIGN.md 12.1), the request carries the canonical `tools` array and the earlier turns as canonical block arrays. The guest rebuilds those bytes exactly. It parses the notarized reply with `parse_reply(body, native = true)`, which keeps `text`, `thinking`, `redacted_thinking` and `tool_use` blocks and rejects any other kind. Code mode still rejects `tool_use`.

## 4a. Tool calls (`http_get`, `http_post`)

With `ToolAuth::ZkTls`, each external tool call is an MPC-TLS session between the operator's proxy and the target website, with the same notary.

- **Request bytes are fixed by the call** (`http::tool_request`): `GET|POST <path?query> HTTP/1.1`, then `host`, `user-agent: provable-harness/0.1`, `accept: */*`, `accept-encoding: identity`, `connection: close`; POST adds `content-type` (JSON if the body is a JSON object or array, else text) and `content-length`. The fragment is never sent. There are no free bytes and no secrets, so nothing can be injected.
- **Only `https://` URLs with a DNS host.** A zkTLS tool session refuses any allowlist entry that is not `https://`.
- **Slot `tool <session> <seq>`.** It is announced before MPC and consumed immediately; the notary writes it into the attestation. Nothing is disclosed to the notary: it learns neither the URL, nor the host, nor any data.
- **Every completed exchange keeps its slot, whatever the HTTP status.** A 404 is a legitimate result. An aborted call burns the slot and ends the challenged session.
- **The guest checks:**
  1. notary key and scheme;
  2. a certificate chain for the URL's host under `ToolTlsConfig.roots`;
  3. TLS 1.2 and a complete transcript;
  4. the slot extension equals `tool <session> <seq>` of this call;
  5. the sent bytes equal `tool_request(call)`;
  6. the response is one complete HTTP/1.1 response (interim 1xx skipped; 204/304 have no body).
- **Result:** `ok = 2xx`; the output is the body (UTF-8, lossy), or `HTTP <status>: <body>` otherwise. A `content-encoding` other than `identity` gives `ok = false`.
- **Truncation is fatal, never a "failed call".** A response that is cut short, close-delimited or ambiguously framed aborts the session. The operator controls the connection; if a truncated response became `ok = false`, the proof would report a failure the server never sent.
- **The model and tool paths parse differently on purpose.** The model path does not skip 1xx responses: its notary decides slot release from the first status line, so `103` followed by `200` would otherwise be a re-roll.

Tests: `zktls/tests/e2e.rs` covers notarization and verification, re-roll refusal (same slot, any URL), binding to exactly one call (other seq, session, URL, method or host all rejected), model/tool slot separation, aborts burning a slot, 404 and chunked POST results, byte flips, and a full session with zkTLS model and tools (live run, replay, reorder, drop, session swap, mode confusion). `core/src/http.rs` tests cover the request templates and response edge cases.

Tests: `zktls/tests/e2e.rs` checks that a second 200 for the same (session, step) is refused, and that non-200 responses do not consume slots.

## 5. Security analysis

### 5.1 Why nothing is redacted, and the API key consequence

TLSNotary can redact ranges, and the obvious design redacts the `x-api-key` value. **That is unsound.**
- Redacted bytes are chosen by the prover, and the verifier cannot see them.
- A malicious operator can place `\r\ncontent-length: N\r\n\r\n<hidden JSON>` inside the "key" range.
- The server would then answer a *hidden* request, while the visible bytes still look like the expected request.

So the presentation discloses everything, the guest checks the key's charset (no CR/LF), and the **API key is inside the witness**. Consequences:
- `witness.bin` and the presentations are secrets. Keep them as private as the API key itself.
- The public claim does not contain the key. **But SP1 core/compressed STARK proofs should not be assumed zero-knowledge.** Before publishing a proof of a session that used a real key:
  - wrap it with Groth16 (`ph prove --mode groth16`, built with `--features groth16`; implemented, not yet run here), or
  - use a short-lived key and revoke it after the session.
- Proving on a third-party prover network gives them the key.
- A cleaner future option: redact the key and prove in ZK that the hidden bytes are `[A-Za-z0-9_-]`. TLSNotary has ZK-on-committed-data tooling; it is not integrated here.

### 5.2 Trust assumptions

| Assumption | If violated |
|---|---|
| The notary does not collude with the operator | MPC-TLS security fails, so forged transcripts become possible. This is inherent to TLSNotary-style zkTLS. Mitigations: an independent notary operator, a notary in a TEE, several notaries over different sessions. |
| The tool sites themselves | zkTLS proves what the server holding the certificate for the URL's host returned. A compromised or lying website is out of scope, as it is for any client. |
| Notary slot state is durable | `ph-zktls notary --state <file>` keeps an append-only journal, bound to the notary key by its first line. Each change is `fsync`ed before the notary acts on it, the file is exclusively locked, and a torn final line is dropped. Still assumed: the disk is not rolled back (e.g. a VM snapshot restore), and the operator never runs two notaries with the same key but different journals. `fsync` on macOS is not `F_FULLFSYNC`. |
| WebPKI: the roots, and the CA that issued `api.anthropic.com`'s certificate | A mis-issued certificate breaks server authentication, as it would for any TLS client. `TlsRoots::Custom` lets a verifier pin, e.g., GTS Root R4 only. |
| Anthropic's server runs the model it reports | zkTLS proves *what the server said*, not how it computed it. |
| The TLS endpoint: `api.anthropic.com` terminates TLS at Cloudflare (`Server: cloudflare` in the fixture) | The proof is about what the certificate holder's edge sent. The CDN is inside the trust boundary. |
| No revocation checking | A revoked but unexpired certificate is accepted. Use pinned roots (`TlsRoots::Custom` with GTS roots) and a short `--tls-max-age-secs`. |
| The verifier's anchors (notary key, roots) are its own | If the operator supplies `zktls.json`, it can name its own notary or CA and forge everything. `ph verify` prints the anchors and warns on custom roots. |
| The proxy holds the API key and has no login | Anything that can reach `127.0.0.1:7050` can spend the key. Requests carrying an `Origin` header, or without `Content-Type: application/json`, get 403, so a web page cannot use the proxy (browsers attach `Origin` to cross-site POSTs, and need a CORS preflight to send JSON). Local processes are not stopped: keep the proxy on localhost, run it only while needed, and use a short-lived, spend-limited key. |
| Who may request slots | With `--operator-tokens`, only operators holding a token can open a session; openings time out after 10 s and MPC sessions after 180 s, and at most `--max-sessions` run at once. Without tokens, anyone who can reach the notary and knows a challenge can burn its slots (griefing). |
| SP1 and the guest code | As in DESIGN.md. |

### 5.3 Other limits

- **TLS 1.2 only.** TLSNotary beta.1 lacks TLS 1.3. `api.anthropic.com` currently offers `ECDHE-ECDSA-AES128-GCM-SHA256` over TLS 1.2, which works.
- **MPC limits.** Requests and responses are capped at 32 KiB (`MAX_SENT`, `MAX_RECV`). `max_tokens` is capped at 2048 (`zktls::MAX_TOKENS`) so replies fit; exceeding the limit is a hard MPC error after the slot is consumed. Long agent sessions need larger limits (MPC cost grows with sent bytes) or context management.
- **Retries.** An authenticated 429/5xx/529 is released by the notary; the live host retries it up to 4 times with backoff. Any other failure burns the slot and ends the challenged session. The witness is not saved per step, so a session cannot be resumed after a crash.
- **Tool calls.** Same limits (32 KiB each way, TLS 1.2, ECDHE with AES-GCM suites). Sites that only offer TLS 1.3, or that send close-delimited, compressed or larger responses, fail or return `ok = false`. No authentication headers exist (no credentials), so only public endpoints can be called.
- **Model ids.** `-latest` aliases are rejected in the config: the API reports the resolved dated id, which would only be caught after the slot was consumed.
- **Cost.**
  - Per step: one MPC-TLS session (about 1-1.5 s locally against the mock).
  - Per step in the guest:
    - about 1.2M cycles with the mock's single RSA certificate;
    - about 19M cycles with Anthropic's real chain, because the intermediate is signed with P-384, verified in software.
  - The verified-chain cache in the fork removes the repeat cost: the fully real session went from 102.0 M to 70.5 M cycles.
- **Guest RNG.** The guest prints SP1's "insecure random number generator" warning. That RNG is a deterministic, fixed-seed `StdRng`, used only to seed `HashMap` hashing inside TLSNotary's verifier. All uses are keyed lookups or duplicate counts, so verification outcomes do not depend on it.

## 6. Measured (Apple M4 Pro, 24 GB, SP1 v6.10 CPU prover)

| Item | Value |
|---|---|
| MPC-TLS notarization per step (mock API, local notary) | 1.1-1.5 s; requests 1.9-4.2 KB; presentations 4.7-7.0 KB |
| Real `api.anthropic.com` notarization (401, no key) | about 0.5 s; presentation 10.4 KB |
| Guest cycles for one real Anthropic presentation (crypto and transcript checks only) | 18.0 M (P-384 in software dominates) |
| **Real end-to-end session** (`weather-injection`, `claude-haiku-5-5`, 2026-11-21, before slot extensions; that witness no longer verifies under the current program): 4 notarized 200s, live run + zkVM execution | 9 s total; 71.1 M cycles; claim matches native replay. Requests 2.2-4.6 KB, responses 1.9-3.7 KB, 4,240 input / 547 output tokens (< $0.001). Steps 1 and 2 returned `thinking` blocks, which the parser skips. Haiku ignored the injection; nothing was tainted or denied. |
| **Fully real session** (`weather-live`, 2026-11-21): real `claude-haiku-5-5` via zkTLS **and** a real `http_get` to `api.open-meteo.com` via zkTLS, one notary, current protocol | 3 model slots + 1 tool slot; 102.0 M cycles, **70.5 M with the verified-chain cache**. Re-recorded after the witness format changed (`runs/real3`): compressed proof **1,528 s, 10.2 GB peak**; `ph verify` passes all checks and fails if the tool config is not pinned. |
| **Real zkTLS tool call** (`weather-live`, 2026-11-21): `http_get` to `api.open-meteo.com`, Mozilla roots, independent tool-only proxy (no API key) | 0.80 s notarization; presentation 5.3 KB; 50.5 M cycles in the guest (real WebPKI chain); claim matches native replay. Real temperature JSON in the proven workspace. |
| `weather-injection`, zkTLS model **and** tools (mock API + mock websites, dev CA) | 6.80 M cycles; compressed proof 373.6 s (reduced concurrency); `ph verify` passes with both configs pinned and fails with either one swapped |
| Verified-chain cache (fork `webpki.rs`), fully real session above | 102.0 M -> 70.5 M cycles |
| Provable eval, 10 real Haiku runs (40 notarized calls) in one proof | 85.6 M cycles; compressed proof 2,322 s (docs/EVALS.md) |
| `weather-injection`, gateway mode | 2.48 M cycles |
| `weather-injection`, zkTLS mode (mock, RSA chain, 3 presentations) | 6.12 M cycles |
| Compressed proof, zkTLS mode | 362.6 s, 1.27 MB, 13.5 GB peak RSS. Measured with the reduced concurrency below; the default settings were killed for memory (jetsam, exit 137). |
| `ph verify` | about 1.3 s |

## 7. Running it

Offline, with the mock API (TLS 1.2, a test CA, real MPC-TLS):

```bash
(cd zktls && cargo build --release)
./zktls/target/release/ph-zktls dev --replies fixtures/scenarios/weather-injection/model.json \
    --config-out runs/zk/zktls.json --model claude-mock-1 &
./target/release/ph demo --scenario fixtures/scenarios/weather-injection --out runs/zk/run \
    --zktls-config runs/zk/zktls.json --zktls-proxy http://127.0.0.1:7050 --prove compressed
```

Offline with zkTLS tools too (mock websites for every URL in `world.json`, served under a fresh dev CA that the tool config pins):

```bash
./zktls/target/release/ph-zktls dev --replies fixtures/scenarios/weather-injection/model.json \
    --config-out runs/zk/zktls.json --model claude-mock-1 \
    --web-world fixtures/scenarios/weather-injection/world.json --tool-config-out runs/zk/tools.json &
./target/release/ph demo --scenario fixtures/scenarios/weather-injection --out runs/zk/run \
    --zktls-config runs/zk/zktls.json --zktls-proxy http://127.0.0.1:7050 \
    --zktls-tools runs/zk/tools.json --zktls-tool-proxy http://127.0.0.1:7050 --prove compressed
```

Real websites (tool calls need no API key; the proxy serves `/v1/fetch` either way):

```bash
ph-zktls keygen --out notary.key && ph-zktls notary --key notary.key --state slots.log --addr 127.0.0.1:7048
ph-zktls proxy --notary 127.0.0.1:7048 --addr 127.0.0.1:7061          # tool route only without a key
ph-zktls tool-config --notary-pub <hex> --out tools.json               # Mozilla roots
ph demo --scenario fixtures/scenarios/weather-live --out runs/live --zktls-tools tools.json \
    --zktls-tool-proxy http://127.0.0.1:7061 --prove none
```

Real Anthropic API. The notary should be run by a party independent of the operator:

```bash
# notary operator
ph-zktls keygen --out notary.key                   # prints the public key
ph-zktls notary --key notary.key --state notary-slots.log --addr 0.0.0.0:7047 \
    --operator-tokens operators.txt                # one token (>= 16 bytes) per line
ph-zktls session-log --key notary.key --state notary-slots.log --sessions-file ids.txt --out log.json
# operator
PH_NOTARY_TOKEN=... ph-zktls proxy --notary <notary-host>:7047 --api-key-env PH_ANTHROPIC_KEY
# the proxy spends the key for whoever reaches it: keep it on 127.0.0.1, stop it
# when idle, use a short-lived spend-limited key (it refuses browser requests)
ph-zktls config --notary-pub <hex> --model <anthropic model id> --out zktls.json
ph demo --scenario ... --out runs/real --zktls-config zktls.json --zktls-proxy http://127.0.0.1:7050
# verifier
ph verify --run runs/real --scenario ... --keys runs/real/keys --zktls-config zktls.json \
    [--zktls-tools tools.json] --session <challenge> --check-transcript --tls-max-age-secs 3600
```

`ph-zktls dev --key <file> --state <file>` uses a fixed notary key and a durable journal (restart tests, and `ph-zktls session-log` afterwards). A reply written as `!529:<text>` in the replies file makes the mock answer 529 once, which exercises slot release and host retry.

On a 24 GB Mac the default SP1 CPU settings (sized for GPUs) can get the prover killed for memory. Use the settings below. If other heavy apps are running, halve them (`1/1/2/2`, `ELEMENT_THRESHOLD=67108864`; 323 s for the zkTLS proof).
`SP1_WORKER_NUM_CORE_WORKERS=2 SP1_WORKER_CORE_BUFFER_SIZE=2 SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=4 SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=4 ELEMENT_THRESHOLD=134217728`.
