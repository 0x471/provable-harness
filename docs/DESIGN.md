# Provable Harness: design

Goal: prove more than model inference. Prove what the **agent harness** did:
which context the model saw at every step, which tool calls were made with which
concrete arguments, that each call was checked against a declared policy at the
moment it ran, and what the session produced.

The PoC proves this with the **SP1 zkVM (v6.10, RISC-V `riscv64im`)**.

## 1. What is proven, what is attested, what is trusted

| Component | Status in this PoC | Production path |
|---|---|---|
| Harness logic: loop, context building, script interpreter, policy checks | **Proven.** Executed inside SP1. The SP1 verifying key is the harness identity. | Same |
| File tools on the workspace | **Proven.** Executed inside SP1 on a committed state (`initial/final_workspace_root`). | Merkle state with lazy loading for large workspaces |
| Model inference | **Attested**, in one of two modes. **Gateway:** a trusted signer signs `(request_hash, response_hash)`. **zkTLS:** a TLSNotary presentation of the real HTTPS exchange with `api.anthropic.com` is verified in the guest, so the trust moves to a non-colluding notary plus WebPKI; see [ZKTLS.md](ZKTLS.md). In both modes the guest rebuilds the request from its own state. | Provider-signed responses, TEE-hosted models, zkML for small models |
| External tools (`http_get`, `http_post`) | **Attested.** Either an oracle signs `(call_hash, result_hash)`, or (`ToolAuth::ZkTls`, ZKTLS.md section 4a) a TLSNotary presentation of the exchange with the target website is verified in the guest. | zkTLS needs a non-colluding notary; natively signed APIs would remove it |
| Policy enforcement | **Proven**, on every call, with runtime-computed arguments | Same |

Trusted computing base:
- SP1 soundness and the SP1 verifier.
- The harness program, as reviewed source built into an ELF whose vk the verifier pins. That includes `ph-core` and Rhai.
- The gateway and oracle keys, only for *attribution* claims ("the model said X", "the API returned Y").

Policy compliance does not depend on the gateway. Whoever produced the model text, the proven harness executed only what the policy allowed.

## 2. The I/O and `no_std` question

The zkVM has no network, filesystem, clock, threads or OS randomness. Two separate facts follow.

1. **`no_std` is not required.** SP1's custom toolchain (`rustup run succinct rustc`, 1.93.0-dev) ships a `std` for `riscv64im-succinct-zkvm-elf`. `Vec`, `String`, `BTreeMap`, formatting and the rest work. Only the OS-facing parts of std are unusable. The constraint is therefore "never touch the OS", not "no std". `ph-core` is written that way.
   - Its dependencies are chosen to match. Rhai is built without default features. That drops `ahash/runtime-rng`, so there is no runtime `getrandom`. It also uses `no_time` (no clock), `no_module` (the default module resolver would read the host filesystem) and `no_float` (libm-dependent transcendentals could differ between builds).
   - The Rhai hashing seed is fixed.
   - `cargo tree` on the guest shows `getrandom` reaching ph-core's tree only through `const-random-macro`. That is a build-time proc-macro.

2. **Harness calls are replayed from an authenticated witness.** The core is *sans-IO*. All I/O goes through two traits, `ModelBackend` and `ToolBackend`:
   - **Host, live run:** the backends make real HTTP calls to the gateway and oracle, check each signature, and record `(response, signature)`.
   - **Guest, proof:** the backends pop the next recorded entry and check its signature against a digest the **guest computes from its own state**. The model's signature covers the context hash the guest built. The oracle's signature covers the call (tool, args, session, seq) that the guest's own script execution produced.
   - The witness contains only *responses*, never requests. If an operator edits anything (a reply, a tool result, the system prompt, the task, the order, the session), some signature stops verifying, the guest panics, and no proof exists.

   ```
   operator host (live)                        SP1 guest (proof)
   -------------------                         -----------------
   run_session(input,                          run_session(input,
      LiveModel  --HTTP--> gateway (signs)        WitnessModel  <- witness.model_responses
      LiveTools  --HTTP--> oracle  (signs))       WitnessTools  <- witness.tool_results)
        |  records witness                          |  verifies every signature against
        v                                           v  digests it computed itself
   witness.bin  ------------------------------>  commit(Claim)  -> SP1 proof
   ```

   Both sides run the same `ph_core::run_session`. The host also replays natively (`verify_witness`) and executes the guest in SP1 (`ph prove --execute-only`), comparing claims before it spends time proving.

## 3. Code mode

The model acts the way Claude Code's experimental Code Mode does (<https://code.claude.com/docs/en/code-mode>): it writes a program that makes the tool calls. Here the program is a ```` ```rhai ```` block instead of JavaScript.

That suits proving for three reasons:

- **One artifact per step.** A script with many tool calls is one deterministic program. Proving its execution covers all of its calls together with the control flow that connects them.
- **Runtime-argument policy.** The Code Mode docs note that the auto-mode classifier "reviews each piece of code before it runs, not each tool call. It doesn't see values computed at run time". Here every call is checked inside the proven interpreter, *at call time*, with its concrete arguments. Paths built by string concatenation, URLs from search results and similar values are all covered (test `path_traversal_and_runtime_args_are_checked`).
- **Deterministic language.** Rhai is a pure-Rust embedded language with operation, string, array, call-depth and expression-depth limits. It is sandboxed: no fs, net or `eval`. A budget overrun is a deterministic error.

Scripts may `try/catch` policy denials, which is intended. They must not be able to catch an attestation failure. Rhai re-wraps errors raised inside script-defined functions into a catchable kind, so the error type alone cannot be trusted. Fatal backend errors are therefore stored out of band (`ToolEnv::fatal`). Every later call fails, and `run_script` returns the fatal error no matter what the script did (test `swallowing_a_forged_result_with_try_catch_does_not_help`).

## 4. Protocol

All hashes are SHA-256 with a domain tag and length-prefixed fields (`core/src/hash.rs`). The encoding is prefix-free.

```
c_0     = H("ph/v1/context-genesis", session_id, model_id, system_prompt)
c_{k+1} = H("ph/v1/context-message", c_k, role, content)
req_k   = H("ph/v1/model-request", c_k, step)
gateway signs H("ph/v1/model-attestation", req_k, H("ph/v1/model-response", text))

call    = H("ph/v1/tool-call", session_id, seq, tool, args[])
result  = H("ph/v1/tool-result", ok, output)
oracle signs H("ph/v1/tool-attestation", call, result)
```

The signature scheme is Ed25519 with `verify_strict`. Signatures are checked in the guest using SP1's patched `curve25519-dalek` and `sha2`.

Anti-replay and anti-re-roll:
- `session_id` is bound into every signed digest, so attestations cannot move between sessions. `seq` binds each tool result to its position. Reordering fails (test `rejects_reordered_tool_results`).
- The gateway serves at most one response per `(session, step)`. The oracle accepts `seq` strictly in order. An operator therefore cannot re-sample a step or a tool call and keep the result it likes.
- `ph demo` and `ph verify --session` use a verifier-chosen `session_id`. This stops the operator from running many sessions and proving only the best one. `ph verify` requires `--session`; `--unchallenged` accepts any id and prints a NOT-re-roll-protected warning.
- Limit: an operator may still abort a challenged session it dislikes (at any step). The verifier sees an incomplete session, not a proof. Verifiers must treat challenges as single-use and count failures against the operator.

## 5. Policy

`core/src/policy.rs` holds the policy. Its hash is in the claim.

- **Filesystem.** Read, write and secret directories. Paths must be canonical (no `.`, `..` or empty segments, no control characters). Containment is checked on segment boundaries.
- **Network.** Separate allowlists for GET and POST. Each prefix must have the form `scheme://host/...`. The prefix includes the first `/` after the host, so a matching URL has exactly that authority. `@`, port and suffix-domain tricks fail closed.
  - A URL matches a prefix only at a path boundary: `.../v1/report` admits `.../v1/report?x` and `.../v1/report/a`, not `.../v1/reports-export`.
  - URLs with dot segments (`.`, `..`), `%2e`, `%2f`, `%5c` or `\` are denied, because an HTTP client would normalise them to a path the policy never matched (test `url_allowlist_respects_path_boundaries`).
- **Taint (no egress after secret read).** Reading a secret-labelled file taints the session. After that, every network call is denied, including calls to allowlisted endpoints. Files written while tainted are labelled secret, and the labels are part of the workspace root. Taint therefore survives copies across sessions (test `taint_label_carries_across_sessions`).
  - `list_files` taints too when it returns a secret-labelled path. Otherwise a secret written into a file *name* (`/out/<key>`) could be listed and sent out in a later session (test `listing_secret_named_files_taints`).
  - A tainted session's final answer is withheld from the public claim (only its hash is committed), since the model may have copied secret data into it.
- **Budgets.** Maximum steps, maximum total tool calls, and a Rhai operation budget per script. A script is terminated after `MAX_DENIED_PER_SCRIPT` (16) denied calls, which do not consume the tool budget but are hashed into the action log.
  - Known gap: the operation budget does not bound *proving* cost. Some Rhai operations are far more expensive than others (e.g. size checks on deeply nested arrays are quadratic); a hostile or injected script can push a session to billions of cycles. A cycle-aware cost model is future work.
- **No OS access from scripts.** Rhai's core package includes `sleep`; the harness overrides it with an error (it would hang the host and panic in the zkVM). Test `sleep_is_not_available`.

## 6. The claim (SP1 public values)

`core/src/claim.rs` defines the claim:
- **Session:** session id, model id, `model_auth_hash` (gateway key or zkTLS model config), `tool_auth_hash` (oracle key or zkTLS tool config). Claim v4.
- **Input commitments:** policy hash, system-prompt hash, task hash, initial workspace root.
- **Results:** final workspace root, transcript hash, action-log hash (every call, its decision, and a result digest), outcome, final-answer hash, and the final answer itself only for untainted sessions (claim v3).
- **Counters and flags:** allowed, denied and external call counts, and the taint flag.

`ph verify` checks the following:
1. The SP1 proof is valid under the vk of the embedded harness ELF. The light verifier is used; it performs real verification and never accepts mock proofs.
2. The model and tool authentication configs equal the pinned ones (gateway key or zkTLS model config; oracle key or zkTLS tool config).
3. The policy, system prompt, task and initial workspace hashes equal the verifier's own expectations, computed from the scenario.
4. The session id equals the challenge, when one was given, and the outcome is `Completed`.
5. A disclosed `final_workspace.json` hashes to `final_workspace_root`.
6. Optionally, a disclosed `transcript.json` hashes to `transcript_hash` (selective disclosure).

It first prints its trust anchors: the oracle key, the gateway key or the zkTLS notary key, the host, the roots and the model. These must come from the verifier's own source, not from the operator's run directory: whoever chose them can sign fabricated tool results or replies. Custom TLS roots produce a warning.

Not yet checkable: `action_log_hash` has no disclosed preimage. Disclosing it raises its own question: arguments can contain secrets.

## 7. Threat model and the tests that cover it

The adversary is the operator, who controls the host, the witness and the prover. In `core/tests/session.rs`, every attack below must fail inside `verify_witness`, the function the guest runs:

| Attack | Result |
|---|---|
| Edit a model reply (hide the exfiltration attempt) | model attestation fails |
| Edit a tool result (scrub the prompt injection) | tool attestation fails |
| Change the system prompt or task (hidden instructions) | attestation fails at step 0 |
| Move a witness to another session | attestation fails |
| Truncate or pad the witness | witness error |
| Reorder tool results | attestation fails (seq binding) |
| Relax the policy | the claim's policy hash changes; if behaviour changes, attestations are missing |
| Swallow a forged result with `try/catch`, including inside a function | fatal error persists |
| Path traversal or runtime-built paths | denied, and nothing leaks into the transcript |

## 8. Limitations

- **Inference is attested, not proven.** In gateway mode a trusted signer stands in for provider signatures. zkTLS mode (ZKTLS.md) instead proves what `api.anthropic.com` returned, assuming a non-colluding notary. Neither proves *how* the reply was computed: that needs TEE inference or zkML.
- **External tools are attested, not proven.** Either the oracle's signature or a zkTLS presentation (notary non-collusion plus WebPKI). zkTLS tools need public `https://` endpoints reachable over TLS 1.2; no credentials can be attached yet.
- **Actions outside the harness.** A proof shows what *this* harness did. It cannot stop the operator from also acting outside the harness with their own credentials. Mitigations: tool credentials held only by the oracle, or proof-carrying requests, where the oracle requires a per-step proof before it executes a side effect.
- **Privacy.** The claim exposes only hashes, the final answer and counters. Compressed STARK proofs are not assumed to hide the witness, and zkTLS witnesses contain the API key, so do not publish them. `--mode groth16` (build with `--features groth16`) wraps the proof in Groth16: the STARK becomes a private witness of a zero-knowledge proof. It is implemented and type-checked, but not yet run here: the circuit artifacts are a 6.2 GB download and this machine has about 10 GB free.
- **Determinism between the two builds.** The host and the guest are different binaries of the same `ph-core`. Anything that depends on std's Unicode tables, such as Rhai's `to_upper`, could differ between rustc versions. Three measures:
  - Script values, errors and JSON are rendered by `render.rs`, never by Rust's `{:?}`; Rhai's own formatting is overridden in `script.rs`.
  - `host/build.rs` refuses to build unless the host and SP1 toolchains are the same Rust release.
  - A divergence is a *liveness* failure (`ph prove` detects it before proving), never a soundness failure.
- **Cost.** Proving time grows with transcript length (hashing), signature checks and interpretation. Section 12.2 bounds the worst case: whatever an injected script does, it cannot make proving explode.

## 9. Alternatives considered

- **Stwo (StarkWare).** Very fast Circle-STARK prover. Its mature frontend is Cairo, so the harness (interpreter, Ed25519, policy) would have to be rewritten in Cairo, with no Rust std. A RISC-V frontend on Stwo would allow reuse, but it is not mature. `ph-core` is zkVM-agnostic Rust, so a port is cheap only to RISC-V zkVMs.
- **RISC Zero.** Equivalent architecture. `ph-core` would be reused unchanged, and only the guest wrapper (about 10 lines) and the host prover module would change. The locally installed `risc0-zkvm 2.3.1` is yanked on crates.io.
- **Running the same guest ELF live**, with I/O through SP1 hooks instead of record-then-replay. This gives parity by construction, because there is one binary. The cost is slower live runs and dependence on hook APIs. It is worth doing next.
- **TEE only.** Cheaper and faster, but trust moves to the hardware vendor and attestation chain, and the result cannot be verified by anyone without trusting that hardware.

## 10. Measured

Apple M4 Pro (12 cores, 24 GB), SP1 v6.10 CPU prover, compressed proofs, harness vk `0x00c144c9...f4b5`.

| Scenario | Model turns / scripts / calls | zkVM cycles | Prove (compressed) | Proof size | Peak RSS |
|---|---|---|---|---|---|
| `minimal` (one reply, no tools) | 1 / 0 / 0 | 1.56 M | n/a (execute only) | n/a | n/a |
| `weather-honest` | 3 / 2 / 4 (2 external) | 2.26 M | 76.9 s | 1.27 MB | 14.2 GB |
| `weather-injection` (2 denied) | 3 / 2 / 6 (1 external) | 2.48 M | 78.0 s | 1.27 MB | 13.5 GB |
| `weather-injection` with real Haiku (`--claude haiku`) | 4 / 3 / 4 (2 external) | 2.48 M | not proven (execute only) | n/a | n/a |

- **Verification:** `ph verify` takes 1.3 s wall time, including vk setup.
- **Fixed overhead:** about 1.5 M cycles. Most of it is building the Rhai engine (standard packages). A raw engine that registers only the needed packages would cut it.
- **Marginal cost:** about 0.35 M cycles per scripted step. That covers SHA-256 context chaining, Ed25519 checks with SP1 precompiles, and interpretation.

**Adversary example** (`cargo run --release -p ph-host --example adversary -- runs/weather-injection`):
- The guest exits non-zero, so no proof can exist, for each of: a scrubbed injection, a replaced model reply, a weaker policy, a hidden system-prompt edit, and truncation.
- A real proof whose public values were edited (`calls_denied = 0`, `tainted = false`) is rejected with `InvalidPublicValues`.
- After the harness code changed, the old proof was rejected with `sp1 vk hash mismatch`. A different harness means a different identity.

## 11. Next steps (as of the first version; see 12 for what is done)

1. **Same-ELF live execution.** Drive the live run by executing the guest ELF in SP1's executor with I/O hooks. One binary gives host/guest parity by construction.
2. **Real attestation sources.**
   - zkTLS for `http_get`: TLSNotary presentations, verified in-guest or composed as a proof.
   - Provider-signed or TEE-attested inference instead of the gateway.
3. **Proof-carrying side effects.** The oracle executes a side-effecting call only after it sees a proof (or an incremental proof) that the call came from the compliant harness. This closes the "operator acts outside the harness" gap.
4. **Incremental proofs.** Prove per step and aggregate with SP1 recursion, so long sessions stream and a verifier can follow along.
5. **Privacy.** Groth16/PLONK wrapping, plus selective disclosure of transcript ranges against `transcript_hash` using Merkle commitments in place of the hash chain.
6. **Cheaper guest.** A trimmed Rhai engine, and a Merkle workspace with lazy loading.

## 12. Additions (2026-11-21, program vk `0x005b467c...d845`, format v3, claim v6)

### 12.1 Native tool use (`core/src/native.rs`)

Besides code mode, a session or suite can declare native tools (`ToolMode::Native`). The model calls them with the API's `tool_use` blocks. Each tool is *bound* to one harness action:
- `read_file { param, prefix }`;
- `http_get { url, query }`, with input fields appended as a percent-encoded query;
- `http_post { url }`, with the input as canonical JSON.

So every native call goes through the same `invoke` path as a script call: runtime policy check, budgets, taint, canary counting, action log and backends.

Binding to the transcript and claim:
- The canonical `tools` array is in every request.
- It is in the context genesis (domain `CTX_GENESIS_TOOLS`; code mode keeps the original genesis).
- It is committed in the claim (`tool_mode_hash`).

Assistant turns are stored as canonical block arrays (`Role::AssistantBlocks`). `thinking` blocks are echoed verbatim, as the API requires with tools. Tool results are `tool_result` arrays (`Role::ToolResults`).

In zkTLS mode the guest rebuilds the exact request bytes, including tools, and re-parses the notarized reply into the same canonical blocks. `zktls/tests/e2e.rs::native_tool_use_over_zktls` shows:
- a session with a `thinking` block and a tool call verifies;
- the same evidence does not verify as code mode, or with a changed tool description.

### 12.2 Proving-cost bound (metered scripts)

Rhai meters *operations*, but the zkVM cost of one operation grows with the size of the data it touches. These adversarial scripts were measured under the old policy (50 k operations per script):

| Script (one step) | zkVM cycles |
|---|---|
| plain loop | 19.8 M |
| `contains` on 128 KiB | 0.99 B |
| `s + s` on 128 KiB | 26.9 B |
| `to_upper()` on 128 KiB | 30.7 B |

So one prompt injection could make a run cost days of proving on this laptop.

**Fix.** `vendor/rhai` is Rhai 1.27.0 plus a *data-volume meter* (`Engine::on_data_volume`, see `vendor/rhai/PATCHES.md`). It charges:
- the arguments and result of every native call (operators included: the harness turns fast operators off);
- variable, element and property reads, because they clone arrays and maps;
- `switch` hashing, and string indexing.

The unit is a string byte or 16 per array/map element (walking an element costs about 16x a byte). Three policy fields bound a session:
- `max_session_operations`, across scripts;
- `max_string_bytes`, deep, tool outputs included;
- `max_session_data`, in meter units.

The meter is deterministic, so the host and the guest stop at the same point.

Worst case under the fixture defaults (20 k ops/script, 60 k ops/session, 64 KiB strings, 16 M units), with every attack script repeated on every step until the budgets run out:

| Attack | Before (budgets only) | Metered |
|---|---|---|
| `to_upper` on 64 KiB | 18.4 B | **156 M** |
| `switch` on a 64 KiB string | 9.9 B | 127 M |
| `s + s`, `replace` | 8.1 B, 5.3 B | 71 M, 81 M |
| string index `s[64000]` | 6.7 B | 69 M |
| clone / build 4 000-map arrays | 1.24 B | 84 M / 114 M |
| plain loop, sort, `parse_json` | | 41 M, 30-36 M, 38 M |

The worst session (about 160 M cycles) costs about 2x a real zkTLS session (70 M).

### 12.3 Disclosable action log

Each action-log link commits to *salted field commitments*: `H(salt(blind, i, j), field)`. The salts come from a per-run blinding seed carried in the witness.

The host writes `actions.json`:
- untainted sessions show every field;
- tainted sessions show tool names and outcomes, with every value hidden.

`ph verify` recomputes `action_log_hash` from it. Hidden fields cannot be brute-forced, because their salts are secret.

### 12.4 Reproducible program vk

A verifier pins the program vk, so the vk must be rebuildable from source. Three causes made it machine-dependent:
1. Source paths in panic messages (the home directory, the checkout location).
2. Cargo folding path-carrying `--remap-path-prefix` flags into crate hashes.
3. Rhai's `ahash/compile-time-rng`, which embedded fresh random keys in **every** compile.

`tools/repro-guest-build.sh` fixes them:
- it copies the guest sources to a fixed directory with a fixed `CARGO_HOME`;
- it builds with sp1-build's exact flags in a cleared environment;
- the vendored Rhai drops `compile-time-rng`, and the guest uses `codegen-units = 1`.

`host/build.rs` embeds that ELF. Result: two clean builds, and a build from a copy at another path, gave the same ELF (SHA-256 `8144eb27...10c0d1`).

Limit: same SP1 toolchain build only. The prebuilt macOS and Linux toolchains embed different std paths, so a cross-OS canonical vk needs SP1's Docker build. `ph vk` prints the vk.

### 12.5 Formats and fuzzing

- **Formats.** Witnesses and eval batches start with `FORMAT_VERSION` (now 3); old files fail with a clear message naming the `vk-*` git tag to use. Claim v6 adds `tool_mode_hash`.
- **Fuzzing** (`fuzz/`, `cargo +nightly fuzz run -O <target>`):

  | Target | Result |
  |---|---|
  | HTTP response parser | 8.1 M runs, clean |
  | model replies (fixed-point check of canonical blocks) | found float canonicalization was not a fixed point: serde_json's default float parsing is not correctly rounded. Fixed with `float_roundtrip`, which also gives Python `float()` semantics for graded amounts. 10.2 M runs since. |
  | URL policy | 17.1 M runs, clean (the one crash was a bug in the fuzz target) |
  | bank API | 6.9 M runs, clean |
  | signature differential vs ring (`webpki-algs`, 13 algorithms) | 548 k runs, no divergence |

