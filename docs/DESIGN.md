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
  - URLs with dot segments (`.`, `..`) or `%2e`, `%2f`, `%5c` in the path, or `\` anywhere, are denied, because an HTTP client would normalise them to a path the policy never matched (test `url_allowlist_respects_path_boundaries`). Queries are not normalised, so encoded characters there are allowed: native tool inputs encode a `/` in a query value as `%2F`.
- **Taint (no egress after secret read).** Reading a secret-labelled file taints the session. After that, every network call is denied, including calls to allowlisted endpoints. Files written while tainted are labelled secret, and the labels are part of the workspace root. Taint therefore survives copies across sessions (test `taint_label_carries_across_sessions`).
  - `list_files` taints too when it returns a secret-labelled path. Otherwise a secret written into a file *name* (`/out/<key>`) could be listed and sent out in a later session (test `listing_secret_named_files_taints`).
  - A tainted session's final answer is withheld from the public claim (only a salted commitment to it is published, section 13.1), since the model may have copied secret data into it.
- **Budgets.** Maximum steps and total tool calls; Rhai operations per script and per session; string size; and a data-volume budget that bounds the proving cost of scripts (section 12.2). A script is terminated after `MAX_DENIED_PER_SCRIPT` (16) denied calls, which do not consume the tool budget but are hashed into the action log.
- **No OS access from scripts.** Rhai's core package includes `sleep`; the harness overrides it with an error (it would hang the host and panic in the zkVM). Test `sleep_is_not_available`.

## 6. The claim (SP1 public values)

`core/src/claim.rs` defines the claim:
- **Session:** session id, model id, `model_auth_hash` (gateway key or zkTLS model config), `tool_auth_hash` (oracle key or zkTLS tool config), `tool_mode_hash`.
- **Input commitments:** policy hash, system-prompt hash, task hash, initial workspace root.
- **Results:** final workspace root, transcript hash, action-log hash (every call, its decision, and a result digest), outcome, final-answer hash, and the final answer itself only for untainted sessions. The first two and the final-answer hash are salted commitments (claim v7, section 13.1); the action log's fields are salted too (12.3).
- **Counters and flags:** allowed, denied and external call counts, the taint flag, the notarized time range, and (eval sessions only) the grade.

`ph verify` checks the following:
1. The SP1 proof is valid under the vk of the embedded harness ELF. The light verifier is used; it performs real verification and never accepts mock proofs.
2. The model and tool authentication configs equal the pinned ones (gateway key or zkTLS model config; oracle key or zkTLS tool config).
3. The policy, system prompt, task and initial workspace hashes equal the verifier's own expectations, computed from the scenario.
4. The session id equals the challenge, when one was given, and the outcome is `Completed`.
5. The claim carries no eval grade: a grader is pinned only by `ph eval verify` (13.3).
6. A disclosed `final_workspace.json` (files plus their salt) opens `final_workspace_root`, and a disclosed `actions.json` opens `action_log_hash`.
7. Optionally (`--check-transcript`), a disclosed `transcript.json` (messages plus salts) opens `transcript_hash` and `final_answer_hash`.

It first prints its trust anchors: the oracle key, the gateway key or the zkTLS notary key, the host, the roots and the model. These must come from the verifier's own source, not from the operator's run directory: whoever chose them can sign fabricated tool results or replies. Custom TLS roots produce a warning.


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
| Run the prefix of a script whose reply was cut off at `max_tokens` | nothing in the reply runs (13.2) |
| Attach a grader of the operator's choice to a single session | the guest refuses the witness (13.3) |
| Confirm a guessed secret answer or file from the public claim | the commitments are salted with a private seed (13.1) |

## 8. Limitations

- **Inference is attested, not proven.** In gateway mode a trusted signer stands in for provider signatures. zkTLS mode (ZKTLS.md) instead proves what `api.anthropic.com` returned, assuming a non-colluding notary. Neither proves *how* the reply was computed: that needs TEE inference or zkML.
- **External tools are attested, not proven.** Either the oracle's signature or a zkTLS presentation (notary non-collusion plus WebPKI). zkTLS tools need public `https://` endpoints reachable over TLS 1.2; no credentials can be attached yet.
- **Actions outside the harness.** A proof shows what *this* harness did. It cannot stop the operator from also acting outside the harness with their own credentials. Mitigations: tool credentials held only by the oracle, or proof-carrying requests, where the oracle requires a per-step proof before it executes a side effect.
- **Privacy.** The claim exposes only salted commitments, hashes of public inputs, the final answer of untainted sessions, and counters. Compressed STARK proofs are not assumed to hide the witness, and zkTLS witnesses contain the API key, so do not publish them. `--mode groth16` (build with `--features groth16`) wraps the proof in Groth16, which SP1's documentation describes as zero-knowledge: the STARK becomes a private witness. It is implemented and type-checked, but has never produced a proof here (the circuit artifacts are a 6.2 GB download), so its privacy is untested.
- **Determinism between the two builds.** The host and the guest are different binaries of the same `ph-core`. Anything that depends on std's Unicode tables, such as Rhai's `to_upper`, could differ between rustc versions. Three measures:
  - Script values, errors and JSON are rendered by `render.rs`, never by Rust's `{:?}`; Rhai's own formatting is overridden in `script.rs`.
  - `host/build.rs` refuses to build unless the host and SP1 toolchains are the same Rust release.
  - A divergence is a *liveness* failure (`ph prove` detects it before proving), never a soundness failure.
- **Cost.** Proving time grows with transcript length (hashing), signature checks and interpretation. Section 12.2 measures the worst case of scripts: about 270 M cycles per session under the default budgets, from a checked-in suite of attack scripts. That is a measurement, not a proof that no script costs more.

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
| `weather-injection` with real Haiku (`--claude haiku`) | 4 / 3 / 4 (2 external) | not recorded | not proven (execute only) | n/a | n/a |

- **Verification:** `ph verify` takes 1.3 s wall time, including vk setup.
- **Fixed overhead:** about 1.5 M cycles. Most of it is building the Rhai engine (standard packages). A raw engine that registers only the needed packages would cut it.
- **Marginal cost:** about 0.35 M cycles per scripted step. That covers SHA-256 context chaining, Ed25519 checks with SP1 precompiles, and interpretation.

(The `--claude haiku` row once repeated the 2.48 M of the row above; that run's cycle count was not kept.)

**Adversary example** (`cargo run --release -p ph-host --example adversary -- runs/weather-injection`):
- An edited fetched page, a replaced model reply, and truncation make the guest exit non-zero, so no proof can exist.
- Another policy or a hidden system-prompt edit either makes the guest fail, or (when the run never needed the changed rule) yields a claim whose policy or prompt hash differs from what the verifier pins. The example checks for either.
- A real proof whose public values were edited (another denied-call count, the taint flag flipped) is rejected with `InvalidPublicValues`.
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

Rhai meters *operations*, but the zkVM cost of one operation grows with the size of the data it touches. These attack scripts were measured under the first policy (50 k operations per script):

| Script (one step) | zkVM cycles |
|---|---|
| plain loop | 19.8 M |
| `contains` on 128 KiB | 0.99 B |
| `s + s` on 128 KiB | 26.9 B |
| `to_upper()` on 128 KiB | 30.7 B |

So one prompt injection could make a run cost days of proving on this laptop.

**The meter.** `vendor/rhai` is Rhai 1.27.0 with a *data-volume meter* (`Engine::on_data_volume`, see `vendor/rhai/PATCHES.md`), and `core/src/script.rs` adds the harness's own counting. Charged:
- every operation, counted by the harness itself against the per-script and per-session budgets. Rhai's own counter restarts in every callback that a native function such as `map` or `sort` makes, so it could not see work done in callbacks. Exhaustion is sticky: if a native function swallows the error, the next operation stops again. Each operation also costs 256 units of the data budget, so one budget bounds both kinds of work;
- every native call (64 units, operators included: the harness turns fast operators off), its arguments, and its result;
- values cloned by variable, element and property reads, by copies of script-function arguments, and by calls and currying of function pointers. A clone counts string bytes it copies, 16 units per element, map keys, curried values, and 96 per array, map, BLOB or function pointer (allocation and drop);
- string interpolation, `switch` hashing, string indexing;
- work Rhai does inside one call: `replace` checks and charges the result size (and 16 per match) before building it, Unicode case mapping costs 32 extra units per non-ASCII byte, `parse_json` 32 per input byte.

Parsing is not metered: scripts are capped at 32 KiB, and Rhai's optimizer, which folded nested constants at compile time with no meter at all (10^6 elements from six lines), is off.

Three policy fields bound a session: `max_session_operations` (across scripts), `max_string_bytes` (deep, tool outputs included) and `max_session_data` (meter units). The meter depends only on data sizes, so the host and the guest stop at the same point.

**Upstream costs fixed in the vendored crates.** In the zkVM, memory has no in-place `realloc`:
- `smartstring` reallocated (so copied the whole buffer) on every pushed character. One `s.pad(65536, 'x')` cost 1.25 B cycles; with the fix (`vendor/smartstring/PATCHES.md`) it costs 0.1 M.
- `pad` and string character assignment built strings one character at a time; `drain` and `retain` with a callback removed elements one by one (quadratic). All now copy in bulk, with Rhai's behaviour unchanged (test `rewritten_rhai_functions_keep_upstream_behaviour`).
- `pad` with an empty padding string looped forever inside a native function, where no meter runs.

**Measured.** `tools/cost-suite.py` runs 57 attack scripts, each repeated on every step until the budgets run out, under the fixture budgets (20 k operations per script, 60 k per session, 64 KiB strings, 16 M data units), and fails if any session exceeds 300 M cycles. The worst cases:

| Attack | Before the review fixes | Now |
|---|---|---|
| `contains` / `index_of` scans of 64 KiB | | **272 M** |
| interpolation of a 64 KiB string | 6.8 B | 258 M |
| array comparisons, then string scans | | 250 M |
| `to_lower` on 64 KiB of capital sigma | 4.3 B | 244 M |
| `drain` / `retain` on 4 096 elements | | 223 M |
| `in` / `index_of` / `==` on 4 000 elements | 2.0 B | 200-220 M |
| arrays of maps passed to a script function | | 205 M |
| curried function pointers (doubling, nesting) | 4.5-34.9 B | 150-190 M |
| nested constant arrays | 1.38 B | 3 M |
| `pad` to 64 KiB, in a loop | 1.25 B for one call | 22 M |
| `replace` that builds 512 MiB | 610 M (built before the size check) | refused before building (5.5 M) |

So the worst session found costs about 270 M cycles, about 16 cycles per unit of the 16 M data budget. This is measured, not proven: the suite covers the expensive paths that the first metering missed and that a review found, not every path in Rhai. Smaller budgets lower the bound roughly in proportion.

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

`host/build.rs` embeds that ELF. Result: two clean builds, and a build from a copy at another path, gave the same ELF (SHA-256 `62f2262d...c43183` for the current program).

Limits:
- The build directory is part of the flags, so only `/tmp/ph-repro` gives the published vk. `PH_REPRO_DIR` picks another one for experiments; the script then prints `canonical no` and `host/build.rs` warns. The script refuses a directory owned by another user or writable by others: `/tmp` is shared, and such a directory could hold planted sources or crates.
- Same SP1 toolchain build only. The prebuilt macOS and Linux toolchains embed different std paths, so a cross-OS canonical vk needs SP1's Docker build. Reproduction has only been checked on one macOS machine. `ph vk` prints the vk.

### 12.5 Formats and fuzzing

- **Formats.** Witnesses and eval batches start with `FORMAT_VERSION` (now 3); old files fail with a clear message. Claim v6 added `tool_mode_hash`; v7 salts the commitments to private data (13.1).
- **Fuzzing** (`fuzz/`, `cargo +nightly fuzz run -O <target>`):

  | Target | Result |
  |---|---|
  | HTTP response parser | 8.1 M runs, clean |
  | model replies (fixed-point check of canonical blocks) | found float canonicalization was not a fixed point: serde_json's default float parsing is not correctly rounded. Fixed with `float_roundtrip`, which also gives Python `float()` semantics for graded amounts. 10.2 M runs since. |
  | URL policy | 17.1 M runs, clean (the one crash was a bug in the fuzz target) |
  | bank API | 6.9 M runs, clean |
  | signature differential vs ring (`webpki-algs`, 13 algorithms) | 548 k runs, no divergence |

## 13. Review fixes (2026-11-22, program vk `0x00923577...3943`, claim v7)

An independent review found no input the guest accepts and should reject, but found weak spots around the proven statement. Besides the metering rework (12.2):

### 13.1 Salted claim commitments

The claim's `final_answer_hash`, `final_workspace_root` and `transcript_hash` were plain hashes, so anyone holding a claim could confirm a guessed answer or file (a withheld short answer, a guessable secret written to the workspace). Each is now `H("ph/v1/salted-commitment", salt, value)` with `salt = H("ph/v1/claim-salt", blind, label)`, where `blind` is the run's private seed (the one that already salts the action log). The host writes the salts into the disclosure files: `transcript.json` carries the transcript and final-answer salts, `final_workspace.json` the workspace salt. Disclosing one does not reveal the others. `initial_workspace_root` stays unsalted: the verifier recomputes it from the published workspace.

### 13.2 Replies cut off at `max_tokens`

A reply that stopped at `max_tokens` may end in the middle of a script, and the prefix can still parse and do something else. zkTLS backends now report the attested `stop_reason`; the session runs nothing from such a reply. In code mode the tool message says the script was not run; in native mode every `tool_use` of the reply gets an error result. A truncated final answer (no script, no tool call) still ends the session.

### 13.3 Graders belong to evals

A single-session witness could carry an `EvalSpec`, and `ph verify` printed its grade as proven although no verifier pinned the grader. The guest now refuses a single session with a grader (`verify_witness`), and `ph verify` fails on a claim that carries a grade.

### 13.4 Pre-registration and the notary log

See EVALS.md ("Seed shopping", "Missing runs") and ZKTLS.md 4.1. In short: the notary time-stamps each pre-registration with a signed receipt, which `ph eval verify` requires to predate the drand round; every session log lists all pre-registrations, so one suite pre-registered twice is visible; a missing run is either "never started" or "started and not delivered"; and `ph eval verify` fails on missing runs unless `--allow-missing` accepts them.

### 13.5 Smaller fixes

- The guest's TLSNotary provider refuses the library's built-in signature schemes outright, not only in a check after verification.
- Model ids: only a dated snapshot (`-YYYYMMDD`) of the pinned model is accepted; before, any digit suffix was, so `claude-haiku-5` accepted `claude-haiku-5-5`.
- Key files (`ph keygen`, `ph-zktls keygen`) are created owner-only and never overwritten.
- The notary refuses to run without operator tokens on a non-loopback address unless told `--open`, and caps the attestation request it reads at 1 MiB.
- `ph eval run` saves each run's evidence as soon as it exists and resumes from it.
- AgentDojo ports: the code-mode slice (v2) grades the final bank state, as AgentDojo does; the native port allows AgentDojo's 16 model calls and slices recent transactions as Python does.
