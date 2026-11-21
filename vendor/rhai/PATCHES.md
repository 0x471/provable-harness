# Rhai 1.27.0, patched for provable-harness

Unmodified crates.io `rhai 1.27.0` (MIT OR Apache-2.0) plus one feature: a
**data-volume meter** (`Engine::on_data_volume`), so the harness can bound the
zkVM cost of any script. Rhai meters operations only, but the cost of one
operation grows with the size of the data it touches (measured in the zkVM:
`to_upper` on 64 KiB ~0.9 M cycles, `switch` on a 64 KiB string ~0.5 M cycles,
versus ~400 cycles for a plain operation).

Every change is marked `(provable-harness patch)`:

- `func/native.rs`, `engine.rs`, `api/events.rs`: the callback type, the
  `Engine::data_volume` field, and `Engine::on_data_volume`.
- `eval/data_check.rs`: `track_data_volume`, `track_value_volume`,
  `track_clone_volume`, `track_args_volume`; `check_data_size` meters every
  checked result.
- `func/func_call.rs`, `func/call.rs`, `types/fn_ptr.rs`: arguments of every
  native call (named, method, function-pointer and qualified calls). With fast
  operators off (the harness sets this), operators are native calls too.
- `eval/expr.rs`, `eval/chaining.rs`: variable, element and property reads
  (they clone arrays and maps).
- `eval/stmt.rs`: `switch` hashes its value; `eval/indexing.rs`: indexing a
  string by position walks it.

Units: string bytes, plus 16 per array or map element (`ELEMENT_WEIGHT`; walking
an element costs ~16x a string byte in the zkVM), plus 1 per call. The meter is
deterministic (it depends only on data sizes), so the native host run and the
zkVM replay stop at the same point.

