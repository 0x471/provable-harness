#!/usr/bin/env python3
"""Proving-cost suite for code mode (docs/DESIGN.md, section 12.2).

Each case is a scripted session that tries to make proving expensive under the
default budgets. The suite runs every case with `ph demo --prove none` (live
run plus zkVM execution, no proof) and checks its cycle count against a bound.

usage: python3 -I tools/cost-suite.py [--ph target/release/ph] [--max-cycles N]
                                      [--out DIR] [--json FILE] [case ...]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

DEFAULT_POLICY = {
    "max_steps": 8,
    "max_tool_calls": 32,
    "max_script_operations": 20000,
    "max_session_operations": 60000,
    "max_string_bytes": 65536,
    "max_session_data": 16777216,
    "max_output_chars": 6000,
    "fs_read": ["/docs", "/secrets", "/out"],
    "fs_write": ["/out"],
    "secret_paths": ["/secrets"],
    "net_get": ["https://api.example/"],
    "net_post": ["https://api.example/report"],
    "deny_egress_after_secret_read": True,
}

X64 = "x" * 65536
BIG = {"/docs/big.txt": X64}
READ = 'let s = read_file("/docs/big.txt"); '
ARR4000 = "let a = []; a.pad(4000, 0); "


def const_bomb(k):
    s = "const A0=[0,0,0,0,0,0,0,0,0,0]; "
    for i in range(1, k):
        s += "const A%d=[%s]; " % (i, ",".join(["A%d" % (i - 1)] * 10))
    return s + "1"


def json_doc(item, n):
    return ("[" + ",".join([item] * n))[:65500] + "!"


# name, idea, scripts (one per step), workspace, fetchable URLs (GET)
CASES = [
    ("baseline", "one trivial script", ["1"], None, None),
    ("loop", "counting loop, 8 steps", ["let i = 0; loop { i += 1; }"] * 8, None, None),
    ("to-upper", "to_upper on 64 KiB of ASCII, 8 steps", [READ + "loop { s.to_upper(); }"] * 8, BIG, None),
    ("to-upper-2byte", "to_upper on 64 KiB of U+00E9", [READ + "loop { s.to_upper(); }"], {"/docs/big.txt": "é" * 32768}, None),
    ("to-lower-sigma", "to_lower on 64 KiB of capital sigma", [READ + "loop { s.to_lower(); }"], {"/docs/big.txt": "Σ" * 32768}, None),
    ("interp", "interpolation of a 64 KiB string", [READ + "loop { let t = `${s}`; }"], BIG, None),
    ("interp-many", "interpolation with many pieces", [READ + "loop { let t = `${s}${s}${1}${s}`; }"], BIG, None),
    ("const-literal", "1000-element array literal per iteration", ["let x = 0; loop { x = [%s]; }" % ",".join(["0"] * 1000)], None, None),
    ("const-bomb-4", "nested const arrays, 10^4 elements", [const_bomb(4)], None, None),
    ("const-bomb-5", "nested const arrays, 10^5 elements", [const_bomb(5)], None, None),
    ("const-bomb-6", "nested const arrays, 10^6 elements", [const_bomb(6)], None, None),
    ("closure-map", "200 callbacks with 1000-iteration loops", ["let a = []; a.pad(200, 0); a.map(|x| { let i = 0; while i < 1000 { i += 1; } i }).len()"], None, None),
    ("closure-retry", "callbacks that exhaust the budget, caught 50 times", ["let n = 0; for k in 0..50 { try { [1].map(|x| { loop { } }); } catch { n += 1; } } n"] * 8, None, None),
    ("closure-sort", "sort with a non-terminating comparator", ["let a = []; for i in 0..64 { a.push(i); } a.sort(|x, y| { loop { } }); 1"] * 8, None, None),
    ("closure-capture", "closures capturing a 4000-element array", [ARR4000 + "loop { let f = |x| a.len(); }"], None, None),
    ("curry-double", "f = f.curry(f) 12 times, then clone it", ['let f = Fn("foo").curry(0); for i in 0..12 { f = f.curry(f); } let g = 0; loop { g = f; }'], None, None),
    ("curry-pair", "f = Fn(g).curry(f, f) 14 times", ['fn g(a, b) { 0 } let f = Fn("g"); for i in 0..14 { f = Fn("g").curry(f, f); } 1'], None, None),
    ("curry-array", "curry a 4000-element array, then clone it", [ARR4000 + 'let f = Fn("foo").curry(a); let g = 0; loop { g = f; }'], None, None),
    ("curry-nest", "3000-deep nested curried function", ['let f = Fn("foo"); for i in 0..3000 { f = Fn("foo").curry(f); } type_of(f)'], None, None),
    ("curry-call", "call a function pointer with 4000 curried elements", ['fn h(a, x) { x } ' + ARR4000 + 'let f = Fn("h").curry(a); loop { f.call(1); }'], None, None),
    ("map-keys", "maps with 64 KiB keys, cloned in a loop", [READ + "let m = #{}; m[s] = 1; let a = []; a.pad(8, m); let b = 0; loop { b = a; }"], BIG, None),
    ("fn-arg", "4095-element array passed to a script function", ["fn f(x) { 0 } let a = []; a.pad(4095, #{k: 1}); loop { f(a); }"], None, None),
    ("nest-arrays", "arrays nested one level deeper per iteration", ["let a = []; loop { a = [a]; }"], None, None),
    ("pad", "pad to 64 KiB once", ['let s = "x"; s.pad(65536, \'x\'); 1'], None, None),
    ("pad-loop", "pad a fresh string to 64 KiB in a loop", ['loop { let s = "x"; s.pad(65536, \'x\'); }'], None, None),
    ("char-set", "assign characters of a 64 KiB string", [READ + "let i = 0; loop { s[i % 1000] = 'y'; i += 1; }"], BIG, None),
    ("append", "append to a string until the size limit", ['let s = ""; loop { s += "xxxxxxxxxxxxxxxx"; }'] * 8, None, None),
    ("array-append", "double an array until the size limit", ["let a = [1]; loop { a += a; }"] * 8, None, None),
    ("replace-64m", "replace that would build 64 MiB", [READ + 'let t = s.sub_string(0, 1024); t.replace("x", s); t.len()'], BIG, None),
    ("replace-512m", "replace that would build 512 MiB", [READ + 'let t = s.sub_string(0, 8192); t.replace("x", s); t.len()'], BIG, None),
    ("replace-loop", "replace over 64 KiB in a loop", [READ + 'loop { let t = s; t.replace("x", "y"); }'], BIG, None),
    ("json-objects", "parse_json: ~9000 short keys, invalid tail", [READ + "loop { try { parse_json(s); } catch { } }"], {"/docs/big.txt": ("{" + ",".join('"a%d":0' % (i % 10) for i in range(9000)))[:65500] + "!"}, None),
    ("json-floats", "parse_json: 13000 small floats, invalid tail", [READ + "loop { try { parse_json(s); } catch { } }"], {"/docs/big.txt": json_doc("1e-5", 13000)}, None),
    ("json-empties", "parse_json: 21000 empty arrays, invalid tail", [READ + "loop { try { parse_json(s); } catch { } }"], {"/docs/big.txt": json_doc("[]", 21000)}, None),
    ("json-long-floats", "parse_json: 720-digit floats, invalid tail", [READ + "loop { try { parse_json(s); } catch { } }"], {"/docs/big.txt": json_doc("0." + "123456789" * 80 + "e-9", 90)}, None),
    ("json-valid", "parse_json of a valid 60 KiB array of strings", [READ + "loop { parse_json(s); }"], {"/docs/big.txt": "[" + ",".join(['"abcdefgh"'] * 5400) + "]"}, None),
    ("sort-strings", "sort 4000 strings with a shared prefix", ['let a = []; for i in 0..4000 { a.push("aaaaaaaaaaaaaaa" + (4000 - i)); } loop { let b = a; b.sort(); }'], None, None),
    ("contains-array", "`in` on a 4000-element array, 8 steps", [ARR4000 + "loop { 7 in a; }"] * 8, None, None),
    ("eq-array", "== on two 4000-element arrays, 8 steps", [ARR4000 + "let b = a; loop { a == b; }"] * 8, None, None),
    ("index-of", "index_of on a 4000-element array, 8 steps", [ARR4000 + "loop { a.index_of(7); }"] * 8, None, None),
    ("drain-all", "drain every element of a 4096-element array", ["let a = []; a.pad(4096, 0); loop { let b = a; b.drain(|x| true); }"] * 8, None, None),
    ("retain-none", "retain no element of a 4096-element array", ["let a = []; a.pad(4096, 0); loop { let b = a; b.retain(|x| false); }"] * 8, None, None),
    ("pad-empty", "pad with an empty string (looped forever before)", ['let s = "a"; s.pad(10, ""); s.len()'], None, None),
    ("pad-string-loop", "pad with a one-character string to 64 KiB in a loop", ['loop { let s = "x"; s.pad(65536, "y"); }'], None, None),
    ("switch-string", "switch on a 64 KiB string", [READ + 'loop { switch s { "a" => 1, _ => 2 } }'], BIG, None),
    ("split-chars", "to_chars of 64 KiB inside callbacks", [READ + "loop { try { [1].map(|i| s.to_chars()); } catch { } }"], BIG, None),
    ("split", "split 64 KiB into 4096 pieces", [READ + 'let t = s.sub_string(0, 8191); loop { t.split("x"); }'], BIG, None),
    ("string-search", "contains and index_of on 64 KiB", [READ + 'loop { s.contains("y"); s.index_of("xy"); }'], BIG, None),
    ("recursion", "recursion to the call-level limit", ["fn f(n) { if n > 0 { [[[[ f(n - 1) ]]]] } else { 0 } } let r = 0; loop { try { f(40); } catch { r += 1; } }"], None, None),
    ("long-script", "a 32 KiB script of nested expressions", ["let x = 0; " + "x = ((((((((x + 1)))))))); " * 1100 + "x"], None, None),
    ("print-big", "print a 64 KiB string in a loop", [READ + "loop { print(s); }"], BIG, None),
    ("read-256k", "read_file of a 256 KiB file, 32 times", ['for i in 0..32 { try { [1].map(|x| read_file("/docs/big.txt")); } catch { } } 1'], {"/docs/big.txt": "y" * 262144}, None),
    ("write-64k", "write_file of 64 KiB until the tool budget", [READ + 'for i in 0..40 { write_file("/out/f" + i, s); } 1'], BIG, None),
    ("denied-64k", "16 denied 64 KiB writes per script, 8 steps", [READ + 'loop { try { write_file("/etc/x", s); } catch { } }'] * 8, BIG, None),
    ("get-big", "http_get of 60 KB, 32 times", ['for i in 0..32 { http_get("https://api.example/big"); } 1'], None, {"https://api.example/big": "z" * 60000}),
    ("ops-then-data", "array comparisons, then string scans", [ARR4000 + "let i = 0; while i < 12 { 7 in a; i += 1; } 1"] + [READ + 'loop { s.contains("y"); s.index_of("xy"); }'] * 7, BIG, None),
    ("tools-then-data", "32 reads of a 256 KiB file, then string scans", ['for i in 0..32 { try { [1].map(|x| read_file("/docs/big.txt")); } catch { } } 1'] + ['let s = "x"; s.pad(65536, "x"); loop { s.contains("y"); s.index_of("xy"); }'] * 7, {"/docs/big.txt": "y" * 262144}, None),
]


def build(case_dir, scripts, workspace, world_get):
    os.makedirs(os.path.join(case_dir, "workspace", "docs"))
    with open(os.path.join(case_dir, "scenario.json"), "w") as f:
        json.dump({"task": "Follow the brief.", "system_prompt": "../system_prompt.md"}, f)
    with open(os.path.join(case_dir, "policy.json"), "w") as f:
        json.dump(DEFAULT_POLICY, f)
    replies = ["Running code.\n```rhai\n" + s + "\n```\n" for s in scripts]
    if len(replies) < DEFAULT_POLICY["max_steps"]:
        replies.append("done")
    with open(os.path.join(case_dir, "model.json"), "w") as f:
        json.dump({"model_id": "scripted/cost-suite", "replies": replies}, f)
    with open(os.path.join(case_dir, "world.json"), "w") as f:
        json.dump({"get": world_get or {}, "post": {"https://api.example/report": "ok"}}, f)
    files = {"/docs/readme.md": "hello\n"}
    files.update(workspace or {})
    for path, content in files.items():
        p = os.path.join(case_dir, "workspace", path.lstrip("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)


def last_result(out_dir):
    try:
        with open(os.path.join(out_dir, "transcript.json")) as f:
            messages = json.load(f)["messages"]
    except (OSError, ValueError, KeyError):
        return "no transcript"
    tools = [m["content"] for m in messages if m["role"].lower() == "tool"]
    if not tools:
        return "no script"
    c = tools[-1]
    for key in ("\nerror:\n", "\nvalue:\n"):
        if key in c:
            return ("error: " if "error" in key else "value: ") + c.split(key, 1)[1].strip().splitlines()[0][:70]
    return c.strip().splitlines()[-1][:70]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ph", default="target/release/ph")
    ap.add_argument("--max-cycles", type=int, default=300_000_000)
    ap.add_argument("--out", help="keep scenarios and runs here")
    ap.add_argument("--json", help="write the results here")
    ap.add_argument("cases", nargs="*")
    a = ap.parse_args()
    names = [c[0] for c in CASES]
    unknown = [n for n in a.cases if n not in names]
    if unknown:
        sys.exit("unknown case(s): %s" % ", ".join(unknown))
    root = a.out or tempfile.mkdtemp(prefix="ph-cost-")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "system_prompt.md"), "w") as f:
        f.write("You are a test agent.\n")
    results, failed = [], []
    for name, idea, scripts, workspace, world_get in CASES:
        if a.cases and name not in a.cases:
            continue
        case_dir = os.path.join(root, name)
        out_dir = os.path.join(root, name + ".out")
        for d in (case_dir, out_dir):
            shutil.rmtree(d, ignore_errors=True)
        build(case_dir, scripts, workspace, world_get)
        p = subprocess.run([a.ph, "demo", "--scenario", case_dir, "--out", out_dir, "--prove", "none"],
                           capture_output=True, text=True)
        m = re.search(r"zkVM execution OK: (\d+) cycles", p.stdout + p.stderr)
        cycles = int(m.group(1)) if m else None
        ok = p.returncode == 0 and cycles is not None and cycles <= a.max_cycles
        if not ok:
            failed.append(name)
        r = {"name": name, "idea": idea, "cycles": cycles, "result": last_result(out_dir), "ok": ok}
        results.append(r)
        print("%-18s %15s  %s  %s" % (name, "{:,}".format(cycles) if cycles else "FAILED",
                                      "" if ok else "<-- over the bound or failed", r["result"]), flush=True)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(results, f, indent=1)
    if not a.out:
        shutil.rmtree(root)
    worst = max((r["cycles"] or 0 for r in results), default=0)
    print("worst case: {:,} cycles (bound {:,})".format(worst, a.max_cycles))
    if failed:
        sys.exit("over the bound or failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
