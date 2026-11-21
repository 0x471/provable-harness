use std::process::Command;

/// "rustc 1.93.0-dev (abc 2025-..)" -> "1.93.0".
fn release(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("running {what}: {e}"));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let version = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("unexpected `{what}` output: {text:?}"));
    version.split('-').next().unwrap_or(version).to_string()
}

fn main() {
    // The host replays ph-core natively and the guest replays it in the zkVM;
    // both must produce identical text. Text depends on std's Unicode tables
    // (case mapping, `{:?}` escaping inside dependencies), which only match if
    // both are built by the same Rust release. Refuse to build otherwise: a
    // mismatch would make some honest runs unprovable.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let host = release(Command::new(&rustc).arg("--version"), "host rustc --version");
    let guest = release(Command::new("rustc").args(["+succinct", "--version"]), "rustc +succinct --version");
    if host != guest {
        panic!(
            "host Rust {host} differs from the SP1 guest toolchain's Rust {guest}; \
             pin rust-toolchain.toml to {guest} (host and guest must share std's Unicode tables)"
        );
    }
    println!("cargo:rerun-if-changed=../rust-toolchain.toml");

    // The guest ELF is built by tools/repro-guest-build.sh: sources copied to a
    // fixed directory, a fixed CARGO_HOME, sp1-build 6.10.0's exact flags, in a
    // cleared environment (nothing from this cargo leaks in). So the embedded
    // ELF, and the program vk, are the ones anyone rebuilds from this commit
    // with the same SP1 toolchain (docs/DESIGN.md, "Reproducible builds").
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let repo = manifest.parent().expect("host/ has a parent").to_path_buf();
    let mut cmd = Command::new(repo.join("tools/repro-guest-build.sh"));
    cmd.env_clear();
    for k in ["PATH", "HOME", "RUSTUP_HOME", "TMPDIR", "USER", "PH_REPRO_DIR"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    let out = cmd.output().expect("running tools/repro-guest-build.sh");
    if !out.status.success() {
        panic!("guest build failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let field = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(k).map(str::trim).map(str::to_string))
            .unwrap_or_else(|| panic!("no {k} in guest build output: {stdout}"))
    };
    let elf = field("elf ");
    println!("cargo:warning=ph-program ELF sha256 {}", field("elf_sha256 "));
    println!("cargo:rustc-env=SP1_ELF_ph-program={elf}");
    for p in ["core", "program/src", "program/Cargo.toml", "program/Cargo.lock", "vendor/rhai", "vendor/tlsn", "webpki-algs", "tools/repro-guest-build.sh", "Cargo.toml"] {
        println!("cargo:rerun-if-changed={}", repo.join(p).display());
    }
    println!("cargo:rerun-if-env-changed=PH_REPRO_DIR");
}
