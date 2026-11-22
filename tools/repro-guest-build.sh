#!/bin/sh
# Canonical, reproducible build of the harness guest ELF.
#
# Cargo folds RUSTFLAGS (and so any --remap-path-prefix holding a local path)
# into crate hashes, and source paths end up in panic messages, so a build in
# place depends on the checkout location and on $CARGO_HOME. This script copies
# the guest's sources to a fixed directory and uses a fixed CARGO_HOME there,
# then builds with sp1-build 6.10.0's exact flags. Same commit + same SP1
# toolchain build (same OS) => same ELF, whoever and wherever builds it.
#
# Usage: tools/repro-guest-build.sh            (prints elf_sha256 and the ELF path)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
BASE=${PH_REPRO_DIR:-/tmp/ph-repro}
mkdir -p "$BASE"
BASE=$(cd "$BASE" && pwd -P)
# /tmp is shared: a directory another user created, or can write to, could hold
# planted sources or crates that this build would compile into the guest.
PERM=$(ls -ld "$BASE" | cut -c1-10)
case "$PERM" in
?????w????|????????w?) echo "refusing $BASE: writable by group or others" >&2; exit 1 ;;
esac
if [ ! -O "$BASE" ]; then
    echo "refusing $BASE: owned by another user" >&2
    exit 1
fi
SRC="$BASE/src"
mkdir -p "$SRC"
for d in program core vendor/rhai vendor/smartstring vendor/tlsn webpki-algs; do
    mkdir -p "$SRC/$d"
    rsync -a --delete --exclude target "$ROOT/$d/" "$SRC/$d/"
done
cp "$ROOT/rust-toolchain.toml" "$SRC/"
# core/ and webpki-algs/ inherit package fields from the root workspace; keep it
# without the host (not part of the guest).
sed 's/^members = .*/members = ["core", "webpki-algs"]/' "$ROOT/Cargo.toml" > "$SRC/Cargo.toml"
US=$(printf '\037')
FLAGS="-C${US}passes=lower-atomic${US}-C${US}link-arg=--image-base=2013265920${US}-C${US}panic=abort${US}--cfg${US}getrandom_backend=\"custom\"${US}-C${US}llvm-args=-misched-prera-direction=bottomup${US}-C${US}llvm-args=-misched-postra-direction=bottomup${US}--remap-path-prefix=$SRC=/ph${US}--remap-path-prefix=$BASE/cargo=/cargo"
RUSTC_BIN="$(RUSTUP_TOOLCHAIN=succinct rustc --print sysroot)/bin/rustc"
cd "$SRC/program"
env -u RUSTC RUSTUP_TOOLCHAIN=succinct RUSTC="$RUSTC_BIN" RUSTC_BOOTSTRAP=1 \
    CARGO_HOME="$BASE/cargo" CARGO_ENCODED_RUSTFLAGS="$FLAGS" CARGO_TARGET_DIR="$BASE/target" \
    cargo build --locked --release --target riscv64im-succinct-zkvm-elf >&2
ELF="$BASE/target/riscv64im-succinct-zkvm-elf/release/ph-program"
echo "elf_sha256 $(shasum -a 256 "$ELF" | cut -d' ' -f1)"
echo "elf $ELF"
