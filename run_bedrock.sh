#!/usr/bin/env bash
#
# Runs every command from doc/src/usage/bedrock.md, in order, so that fuzzing
# bedrock is one command instead of ten.
#
# Usage:
#   ./run_bedrock.sh [BEDROCK] [BITCOIN] [WD] [CORES] [GUEST_MEMORY_MB] \
#                    [TIMEOUT] [SETUP_TIMEOUT]
#
# Every argument is optional; the defaults below are used for any not given.
#   ./run_bedrock.sh
#   ./run_bedrock.sh /root/bedrock /root/bitcoin /tmp/fuzzamoto-bedrock 0-7 4096
#
# Environment overrides:
#   AFL           AFL++ checkout to instrument the target with (/root/AFLplusplus)
#   SOURCES_PATH  depends download cache ($WD/bitcoin-depends)
#
set -euo pipefail

case "${1-}" in -h|--help) sed -n '2,19p' "$0"; exit 0;; esac

if [ "$#" -gt 7 ]; then
    echo "too many arguments; see $0 --help" >&2
    exit 2
fi

BEDROCK=${1:-/root/bedrock}
BITCOIN=${2:-/root/bitcoin}
WD=${3:-/tmp/fuzzamoto-bedrock}
CORES=${4:-0-3}
GUEST_MEMORY_MB=${5:-6144}
TIMEOUT=${6:-30000}
SETUP_TIMEOUT=${7:-120}

FUZZAMOTO=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

LLVM_V=19
LLD=lld-$LLVM_V
AFL=${AFL:-/root/AFLplusplus}
SOURCES_PATH=${SOURCES_PATH:-$WD/bitcoin-depends}

step() { echo; echo "=== $* ==="; }

# --- paths ------------------------------------------------------------------
step "Setting up paths in $WD"
mkdir -p "$WD"
VM=$(cd "$BEDROCK" && nix build .#guestKernel --print-out-paths --no-link)/vmlinux
echo "guest kernel: $VM"

# --- afl++ ------------------------------------------------------------------
# The target is instrumented exactly like the Nyx campaign's (Dockerfile.libafl):
# AFL++ PCGUARD via afl-clang-fast, so `cov` percentages from the two backends
# measure the same thing. The agent hands the map to the target over
# __AFL_SHM_ID; see fuzzamoto-bedrock-sys/src/bedrock-agent.c.
step "Looking for AFL++ in $AFL"
AFL_CC="$AFL/afl-clang-fast"
AFL_CXX="$AFL/afl-clang-fast++"
if [ ! -x "$AFL_CC" ] || [ ! -x "$AFL_CXX" ]; then
    cat >&2 <<EOF
afl-clang-fast{,++} not found in $AFL. Build AFL++ first:

    git clone https://github.com/AFLplusplus/AFLplusplus $AFL
    LLVM_CONFIG=llvm-config-$LLVM_V make -C $AFL PERFORMANCE=1 -j\$(nproc)

or point AFL= at an existing checkout.
EOF
    exit 1
fi

# --- target patches ---------------------------------------------------------
# doc/src/usage/target-patches.md. The aggressive RNG patch is the one that
# matters here: bedrock's determinism guarantees stop at the guest's own
# non-determinism, and Core reseeds its RNG per thread without it. The two RNG
# patches are alternatives -- do not apply both.
# (bitcoin-core-reset-coverage-counters.patch is for source-based coverage
# tooling, not for a campaign, so it is not applied -- the agent zeroes the map
# before the checkpoint, which is what a campaign needs.)
step "Applying target patches to $BITCOIN"
for patch in "$FUZZAMOTO/target-patches/bitcoin-core-aggressive-rng.patch"; do
    name=$(basename "$patch")
    if git -C "$BITCOIN" apply --check --reverse "$patch" >/dev/null 2>&1; then
        echo "$name: already applied, skipping"
    elif git -C "$BITCOIN" apply "$patch"; then
        echo "$name: applied"
    else
        echo "$name: failed to apply -- rebase it against $BITCOIN and retry" >&2
        exit 1
    fi
done

# --- bitcoin core -----------------------------------------------------------
# Same toolchain, sanitizer, depends tree and instrumentation denylist as
# Dockerfile.libafl's build_fuzz, in its own build dir. Anything that differs
# here shows up as a difference in the coverage map, so keep the two in sync.
cd "$BITCOIN"
export CC=$AFL_CC CXX=$AFL_CXX LD=$AFL_CC
export AFL_LLVM_DENYLIST="$FUZZAMOTO/target-patches/bitcoin-core-ir-denylist.txt"
export SOURCES_PATH

step "Building Bitcoin Core depends (AFL++ instrumented)"
make -C depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 download-linux
make -C depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
  AR=llvm-ar-$LLVM_V NM=llvm-nm-$LLVM_V RANLIB=llvm-ranlib-$LLVM_V \
  STRIP=llvm-strip-$LLVM_V \
  -j"$(nproc)"

step "Building Bitcoin Core (build_bedrock, AFL++/ASan)"
# An earlier trace-pc-guard tree in this directory was configured without the
# depends toolchain; cmake refuses to switch, so say so instead of failing deep
# inside the configure step.
if [ -f build_bedrock/CMakeCache.txt ] &&
   ! grep -q '^CMAKE_TOOLCHAIN_FILE' build_bedrock/CMakeCache.txt; then
    echo "$BITCOIN/build_bedrock was configured without the depends toolchain;" >&2
    echo "remove it (rm -rf $BITCOIN/build_bedrock) and re-run." >&2
    exit 1
fi
# Everything not stated here is left at its default *on purpose*: the Nyx build
# passes no ENABLE_IPC, no ENABLE_WALLET and no WITH_SQLITE either, so IPC (which
# cmake_dependent_option defaults ON off Windows, with Cap'n Proto coming from
# depends' ipc_packages), the wallet and sqlite are all compiled in on both
# backends. The denylist, not the build configuration, is what keeps rpc/wallet
# code out of the coverage map.
cmake -B build_bedrock -G Ninja \
  --toolchain "./depends/$(./depends/config.guess)/toolchain.cmake" \
  -DSANITIZERS=address \
  -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DBUILD_GUI=OFF \
  -DAPPEND_CPPFLAGS="-DFUZZAMOTO_FUZZING -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DABORT_ON_FAILED_ASSUME" \
  -DAPPEND_LDFLAGS="-fuse-ld=$LLD"
cmake --build build_bedrock -j"$(nproc)" --target bitcoind

BITCOIND="$BITCOIN/build_bedrock/bin/bitcoind"
# The agent sizes the coverage buffer it registers from this binary's own map
# size, which the crate's build script reads back with AFL_DUMP_MAP_SIZE=1.
export BITCOIND_PATH="$BITCOIND"
echo "coverage map: $(AFL_DUMP_MAP_SIZE=1 "$BITCOIND" || true) bytes"

# --- guest image ------------------------------------------------------------
# Back to a plain toolchain for everything that is not the target, as
# Dockerfile.libafl does: the agent and the scenario must stay uninstrumented,
# or they link AFL++'s runtime and attach the target's map themselves.
export CC=clang-$LLVM_V CXX=clang++-$LLVM_V LD=$LLD
unset AFL_LLVM_DENYLIST

step "Building the guest image"
cd "$FUZZAMOTO"
cargo build --release -p fuzzamoto-scenarios --features fuzz_bedrock
gcc -O2 -static -I"$BEDROCK/guest" -o "$WD/init" \
    fuzzamoto-bedrock-sys/guest/init.c
./fuzzamoto-bedrock-sys/guest/build-initramfs.sh \
    target/release/scenario-ir "$BITCOIND" \
    "$WD/init" "$WD/fuzzamoto-ir.cpio.gz"

# --- campaign ---------------------------------------------------------------
step "Building fuzzamoto-libafl (bedrock backend)"
cargo build --release -p fuzzamoto-libafl --no-default-features --features std,bedrock

step "Running the campaign"
mkdir -p "$WD/in"
exec ./target/release/fuzzamoto-libafl \
    --input "$WD/in" --output "$WD/out" \
    --vmlinux "$VM" --initramfs "$WD/fuzzamoto-ir.cpio.gz" \
    --cores "$CORES" --guest-memory-mb "$GUEST_MEMORY_MB" \
    --timeout "$TIMEOUT" --setup-timeout "$SETUP_TIMEOUT"
