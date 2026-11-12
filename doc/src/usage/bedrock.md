# Fuzzing with bedrock

*Bedrock has stricter hardware requirements than Nyx. Some of the hardware listed under
[system requirements](./requirements.md) may not work. Refer to the bedrock [README](https://github.com/oss-garage/bedrock/blob/master/README.md) for a
list of confirmed working hardware. Intel generations before Skylake may work but have not been tested.*

---

*Note: currently fuzzing support is not merged into bedrock and bedrock support is not merged into fuzzamoto.
Therefore, you must checkout the bedrock code from [this PR](https://github.com/oss-garage/bedrock/pull/68) and you must checkout the
fuzzamoto code from [this PR](https://github.com/oss-garage/fuzzamoto/pull/165).*

Currently bedrock support only works for [`fuzzamoto-libafl`](https://github.com/oss-garage/fuzzamoto/tree/master/fuzzamoto-libafl).

It is assumed that the host kernel is linux 6.18 with `CONFIG_RUST=y`. Build
instructions for this are not provided as this may vary between machines.
It is also assumed that `apt` is installed, but the below instructions should work
with a different package manager.

First, we'll use some environment variables as shorthand to make this document
less verbose:

```
AFL=/path/to/AFLplusplus
BEDROCK=/path/to/bedrock
BITCOIN=/path/to/bitcoin
FUZZAMOTO=/path/to/fuzzamoto
LINUX=/path/to/linux-6.18-tree
WORKDIR=/path/to/workdir
```

Install the below dependencies:

```
apt install make libelf1t64 curl ca-certificates xz-utils \
    git gcc g++ libc6-dev cmake ninja-build patch pkg-config libssl-dev \
    pax-utils cpio
```

It is beneficial to install a recent LLVM from source instead of from `apt` or similar:

```
git clone --depth 1 --branch llvmorg-23.1.5 https://github.com/llvm/llvm-project

# If you want to run fuzzamoto with MSAN or TSAN, different options are needed.
cmake -G Ninja -S llvm-project/llvm -B llvm-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD=Native \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_ENABLE_RUNTIMES="compiler-rt"

ninja -C llvm-build install

# This should show version 23.1.5
clang --version
```

You will also need to install the Nix package manager (not to be confused with
the *Nyx* hypervisor!) with the flakes feature enabled:

```
sh <(curl -L https://nixos.org/nix/install) --daemon --yes
echo 'experimental-features = nix-command flakes' >> /etc/nix/nix.conf
```

Next, build `bedrock.ko`, the guest kernel, and insert `bedrock.ko`:

```
cd "$BEDROCK"

make -C crates/bedrock KDIR="$LINUX" \
  LLVM=1 \
  KCFLAGS=-Wno-error=unused-command-line-argument \
  KAFLAGS=-Wno-error=unused-command-line-argument

# Insert the built kernel module
insmod crates/bedrock/bedrock.ko

# There should be an entry for this
ls /dev/bedrock

# Build the guest kernel which will run inside the VM
GUEST=$(nix build .#guestKernel --print-out-paths --no-link)/vmlinux
```

Then, build AFL++:

```
git clone https://github.com/AFLplusplus/AFLplusplus "$AFL"
LLVM_CONFIG=llvm-config make -C "$AFL" PERFORMANCE=1 -j$(nproc)
```

Then, patch and build Bitcoin Core with AFL++:

```
cd "$BITCOIN"

# Apply the patch for deterministic RNG
git apply "$FUZZAMOTO/target-patches/bitcoin-core-aggressive-rng.patch"

# Build the dependencies
export CC="$AFL/afl-clang-fast"
export CXX="$AFL/afl-clang-fast++"
export LD="$AFL/afl-clang-fast"
export AFL_LLVM_DENYLIST="$FUZZAMOTO/target-patches/bitcoin-core-ir-denylist.txt"
export SOURCES_PATH="$WORKDIR/bitcoin-depends"

make -C depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 download-linux SOURCES_PATH="$SOURCES_PATH"
make -C depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 AR=llvm-ar NM=llvm-nm RANLIB=llvm-ranlib STRIP=llvm-strip -j$(nproc)

# Build bitcoind with AFL++ coverage and ASAN
cmake -B build_bedrock -G Ninja \
  --toolchain "./depends/$(./depends/config.guess)/toolchain.cmake" \
  -DSANITIZERS=address \
  -DAPPEND_CPPFLAGS="-DFUZZAMOTO_FUZZING -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DABORT_ON_FAILED_ASSUME -U_FORTIFY_SOURCE" \
  -DAPPEND_LDFLAGS="-fuse-ld=lld"

cmake --build build_bedrock -j$(nproc) --target bitcoind
```

Next, build fuzzamoto and the guest's initramfs:

```
cd "$FUZZAMOTO"

export CC=clang
export CXX=clang++
export LD=lld
export BITCOIND_PATH="$BITCOIN/build_bedrock/bin/bitcoind"

# Build fuzzamoto (add oracles if you wish)
cargo build --release --workspace --no-default-features --features std,fuzz_bedrock

# Build the guest's /init
gcc -O2 -static -I"$BEDROCK/guest" -o "$WORKDIR/init" fuzzamoto-bedrock-sys/guest/init.c

# Build the guest's initramfs
./fuzzamoto-bedrock-sys/guest/build-initramfs.sh \
  target/release/scenario-ir "$BITCOIND_PATH" "$WORKDIR/init" "$WORKDIR/fuzzamoto-ir.cpio.gz"
```

Finally, run the campaign:

```
mkdir -p "$WORKDIR/in"

# Tune below parameters to your preference
./target/release/fuzzamoto-libafl \
  --input "$WORKDIR/in" --output "WORKDIR/out" \
  --vmlinux "$GUEST" --initramfs "$WORKDIR/fuzzamoto-ir.cpio.gz" \
  --cores 0-15 --guest-memory-mb 4096 \
  --timeout 30000 --setup-timeout 120
```

Once it's running, you should see the stability at 100.000%. If it is not 100.000%, please file a bug report.
