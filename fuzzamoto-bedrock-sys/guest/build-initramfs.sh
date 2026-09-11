#!/bin/bash
# Build the guest initramfs for fuzzamoto's bedrock backend.
#
#   build-initramfs.sh <scenario> <bitcoind> <init> <out.cpio.gz>
#
# The image is deliberately flat: /init, /scenario, /bitcoind, and the shared
# libraries those two need. This is the same job `fuzzamoto-cli init` does for
# Nyx's share dir — collect a binary plus its dependency closure — so the
# dependency walk uses lddtree the same way.
set -euo pipefail

if [ $# -ne 4 ]; then
    sed -n '2,8p' "$0" >&2
    exit 2
fi
SCENARIO=$1; BITCOIND=$2; INIT=$3; OUT=$4

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

# Mount points init needs to exist before it can mount anything on them.
mkdir -p "$root"/{proc,sys,dev,tmp,lib,lib64}

install -m 0755 "$INIT" "$root/init"
install -m 0755 "$SCENARIO" "$root/scenario"
install -m 0755 "$BITCOIND" "$root/bitcoind"

# Copy each binary's shared-library closure, preserving the paths the dynamic
# loader will look them up under. lddtree prints "name => path" lines; the
# loader itself (ld-linux) appears too and must come along.
for bin in "$SCENARIO" "$BITCOIND"; do
    lddtree "$bin" | tail -n +2 | while read -r line; do
        case "$line" in *"=>"*) ;; *) continue ;; esac
        path=${line#*=> }
        path=${path%% *}
        [ -f "$path" ] || continue
        dest="$root${path}"
        mkdir -p "$(dirname "$dest")"
        [ -f "$dest" ] || install -m 0755 "$path" "$dest"
    done
done

( cd "$root" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "$OUT" )
echo "$OUT: $(du -h "$OUT" | cut -f1) ($(find "$root" -type f | wc -l) files)"
