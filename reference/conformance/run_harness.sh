#!/usr/bin/env bash
# ShareNet cross-language conformance harness (work item R1-003, lock L022).
#
# Runs the Rust, TypeScript and Python conformance legs over the committed
# protocol vectors and diffs their canonical outputs byte-for-byte. Any
# divergence is a protocol-profile break and fails the build.
#
# Usage:
#   reference/conformance/run_harness.sh [VECTORS_DIR]
#
# Requirements: cargo (rust), bun (or node with tsx), python3 (>= 3.10).
# The vectors default to reference/crates/sharenet-protocol/tests/vectors.

set -euo pipefail

# rustup installs to ~/.cargo by default; pick it up when present
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VECTORS="${1:-$ROOT/reference/crates/sharenet-protocol/tests/vectors}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "== ShareNet cross-language conformance harness =="
echo "vectors: $VECTORS"

# ---- Rust leg ----
echo "[1/3] rust leg (sharenet-conformance)"
(cd "$ROOT/reference" && cargo build -p sharenet-conformance --quiet)
"$ROOT/reference/target/debug/sharenet-conformance" "$VECTORS" > "$OUT/rust.txt"

# ---- TypeScript leg ----
echo "[2/3] typescript leg (bun)"
if command -v bun >/dev/null 2>&1; then
    bun "$ROOT/reference/conformance/typescript/runner.ts" "$VECTORS" > "$OUT/ts.txt"
else
    echo "bun not found: the TypeScript conformance leg requires bun" >&2
    exit 1
fi

# ---- Python leg ----
echo "[3/3] python leg (python3)"
(
    cd "$ROOT/reference/conformance/python"
    python3 -m sharenet_conformance.runner "$VECTORS" > "$OUT/python.txt"
)

# ---- Three-way byte-exact diff ----
fail=0
for leg in ts python; do
    if ! diff -u "$OUT/rust.txt" "$OUT/$leg.txt" > "$OUT/diff_rust_$leg.txt"; then
        echo "CONFORMANCE FAILURE: rust vs $leg diverged:" >&2
        cat "$OUT/diff_rust_$leg.txt" >&2
        fail=1
    fi
done

LINES=$(wc -l < "$OUT/rust.txt" | tr -d ' ')
if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL ($LINES vector lines, languages diverged)" >&2
    exit 1
fi
echo "RESULT: PASS — three languages byte-identical across $LINES conformance lines"
