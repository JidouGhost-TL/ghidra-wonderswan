#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Unit tests for the Mesen 2 trace/coverage/CDL parsers (plain javac/java, no Ghidra, no framework).
# Usage: wonderswan/tests/run.sh [sampledir]   (sampledir with real trace.tsv/coverage.tsv/*.cdl
# runs the cross-file invariants too; the committed synthetic fixtures always run)
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src/main/java/jidoughost/wonderswan"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/wstrace-test.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT
javac -d "$OUT" "$SRC/WSHardware.java" "$SRC/WSHeader.java" "$SRC/WSMesenTrace.java" "$SRC/WSEvidence.java" \
  "$SRC/WSComputedEdges.java" "$ROOT/tests/stubs/WSMachine.java" "$ROOT/tests/WSMesenTraceTest.java"
if [ -n "${1:-}" ]; then java -cp "$OUT" WSMesenTraceTest "$ROOT/tests/fixtures" "$1"; else java -cp "$OUT" WSMesenTraceTest "$ROOT/tests/fixtures"; fi
