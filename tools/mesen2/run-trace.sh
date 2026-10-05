#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Trace a WonderSwan ROM in headless Mesen 2 (container). Usage: run-trace.sh ROM OUTDIR [frames] [trace_n] [shot_every]
# Builds the image on first use (see Dockerfile). Outputs: see trace.lua (trace.tsv, coverage.tsv,
# trace.cdl, ram.bin, shots, summary.txt). Mesen's test runner does not exit after the script
# calls emu.exit(), so the container is stopped as soon as summary.txt appears.
# Env: MESEN_IMAGE (default ghidra-wonderswan/mesen2:b9fa69d), MESEN_INPUT_MODE (standard|long),
# MESEN_SEED (long-mode PRNG seed).
set -e
IMAGE="${MESEN_IMAGE:-ghidra-wonderswan/mesen2:b9fa69d}"
HERE="$(cd "$(dirname "$0")" && pwd)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -q -t "$IMAGE" "$HERE"
ROM="$(realpath "$1")"; OUT="$(realpath -m "$2")"; mkdir -p "$OUT"; chmod 777 "$OUT"; rm -f "$OUT/summary.txt"
NAME="$(basename "$ROM")"
CID=$(docker run -d --rm \
  -v "$ROM:/work/rom/$NAME:ro" -v "$HERE/trace.lua:/work/trace.lua:ro" -v "$OUT:/work/out" \
  -v "$HERE/settings.json:/home/mesen/.config/Mesen2/settings.json:ro" \
  -e MESEN_FRAMES="${3:-1500}" -e MESEN_TRACE_N="${4:-20000}" -e MESEN_SHOT_EVERY="${5:-100}" -e MESEN_OUT=/work/out \
  -e MESEN_INPUT_MODE="${MESEN_INPUT_MODE:-standard}" -e MESEN_SEED="${MESEN_SEED:-0}" -e MESEN_TRACE_TIMING="${MESEN_TRACE_TIMING:-0}" -e MESEN_TRACE_FROM="${MESEN_TRACE_FROM:-1}" -e MESEN_FRAMESIG="${MESEN_FRAMESIG:-0}" \
  "$IMAGE" --testRunner /work/trace.lua "/work/rom/$NAME" --timeout=3600)
while [ ! -s "$OUT/summary.txt" ] && docker ps -q --no-trunc | grep -q "$CID"; do sleep 1; done
docker stop -t 1 "$CID" >/dev/null 2>&1 || true
cat "$OUT/summary.txt" 2>/dev/null || { echo "no summary: trace failed" >&2; exit 1; }
