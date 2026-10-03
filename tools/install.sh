#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build both extensions and install them into the per-user Ghidra extensions directory, then clear
# Ghidra's compiled-script cache (Gradle zips carry a fixed 1980 timestamp, so Ghidra would otherwise
# keep running stale compiled copies of changed scripts).
# Usage: tools/install.sh [v30mz|wonderswan ...]   (default: both)
set -e
# Serialise concurrent builds/installs (several agents may work in parallel).
LOCK=/tmp/ghidra-wonderswan-install.lock
exec 9>"$LOCK"; flock 9
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${GHIDRA_INSTALL_DIR:=/opt/ghidra_12.1.3_PUBLIC}"
VER="$(sed -n 's/^application.version=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")"
USERDIR="$HOME/.config/ghidra/ghidra_${VER}_PUBLIC"
EXT="$USERDIR/Extensions"
MODULES="${*:-v30mz wonderswan}"
TASKS=""; for m in $MODULES; do TASKS="$TASKS :$m:buildExtension"; done
"$ROOT/build.sh" -q $TASKS
mkdir -p "$EXT"
for m in $MODULES; do
  rm -rf "$EXT/$m"
  unzip -q -o "$(ls -t "$ROOT/$m"/dist/*_"$m".zip | head -1)" -d "$EXT"
  echo "installed $m -> $EXT/$m"
done
rm -rf "$USERDIR"/osgi/compiled-bundles/*
