#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Isolated headed GUI smoke test: builds the v30mz language, installs it to an
# isolated Ghidra user dir, and runs :wonderswan:guiTest under Xvfb (CI-ready)
# or the current DISPLAY (local use only, not for CI).
# Usage: ./wonderswan/gui-test/run.sh
# Env: GHIDRA_INSTALL_DIR (/opt/ghidra_12.1.3_PUBLIC), XDG_CONFIG_HOME (default: <repo>/build/gui-test-config).
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${GHIDRA_INSTALL_DIR:=/opt/ghidra_12.1.3_PUBLIC}"
export GHIDRA_INSTALL_DIR
: "${XDG_CONFIG_HOME:=$ROOT/build/gui-test-config}"
export XDG_CONFIG_HOME
mkdir -p "$XDG_CONFIG_HOME"

# The smoke test needs the V30MZ language: install the freshly built v30mz
# extension to the isolated settings (both user-specific and plain layouts;
# Ghidra picks one depending on whether the config dir is inside $HOME).
VER="$(sed -n 's/^application.version=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")"
REL="$(sed -n 's/^application.release.name=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")"
ME="$(whoami)"
"$ROOT/build.sh" -q :v30mz:buildExtension
ZIP="$(ls -t "$ROOT"/v30mz/dist/*_v30mz.zip | head -1)"
for base in "$XDG_CONFIG_HOME/$ME-ghidra/ghidra_${VER}_${REL}" "$XDG_CONFIG_HOME/ghidra/ghidra_${VER}_${REL}"; do
  mkdir -p "$base/Extensions"
  rm -rf "$base/Extensions/v30mz"
  unzip -q -o "$ZIP" -d "$base/Extensions"
  rm -rf "$base/osgi/compiled-bundles/"*
done
echo "run.sh: v30mz installed to isolated $XDG_CONFIG_HOME"

if command -v Xvfb >/dev/null 2>&1; then
  # Start Xvfb directly (xvfb-run's SIGUSR1 wait hangs as PID 1 in containers).
  DISP=":99"
  rm -f "/tmp/.X${DISP#:}-lock"
  Xvfb "$DISP" -screen 0 1280x1024x24 -nolisten tcp -ac &
  XVFB_PID=$!
  for i in $(seq 1 100); do
    [ -S "/tmp/.X11-unix/X${DISP#:}" ] && break
    sleep 0.1
  done
  export DISPLAY="$DISP"
  echo "run.sh: Xvfb on $DISPLAY (pid $XVFB_PID)" >&2
  set +e
  "$ROOT/build.sh" :wonderswan:guiTest
  RET=$?
  kill "$XVFB_PID" 2>/dev/null
  wait "$XVFB_PID" 2>/dev/null
  exit "$RET"
elif [ -n "$DISPLAY" ]; then
  echo "run.sh: no Xvfb; using DISPLAY=$DISPLAY (local use only, not for CI)" >&2
  exec "$ROOT/build.sh" :wonderswan:guiTest
else
  echo "run.sh: no Xvfb and no DISPLAY; cannot run headed test" >&2
  exit 1
fi
