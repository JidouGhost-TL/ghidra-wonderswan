#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Build both extensions with the Gradle wrapper that ships inside Ghidra.
# GHIDRA_INSTALL_DIR defaults to /opt/ghidra_12.1.3_PUBLIC.
set -e
: "${GHIDRA_INSTALL_DIR:=/opt/ghidra_12.1.3_PUBLIC}"
export GHIDRA_INSTALL_DIR
exec "$GHIDRA_INSTALL_DIR/support/gradle/gradlew" -p "$(dirname "$0")" "${@:-buildExtension}"
