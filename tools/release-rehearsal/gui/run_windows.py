#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the private foreground Windows desktop rehearsal."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here.parent))

import rehearse


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checked(command, env, log, timeout=60):
    return rehearse.run(command, env, log, timeout=timeout)


def database_hashes(projects):
    saved = {str(path.relative_to(projects)): rehearse.digest(path) for path in projects.glob("*.rep/idata/**/*.gbf")}
    require(len(saved) == 2, "Expected two saved GUI project databases")
    return saved


def windows_launch(support, agent, control, original=None):
    args = [str(support), "fg", "jdk", "Ghidra", "2G",
            f"-javaagent:{agent}={control}", "ghidra.GhidraRun"]
    if original:
        args.append(str(original))
    require(all(not re.search(r'[%!&|<>^"\r\n]', item) for item in args),
            "Use a local path without cmd metacharacters")
    require(all(not re.search(r"\s", str(path)) for path in [agent, control]),
            "Use a private job directory without spaces for the Java agent")
    quoted = " ".join(f'"{value}"' for value in args)
    return f'cmd.exe /d /s /c "{quoted}"'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    require(platform.system() == "Windows" and platform.machine() in {"AMD64", "x86_64"},
            "Native Windows x64 and an interactive foreground desktop are required")
    host = "Windows-x64"
    output = args.output.resolve()
    require(not output.exists() and not re.search(r'[%!&|<>^"\s]', str(output)),
            "Use a new local private job directory without spaces or cmd metacharacters")
    extensions = rehearse.prepare(output, host, args.cache)
    ghidra, java, _, env = rehearse.paths(output, host)
    probe = checked([java, here.parent / "DesktopProbe.java"], env, output / "desktop-probe.log")
    require("DESKTOP_PROBE_PASS" in probe.splitlines(), "Native GUI pixels not observed")
    for archive in extensions:
        rehearse.unzip(archive, rehearse.extension_tree(output))
    installed = rehearse.verify_install(output)
    agent = output / "gui-agent.jar"
    classes = output / "classes"
    classes.mkdir()
    manifest = output / "agent-manifest"
    manifest.write_text("Premain-Class: GuiAgent\n", encoding="ascii")
    javac = java.with_name("javac.exe")
    jar = java.with_name("jar.exe")
    checked([javac, "-d", classes, here / "GuiAgent.java"], env, output / "compile.log")
    checked([jar, "--create", "--file", agent, "--manifest", manifest, "-C", classes, "."],
            env, output / "jar.log")
    projects = output / "projects"
    projects.mkdir()
    project = projects / "portable-gui.gpr"
    observed = output / "observed.jsonl"
    result = {"platform": host, "installed_extension_files": installed}
    for phase in ["import", "reopen"]:
        control = output / (phase + "-control")
        proof = output / (phase + ".json")
        launcher = windows_launch(ghidra / "support" / "launch.bat", agent, control,
                                  project if phase == "reopen" else None)
        with (output / (phase + "-ghidra.log")).open("xb") as log:
            child = subprocess.Popen(launcher, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                checked([sys.executable, "-B", here / "exercise.py", phase, control, proof,
                         "--fixture-dir", output / "roms", "--project-dir", projects, "--report", observed],
                        env, output / (phase + "-driver.log"), timeout=720)
                require(child.wait(timeout=45) == 0, "Foreground Ghidra did not exit cleanly")
            finally:
                if child.poll() is None:
                    taskkill = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
                    cleanup = subprocess.run([taskkill, "/pid", str(child.pid), "/t", "/f"],
                                             stdout=log, stderr=subprocess.STDOUT, timeout=30)
                    require(cleanup.returncode == 0, "Could not stop the owned foreground process tree")
        result[phase] = json.loads(proof.read_text())
        actual = database_hashes(projects)
        if phase == "import":
            result["saved_database_hashes"] = actual
        else:
            require(actual == result["saved_database_hashes"], "Read-only GUI changed database bytes")
    require(result["import"]["gui_jvm_pid"] != result["reopen"]["gui_jvm_pid"],
            "GUI reopen did not use a distinct JVM")
    rows = [json.loads(line) for line in observed.read_text().splitlines()]
    require(any(row.get("site") == "ram:f000:010d" and row.get("outcome") == "OVERRIDE" and
                row.get("target") == "ROM0_BANK_00FE::020069" for row in rows),
            "Imported observed analysis lacks the expected banked call")
    (output / "GUI-RECEIPT.json").write_text(json.dumps(result, indent=2) + "\n")
    print("GUI_REPLAY_PASS")


if __name__ == "__main__":
    main()
