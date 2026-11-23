#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Replay the pinned public GUI in a private macOS foreground process group."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

from exercise import PROJECT
from run_windows import (
    Diagnostic, GuiDriverFailure, collect_proof, desktop_checks, emit, read_checkpoint,
    rehearse, require, saved_databases,
)

here = Path(__file__).resolve().parent
hosts = {"arm64": "Darwin-arm64", "x86_64": "Darwin-x64"}


def running_translated():
    value = ctypes.c_int()
    length = ctypes.c_size_t(ctypes.sizeof(value))
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.sysctlbyname(b"sysctl.proc_translated", ctypes.byref(value), ctypes.byref(length),
                               None, ctypes.c_size_t(0))
    if result == -1:
        status = ctypes.get_errno()
        if status == errno.ENOENT:
            return False
        raise OSError(status, "macOS translation status unavailable")
    require(length.value == ctypes.sizeof(value) and value.value in (0, 1), "Invalid macOS translation status")
    return bool(value.value)


def require_native_host(expected):
    require(platform.system() == "Darwin" and hosts.get(platform.machine()) == expected,
            "Expected native macOS target architecture")
    require(not running_translated(), "Translated macOS execution was refused")


def require_gui_session():
    subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)


def build_driver(output, java, env):
    classes = output / "classes"
    classes.mkdir()
    agent = output / "gui-agent.jar"
    manifest = output / "agent-manifest"
    manifest.write_bytes(b"Premain-Class: GuiAgent\n")
    rehearse.run([java.with_name("javac"), "-d", classes, here / "GuiAgent.java"],
                 env, output / "compile.log", timeout=60)
    rehearse.run([java.with_name("jar"), "--create", "--file", agent, "--manifest", manifest, "-C", classes, "."],
                 env, output / "jar.log", timeout=60)
    return agent


def program_command(ghidra, agent, control, project=None):
    require(not any(re.search(r"[\s=]", str(path)) for path in (agent, control)), "Unsafe agent path")
    options = f"-javaagent:{agent}={control} -Dapple.laf.useScreenMenuBar=false"
    args = [ghidra / "support" / "launch.sh", "fg", "jdk", "Ghidra", "2G", options, "ghidra.GhidraRun"]
    if project:
        args.append(project)
    return args


def launcher_status(child):
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def signal_owned_group(child, signum):
    # The launcher was started as this group's leader. Keep its PID reserved
    # until every cleanup signal has been issued, even if the shell has exited.
    launcher_status(child)
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        pass


def stop_owned_group(child):
    if child.returncode is not None:
        return
    signal_owned_group(child, signal.SIGTERM)
    time.sleep(1)
    signal_owned_group(child, signal.SIGKILL)
    child.wait(timeout=15)


def wait_for_clean_exit(child, gui):
    deadline = time.monotonic() + 45
    status = launcher_status(child)
    while status is None:
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired("foreground GUI launcher", 45)
        time.sleep(0.2)
        status = launcher_status(child)
    require(status.si_code == os.CLD_EXITED and status.si_status == 0, "Foreground Ghidra did not exit cleanly")
    try:
        group = os.getpgid(gui)
    except ProcessLookupError:
        pass
    else:
        require(group != child.pid, "The foreground GUI JVM remained alive after launcher exit")
    require(child.wait(timeout=1) == 0, "Foreground Ghidra exit status changed")


def foreground_pid(child, control):
    ready = control / "ready.txt"
    deadline = time.monotonic() + 90
    while not ready.is_file():
        require(launcher_status(child) is None, "Foreground launcher exited before the GUI initialized")
        if time.monotonic() >= deadline:
            raise TimeoutError("Foreground GUI JVM did not initialize")
        time.sleep(0.2)
    pid = int(ready.read_text())
    require(os.getpgid(child.pid) == os.getpgid(pid) == child.pid,
            "Foreground JVM is outside the owned group")
    require(os.getsid(pid) == os.getsid(os.getpid()), "Foreground JVM left the desktop process session")
    return pid


def phase_run(phase, output, ghidra, agent, projects, env, diagnostic, *, finish_with_space=False):
    control = output / (phase + "-control")
    proof = output / (phase + ".json")
    project = projects / (PROJECT + ".gpr") if phase == "reopen" else None
    command = program_command(ghidra, agent, control, project)
    diagnostic.begin("gui_" + phase + "_process_group")
    with (output / (phase + "-ghidra.log")).open("xb") as log:
        child = subprocess.Popen(command, env=env, cwd=output, process_group=0,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            gui = foreground_pid(child, control)
            diagnostic.begin("gui_import_save" if phase == "import" else "gui_readonly_reopen")
            try:
                driver = [sys.executable, "-B", here / "exercise.py", phase, control, proof,
                          "--fixture-dir", output / "roms", "--project-dir", projects,
                          "--report", output / "observed.jsonl"]
                if phase == "import":
                    driver.extend(("--guarded-analysis-options", "--analyzer-page-keys"))
                    if finish_with_space:
                        driver.extend(("--wizard-finish-with-space", "--project-row-open"))
                else:
                    driver.append("--guarded-reference-open")
                rehearse.run(driver, env, output / (phase + "-driver.log"), timeout=600)
            except subprocess.CalledProcessError as error:
                diagnostic.item = read_checkpoint(control, phase)
                raise GuiDriverFailure(error.returncode) from error
            except subprocess.TimeoutExpired:
                diagnostic.item = read_checkpoint(control, phase)
                raise
            diagnostic.begin("gui_" + phase + "_exit")
            wait_for_clean_exit(child, gui)
        except BaseException as failure:
            try:
                stop_owned_group(child)
            except (OSError, RuntimeError, subprocess.SubprocessError) as cleanup:
                failure.add_note(f"Owned launcher cleanup failed: {type(cleanup).__name__}")
            raise
    diagnostic.begin("gui_" + phase + "_proof_read")
    result = json.loads(proof.read_bytes())
    require(result["gui_jvm_pid"] == gui, "GUI receipt does not identify the verified JVM")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--expected-host", required=True, choices=hosts.values())
    args = parser.parse_args()
    host = args.expected_host
    diagnostic = Diagnostic(host)
    try:
        diagnostic.begin("native_architecture")
        require_native_host(host)
        diagnostic.begin("desktop_session")
        require_gui_session()
        output = args.output.resolve()
        require(not output.exists() and not re.search(r"[\s=]", str(output)), "Expected a fresh GUI scratch path")
        extensions = rehearse.prepare(output, host, None, diagnostic)
        ghidra, java, _, env = rehearse.paths(output, host)
        desktop_checks(output, java, env, diagnostic)
        diagnostic.begin("install_extensions")
        for archive in extensions:
            rehearse.unzip(archive, rehearse.extension_tree(output))
        installed = rehearse.verify_install(output)
        diagnostic.begin("build_driver")
        agent = build_driver(output, java, env)
        projects = output / "projects"
        projects.mkdir()
        imported = phase_run("import", output, ghidra, agent, projects, env, diagnostic,
                             finish_with_space=host == "Darwin-arm64")
        diagnostic.begin("gui_inventory_before_reopen")
        before = saved_databases(projects)
        reopened = phase_run("reopen", output, ghidra, agent, projects, env, diagnostic)
        diagnostic.begin("gui_inventory_after_reopen")
        after = saved_databases(projects)
        diagnostic.begin("verify_gui_receipt")
        events = [json.loads(line) for line in (output / "observed.jsonl").read_text().splitlines()]
        fixtures = collect_proof(imported, reopened, before, after, events)
        state = json.loads((output / "setup.json").read_bytes())
        pin_fields = ("ghidra_sha256", "jdk_sha256", "native_sha256")
        require(state["platform"] == host and all(re.fullmatch(r"[0-9a-f]{64}", state[key]) for key in pin_fields),
                "Invalid native release receipt")
        result = {"schema": 1, "platform": host, "owned_foreground_process_groups": 2,
                  "desktop_pixels_and_input": True, "forced_headless_refused": True, "fresh_gui_process": True,
                  "installed_files": installed, "same_saved_database_sha256": sorted(before.files.values()),
                  "fixtures": fixtures, "extension_sha256": [item[3] for item in rehearse.pins["extensions"]],
                  **{key: state[key] for key in pin_fields}}
        (output / "GUI-RECEIPT.json").write_text(json.dumps(result, indent=2) + "\n")
        emit("PUBLIC_GHIDRA_GUI_PASS", result)
        return 0
    except Exception as error:
        diagnostic.fail(error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
