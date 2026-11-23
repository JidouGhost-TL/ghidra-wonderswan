#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the pinned public release in a fresh Windows foreground console."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

from exercise import FIXTURES, PROJECT, VISIBLE_STORE

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here.parent))

import rehearse


def emit(tag, receipt):
    print(tag + " " + json.dumps(receipt, separators=(",", ":")), flush=True)


class Diagnostic(rehearse.Diagnostic):
    def emit(self, status, reason=None):
        record = {"platform": self.platform, "stage": self.stage, "status": status}
        if reason is not None:
            record["reason"] = reason
        emit("PUBLIC_GHIDRA_GUI_STAGE", record)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def saved_databases(projects):
    saved = {path.relative_to(projects): rehearse.digest(path) for path in projects.glob("*.rep/idata/**/*.gbf")}
    require(len(saved) == 2, "Expected two saved GUI program databases")
    return saved


def program_command(support, agent, control, project=None):
    args = [str(support), "fg", "jdk", "Ghidra", "2G",
            f"-javaagent:{agent}={control}", "ghidra.GhidraRun"]
    if project:
        args.append(str(project))
    require(all(not re.search(r'[%!&|<>^"\r\n]', item) for item in args), "Unsafe command path")
    require(all(not re.search(r"\s", str(path)) for path in [agent, control]), "Unsafe Java agent path")
    quoted = " ".join(f'"{value}"' for value in args)
    return f'cmd.exe /d /s /c "{quoted}"'


def console_session(pid):
    session = ctypes.c_ulong()
    ok = ctypes.windll.kernel32.ProcessIdToSessionId(ctypes.c_ulong(pid), ctypes.byref(session))
    require(ok and session.value != 0, "No native interactive Windows console session")
    return session.value


def desktop_checks(output, java, env, diagnostic):
    probe = here / "DesktopInputProbe.java"
    diagnostic.begin("desktop_input")
    text = rehearse.run([java, probe], env, output / "desktop-input.log", timeout=30)
    require("PUBLIC_GHIDRA_GUI_DESKTOP_INPUT_PASS" in text.splitlines(), "Desktop input probe did not pass")
    diagnostic.begin("desktop_refusal")
    log = output / "desktop-refusal.log"
    with log.open("xb") as stream:
        result = subprocess.run([str(java), "-Djava.awt.headless=true", str(probe)], env=env,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=30)
    require(result.returncode == 2 and
            "PUBLIC_GHIDRA_GUI_DESKTOP_REFUSED" in log.read_text(encoding="utf-8").splitlines(),
            "Headless desktop control was not refused at the expected boundary")


def install_driver(output, java, env):
    classes = output / "classes"
    classes.mkdir()
    agent = output / "gui-agent.jar"
    manifest = output / "agent-manifest"
    manifest.write_bytes(b"Premain-Class: GuiAgent\n")
    rehearse.run([java.with_name("javac.exe"), "-d", classes, here / "GuiAgent.java"],
                 env, output / "compile.log", timeout=60)
    rehearse.run([java.with_name("jar.exe"), "--create", "--file", agent, "--manifest", manifest, "-C", classes, "."],
                 env, output / "jar.log", timeout=60)
    return agent


def verify_foreground_console(child, control, env, log, session):
    ready = control / "ready.txt"
    deadline = time.monotonic() + 90
    while not ready.is_file():
        if child.poll() is not None:
            raise RuntimeError("Foreground launcher exited before the GUI JVM initialized")
        if time.monotonic() >= deadline:
            raise TimeoutError("Foreground GUI JVM did not initialize")
        time.sleep(0.2)
    gui = int(ready.read_text())
    require(console_session(gui) == session, "GUI JVM changed interactive session")
    with log.open("xb") as stream:
        subprocess.run([sys.executable, "-B", str(here / "console_members.py"),
                        str(child.pid), str(gui), str(os.getpid())],
                       env=env, creationflags=subprocess.DETACHED_PROCESS,
                       stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                       check=True, timeout=30)


def phase_run(phase, output, ghidra, agent, projects, env, session, diagnostic):
    diagnostic.begin("gui_" + phase + "_console")
    control = output / (phase + "-control")
    proof = output / (phase + ".json")
    project = projects / (PROJECT + ".gpr") if phase == "reopen" else None
    launcher = program_command(ghidra / "support" / "launch.bat", agent, control, project)
    system = Path(os.environ["SystemRoot"]) / "System32"
    with (output / (phase + "-ghidra.log")).open("xb") as log:
        child = subprocess.Popen(launcher, executable=str(system / "cmd.exe"), env=env, cwd=output,
                                 creationflags=subprocess.CREATE_NEW_CONSOLE,
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            require(console_session(child.pid) == session, "Foreground console changed session")
            verify_foreground_console(child, control, env, output / (phase + "-console.log"), session)
            diagnostic.begin("gui_import_save" if phase == "import" else "gui_readonly_reopen")
            rehearse.run([sys.executable, "-B", here / "exercise.py", phase, control, proof,
                          "--fixture-dir", output / "roms", "--project-dir", projects,
                          "--report", output / "observed.jsonl"],
                         env, output / (phase + "-driver.log"), timeout=600)
            require(child.wait(timeout=45) == 0, "Foreground Ghidra did not exit cleanly")
        finally:
            if child.poll() is None:
                subprocess.run([str(system / "taskkill.exe"), "/pid", str(child.pid), "/t", "/f"],
                               stdout=log, stderr=subprocess.STDOUT, timeout=30, check=True)
                child.wait(timeout=30)
    return json.loads(proof.read_bytes())


def collect_proof(imported, reopened, before, after, observed):
    require(imported["gui_jvm_pid"] != reopened["gui_jvm_pid"], "Both phases used the same GUI JVM")
    require(before == after, "Read-only GUI changed program database bytes")
    require(set(imported["cases"]) == set(reopened["cases"]) == set(FIXTURES), "Unexpected fixture result set")
    result = {}
    for fixture, pinned in FIXTURES.items():
        first, second = imported["cases"][fixture], reopened["cases"][fixture]
        positive = fixture == "bank-fe.ws"
        expected_title = "CodeBrowser: " + PROJECT + ":/" + fixture + " [Read-Only]"
        rows = second["visible_reference_rows"]
        raw = [row for row in rows if row["Destination"] == "ram:2000:0069" and
               row["Ref-Type"] == "UNCONDITIONAL_CALL" and row["Source"] == "DEFAULT"]
        overrides = [row for row in rows if row["Ref-Type"] == "CALL_OVERRIDE_UNCONDITIONAL"]
        require(first["import_sha256"] == pinned and second["read_only_title"] == expected_title
                and first["analysis_mode"] == ("observed" if positive else "static")
                and len(raw) == 1 and len(overrides) == int(positive), "GUI case proof differs")
        for capture in (first["import_visible_capture"], first["analyzer_options_capture"], second["reference_capture"]):
            require(re.fullmatch(r"[0-9]+x[0-9]+ [0-9a-f]{64}", capture), "Missing rendered GUI capture proof")
        if positive:
            require(overrides[0]["Destination"] == "ROM0_BANK_00FE::020069"
                    and overrides[0]["Source"] == "ANALYSIS"
                    and re.fullmatch(VISIBLE_STORE, second["visible_store"])
                    and re.fullmatch(r"[0-9]+x[0-9]+ [0-9a-f]{64}", second["marker_capture"]),
                    "Observed bank or marker differs")
        result[fixture] = {"fixture_sha256": pinned, "read_only": True, "raw_far_call": True,
                           "physical_overrides": len(overrides)}
        if positive:
            result[fixture]["marker"] = "42"
    require(sum(row.get("rule") == "B3" and row.get("site") == "ram:f000:010d"
                and row.get("outcome") == "OVERRIDE" and row.get("target") == "ROM0_BANK_00FE::020069"
                for row in observed) == 1, "Expected analyzer event missing or ambiguous")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    host = "Windows-x64"
    diagnostic = Diagnostic(host)
    try:
        diagnostic.begin("console_session")
        require(platform.system() == "Windows" and platform.machine() in {"AMD64", "x86_64"},
                "Native Windows x64 console required")
        session = console_session(os.getpid())
        output = args.output.resolve()
        require(not output.exists() and not re.search(r'[%!&|<>^"\s]', str(output)),
                "Expected a fresh local path without spaces or command characters")
        extensions = rehearse.prepare(output, host, None, diagnostic)
        ghidra, java, _, env = rehearse.paths(output, host)
        desktop_checks(output, java, env, diagnostic)
        diagnostic.begin("install_extensions")
        for archive in extensions:
            rehearse.unzip(archive, rehearse.extension_tree(output))
        installed = rehearse.verify_install(output)
        diagnostic.begin("build_driver")
        agent = install_driver(output, java, env)
        projects = output / "projects"
        projects.mkdir()
        imported = phase_run("import", output, ghidra, agent, projects, env, session, diagnostic)
        before = saved_databases(projects)
        reopened = phase_run("reopen", output, ghidra, agent, projects, env, session, diagnostic)
        diagnostic.begin("verify_gui_receipt")
        events = [json.loads(line) for line in (output / "observed.jsonl").read_text().splitlines()]
        fixtures = collect_proof(imported, reopened, before, saved_databases(projects), events)
        state = json.loads((output / "setup.json").read_bytes())
        pin_fields = ("ghidra_sha256", "jdk_sha256", "native_sha256")
        require(all(re.fullmatch(r"[0-9a-f]{64}", state[key]) for key in pin_fields), "Invalid release receipt pin")
        result = {"schema": 1, "platform": host, "new_foreground_consoles": 2,
                  "desktop_pixels_and_input": True, "forced_headless_refused": True, "fresh_gui_process": True,
                  "installed_files": installed, "same_saved_database_sha256": sorted(before.values()),
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
