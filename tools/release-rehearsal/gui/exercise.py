#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Drive the published fixtures through visible Ghidra windows."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import traceback
import time

from drive import Session


FIXTURES = {
    "bank-fe.ws": "a02fc44294fab2e9128b64439d8ebd98b119d84887959d4c2d03ca9558c148ef",
    "bank-unknown.ws": "bbe488e4cdc1e9427c9c2592245ea5409a477d1688b1976d12e8b604d9ad0964",
}
PROJECT = "portable-gui"
VISIBLE_STORE = r"uRam00000200 *= *0x42 *;"
MANAGER = "Ghidra: " + PROJECT
CHECKPOINT_FILE = "driver-checkpoint.txt"
CHECKPOINTS = {
    "import": {"startup", "create_project", "save_project", "exit_ghidra"},
    "reopen": {"startup", "open_saved_project", "exit_ghidra"},
}
FIXTURE_CHECKPOINTS = {
    "import": {"open_import_chooser", "activate_import_chooser", "verify_import_chooser_path",
               "dismiss_import_chooser", "open_import_options", "activate_import_options",
               "verify_import_language", "verify_import_loader", "inspect_import_summary",
               "open_program", "configure_analysis", "wait_for_analysis", "save_program", "set_read_only"},
    "reopen": {"open_read_only_program", "open_references", "inspect_references", "inspect_decompiler",
               "close_program"},
}
EVIDENCE_TIMEOUT = 20
TRANSPORT_TIMEOUT = 21


class VisibleEvidenceTimeout(TimeoutError):
    pass


def literal(text):
    return re.escape(text)


class GhidraGui(Session):
    def checkpoint(self, step, fixture=None):
        value = step if fixture is None else f"{step} {fixture}"
        (self.directory / CHECKPOINT_FILE).write_text(value, encoding="ascii")

    def wait(self, pattern, timeout=45, *, present=True):
        start = time.monotonic()
        while True:
            view = self.call("snapshot")
            if bool(re.search(pattern, view, flags=re.M | re.I)) == present:
                return view
            if time.monotonic() - start > timeout:
                expectation = "present" if present else "absent"
                raise VisibleEvidenceTimeout(f"Expected GUI evidence to be {expectation}: {pattern}")
            time.sleep(0.25)

    def direct(self, operation, role, label):
        self.wait(rf"^(?:{role})\t(?:{label})\t")
        return self.call(operation, role, label)

    def click(self, role, value):
        return self.direct("click", role, literal(value))

    def choose(self, menu, action):
        self.click("JMenu", menu)
        self.click("DockingMenuItem", action)

    def button(self, name):
        self.click("JButton", name)

    def enter_text(self, text):
        self.call("select-all")
        self.call("paste", text)

    def open_program(self, name, read_only=False):
        title = "CodeBrowser: " + PROJECT + ":/" + name + (" [Read-Only]" if read_only else "")
        view = self.call("snapshot")
        if not re.search(r"^(?:ACTIVE|WINDOW)\t" + literal(title) + r"\t", view, re.M):
            self.call("focus", literal(MANAGER))
            entry = next(line for line in self.wait(rf"^tree\t{literal(name)}\t").splitlines()
                         if line.startswith("tree\t" + name + "\t"))
            self.call("point", *entry.split("\t")[-1].split(","))
            self.call("key", "ENTER")
        start = time.monotonic()
        while time.monotonic() - start < 45:
            view = self.call("snapshot")
            if "ACTIVE\tNew Plugins Found!" in view:
                self.button("No")
            if ("ACTIVE\t" + title + "\t" in view or "WINDOW\t" + title + "\t" in view) and (
                    read_only or "ACTIVE\tAnalyze?\t" in view):
                return title
            time.sleep(0.25)
        raise VisibleEvidenceTimeout(f"Expected a visible {'read-only' if read_only else 'fresh'} CodeBrowser")

    def analysis_option(self, label, role):
        view = self.wait(rf"^GDLabel\t{literal(label)}\t")
        row = next(line for line in view.splitlines() if line.startswith("GDLabel\t" + label + "\t"))
        y = row.split(",")[-1]
        matches = [line for line in view.splitlines() if
                   line.startswith(role + "\t") and line.endswith("," + y)]
        if len(matches) != 1:
            raise RuntimeError(f"Expected exactly one visible editor beside {label}: {matches}")
        name = matches[0].split("\t")[1]
        self.call("point", *matches[0].split("\t")[-1].split(","))
        return name

    def exit_ghidra(self, title):
        self.call("focus", literal(title))
        self.click("JMenu", "File")
        self.wait(r"^DockingMenuItem\tExit Ghidra\t")
        self.call("exit-click", "DockingMenuItem", literal("Exit Ghidra"))

    def go(self, address):
        self.call("key", "G")
        self.wait(r"^ACTIVE\tGo To \.\.\.\t")
        self.enter_text(address)
        self.call("key", "ENTER")


def stage_import(ui, fixture_dir, project_dir, report_path):
    ui.wait(r"^(?:ACTIVE|WINDOW)\t")
    start = time.monotonic()
    while time.monotonic() - start < 60:
        view = ui.call("snapshot")
        if "JButton\tI Agree\t" in view:
            ui.button("I Agree")
        if "Ghidra: NO ACTIVE PROJECT" in view:
            break
        time.sleep(0.3)
    ui.checkpoint("create_project")
    ui.call("focus", literal("Ghidra: NO ACTIVE PROJECT"))
    ui.choose("File", "New Project...")
    ui.button("Next >>")
    ui.direct("click", "ElidingFilePathTextField", ".*")
    ui.enter_text(project_dir)
    ui.direct("click", "JTextField", r"\(empty\)")
    ui.call("paste", PROJECT)
    ui.button("Finish")
    ui.wait(r"^(?:WINDOW|ACTIVE)\t" + literal(MANAGER) + r"\t")
    summary = {}
    for file, sha in FIXTURES.items():
        ui.checkpoint("open_import_chooser", file)
        ui.call("focus", literal(MANAGER))
        ui.choose("File", "Import File...")
        chooser = literal("Select File to Import")
        chooser_visible = r"^(?:ACTIVE|WINDOW)\t" + chooser + r"\t"
        ui.checkpoint("activate_import_chooser", file)
        ui.wait(chooser_visible)
        ui.call("front", chooser)
        ui.wait(r"^ACTIVE\t" + chooser + r"\t")
        ui.checkpoint("verify_import_chooser_path", file)
        fixture_path = str(Path(fixture_dir) / file)
        ui.direct("click", "DropDownSelectionTextField", ".*")
        ui.enter_text(fixture_path)
        ui.wait(r"^DropDownSelectionTextField\t" + literal(fixture_path) + r"\t")
        ui.wait(r"^ACTIVE\t" + chooser + r"\t")
        ui.checkpoint("dismiss_import_chooser", file)
        ui.call("key", "ENTER")
        ui.wait(chooser_visible, present=False)
        ui.checkpoint("open_import_options", file)
        import_dialog = r"Import .*[\\/]" + literal(file)
        ui.wait(r"^(?:ACTIVE|WINDOW)\t" + import_dialog + r"\t")
        ui.checkpoint("activate_import_options", file)
        ui.call("front", import_dialog)
        ui.wait(r"^ACTIVE\t" + import_dialog + r"\t")
        ui.checkpoint("verify_import_language", file)
        ui.wait(r"^JTextField\tV30MZ:LE:16:default:default\t")
        ui.checkpoint("verify_import_loader", file)
        ui.wait(r"^GhidraComboBox\t.*WonderSwanLoader")
        ui.button("OK")
        ui.checkpoint("inspect_import_summary", file)
        ui.wait(r"^JTextField\t" + sha + r"\t")
        ui.wait(r"^JTextField\tWonderSwan Cartridge\t")
        ui.call("front", literal("Import Results Summary"))
        ui.wait(r"^ACTIVE\tImport Results Summary\t")
        summary[file] = {"import_sha256": sha, "import_visible_capture": ui.call("capture", literal("Import Results Summary"))}
        ui.button("OK")
    for file in FIXTURES:
        ui.checkpoint("open_program", file)
        title = ui.open_program(file)
        ui.call("fit", literal(title))
        ui.call("front", literal("Analyze?"))
        ui.button("Yes")
        ui.checkpoint("configure_analysis", file)
        ui.wait(r"^ACTIVE\tAnalysis Options\t")
        ui.call("front", literal("Analysis Options"))
        ui.click("table:Analyzer", "Aggressive Instruction Finder (Prototype)")
        ui.call("key", "END")
        ui.click("table:Analyzer", "WonderSwan Execution Evidence")
        if file == "bank-fe.ws":
            ui.analysis_option("Evidence report file (JSON lines; empty = none)", "PropertyText")
            ui.enter_text(report_path)
        else:
            state = ui.analysis_option("Run WSMachine", "PropertyBoolean:checked")
            if not state.endswith("=true"):
                raise RuntimeError(f"Unexpected default Run WSMachine state: {state}")
            ui.wait(r"^PropertyBoolean:checked\t.*Run the WSMachine.*=false\t")
        summary[file]["analysis_mode"] = "observed" if file == "bank-fe.ws" else "static"
        summary[file]["analyzer_options_capture"] = ui.call("capture", literal("Analysis Options"))
        ui.button("Apply")
        ui.button("Analyze")
        ui.checkpoint("wait_for_analysis", file)
        ui.wait(r"^ACTIVE\tAuto Analysis Summary\t", timeout=120)
        ui.button("OK")
        ui.checkpoint("save_program", file)
        ui.call("focus", literal(title))
        ui.choose("File", "Save '" + file + "'")
        ui.choose("File", "Close Tool")
        view = ui.call("snapshot")
        if "ACTIVE\tSave Program?\t" in view:
            ui.button("Save")
        ui.wait(r"^(?:WINDOW|ACTIVE)\t" + literal(MANAGER) + r"\t")
        ui.checkpoint("set_read_only", file)
        ui.call("focus", literal(MANAGER))
        ui.direct("right", "tree", literal(file))
        ui.wait(r"^DockingCheckBoxMenuItem:checked\tRead-Only=false\t")
        ui.click("DockingCheckBoxMenuItem", "Read-Only")
    ui.checkpoint("save_project")
    ui.call("focus", literal(MANAGER))
    ui.choose("File", "Save Project")
    ui.checkpoint("exit_ghidra")
    ui.exit_ghidra(MANAGER)
    return summary


def rows_at(view, address, expected_type, expected_source):
    rows = {}
    for line in view.splitlines():
        if line.startswith("table:"):
            field, value, coordinates = line.split("\t")
            row = rows.setdefault(coordinates.split(",")[-1], {})
            row[field.removeprefix("table:")] = value
    rows = list(rows.values())
    assert sum(row.get("Destination", "").lower() == address.lower() and
               row.get("Ref-Type") == expected_type and row.get("Source") == expected_source for row in rows) == 1, rows
    return rows


def stage_reopen(ui):
    ui.checkpoint("open_saved_project")
    ui.wait(r"^(?:ACTIVE|WINDOW)\t" + literal(MANAGER) + r"\t")
    receipt = {}
    for file in FIXTURES:
        ui.checkpoint("open_read_only_program", file)
        title = ui.open_program(file, read_only=True)
        ui.call("fit", literal(title))
        ui.checkpoint("open_references", file)
        ui.go("F000:010D")
        ui.direct("right", "field", "(?i:ram:f000:010d)")
        ui.click("JMenu", "References")
        ui.click("DockingMenuItem", "Add/Edit...")
        ui.checkpoint("inspect_references", file)
        reference = r"References Editor @ ram:f000:010d .*"
        view = ui.wait(r"^ACTIVE\t" + reference + r"\t")
        rows = rows_at(view, "ram:2000:0069", "UNCONDITIONAL_CALL", "DEFAULT")
        record = {"read_only_title": title, "visible_reference_rows": rows,
                  "reference_capture": ui.call("capture", reference)}
        overrides = [row for row in rows if row.get("Ref-Type") == "CALL_OVERRIDE_UNCONDITIONAL"]
        if file == "bank-fe.ws":
            rows_at(view, "ROM0_BANK_00FE::020069", "CALL_OVERRIDE_UNCONDITIONAL", "ANALYSIS")
            assert len(overrides) == 1
            ui.checkpoint("inspect_decompiler", file)
            ui.call("focus", literal(title))
            ui.go("ROM0_BANK_00FE::020069")
            ui.wait(r"^field\tAL,0x42\t")
            ui.direct("click", "field", literal("AL,0x42"))
            rendered = ui.wait(r"^decompiled\t(" + VISIBLE_STORE + r")\t")
            record["visible_store"] = re.search(r"^decompiled\t(" + VISIBLE_STORE + r")\t",
                                                rendered, flags=re.M).group(1)
            record["marker_capture"] = ui.call("capture", literal(title))
        else:
            assert not overrides
        receipt[file] = record
        ui.checkpoint("close_program", file)
        ui.call("focus", literal(title))
        ui.choose("File", "Close Tool")
    ui.checkpoint("exit_ghidra")
    ui.exit_ghidra(MANAGER)
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["import", "reopen"])
    parser.add_argument("control", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--fixture-dir")
    parser.add_argument("--project-dir")
    parser.add_argument("--report")
    args = parser.parse_args()
    ui = GhidraGui(args.control)
    deadline = time.monotonic() + 90
    ready = args.control / "ready.txt"
    while not ready.is_file():
        if time.monotonic() > deadline:
            raise TimeoutError("Native AWT Robot did not initialize")
        time.sleep(0.2)
    pid = int(ready.read_text())
    ui.checkpoint("startup")
    if args.phase == "import":
        data = stage_import(ui, args.fixture_dir, args.project_dir, args.report)
    else:
        data = stage_reopen(ui)
    args.output.write_text(json.dumps({"gui_jvm_pid": pid, "cases": data}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except VisibleEvidenceTimeout:
        traceback.print_exc()
        raise SystemExit(EVIDENCE_TIMEOUT)
    except TimeoutError:
        traceback.print_exc()
        raise SystemExit(TRANSPORT_TIMEOUT)
