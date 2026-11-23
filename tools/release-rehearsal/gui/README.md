# Foreground Windows GUI rehearsal

The manual **Public Windows Ghidra GUI rehearsal** runs on the canonical repository's main branch. It uses the exact published Ghidra extensions and public synthetic banked-call fixtures.

For a local run, use a disposable native Windows x64 desktop with an unlocked interactive session, PowerShell 7, Python 3.12 or newer, and a fresh scratch path without whitespace. Robot sends desktop mouse and keyboard events and uses the clipboard.

```powershell
.\Run-NativeGui.ps1 -Output C:\gui-rehearsal
```

The preparer verifies the public releases and preinstalls all 44 required extension files from the two approved ZIPs. A foreground desktop probe checks rendered pixels, mouse input and keyboard input. The same probe refuses forced headless mode.

The driver verifies that each foreground JVM shares its launcher’s newly created Windows console. It uses visible Ghidra controls to create a project, import both cartridges, run observed and static analysis, save, and set both programs read-only. The second foreground launch opens the saved project after the first process exits.

The read-only check uses the References Editor and visible decompiler. It requires the observed bank FE override, the raw far call in both cases, zero overridden calls in the static case, the observed 0x42 store, and unchanged program database hashes. Screen pixels stay in memory. The hosted log contains structured phase results and a bounded pass receipt.

A failed GUI driver can report its last checkpoint and distinguish a wait for visible evidence from a control transport timeout or another driver exit. The checkpoint contains a fixed step name and, when applicable, the public synthetic fixture name. Driver logs and exception details stay in scratch.

## Foreground macOS rehearsal

The manual **Public macOS Ghidra GUI rehearsal** runs independently on native Apple Silicon and Intel runners. For a local run, use a disposable unlocked macOS desktop with Python 3.13 and a fresh scratch path without whitespace. Select the matching host argument.

```bash
python3 -B tools/release-rehearsal/gui/run_macos.py /path/to/fresh-rehearsal --expected-host Darwin-arm64
```

Use `Darwin-x64` on Intel. The runner verifies the login GUI session and requires the foreground pixel and Robot input probe before creating the GUI project. The session must permit AWT screen observation and input. Each foreground JVM stays in an owned process group within the existing desktop session. The same strict visible evidence and read-only database checks apply to both architectures.

The macOS failure log uses the same bounded checkpoints and timeout categories as Windows.

The disposable macOS cold-reopen JVM starts with Ghidra's stock startup-tip preference disabled through `-DSHOW_TIPS=false`. The import JVM keeps the normal Ghidra startup behavior. The harness still refuses competing dialogs before reference input. [Stock preference](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/totd/TipOfTheDayPlugin.java#L91-L110)
