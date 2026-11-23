# Foreground Windows GUI rehearsal

The manual **Public Windows Ghidra GUI rehearsal** runs on the canonical repository's main branch. It uses the exact published Ghidra extensions and public synthetic banked-call fixtures.

For a local run, use a disposable native Windows x64 desktop with an unlocked interactive session, PowerShell 7, Python 3.12 or newer, and a fresh scratch path without whitespace. Robot sends desktop mouse and keyboard events and uses the clipboard.

```powershell
.\Run-NativeGui.ps1 -Output C:\gui-rehearsal
```

The preparer verifies the public releases and preinstalls all 44 required extension files from the two approved ZIPs. A foreground desktop probe checks rendered pixels, mouse input and keyboard input. The same probe refuses forced headless mode.

The driver verifies that each foreground JVM shares its launcher’s newly created Windows console. It uses visible Ghidra controls to create a project, import both cartridges, run observed and static analysis, save, and set both programs read-only. The second foreground launch opens the saved project after the first process exits.

The read-only check uses the References Editor and visible decompiler. It requires the observed bank FE override, the raw far call in both cases, zero overridden calls in the static case, the observed 0x42 store, and unchanged program database hashes. Screen pixels stay in memory. The hosted log contains structured phase results and a bounded pass receipt.
