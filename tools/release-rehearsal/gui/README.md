# Foreground Windows GUI rehearsal

Run this on a native Windows x64 desktop with an unlocked interactive session, Python 3.12 or newer, and a new local scratch path with no whitespace. The existing release preparer acquires or checks the exact published artifacts and stages the public synthetic fixtures.

```powershell
.\Run-NativeGui.ps1 -Output C:\gui-rehearsal
```

The isolated install verifies all 44 files against the two published extension ZIPs. Ghidra opens in a foreground process. The driver reads visible Swing controls and uses AWT Robot input to create a project, import both synthetic cartridges, run observed and static analysis, save, and set the programs read-only. It exits before the second foreground launch opens the saved project.

The read-only check uses the real References Editor table and the visible decompiler. It requires the observed bank FE override, the raw far call in both cases, no overridden call in the static case, the observed 0x42 store, and unchanged program database hashes. The screen capture contributes only a hash and dimensions to the local receipt. Keep the private output directory off public build logs and artifact uploads.

The source prototype was exercised on Linux Xvfb. Windows requires its own result from a real desktop.
