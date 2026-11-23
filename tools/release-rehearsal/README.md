# Rehearse the published Ghidra v0.1.0 release

Use a disposable native machine or runner. The rehearsal downloads the public Ghidra distribution, the native Temurin JDK and both released extensions to a new directory. It verifies the pinned digests and uses only the public synthetic banked example. It writes its settings, projects and evidence inside that directory.

## Headless release check

Run this from the repository root with Python 3.12. Use a new directory on each run.

```text
python tools/release-rehearsal/rehearse.py headless rehearsal-headless
```

The check installs the two verified archives into the isolated settings through extraction and checks each installed file against its ZIP. It imports and analyzes three observed profiles and an opposing static profile, then opens all four read-only in fresh processes. Each observed profile must produce its expected original offset and byte store in native decompilation. The static profile must retain the raw call without a physical override. The report records the digest of each unchanged saved database and its inspection receipt. This check covers the native headless launchers and Ghidra software; interactive desktop acceptance is separate.

The optional Actions rehearsal uses Linux x64, Windows x64, Intel macOS and Apple Silicon runners. The official Ghidra 12.1.3 ZIP has Windows and Linux x64 native decompilers. On macOS, the rehearsal builds the upstream packaged native code for the active architecture using the archive's Gradle wrapper and a pinned distribution checksum. It records Xcode and verifies the resulting Mach-O architecture and digest. Xcode or compatible command-line tools must already be available in that disposable macOS environment. [Ghidra 12.1.3 native build instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/GettingStarted.md#building-native-binaries) · [Hosted runner architectures](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

## Interactive desktop check

In an unlocked disposable desktop session, open a terminal, stage the same exact artifacts and check that a real native window can be displayed and observed:

```text
python tools/release-rehearsal/rehearse.py stage-gui rehearsal-gui
python tools/release-rehearsal/rehearse.py gui-probe rehearsal-gui
python tools/release-rehearsal/rehearse.py launch-gui rehearsal-gui
```

The desktop probe renders a single colored panel and reads one test-window pixel. It stores no screen image and establishes graphics capability only. A service without an interactive desktop, or a session where macOS limits screen capture, can fail this check. A hosted desktop-capability pass supports trying UI automation on the same runner image, while a native headless pass supplies no desktop evidence. [Windows interactive desktop tests](https://learn.microsoft.com/en-us/dotnet/core/testing/unit-testing-mstest-ui-automation) · [macOS capture access](https://developer.apple.com/documentation/screencapturekit/capturing-screen-content-in-macos)

1. In the project window, capture the fresh **File → Install Extensions** table. Add the two ZIPs from `rehearsal-gui/downloads`, V30MZ first and WonderSwan second, and capture both enabled. Exit Ghidra fully and wait for the foreground launch to return. Check the installed files with the command below.
2. Launch again. Create a non-shared project named `banked` inside `rehearsal-gui`. Import `rehearsal-gui/roms/bank-fe.ws` and verify the WonderSwan Cartridge loader and V30MZ processor. Open in CodeBrowser and select **Run WSMachine** under **WonderSwan Execution Evidence** for analysis.
3. Navigate to `F000:010D`. Confirm the raw window call and the qualified overlay at `ROM0_BANK_00FE::020069` with the reference dialog. Follow the latter and confirm the decompiler shows the byte store `uRam00000200 = 0x42`. Save and exit fully again.
4. Start the foreground launcher with the saved `.gpr` path as below. Open the saved program, return to the call and destination, and capture the same reference and marker without rerunning analysis. Retain screenshots of the two installation states, the loader and the restored reference and marker. Record native OS and architecture, both completed foreground launches, and any startup or analysis dialogs.

```text
python tools/release-rehearsal/rehearse.py verify-gui-install rehearsal-gui
python tools/release-rehearsal/rehearse.py launch-gui rehearsal-gui --project rehearsal-gui/banked.gpr
```

Reproduce the headless case independently using the same published example. [Banked example](../../examples/banked-call/README.md) · [Exact extension release](https://github.com/JidouGhost-TL/ghidra-wonderswan/releases/tag/v0.1.0)
