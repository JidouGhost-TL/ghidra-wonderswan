# ghidra-wonderswan

Ghidra 12 support for the Bandai WonderSwan / WonderSwan Color (and SwanCrystal, which runs colour
cartridges): a NEC V30MZ processor language, a cartridge loader, execution-evidence analyzers and a
headless emulator built on Ghidra's p-code engine. Pure Java / SLEIGH.

| Module | What |
|---|---|
| [`v30mz/`](v30mz/README.md) | Processor module: NEC V30MZ language `V30MZ:LE:16:default`. Knows nothing about the WonderSwan. |
| [`wonderswan/`](wonderswan/README.md) | Platform module: `WonderSwanLoader`, the `WSMachine` emulator, `WSRender`, the evidence analyzers and the `WSEmulate` script. Requires `v30mz`. |

Reference material: [`docs/V30MZ-SPEC-NOTES.md`](docs/V30MZ-SPEC-NOTES.md) (cited ISA brief),
[`docs/V30MZ-UNDEFINED-ENCODINGS.md`](docs/V30MZ-UNDEFINED-ENCODINGS.md) (verified undefined encodings),
[`docs/SOURCES.md`](docs/SOURCES.md) (sources, versions, licences).

No ROMs are included. Use cartridge dumps you are entitled to use.

## Requirements

- Ghidra **12.1.3** (extensions are built against, and only install into, the exact Ghidra version)
- JDK 21 (as required by Ghidra 12.1)

## Build and install

```sh
tools/install.sh            # Linux: builds both extensions and installs them for Ghidra (GUI + headless)
```

`install.sh` runs `./build.sh` (Ghidra's bundled Gradle; `GHIDRA_INSTALL_DIR` defaults to
`/opt/ghidra_12.1.3_PUBLIC`), unzips each extension into the per-user Ghidra `Extensions/` directory
and clears Ghidra's compiled-script cache. The Ghidra install tree is not modified; deleting the
extension directories uninstalls. The helper assumes the Linux layout of Ghidra's per-user settings
directory (`~/.config/ghidra/ghidra_<version>_PUBLIC`); it is not a Windows or macOS installer.

On any platform, run `./build.sh` and install `v30mz/dist/*.zip` and then `wonderswan/dist/*.zip` from
Ghidra's *File → Install Extensions*. `./build.sh` with no arguments runs `buildExtension` for both
modules. Any arguments replace that default task list and are passed to Gradle as given, so name a
task alongside custom options (`./build.sh -q buildExtension`); `./build.sh -q` alone runs Gradle's
default `help` task and builds nothing.

Gotchas:
- **Stale scripts.** Gradle zips use a fixed 1980 timestamp, so after reinstalling Ghidra may keep
  running an old compiled script. `install.sh` clears `osgi/compiled-bundles`; if you install by
  hand, clear it too. The installed copy of a script shadows `-scriptPath`.
- **Stale `.sla`.** If an installed `.sla` is missing, or is writable and older than its `.slaspec` (or
  from another SLEIGH version), Ghidra recompiles it at load. The build ships a compiled `.sla`.

## Use

Import and analyse a cartridge (GUI: File → Import picks the *WonderSwan Cartridge* loader):

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.3_PUBLIC
G=$GHIDRA_INSTALL_DIR/support/analyzeHeadless
$G <projdir> <project> -import game.wsc -loader WonderSwanLoader -processor "V30MZ:LE:16:default"
```

Auto-analysis runs the emulator in-process (by default 1500 frames with a scripted Start/A input) and
seeds code discovery from what executed; see the evidence rules in
[`wonderswan/README.md`](wonderswan/README.md). The extra time depends on the cartridge, the frame
settings and the computer. It can be turned
off, or pointed at a saved `WSEmulate` run, under Analysis Options → *WonderSwan Execution Evidence*
(*Run WSMachine*, *Frames*, *Evidence directory*). A Mesen 2 recording of the cartridge can be
merged in as well (*Mesen trace directory or CDL file*; see `wonderswan/README.md`).

Run the emulator on an imported program (outputs coverage, traces, RAM, screenshots):

```sh
$G <projdir> <project> -process game.wsc -noanalysis -readOnly \
   -postScript WSEmulate.java <outdir> [frames] [insns/frame] [stopAt|-] [shotEvery] \
   [savesDir|-] [inputScript|-] [environment|-]
```

The optional eighth argument is a comma-separated environment list (`hp=`, `eep=`, `owner=`, `cyc=`,
`trace=`, `sig=`, `model=`); see [`wonderswan/README.md`](wonderswan/README.md#wsemulate).

## Validation

Results as of 2026-10. The validation harnesses depend on cartridge dumps and reference traces that are not
distributed, so they are not part of this repository.

- **Decoding:** a differential harness (`v30mz/ghidra_scripts/V30MZDecodeDiff.java`) compares every
  opcode/ModRM form, and all code executed by a set of commercial titles, against Ghidra's x86 real
  mode: 0 unexplained differences; undefined-encoding lengths verified against hardware-tested sources.
- **Semantics:** WSCpuTest 48/48 groups (flags included, many exhaustive) and the ws-test-suite CPU
  tests (80186 quirks, prefixes, interrupt timing) pass on `WSMachine`.
- **Emulator:** coverage agreement with Mesen 2 of 99.4–99.96 % on commercial titles over 1500 frames.
- **Saves:** cartridge and internal EEPROM (full serial protocol) and SRAM are emulated; the ws-test-suite EEPROM
  test ROMs (internal, 1 Kbit, 16 Kbit) pass. Save images load and save as files (see `wonderswan/README.md`).

## Limitations

- The emulator is a probe for code discovery, not a cycle-exact console. By default frames are
  instruction-count based; the optional cycle-timed mode (`cyc=1`) charges V30MZ cycles and runs lines,
  timers, sound DMA transfers and general-DMA CPU stalls by cycles, but it is not validated as
  cycle-exact for every instruction mix.
- Modelled to a register level: general DMA (masks, refusals, transfers), sound DMA registers and
  transfers (in cycle-timed mode), the channel-3 sweep and channel-4 noise generator, the 2003-mapper
  RTC (alarm output pin not modelled) and self-flash on flash cartridges (operations complete
  instantly). Not modelled: audible sound output, NMI (low battery), open-bus values.
- Code in the ROM bank windows is found only where execution reached it (one overlay per observed bank).
  Code copied to RAM/SRAM and run there has no captured image: executed RAM is bookmarked, not decoded
  (rule H1), and RAM/SRAM code that analysis decodes anyway is kept as an unresolved hypothesis, tagged
  `ram-code: unknown, no evidence` (rule H2), rather than resolved or deleted.
- Evidence comes from one scripted input over the first frames of play; code reached only later is found
  by static analysis alone.

## Licence

Licensed under either of

- MIT License ([`LICENSE-MIT`](LICENSE-MIT))
- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option.

Three V30MZ language files are derived from Ghidra's x86 specification (Apache-2.0): `v30mz.slaspec`,
`v30mz_insn.sinc` and `v30mz.cspec`. The portions taken from Ghidra remain subject to the Apache License,
Version 2.0; see [`NOTICE`](NOTICE). Each file carries an SPDX identifier.

Third-party sources are listed with their licences in [`docs/SOURCES.md`](docs/SOURCES.md). GPL and
unlicensed sources were used as references only; no code was copied from them.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this
work, as defined in the Apache-2.0 licence, shall be dual-licensed as above, without any additional terms
or conditions.
