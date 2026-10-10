# wonderswan — WonderSwan platform module for Ghidra 12.1.3

Package `jidoughost.wonderswan`. Requires the `v30mz` extension (language `V30MZ:LE:16:default`).

| Class / script | Role |
|---|---|
| `WonderSwanLoader` | Cartridge loader (*WonderSwan Cartridge*) |
| `WSHeader` | Footer parse + checksum |
| `WSHardware` | Memory map, bank mapping, port names, entry state — single source of truth |
| `WSCartridge` | Mapper/save detection shared by the loader and the machine |
| `WSRtc` | 2003-mapper RTC (S-3511A over the $CA/$CB protocol) |
| `WSFlash` | NOR flash behind the $CE self-flash window |
| `WSKarnak` | KARNAK ADPCM decoder + timer (Pocket Challenge V2) |
| `WSMachine` | Headless emulator on Ghidra's `PcodeEmulator` |
| `WSDebuggerEmulator` | `WSMachine` as a Debugger p-code machine: per-step interrupts, line/timer advance, trace recording |
| `WSEmulatorFactory` | Debugger emulator factory (*WonderSwan Concrete P-code Emulator*) |
| `WSFrameScheduler` | Run-until-VBlank scheduler for the frame-step action |
| `WSDebuggerPlugin` | Debugger plugin: screen view, controller input, frame-step and *Run N Frames...* actions |
| `WSRender` | Screen renderer (diagnostic) |
| `WSEvidenceAnalyzer` | Auto-analysis phase 1: runs `WSMachine` (or loads WSEmulate output) and seeds code from execution evidence |
| `WSEvidenceRepairAnalyzer` | Auto-analysis phase 2: checks Ghidra's results against the same evidence; jump tables; calling convention |
| `WSJumpTables` | Rule J1 (used by phase 2) |
| `WSCodeContext` | Rule C0: a default code segment for undecoded ROM bytes before flow (loader, phases 1 and 2) |
| `WSRamCode` | Rule H2: RAM/SRAM code without a captured image is kept and tagged as an unresolved hypothesis (phase 2) |
| `WSExecutedFunctions` | Rule E5: executed code outside every function gets a function (phase 2) |
| `WSStaticCode` + `ghidra_scripts/WSSeedStatic.java` | Post-analysis static call seeding in undefined ROM (strict trial decode; no execution evidence synthesized) |
| `WSCodePointers` | Rules F1-F4: code reached through code-pointer variables and pushed return addresses (phase 2) |
| `WSGapCode` | Rules G1/U1: dead code and unreferenced functions found structurally after a terminator (phase 2) |
| `WSMerge` | Rules M1/T1: merge split routines back together (post-script `WSMergeRoutines`) |
| `WSBranchContext` | Rule D2: re-disassemble near branches resolving cross-segment with their own context (phase 2) |
| `WSReturns` | Rule R1: register return values from caller/callee evidence (phase 2) |
| `WSVolatile` | Rule V1: interrupt-written poll flags are volatile (phase 2) |
| `WSAssets` | Headless asset core: tile / tilemap / palette / sprite decode, screen compose (via `WSRender`), PNG export |
| `WSSnapshot` | Display-state snapshot (RAM, ports, per-line ports, hardware model) for the asset core |
| `WSTileFormat` | Tile pixel formats (2bpp, 4bpp planar / packed) |
| `WSTileArrangement` | Tile groupings for display: plain 8x8, 8x16, 16x16 row/column-major, custom WxH |
| `WSRom` | Read the stored ROM image by file offset; map listing addresses back to ROM offsets |
| `WSCodec`, `WSCodecRegistry` | Pluggable decompression interface for the asset viewer (no game-specific codecs shipped) |
| `WSAssetPlugin`, `WSAssetProvider` | GUI asset viewer (listing/ROM/decoded tiles, tilemaps, emulator VRAM / palettes / sprites, PNG export, decompress-here) |
| `ghidra_scripts/WSEmulate.java` | Runs `WSMachine` on the current program and writes evidence files |
| `WSMesenTrace` | Parsers for Mesen 2 trace logs (`trace.tsv` + `coverage.tsv`) and code/data logs (`.cdl`) |
| `ghidra_scripts/WSImportTrace.java` | Imports Mesen 2 evidence into the current program (headless use) |
| `ghidra_scripts/WSAssetExport.java` | Headless asset export: screen, tile atlases, layers, palettes, sprite table to PNG/TSV |
| `ghidra_scripts/WSRomTiles.java` | Headless ROM-offset tile render: FileBytes at an offset through an arrangement to PNG |
| `ghidra_scripts/WSViewerSmoke.java` | Headless smoke test: instantiate the viewer plugin and provider in a bare tool |
| `WSGuiSmoke` (`src/test`) + `gui-test/` | Headed GUI smoke test (`guiTest` task, Xvfb container): plugins, providers, actions, Tiles ROM-offset render, re-registration |

## Link mode

`WSLinkEmulate.java` boots two cartridges in one process with independent RAM, save memory,
internal EEPROM and inputs. Import console A with the WonderSwan loader, then run this post-script:

```
WSLinkEmulate.java <ROM B> <output dir> [frames=1500] [shotEvery=100]
                  [input A|-] [input B|-] [saves A|-] [saves B|-]
                  [model A=auto|mono|color] [model B=auto|mono|color]
```

Input files contain `from to buttons` spans (inclusive frame numbers, hexadecimal keypad mask,
as in `WSEmulate`). Missing inputs hold no buttons. Save directories use `cart.sram`, `cart.eeprom`
and `internal.eeprom` as applicable; input images are read without modification. `A/` and `B/`
contain periodic screenshots, `final.png`, final RAM/ports, `saves/` and `coverage.tsv` (executed ROM file byte ranges `rom_start rom_end first_frame`, hex offsets, decimal first shared frame). `serial.tsv` records direction,
frame, master clock, value, baud rate and delivery/drop result; `summary.txt` records completion/errors.

The cable interleaves cycle-timed CPU instructions on a shared 3.072 MHz clock. The wire advances
on every shared hardware clock, including DMA stalls. An 8N1 byte takes
3,200 clocks at 9,600 baud or 800 at 38,400 baud. Each frame interval is 159 × 256 clocks; the consoles
retain their own display phase. B1/B3 buffers, overrun and the B2/B6 serial interrupt levels follow the
[UART](https://ws.nesdev.org/wiki/UART) and [interrupt](https://ws.nesdev.org/wiki/Interrupts) hardware
documentation. `WSSerial.Peer` is the transport interface for future adapter/device models.
Detached machines retain the existing instant serial output behavior. Linked save-state snapshots
are unsupported; final cartridge save images are supported. `WSLinkTest.java` exercises a synthetic
two-console fixture. Link play can, for example, connect a two-player puzzle game or a save-transfer utility.

### Serial endpoint

`WSSerialEndpointRun.java` runs the current cartridge as one console whose serial port (the EXT connector's UART) is a
raw byte stream over TCP. Anything that speaks raw serial bytes can be the cable partner: another console in a
separate process or on another machine, a relay, or a bridge to a serial device or another program.

```
WSSerialEndpointRun.java <endpoint> <output dir> [frames=1500] [shotEvery=100] [input|-] [saves|-]
                         [model=auto|mono|color] [pacing=pull|wire] [timing=realtime|fast]
```

The endpoint is `tcp:<host>:<port>` (connect, retried for 60 s) or `listen:[<host>:]<port>` (one partner, 60 s);
frames start once connected. The stream carries raw 8N1 data bytes and no speed, so both ends must select the same
one. A byte leaves at the end of its byte time; received bytes arrive no sooner than one byte time apart. `pull`
pacing also holds a received byte while the previous one is unread (no overrun from bursts on the network); `wire`
delivers at line rate, so an unread byte causes overrun. Bytes arriving while the port is disabled are dropped.
`realtime` paces frames to wall-clock time (about 75.5 per second) for partners that run in real time; `fast` runs
unthrottled. Output: periodic `shot_NNNNN.png`, `final.png`,
`ram.bin`, `saves/`, `serial.tsv` (`TX`/`RX` rows: direction, frame, master clock, value, baud, result) and `summary.txt`. Unlike the
in-process cable, runs are not deterministic: arrival depends on the partner.

Examples:

- Two consoles in separate processes: run one with `listen:4300`, the other with `tcp:<host>:4300`.
- A USB serial adapter on a real console's EXT port, bridged with a generic tool, e.g.
  `socat TCP-LISTEN:4300,reuseaddr /dev/ttyACM0,raw,echo=0,b9600` and `tcp:127.0.0.1:4300` here (untested on
  hardware so far).
- A program that talks serial bytes on stdin/stdout, e.g. `socat TCP-LISTEN:4300,reuseaddr EXEC:<program>`.

## Loader

Detects a cartridge by its 16-byte footer (`EA` far JMP) alone; the load spec is preferred when the
footer checksum verifies. The file extension plays no part in detection: after it, `.wsc` selects
colour hardware and `.pc2` the Pocket Challenge V2 mapper (below). Load specs: `V30MZ:LE:16:default` (preferred) and
`x86:LE:16:Real Mode` (comparison only; no csval/io setup).

The mapper comes from footer byte $D ($00 = 2001, $01 = 2003), the save hardware from the save
byte, and a `.pc2` file selects the Pocket Challenge V2 KARNAK mapper. A 2003-family image with
WonderWitch markers (zero checksum field, version bit 7, 512 KiB flash size) loads as a
flash-backed WonderWitch cartridge. Non-power-of-two images are read as the next power of two
with padding at the start (so the footer stays at the top); banking always uses the file size,
never the footer's size code. Every unknown or contradictory value (mapper, save type, size code,
checksum) is reported in the import log; nothing defaults silently. Detection facts land under
Program Options → *WonderSwan* (`Mapper`, `RTC`, `Flash`, …).

| CPU address | Block | Notes |
|---|---|---|
| `0000:0000` | `RAM` | 64 KiB colour / 16 KiB mono, zero-filled; labels IVT, TILES_2BPP, TILES_4BPP, PALETTES |
| `1000:0000` | `SRAM` | uninitialised, volatile (bank port C1) |
| `2000:0000`, `3000:0000` | `ROM0_WINDOW`, `ROM1_WINDOW` | uninitialised, volatile, not executable (ports C2/C3) |
| `4000:0000`–`F000:FFFF` | `LIN_4000` … `LIN_F000` | twelve 64 KiB blocks from FileBytes through C0 = 0xFF; small ROMs mirror |
| overlay of `0000:0000` | `ROM_xx` | one 64 KiB read-only non-executable overlay per ROM bank not in the linear window (e.g. `ROM_3A`), each in its own overlay space; any ROM offset reachable via Go-To, labels, references |
| `io:0000`–`io:00FF` | `IO` | ports, labelled (`KEYPAD`, `BANK_ROM0`, …), byte/word typed, volatile |

Also: `WSCartridgeFooter` structure at `F000:FFF0`, an external entry + one-address `reset`
function at the reset vector (Ghidra's entry-point analyzer skips *named* entries otherwise),
`csval` context = reset segment at the entry, `DS`/`SS` = 0 over the linear ROM, header facts under
Program Options → *WonderSwan*. Rule C0 (`WSCodeContext`) gives every undecoded byte of the linear
ROM blocks a default `csval` before any flow: the 64 KiB-aligned segment of its linear address
(`(linear >> 4) & 0xF000`), one span per 64 KiB, skipping existing instructions and any `csval` already
stored there; RAM and the `ROM_xx` data views get none. The loader does not store `colorsoc` (MUL
sets ZF on the colour SoC) as a range over the ROM: a stored context range over undecoded bytes would
override the flowing context. The evidence analyzer sets `colorsoc` = 1 with `csval` at each executed
address of a colour-hardware program, and it flows from there.
The whole ROM is stored as FileBytes so analyzers can add banks as overlays later.

Hardware model (`Color` option): colour when the footer flag is set **or** the file is a `.wsc` (colour releases
with footer flag 0 exist; `Color source` and `Footer color flag` record which). It sets RAM size, `colorsoc`,
and the machine every tool emulates.

Loader option *Map all ROM banks as data overlays* (default on): the `ROM_xx` blocks above.
Disable it for a linear-window-only import. Executable bank overlays for window code are created
by the evidence analyzer (rule B2, `ROM0_BANK_XXXX` / `ROM1_BANK_XXXX` at `2000:0000` / `3000:0000`),
not the loader: B2 overlays are executable views at the window address, `ROM_xx` blocks are
read-only data views overlaying `0000:0000`. Both use uppercase hex bank numbers; `ROM_xx` uses
the effective bank index (e.g. bank `0x3A` → `ROM_3A`, file offset `0x3A0000` on power-of-two images).
Non-executable, so Ghidra's code finders (entry points, aggressive instruction finder, function
starts) and WS rules F/G/U/J (all gated on executable, plus an explicit `ROM_xx` name guard)
leave them as pure data; the decompiler only sees functions.

## Evidence analyzers

Every decision can be written to a JSON-lines report (analysis option *Evidence report file*). Phase 1
(and `WSImportTrace`, which applies the same seeding to imported evidence) overwrites the file; phase 2 and the post-analysis scripts
`WSMergeRoutines` and `WSJumpTableFinish` append to it. `WSSeedStatic` writes its own optional output
file and overwrites it. Copy a report before rerunning a step that overwrites it if a later script
still needs it.

| Rule | Phase | What |
|---|---|---|
| E0b | 0 | Evidence hygiene in `WSMachine` (`WSComputedEdges`): a computed JMP/CALL resolves to the next instruction in its own interrupt context — an edge pre-empted by an interrupt stays pending across the handler flow (nested interrupts included) and is recorded at the post-IRET instruction, never inside the handler |
| C0 | 1-2 | Before flow, undecoded bytes of the linear and executable bank-window ROM blocks get a default code segment (`csval` = the block's 64 KiB-aligned segment), so code reached by later disassembly resolves near branches in a plausible segment instead of CS = 0. It is a default only: existing instructions and stored segment observations (E1, D2, F2, …) are kept and win. Run by the loader and at the start of both phases (phase 1 report line `rom_context_spans`); each B2 bank overlay also gets its window segment over the whole block |
| B2 | 1 | Code executed in the ROM0/ROM1 windows: one overlay block per (window, bank) observed (`ROM0_BANK_xxxx`, from FileBytes), seeded like linear code; a window address that ran under several banks is seeded in each |
| B3 | 1 | Direct call/jump into a window whose target ran under exactly one bank: resolved to that bank's overlay and disassembled there; calls get a call-override reference, jumps a data reference (a cross-space jump override fails every decompile it reaches) |
| E1 | 1 | Executed address = instruction start, `csval` = observed CS (executed RAM is H1 instead) |
| H1 | 1 | Executed work RAM is never decoded (load-time bytes are loader zero-fill): each run is bookmarked (*RAM code, no image yet*) and reported |
| H2 | 2 | Code in RAM/SRAM (below `2000:0000`) without a captured image of what ran there is an unresolved hypothesis, not an artefact: each decoded run is kept, bookmarked `ram-code: unknown, no evidence` (category `ram-code`) and its functions tagged the same; the cleanup rules (A1, J1h, J1r, J1t, P1, D2) skip it instead of clearing or removing it (report line `unknown_ram_runs`, outcome `KEPT`) |
| E2 | 1 | Call / interrupt edge target = function entry |
| E3 | 1 | Computed jump: observed targets as references + JumpTable override |
| S1 | 1 | Code seed file (option *Code seed file*; TSV `address class method start start_kind …`): class `function`, or `code-strong` with start kind `prologue` / `after-terminator`, seeds a function at the start column (not inside an existing function); other `code-strong`, `executed*` and `code` seeds are instruction starts (`csval` = the seed's segment); other classes and seeds that conflict with existing code are reported, not applied |
| N1 | 2 | Clear "does not return" where a call's fall-through executed |
| E1R | 2 | Re-seed executed code later analysis removed |
| J1 | 2 | CS-relative jump/call tables: backward slice for base + index bound (mask = upper bound, CMP/JA), stop rules EXECUTED_CODE / TABLE_BOUNDARY / OUT_OF_ROM / MID_INSTRUCTION / DEFINED_DATA / SELF; observed targets must be a subset (missing ones added and reported); overlay sites resolve within their overlay; J1o skips slots targeting the last overlay byte and deletes unproven computed references there |
| D0 | 2 | Title DS default: if one DS ≠ 0 covers ≥ 50 % of executed addresses that ran with a single DS, it replaces the loader's DS = 0 default over the ROM (LSI C-86 titles run with DS = 1000, SRAM) — `WSCompilerRules` |
| P1 | 2 | Functions whose entry has no bytes (phantoms) removed, reported with their creating references |
| F1 | 2 | Far code-pointer variables: a word pair (M, M+2) whose contents are transferred to by `CALLF/JMPF [M]` or the push-return dispatch `PUSH [M+2]; PUSH [M]; RETF` (directly or through a register), and the interrupt vector table (0000:0000-03FF); near variables: `CALL/JMP word ptr [M]` (not CS) or `PUSH [M]; RET`. Found by a forward constant tracker over every fall-through chain (reset at flow joins, registers unknown after calls; DS from the context after a reset or call) |
| F2 | 2 | A constant offset stored to M with a constant segment stored to M+2 in the same chain (far), or a constant stored to a near variable, is a code pointer: disassembled with `csval` = the stored segment, made a function, bookmarked; targets that are offcut, in data, undecodable, in a bank window or RAM are reported (`0000:0000` = `NULL_POINTER`, a cleared variable) |
| F3 | 2 | Setter functions: a function whose entry chain stores two of its input registers into M and M+2 of a far variable (or one into a near one); the constant register values at each call to it are code pointers (F2) |
| F4 | 2 | The constant segment:offset pushed below a push-return dispatch pair is the dispatched code's return point: code, no function |
| G1 | 2 | Dead code: the undefined bytes after an unconditional near JMP inside a function that decode (trial flow walk) into a run that rejoins that function: disassembled, no function, bookmarked |
| U1 | 2 | Unreferenced function: the undefined bytes after any terminator, or after a run of >= 16 identical 00/FF fill bytes in a block that holds code, that decode into a closed flow (every path ends in RET/RETF/IRET or joins existing code; no overlap, no undecodable or implausible instruction, no computed branch, calls only to existing function entries or to undefined bytes of the same block, which are walked too and become functions) with at least 3 instructions and 2 anchors (a call to an existing function, a RAM / I/O operand existing code also uses, or 2 for a push/pop discipline that balances at every return); tag `WS_UNREFERENCED`. Weaker candidates are reported (`WEAK`) and left as bytes |
| J1f/g/h | 2 | Table ends at another CS table's base (TABLE_BASE); computed refs not in a proven table are superseded; code decoded only from superseded refs is cleared (bytes kept, never executed / still referenced / fallen into from kept code / RAM code, `RAM_CODE_KEPT`; containment in a function entered elsewhere is reported, not a veto, since unreachable bytes are freed for the routine-start rule) and proven targets re-flowed; an automatic function whose whole body lies in the cleared run is removed with its decode (`ORPHAN_FUNCTION_REMOVED`), while user-defined, imported, thunk, external and RAM functions stay |
| J1l | 2 | An unresolved site with a decode conflict in its function, or a guessed target that is an offcut / ERROR / undecodable, is quarantined: guessed (non-observed, non-user) references deleted, their orphan decode cleared, the site re-attempted every pass; still-unresolved sites keep the guesses deleted (the addresses stay in the evidence for rule J1m) |
| J1m | 2 | Post-analysis script `WSJumpTableFinish` (after the merges): at a quarantined site, re-deletes any guessed reference a later analysis re-derived and locks the switch to its observed targets with a stored jump-table override; with no observed target the site stays an opaque indirect branch; unresolved sites with E3 targets get the same lock; J1p re-locks recovered jump sites (merges strip the recovery override); J1q filters every lock to the site's address space |
| J1n | 2 | A kept table target shadowed by single-byte data (a data pointer read the slot first) is deshadowed so it disassembles; user/imported and multi-byte data stay |
| J1r | 2 | A quarantined site whose own instruction is gone (a guessed offcut polluted the backward slice, then the quarantine's orphan clear removed the dispatch setup with it) gets one restoration attempt before the final verdict: the cleared run is re-decoded from the fall-through of the nearest preceding kept instruction in the same function and the site re-attempted; a recovered site applies normally, a still-unresolved one keeps its restored decode and stays quarantined |
| J1s | 2 | A table target skipped as an offcut is retried on later passes: once the conflicting decode is gone and the target disassembles, it is committed like a kept target (disassembled, referenced, functioned for CALL sites) |
| J1t | 2 | Post-analysis script `WSJumpTableFinish` (after the J1m lock): a function at a recovered JMP site's kept target whose body contains another kept target of the same site and partitions exactly into terminal spans is demoted per span (stock case names stripped throughout): RET-terminated spans are real functions and kept, JMP-terminated spans are case-blocks of the switch parent and dropped (no function; the parent absorbs them); the site is re-locked to its current computed-targets-to-code so the decompiler renders the proven cases instead of re-deriving stock's over-approximation; anything else stays as it is |
| M1 | 2 | A function reached only by plain jumps from inside one other function, with no nested entry and every exit landing in the two, is merged into it (compare-chain cases rejoin their chain); tail-call overrides on the referring jumps are cleared (else the fixup won't follow them), call-typed references retyped, a non-default name kept as a label; anything the fixup doesn't pull is restored; real calls, computed branches, recursion and interrupt entries veto |
| T1 | 2 | A function with no return whose last instruction is a call to a returning function and whose fall-through is exactly another function's entry is merged with it (one routine split in two); thunks and interrupt entries veto |
| E1A | 1-2 | Executed alignment outranks speculative decode: where a guessed instruction overlaps an executed instruction start, the guess is cleared and guessed edges into the offcut removed; where both alignments executed, or the losing decode is protected (user/imported), the conflict is reported (`AMBIGUOUS_OR_PROTECTED_ALIGNMENT`) and nothing is changed |
| B2R | 1-2 | Physical ROM evidence stays distinct from CPU instruction starts: every bank gets a non-executable view in both windows; a window bank proven by constant bank writes in an uninterrupted predecessor chain places code in that bank's view; an automatic function in a window view with no known bank (no instruction image) keeps its provenance and navigation candidates and is classified (`UNMAPPED_WINDOW_PLACEHOLDER`) instead of being trusted |
| Z1 | 2 | Long runs of one byte value (64+ bytes of `00` or `FF`, 256+ of any other value) that never executed are fill, marked as data (bookmark category `WSFillRun`) and cleared of speculative decode; executed bytes reopen fill as code (`EXECUTION_REOPENS_FILL`) and explicit user code is protected (`PROTECTED_CODE`) |
| A2 | 2 + finish | Function bodies keep decoded graph components and never join through undecodable bytes; speculative growth is bounded after 256 consecutive bytes without execution evidence; independently executed components are split into their own functions (`EXECUTED_COMPONENT_SPLIT`); user bodies stay. Runs in phase 2 and again in `WSJumpTableFinish` |
| A3 | finish | Decompiler boundaries (`WSJumpTableFinish`, after merges and J1 locks): independently executed exterior entries become their own functions, direct jumps between the resulting functions are marked as tail transfers, and unresolved weak tables are locked to executed targets. No ROM bytes or user overrides change |
| J1v | finish | Switch overrides whose site or function no longer matches the current listing are removed (`STALE_OVERRIDE_REMOVED`) before the final locks |

Rules M1 and T1 live in the `WSMergeRoutines` script, not in the repair analyzer, and the script
runs in its own `-noanalysis` process after the analysis process exits: merges performed inside
the analysis process (analyzer or its post-scripts) are undone before save, while merges made in
a later process survive to the saved project. The script re-reads interrupt entries (rule F2 installed vector
targets, rule E2 observed interrupt entries) from the phase-2 evidence report for the merge veto,
and appends its M1/T1 evidence lines to the same report. It is idempotent: a second run finds
nothing left to merge.
| R1 | 2 | A register read-before-written after a call at 3+ call sites, and written (not POP-restored) on a path to a RET of the callee (a CALL/INT provides the call-clobbered AX/BX/CX), becomes the callee's return (byte when every access is 8-bit, else word; several registers = one multi-register storage); user/imported signatures and thunks are left alone |
| V1 | 2 | A RAM address stored on an interrupt handler's flow and loaded (never stored) in a backward-conditional-branch loop elsewhere is split out of the RAM block into a tiny volatile block, so spin-wait loops decompile as loops |
| E5 | 2 | Executed code left outside every function: connected pieces by flow, each piece entry becomes a function (default address space only; work RAM skipped, rule H1) — `WSExecutedFunctions` |
| D1 | 2 | DS context at entries with one non-zero observed DS |
| D2 | 2 | A near branch resolving to another segment is always misdecoded (a 16-bit near branch cannot change CS): unexecuted branches are re-disassembled with their own segment's context (the re-decode must reproduce the mnemonic and length or the original is restored); executed branches stay |
| D3 | 2 | CS-register context over every initialized block (each span's own display segment): `MOV reg,CS` / `PUSH CS` fold to constants instead of unaffected CS inputs — `WSCompilerRules` |
| A1 | 2 | Unexecuted fall-through runs ending in a bad decode: decode cleared, bytes kept, bookmarked; the walk stops before kept jump-table targets (proven code) |
| K1 | 2 | Compiler family from the program's own code (`WSCompilerRules`): LSI C-86 when functions with its frame save order (`PUSH BP; MOV BP,SP [; SUB SP,n]; PUSH CX/DX…`) are ≥ 10 % of ROM functions and stack-argument functions (`[BP+4..0x3f]`) ≤ 20 % (calibrated on the licensed library: 28/29 LSI titles, 0 false positives) |
| C1 | 2 | Functions without a user/imported signature get `__lsic86` when K1 says LSI C-86, else the compiler spec's default (`__wsasm`) |

Each phase-2 rule runs on its own: a rule that throws is reported (analysis log, `Msg.error`, an `ERROR` line
`{"rule":…,"outcome":"ERROR"}` in the report, an error bookmark) and the remaining rules still run; the summary line
ends with `RULES FAILED: [...]`.

J1 and F1-F4 alternate until neither adds code; G1/U1 run once both are stable (a gap they explain is not
"unreferenced"), and the three repeat until nothing changes. A `phase2` line with the summary closes the report.

J1, F1-F4, G1/U1 and C1 have analysis options (on by default).

## WSMachine

A deterministic probe, not a player: it exposes what code runs, with which segment registers,
what is DMA'd from where, and who writes VRAM. Construct with a program imported by the loader.

Modelled:
- **Entry state** (boot ROM skipped): CS:IP = FFFF:0000 (runs the footer JMP), registers per
  WSdev Boot_ROM (SOURCE-CONFLICT with Mesen 2 recorded in `WSHardware`), port A0 = 0x80 |
  (footer flags & 0x0C) | colour | 1, other entry ports, colour palette RAM = 0xFF.
- **Banking**: C0–C3 plus 2003-mapper aliases CF, D0–D5 (16-bit ROM0/ROM1/SRAM banks).
- **I/O**: the language's `io` space. Constant-port IN/OUT compile to plain io varnodes (not
  LOAD/STORE), so the machine scans each instruction's p-code: io inputs get the port value first,
  io outputs go to the port logic after; DX-port forms use the load/store callbacks.
- **CPU glue**: `csval` (decoder context) is synced from the CS register after far transfers
  (`CALLF JMPF RETF IRET INT INT3 INTO`), CPU exceptions and injected interrupts; the decode
  context also gets `hwundef=1` (hardware-faithful undefined opcodes) and `colorsoc` = the
  machine's SoC (MUL's ZF) at construction. Userops: `swi` (INT n / INT3 / INTO / BOUND entry),
  `divtrap` (DIV/IDIV/AAM 0 divide error: INT 0 entry, pushed IP = next instruction, PC
  redirected), `halt` (HLT), `segment`, LOCK/UNLOCK no-ops.
- **Interrupt controller** (WSdev Interrupts): B2 enable mask; B4 status latch (read-only);
  B6 write = acknowledge (clear bits); B0 write = vector base, B0 read = base | highest requested
  level. Edge sources (line match 4, VBlank timer 5, VBlank 6, HBlank timer 7) set their B4 bit
  only if enabled at that moment; the level source UART send ready (0) re-sets its bit while the
  UART (B3 bit 7) and B2 bit 0 are enabled, so an acknowledge does not clear it then.
- **CPU interrupt rules** (checked at each instruction boundary): the highest requested level is
  taken when IF=1, pushing the address of the next instruction to run (for an interrupted REP
  string instruction: its first prefix). One-instruction shadow after STI / POPF / IRET that set
  IF, after POPF / IRET that set TF (also delays the trap), and after MOV SS / POP SS (SS only;
  SOURCE-CONFLICT with STSWS "any sreg", resolved by the datasheet, WSdev and ws-test-suite).
  **HLT** stops execution until B4 ≠ 0 — also with IF=0, then execution simply continues after
  the HLT; the rest of a line is skipped while halted (`haltedLines`, not counted in
  `instructions`). **TF**: after each instruction that ran with TF=1 (and did not just set it),
  INT 1 with the IP of the next instruction.
- **Timers** (A2 control, A4/A6 reload, A8/AA counters; WSdev Timers): the HBlank timer ticks at
  every line start, the VBlank timer at line 144; the IRQ (7 / 5) is requested when the counter is
  1 at a tick (also when counting is disabled), then an enabled counter counts down and reloads
  in repeat mode. Writing a reload value also loads the counter.
- **UART** (B1/B3): an attached peer uses timed one-byte buffers and send/receive level interrupts
  (see Link mode). Detached output is instant (`serialOut`), with no reception and TX-empty while enabled.
- **Timing**: by default a frame = `slice` instructions over 159 lines (144 visible). Port 02 = current
  line; line-match IRQ (level 4) at line = port 03; VBlank IRQ (level 6) at line 144. Display ports are
  snapshotted per visible line for raster effects. Instruction-count frames drift against hardware in
  instruction-mix-heavy scenes. With `cycleTiming` set (`WSEmulate` `cyc=1`), instructions cost V30MZ
  cycles (`WSCpuTiming`: prefetch queue, bus waits) and lines (256 cycles), timers, the channel-3 sweep,
  the channel-4 noise generator and sound DMA run by cycles.
- **General DMA** (40–48): word-alignment and 20-bit masks, refusal of SRAM / slow / 8-bit ROM sources
  (at start and mid-transfer), direction; the CPU stall is charged in cycle-timed mode.
- **Sound DMA** (4A–52): 20-bit source/length with shadow reloads, hold, repeat, rate and direction;
  transfers run in cycle-timed mode (one byte per rate slot, with the CPU steal).
- **Keypad** (B5, scripted via `buttons`).
- **EEPROMs** (`WSEeprom`, WSdev EEPROM): the internal one (BA–BE; 16 Kbit on colour hardware, taking
  1 Kbit-form commands while colour mode is off; 1 Kbit on mono) and the cartridge one (C4–C8; size from
  the footer save type). Serial commands READ / WRITE / ERASE / WRAL / ERAL / WEN / WDS, separate read
  and write buffers, control-port validity rules, status done/ready bits with the 2001-mapper done-bit
  erratum, sticky internal write protection (words ≥ 0x30), write-disabled cartridge EEPROM at power-on.
  Operations take a few instructions. Initial contents: cartridge erased (FF); internal zero-filled (no
  source documents a console's contents; load a dump of a real one if needed). Every operation and every
  refused request is logged (`log`, `operations`, `refused`).
- **SRAM** in the 1000:0000 window (bank port C1, mirrored to the footer's SRAM size).
- **RTC** (`WSRtc`, 2003-family cartridges): the $CA/$CB serial command protocol (status, date+time,
  time, alarm, reset and nonsense commands with ready/busy status bits) over an S-3511A register
  model (BCD validation, 12/24-hour modes, power-failure bit). Time comes from a configurable clock,
  fixed by default for reproducible runs, and advances with the emulated frames. The alarm output
  pin is not modelled.
- **Self-flash window** ($CE, 2003-family): on flash cartridges a NOR flash (`WSFlash`: JEDEC byte
  program, chip/sector erase and ID sequences plus the fast program mode, completing instantly; the
  programmed bytes are visible in every ROM window), on masked-ROM cartridges the ROM read-only.
- **KARNAK** (`WSKarnak`, Pocket Challenge V2 images): the ADPCM decoder ($D6 control, $D8 nybble
  writes top-first, $D9 PCM reads, hardware-verified step tables and saturation) and the $D6 timer,
  which raises the cartridge interrupt on expiry (wiring inferred, not hardware-verified).
- **Save images**: `loadSaves(dir)` / `writeSaves(dir)` with `internal.eeprom`, `cart.eeprom`, `cart.sram`,
  `cart.flash`, `cart.rtc`; sizes are checked.
- **Hooks** for test harnesses: `beforeStep` (called before each instruction, after interrupt
  entry) and `onFault` (called when a step throws; return true to continue). `memoryWatch` (optional) observes every
  CPU load and store to the ram space with the instruction address and value, at no cost when unset. `trace` (last 64
  instructions) is filled when `run()` returns or throws.

Not modelled: audible sound output, the RTC alarm output, NMI (low battery), open-bus values (a
missing SRAM reads 0). Cycle timing is optional and not validated as cycle-exact for every instruction
mix.

EEPROM validation: ws-test-suite `mono/eeprom/internal`, `cartridge_1kbit` and `cartridge_16kbit` pass every
row (10/9/9), matching Mesen 2.

Diagnostics: `windowBanks` (every bank each ROM0/ROM1-window address executed under; evidence rule B1),
`trace` (last 64 instructions), `stopAt` (linear PC), `firstTrace` (first N steps,
Mesen `trace.tsv` format; REP instructions recorded once), `irqStats`, `accessStats`,
`bankWrites`, `dmaLog`, `vramFirstWriter` / `vramWriterBytes`.

## WSRender

Follows the WSdev wiki `Display*` pages: layer order (background, screen 1, low sprites,
screen 2, high sprites), screen-2 and sprite windows (inclusive), sprite priority/window side, colour-0
transparency rules, background colour port, colour 2bpp / 4bpp planar / packed and mono shades.
Each line uses that line's port snapshot. Not modelled: mid-line changes, 32-sprites-per-line,
delayed sprite-table copy, LCD icons and LCD colour response (Mesen applies an LCD tint).

## WSEmulate

```
WSEmulate.java <outdir> [frames=1500] [insns/frame=40000] [stopAt linear hex | -] [shotEvery=100]
               [saves dir to load | -] [input script file | -] [environment | -]
```

The environment argument is a comma-separated `key=value` list:

| Key | Meaning |
|---|---|
| `hp=0\|1` | headphone adapter connected (port 91 bit 7; default 1) |
| `eep=XX` | blank cartridge EEPROM fill byte (hex; default FF as delivered) |
| `owner=NAME[:volume]` | console owner data in the internal EEPROM (default blank) |
| `cyc=0\|1` | cycle-timed lines, timers and interrupts instead of `insns/frame` instructions per frame (default 0) |
| `trace=FROM[:N]` | record `trace.tsv` from logical step FROM (1-based; REP iterations count once) for N steps (default 1:20000) |
| `sig=0\|1` | write `framesig.tsv`: per frame the logical steps so far, the cycle count and the sum of executed linear addresses |
| `model=mono\|color` | console to emulate (default: the loader's choice from the footer / extension) |

Unknown keys are an error.

Default input: Start on frames f ≥ 100 with f % 40 < 3, A on 20 ≤ f % 40 < 23 (use the same
script in the reference emulator when comparing). An input script replaces it: one `from to buttons`
line per span (inclusive frames; buttons hex as `WSMachine.buttons`; `#` comments). Also writes `saves/`
(the save images after the run) and `eeprom.log` (EEPROM operations and refused requests). Writes `coverage.json` (linear, rom_off, CS, DS/ES sets; `banks` for ROM0/ROM1-window code), `trace.tsv` (first
20,000 steps), `edges.tsv` (observed call / jump / interrupt edges with target CS and count), `irqlog.tsv` (interrupt
requests inside the trace window: step, level, line, cycle in line, latched), `banks.json` (bank writes,
DMA log, error), `ram.bin`, optionally `framesig.tsv` (`sig=1`), and per `shotEvery` frames
`shot_N.png`, `ports_N.bin`, `ram_N.bin`. Use `insns/frame` = Mesen instructions ÷ frames to align
with a reference run.

## Asset viewer

`WSAssetPlugin` (GUI, *WS Asset Viewer*) shows bytes as tiles (source, format,
palette, width, arrangement) or tilemaps, and — when the program
is a WonderSwan cartridge the emulator supports — VRAM, palette RAM and the
sprite table from a `WSMachine` run, with PNG export. Tile sources are the
listing cursor/selection, a ROM file offset (stored ROM image, unmapped banks
included, with step/page scrolling and a cursor-offset shortcut), or the last
*Decompress here* output. Tiles group into 8x8, 8x16, 16x16 row/column-major,
or custom WxH cells. *Decompress here* runs a registered `WSCodec` on the
listing or ROM bytes; the extension ships the interface only.

Headless equivalent:

```
WSAssetExport.java <outdir> [frames=300] [insns/frame=15000]
```

Writes `screen.png` (also verified pixel-identical between the machine and
snapshot compose paths), `tiles_2bpp.png`, `tiles_4bpp.png` (colour hardware),
`layer_scr1.png`, `layer_scr2.png`, `palettes.png`, `sprites.tsv`, `summary.txt`.

## Debugger

Run a cartridge inside Ghidra with breakpoints, instruction and frame stepping, memory watches,
register and memory views, and a live screen, from the Debugger tool (the plugin also loads in
the CodeBrowser once the Debugger services are added to it).

| Piece | Role |
|---|---|
| `WSEmulatorFactory` | Emulator factory: *Emulate Program* builds a `WSMachine` for the program behind the trace (resolved through the static mappings) and returns its trace-attached emulator, so the run has real I/O, interrupts, timers, DMA, banking and EEPROMs. Anything else falls back to the default emulator. |
| `WSDebuggerEmulator` | The machine every `WSMachine` runs on. Standalone it behaves exactly like a `PcodeEmulator`; bound for debugging, each step also runs the interrupt boundary, the single-step trap and the display-line advance (mirroring `WSMachine.run` step for step), and every state write is forwarded to the trace writer. Restores registers, RAM, windows and ports when the service re-emulates from a mid-trace snapshot (timers, interrupt latch and EEPROM internals reset; see below). |
| `WSDebuggerPlugin` | Debugger plugin with three parts, all following the emulation the service has cached for the current trace: |

- *WonderSwan Screen* (Window → *WonderSwan Screen*): the current frame via `WSRender`, refreshed whenever emulation stops, plus a Refresh button. It renders the live emulated state; moving through trace history without emulating keeps the last live frame.
- *WonderSwan Input* (Window → *WonderSwan Input*): press-and-hold controller buttons (X/Y pads, START, A, B) feeding the emulated key port live.
- *Debugger → Step Frame (VBlank)*: runs to the next VBlank entry (VBlank raised, handler about to run). Breakpoints still stop the run first.
- *Debugger → Run N Frames...*: asks for a frame count and runs that many frames in one cancellable task. Breakpoints still stop the run first.

Usage: open the program in the Debugger tool, enable the *WonderSwan Debugger* plugin in the
tool config if needed, select *WonderSwan Concrete P-code Emulator* under Debugger → Configure
Emulator, then Emulate Program (or step/run from the control panel) and open the screen/input
windows. Set instruction breakpoints in the listing and data breakpoints in the memory view as
usual; `WSMachine.stopAt` also still throws when reached.

Notes and limits:

- Emulation always starts from the cartridge entry state, wherever the cursor is; starting
  mid-ROM without hardware initialisation is meaningless, so the first step corrects the trace
  position to the entry.
- One CPU, one thread: extra emulated threads are refused with an error.
- Stepping back shows recorded history. Stepping forward again after stepping back (or after
  cache eviction/invalidation) re-emulates from a snapshot with approximated peripherals: code,
  RAM, registers and banks are restored, but timer counters, pending interrupts, EEPROM command
  state and the halted state reset, so the re-run may drift from the recorded run. Long
  uninterrupted runs (frame stepping, run-to-breakpoint) are unaffected.
- P-code stepping advances no peripherals; they catch up on the next instruction step.

Manual GUI smoke test (no headless equivalent): import a test ROM, select the WonderSwan
emulator, Emulate Program, then step once and check the position corrects to the cartridge entry
with `CS` = `FFFF`; step a few more instructions and watch registers change; set an execute
breakpoint a little ahead and Resume to it; Step Frame and check the screen paints and the line
port reads 144 (`0x90`); hold START in the input panel, step through a key-port read and check
the button bit arrives; step back and forward once and confirm the position stays sane.

Headless coverage (a factory check run as a Ghidra script against
an imported test ROM): factory registration and fallback, N-frame identity with `WSMachine`
(RAM, registers, ports, serial bytes, IRQ/access stats, evidence, first trace, rendered
pixels), frame-step landing/determinism/cross-checks, and a trace record/restore round-trip.

## GUI smoke test

`WSGuiSmoke` (`src/test/java/.../WSGuiSmoke.java`, run via `./build.sh :wonderswan:guiTest`)
is the headed counterpart: it creates a tool, imports a small synthetic ROM (generated
in-memory, no game data), adds `WSAssetPlugin` and `WSDebuggerPlugin` (with the debugger
service plugins), shows each provider (`WS Asset Viewer`, `WonderSwan Screen`,
`WonderSwan Input`), and asserts no exceptions, every provider registered exactly once,
the menu actions present (`Show Asset Viewer`, `WS Decompress Here`, `Step Frame (VBlank)`),
the Tiles tab rendering a ROM-offset view, the emulator factory registered, re-registration
(remove + add again) working, and a clean close. A double registration (the shipped
"ComponentProvider WS Asset Viewer was already added" bug: provider added in both the
constructor and `init()`) fails the test at the add step.

It needs a display and the `v30mz` extension. The reproducible path is the container
(`wonderswan/gui-test/Dockerfile`: JDK 21 + Xvfb, Ghidra mounted read-only):

```sh
docker build -t ghidra-ws-guitest wonderswan/gui-test
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/work/build/gui-home \
  -v /opt/ghidra_12.1.3_PUBLIC:/opt/ghidra_12.1.3_PUBLIC:ro -v "$PWD":/work ghidra-ws-guitest
```

Run it as your own user (as above): the repo is mounted read-write, and a root container would leave root-owned
build files behind that break the next normal build.

`wonderswan/gui-test/run.sh` (the image entrypoint) builds `v30mz`, installs it to an
isolated `XDG_CONFIG_HOME`, and runs `guiTest` under `Xvfb` (started directly; `xvfb-run`
hangs as PID 1 in containers). Outside the container it uses `DISPLAY` when `Xvfb` is
absent (local use only, not for CI); plain `./build.sh :wonderswan:guiTest` needs a display
and `v30mz` already installed. The task is intentionally not part of `check`.

## Mesen 2 execution traces

`WSMachine` is a reimplementation; Mesen 2 is the reference WonderSwan emulator. Where it
reaches code the built-in emulator misses (unmodelled hardware, divergence), a Mesen recording
of the same cartridge imports as execution evidence and feeds the same rules: E1 executed code
(instruction starts with the observed CS), E2 call entries, E3 observed jump targets, B2 bank
overlays with B3 window flows, and J1's observed-target checks. The import is optional and off
by default; rule `mesen` report lines record what it contributed (inputs, CS sources, mapping
skips, transfer resolution), and E2/E3 lines it produced carry `"src":"mesen"` (or `"mixed"`).

Supported Mesen version: Mesen 2 at commit `b9fa69d` (see `tools/mesen2/Dockerfile`).

### Recording

```sh
tools/mesen2/run-trace.sh game.wsc /tmp/gametrace [frames=1500] [trace_n=20000] [shot_every=100]
```

runs the cartridge headless in Docker (see `tools/mesen2/README.md`, also for recording in the
Mesen UI). The scripted Start/A input matches `WSMachine`, so traces stay comparable. A
long-play `.cdl` recorded in the Mesen UI (debugger enabled) imports the same way.

### Importing

- At analysis time: Analysis Options → *WonderSwan Execution Evidence* → *Mesen trace
  directory or CDL file*. The path is a trace directory (`trace.tsv` + `coverage.tsv`, plus a
  `.cdl` when exactly one is present), a lone `.tsv`'s directory, or a `.cdl` file. It merges
  with `WSMachine` evidence when that also runs (Mesen CS wins conflicts), or stands alone when
  *Run WSMachine* is off. A bad path warns and keeps `WSMachine` evidence.
- Headless into an analyzed program:

```
WSImportTrace.java <mesen evidence path> [<WSEmulate dir for CS fallback> | -] [<report file>]
```

### Formats

`trace.tsv`: one line per executed instruction for the first N steps (tab-separated):
`n cs ip ax bx cx dx si di bp sp ds es ss flags [c0 c1 c2 c3]` (`n` decimal; registers
4 hex digits; the trailing bank registers 2 hex digits, absent from older logs). Linear
address = `(cs * 16 + ip) & 0xFFFFF`; REP string instructions are recorded once.

`coverage.tsv`: one line per executed linear address over the whole run, no header:
`linear count ds-list es-list [banks]` (`linear` hex, `count` decimal, DS/ES comma-separated
4-hex-digit sets sampled over the first 64 visits). The `banks` column holds the bank register
relevant to the address's window (`C0:ff`, `C2:f2,ff`, …; absent from older logs); bank-window
addresses record their bank on every visit, so their sets are exact.

`trace.cdl` / `*.cdl`: Mesen's `CDLv2` format: `"CDLv2"` + 4-byte little-endian CRC32 of the ROM
+ one flag byte per ROM byte (index = ROM file offset): Code `0x01`, Data `0x02`, JumpTarget
`0x04`, SubEntryPoint `0x08`. Headerless raw flag files are accepted with a warning, as in Mesen.

### Address mapping

CS per address comes from the trace first, then `WSMachine` coverage (live run, `WSEmulate`
directory, or the script's fallback argument), then the bank-aligned guess
`(linear & 0xF0000) >> 4`. Linear-window code seeds only when it ran with the loader's C0 =
0xFF (older logs without bank columns assume that mapping); bank-window code only with observed
banks; SRAM has no program bytes and is reported, not seeded. CDL bytes seed only their
unambiguous linear image, and only when they are known instruction starts (jump targets and
sub-entries; plain code bytes are mostly instruction operands, which must never seed). With a
trace or coverage alongside, a CDL seed additionally needs the address to have executed there
under the loader mapping. CDL sub-entries become call targets (E2); mirrored, window-only and
declined bytes are reported, not guessed. Trace transfers
(consecutive steps) resolve against the disassembled sources: fall-through flows, direct
branches and returns are dropped (static analysis follows them), computed calls/jumps and INTs
become edges, and straight-line discontinuities become interrupt entries.

Parsers are lenient (malformed lines are skipped and counted) and dependency-free:
`wonderswan/tests/run.sh [sampledir]` unit-tests them against synthetic logs (plus a real trace
directory when given).
