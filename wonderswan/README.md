# wonderswan — WonderSwan platform module for Ghidra 12.1.3

Package `jidoughost.wonderswan`. Requires the `v30mz` extension (language `V30MZ:LE:16:default`).

| Class / script | Role |
|---|---|
| `WonderSwanLoader` | Cartridge loader (*WonderSwan Cartridge*) |
| `WSHeader` | Footer parse + checksum |
| `WSHardware` | Memory map, bank mapping, port names, entry state — single source of truth |
| `WSMachine` | Headless emulator on Ghidra's `PcodeEmulator` |
| `WSRender` | Screen renderer (diagnostic) |
| `WSEvidenceAnalyzer` | Auto-analysis phase 1: runs `WSMachine` (or loads WSEmulate output) and seeds code from execution evidence |
| `WSEvidenceRepairAnalyzer` | Auto-analysis phase 2: checks Ghidra's results against the same evidence; jump tables; calling convention |
| `WSJumpTables` | Rule J1 (used by phase 2) |
| `ghidra_scripts/WSEmulate.java` | Runs `WSMachine` on the current program and writes evidence files |

## Loader

Detects a cartridge by its 16-byte footer (power-of-two size, `EA` far JMP); the load spec is
preferred when the footer checksum verifies. Load specs: `V30MZ:LE:16:default` (preferred) and
`x86:LE:16:Real Mode` (comparison only; no csval/io setup).

| CPU address | Block | Notes |
|---|---|---|
| `0000:0000` | `RAM` | 64 KiB colour / 16 KiB mono, zero-filled; labels IVT, TILES_2BPP, TILES_4BPP, PALETTES |
| `1000:0000` | `SRAM` | uninitialised, volatile (bank port C1) |
| `2000:0000`, `3000:0000` | `ROM0_WINDOW`, `ROM1_WINDOW` | uninitialised, volatile, not executable (ports C2/C3) |
| `4000:0000`–`F000:FFFF` | `LIN_4000` … `LIN_F000` | twelve 64 KiB blocks from FileBytes through C0 = 0xFF; small ROMs mirror |
| `io:0000`–`io:00FF` | `IO` | ports, labelled (`KEYPAD`, `BANK_ROM0`, …), byte/word typed, volatile |

Also: `WSCartridgeFooter` structure at `F000:FFF0`, an external entry + one-address `reset`
function at the reset vector (Ghidra's entry-point analyzer skips *named* entries otherwise),
`csval` context = reset segment at the entry, `DS`/`SS` = 0 and, for colour cartridges, `colorsoc` = 1
(MUL sets ZF on the colour SoC; a colour cartridge only runs there) over the ROM, header facts under
Program Options → *WonderSwan*.
The whole ROM is stored as FileBytes so analyzers can add banks as overlays later.

Hardware model (`Color` option): colour when the footer flag is set **or** the file is a `.wsc` (colour releases
with footer flag 0 exist; `Color source` and `Footer color flag` record which). It sets RAM size, `colorsoc`,
and the machine every tool emulates.

Not yet: non-power-of-two ROM padding, 2003-mapper flash/RTC. Bank overlays are created by the
evidence analyzer (rule B2), not the loader.

## Evidence analyzers

Every decision can be written to a JSON-lines report (analysis option *Evidence report file*).

| Rule | Phase | What |
|---|---|---|
| B2 | 1 | Code executed in the ROM0/ROM1 windows: one overlay block per (window, bank) observed (`ROM0_BANK_xxxx`, from FileBytes), seeded like linear code; a window address that ran under several banks is seeded in each |
| E1 | 1 | Executed address = instruction start, `csval` = observed CS |
| E2 | 1 | Call / interrupt edge target = function entry |
| E3 | 1 | Computed jump: observed targets as references + JumpTable override |
| N1 | 2 | Clear "does not return" where a call's fall-through executed |
| E1R | 2 | Re-seed executed code later analysis removed |
| J1 | 2 | CS-relative jump/call tables: backward slice for base + index bound (mask = upper bound, CMP/JA), stop rules EXECUTED_CODE / TABLE_BOUNDARY / OUT_OF_ROM / MID_INSTRUCTION / DEFINED_DATA / SELF; observed targets must be a subset (missing ones added and reported); overlay sites resolve within their overlay |
| D0 | 2 | Title DS default: if one DS ≠ 0 covers ≥ 50 % of executed addresses that ran with a single DS, it replaces the loader's DS = 0 default over the ROM (LSI C-86 titles run with DS = 1000, SRAM) — `WSCompilerRules` |
| P1 | 2 | Functions whose entry has no bytes (phantoms) removed, reported with their creating references |
| J1f/g/h | 2 | Table ends at another CS table's base (TABLE_BASE); computed refs not in a proven table are superseded; code decoded only from superseded refs is cleared (bytes kept) and proven targets re-flowed |
| D1 | 2 | DS context at entries with one non-zero observed DS |
| A1 | 2 | Unexecuted fall-through runs ending in a bad decode: decode cleared, bytes kept, bookmarked |
| K1 | 2 | Compiler family from the program's own code (`WSCompilerRules`): LSI C-86 when functions with its frame save order (`PUSH BP; MOV BP,SP [; SUB SP,n]; PUSH CX/DX…`) are ≥ 10 % of ROM functions and stack-argument functions (`[BP+4..0x3f]`) ≤ 20 % (calibrated on the licensed library: 28/29 LSI titles, 0 false positives) |
| C1 | 2 | Functions without a user/imported signature get `__lsic86` when K1 says LSI C-86, else the compiler spec's default (`__wsasm`) |

Each phase-2 rule runs on its own: a rule that throws is reported (analysis log, `Msg.error`, an `ERROR` line
`{"rule":…,"outcome":"ERROR"}` in the report, an error bookmark) and the remaining rules still run; the summary line
ends with `RULES FAILED: [...]`.

J1 and C1 have analysis options (on by default).

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
- **UART** (B1/B3): transmitting is instant (bytes collected in `serialOut`), nothing is received;
  B3 reads enable/speed and TX-empty while enabled.
- **Timing**: a frame = `slice` instructions over 159 lines (144 visible). Port 02 = current line;
  line-match IRQ (level 4) at line = port 03; VBlank IRQ (level 6) at line 144. Display ports are
  snapshotted per visible line for raster effects. Instruction-count based, not cycles, so frames
  drift against hardware in instruction-mix-heavy scenes (cycle timing is a B item).
- **DMA** (40–48), keypad (B5, scripted via `buttons`).
- **EEPROMs** (`WSEeprom`, WSdev EEPROM): the internal one (BA–BE; 16 Kbit on colour hardware, taking
  1 Kbit-form commands while colour mode is off; 1 Kbit on mono) and the cartridge one (C4–C8; size from
  the footer save type). Serial commands READ / WRITE / ERASE / WRAL / ERAL / WEN / WDS, separate read
  and write buffers, control-port validity rules, status done/ready bits with the 2001-mapper done-bit
  erratum, sticky internal write protection (words ≥ 0x30), write-disabled cartridge EEPROM at power-on.
  Operations take a few instructions. Initial contents: cartridge erased (FF); internal zero-filled (no
  source documents a console's contents; load a dump of a real one if needed). Every operation and every
  refused request is logged (`log`, `operations`, `refused`).
- **SRAM** in the 1000:0000 window (bank port C1, mirrored to the footer's SRAM size).
- **Save images**: `loadSaves(dir)` / `writeSaves(dir)` with `internal.eeprom`, `cart.eeprom`, `cart.sram`;
  sizes are checked.
- **Hooks** for test harnesses: `beforeStep` (called before each instruction, after interrupt
  entry) and `onFault` (called when a step throws; return true to continue). `memoryWatch` (optional) observes every
  CPU load and store to the ram space with the instruction address and value, at no cost when unset. `trace` (last 64
  instructions) is filled when `run()` returns or throws.

Not modelled: sound, sound DMA (4A–52), GDMA register masks/refusals/timing, RTC, NMI (low battery),
cycle timing, open-bus values (a missing SRAM reads 0).

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
               [saves dir to load | -] [input script file | -]
```

Default input: Start on frames f ≥ 100 with f % 40 < 3, A on 20 ≤ f % 40 < 23 (use the same
script in the reference emulator when comparing). An input script replaces it: one `from to buttons`
line per span (inclusive frames; buttons hex as `WSMachine.buttons`; `#` comments). Also writes `saves/`
(the save images after the run) and `eeprom.log` (EEPROM operations and refused requests). Writes `coverage.json` (linear, rom_off, CS, DS/ES sets; `banks` for ROM0/ROM1-window code), `trace.tsv` (first
20,000 steps), `banks.json` (bank writes, DMA log, error), `ram.bin`, and per `shotEvery` frames
`shot_N.png`, `ports_N.bin`, `ram_N.bin`. Use `insns/frame` = Mesen instructions ÷ frames to align
with a reference run.
