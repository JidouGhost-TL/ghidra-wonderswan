# Sources

The V30MZ language and the WonderSwan module were built from the sources below. Citation keys used in
[`V30MZ-SPEC-NOTES.md`](V30MZ-SPEC-NOTES.md) and in the SLEIGH comments are given in brackets. Line-number
citations refer to plain-text renderings of these documents (PDFs via `pdftotext`, wiki pages as raw
wikitext), fetched 2026-10-02.

GPL and unlicensed sources were read as references only; no code was copied from them. Ghidra's x86 SLEIGH
(Apache-2.0) is the basis of the V30MZ port, with attribution kept in the language files.

## CPU

| Key | Source | Licence / status |
|---|---|---|
| `DS` | NEC V30MZ Preliminary User's Manual / datasheet (1998), https://www.ardent-tool.com/CPU/docs/NEC/V20-V30/v30mz.pdf; Renesas reprint A13761EJ1V1UM00 | NEC/Renesas documentation |
| | NEC 16-bit V Series Instruction User's Manual U11301E (1997), archive.org `bitsavers_necdatabooBITVSeriesJun97_693718` | NEC documentation |
| `ST` | STSWS WonderSwan technical reference, http://perfectkiosk.net/stsws.html | reference |
| `WI` `WN` `WF` `WM` | WSdev wiki, NEC V30MZ pages (instruction set, interrupts, flags, overview), https://ws.nesdev.org/wiki/NEC_V30MZ | wiki |
| `CT` `CTR` | WSCpuTest README and test ROM (hardware-verified undefined behaviour and flag results), https://github.com/FluBBaOfWard/WSCpuTest (release v0.7.1; main 71d9d30) | no licence; used as a test oracle |
| `IA` | Ghidra `x86` processor, `ia.sinc` (Ghidra 12.1.3) | Apache-2.0 |
| `AV` `AVM` | ARMV30MZ (FluBBaOfWard) @ 146f5fb; NitroSwan `source/Memory.s` @ 564e171 | all rights reserved; reference only |
| | ares `component/processor/v30mz` @ 4cb8d92 (incl. commit 4b43bbf, F7 /1 fix) | ISC |
| | Mesen 2 `Core/WS/WsCpu` @ b9fa69d | GPL-3.0; reference only |

Analysis of the undefined encodings, with per-source verdicts: [`V30MZ-UNDEFINED-ENCODINGS.md`](V30MZ-UNDEFINED-ENCODINGS.md).

## WonderSwan hardware

| Source | Used for | Licence / status |
|---|---|---|
| WSdev wiki, https://ws.nesdev.org/wiki/WSdev_Wiki (Memory map, I/O ports, Mapper, Bandai 2001/2003, ROM header, Boot ROM, SoC, Display, Interrupts, Timers, UART, EEPROM, DMA, Sound) | memory map, port table, entry state, emulator hardware model, renderer | wiki |
| WSMan rev.7 (trap15), http://daifukkat.su/docs/wsman/ | cross-check | reference |
| ares WonderSwan core | 2003-mapper port map, bank decode | ISC |
| Mesen 2 | reference emulator for differential testing (traces run in a container) | GPL-3.0; not linked |
| nileswan documentation | mapper / boot cross-check | GPL-3.0; reference only |

## Test ROMs (hardware oracles)

| ROM | Source | Licence |
|---|---|---|
| WSCpuTest | https://github.com/FluBBaOfWard/WSCpuTest | no licence |
| ws-test-suite | https://github.com/asiekierka/ws-test-suite | MIT |
| WSHWTest, WSTimingTest | https://github.com/FluBBaOfWard/WSHWTest, https://github.com/FluBBaOfWard/WSTimingTest | no licence |
| MiSTer test ROMs (sprite priority, windows, timing) | Robert Peip, https://github.com/MiSTer-devel/WonderSwan_MiSTer (`testroms/`) | GPL-2.0 |

## Compilers (calling conventions)

| Source | Used for |
|---|---|
| LSI C-86 3.30c (試食版) | `__lsic86` prototype, verified on the compiler's own output |
| Wonderful Toolchain documentation, https://wonderful.asie.pl/ | homebrew gcc-ia16 ABI (reference; commercial titles predate it) |
