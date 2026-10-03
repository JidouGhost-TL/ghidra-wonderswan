# V30MZ undefined encodings: lengths and semantics (verified 2026-10-02)

This note settles the encodings that `v30mz/data/languages/v30mz_hwundef.sinc` used to mark
UNRESOLVED or leave undecoded. A user-supplied research note made a set of claims about them.
Each claim was checked against the primary sources listed below. The SLEIGH changes are in
`v30mz_hwundef.sinc`; the test results are in `v30mz/README.md`.

`D` is the normal 16-bit ModRM displacement length: mod=00 with r/m=110 gives 2, mod=01 gives 1,
mod=10 gives 2, and every other case gives 0.

## Sources

| Key | Source | Pinned at | Licence | Use |
|---|---|---|---|---|
| AV | `FluBBaOfWard/ARMV30MZ` `ARMV30MZ.s`, `ARMV30MZmac.h` (+ `.h .i`, History, README). | `146f5fb4d664f8874792299d3a6e4bd8415df287` (2026-07-23) | **None.** No LICENSE file; GitHub reports no licence; headers say "Copyright © 2021-2025 Fredrik Ahlström. All rights reserved." | Factual reference only. No code copied. |
| AVM | `FluBBaOfWard/NitroSwan` `source/Memory.s`, which defines `v30ReadEAW` and the other EA read/write helpers that AV calls. | `564e171fb93c2c11f98f38607493675727676c2c` | None ("All rights reserved") | Factual reference only |
| MS | Mesen2 `Core/WS/WsCpu.cpp` / `WsCpu.h`. (byte-identical to the pinned commit) | `b9fa69ddc6d0a331fb103fdb5eef6904305703c2` | GPL-3.0 | Factual reference only |
| AR | ares `ares/component/processor/v30mz/*.cpp,hpp`. | `4cb8d92b441557cb6bcaf133c4cbc7f6819b1122` | ISC | Reference |
| CT / CTA | WSCpuTest hardware test ROM: README ([CT]) and source `WSCpuTest.asm` ([CTA]) | `71d9d30` | None | Hardware results |

Notes on independence:
- AV and CT have the same author (FluBBa). AV is the emulator he checks against his own hardware
  tests, so where CT tests something, AV and CT are one line of evidence, not two.
- MS and AR are independent implementations. Both are developed against these test ROMs, and
  AR's V30MZ fixes are written by asie with hardware access (for example, ares commit `4b43bbf`,
  "v30mz: fix opcode 0xF7:1 to match hardware").
- The CT test for F6/F7 /1 pads the encoding with `90` (NOP) bytes, so it does not show whether an
  immediate is consumed (see below).

**Verdict rule.** VERIFIED means at least two independent hardware-tested sources agree. Here that
is at least two of {AV(+CT), MS, AR}. The "hardware coverage" column says whether a hardware test
ROM exercises the encoding itself. SINGLE-SOURCE means only one source speaks to it. CONFLICT
means the sources disagree.

## Claims in the research note: outcome

| Claim | Outcome |
|---|---|
| F1: 1 byte, no operand; ARMV30MZ takes the undefined path | **False for ARMV30MZ.** `i_brks` branches to `i_crash`, a debugger hook that stops the CPU loop, not to `i_undefined` (AV ARMV30MZ.s:3503-3507, :4559-4567). MS and AR do treat F1 as a 1-byte no-op. → CONFLICT |
| F6 /1: 2+D with no imm8; F7 /1: 2+D with no imm16; ares v131 "undocumented F7 subop 1" fix | **Confirmed.** AV, MS and AR agree. The ares change is commit `4b43bbf853865d328afa36192be155a780a5d82b` (Adrian Siekierka, 2022-12-27, "fix opcode 0xF7:1 to match hardware"). It replaced "TEST (undocumented mirror)" with an immediate by "undefined (acts as NOP)" with no fetch. The v131 release-number attribution was not checked. |
| 8F /1-7: 2+D, the same as 8F /0 (POP) | **Confirmed** in AV, MS and AR. |
| C6 /1-7: 3+D; C7 /1-7: 4+D (MOV) | **Confirmed** in AV, MS and AR. |
| mod=11 forms of 8D, C4, C5, 62, FF /3, FF /5 are 2 bytes and do odd data reads | **Length confirmed** for all of them. **Semantics:** LEA, LES, LDS and far CALL/JMP use new base+index modes (CT hardware, AV, MS; AR dissents only on far CALL/JMP). BOUND: the sources conflict. |

## Verdict table

`[AV x]` = ARMV30MZ.s line x; `[AVM x]` = NitroSwan Memory.s; `[MS x]` = WsCpu.cpp; `[AR f:x]` =
ares file:line; `[CTA x]` = WSCpuTest.asm.

### F1

| | Length | Semantics |
|---|---|---|
| AV | none defined: `i_brks: b i_crash` ("BRKS, Break to Security Mode. Not working on V30MZ?") [AV 3503-3507]; `i_crash` calls `debugCrashInstruction` and ends the timeslice [AV 4559-4567] | emulator halt (deliberate "unknown") |
| MS | 1 (`case 0xF1: Undefined()` [MS 2112]; `Undefined()` = `Idle()` [MS 812-815]) | 1-cycle no-op |
| AR | 1 (no `case` for F1; the switch falls through after the opcode fetch [AR instruction.cpp:305]) | no-op, 0 cycles |
| CT | "might be BRKS from NEC V25/V35 or at least ... switches the MD flag. This app doesn't test it" [CT:337]; the test is commented out as `db 0xF1, 0x01 ; BRKS` [CTA 8747] | unknown |

**Verdict: CONFLICT.** MS and AR agree on 1 byte, but no hardware test backs it. The
hardware-test author leaves it open and considers a 2-byte BRKS form. **Not decoded in either
mode.**

### F6 /1, F7 /1

| | Length | Semantics |
|---|---|---|
| AV | 2+D: `i_f6pre`/`i_f7pre` read the EA (consuming the displacement) and dispatch to `undefF6`/`undefF7` = `i_undefined`, which fetches nothing more [AV 3551-3561, 3699-3708, 4550-4556] | log, no-op (the operand is read) |
| MS | 2+D: `Grp3ModRm`: `ReadModRmByte()`, `GetModRm()`, then `case 0x01: break; //NOP` [MS 968-985] | no-op (the operand is read) |
| AR | 2+D: `Group3MemImm`: `case 1: wait(1); break; // undefined (acts as NOP)` [AR instructions-group.cpp:38-43] | no-op (the operand is read). AR's *disassembler* still prints an immediate [AR disassembler.cpp:414-415]; that is display only. |
| CT | Test `F6 C8 90` / `F7 C8 90 90`: flags and registers unchanged [CT:339-341], [CTA 8761-8818]. The 90 padding makes the test **length-agnostic**. | no flag/register change (hardware) |
| STSWS | ModRM + displacement; it mentions no immediate, and says no memory is accessed [ST:13950-13953] | no-op |

**Verdict: VERIFIED (2+D, no immediate)** by AV, MS and AR, with AR's hardware-motivated fix.
Hardware coverage: the effect is hardware-tested for mod=11; the length is not, because the
test pads with NOPs. **Semantics: VERIFIED no-op.** The emulators read the operand and discard
it; STSWS says there is no access. The p-code emits no read.

### 8F /1-/7

| | Length | Semantics |
|---|---|---|
| AV | 2+D: `i_popw` pops, reads ModRM, and writes via `v30ModRmRm` (reg) or `v30WriteEAW2` (mem); the reg bits are never tested [AV 1918-1932] | POP r/m16 |
| MS | 2+D: `PopMemory()` [MS 253-259], dispatched for all of 8F [MS 2007] | POP r/m16 |
| AR | 2+D: `instructionPopMem` [AR instructions-exec.cpp:217-222], for all of 8F [AR instruction.cpp:207] | POP r/m16 |
| CT | only tests `8F C0` (/0, POP AX) [CTA 7853-7870] | — |

**Verdict: VERIFIED** (length and semantics) by AV, MS and AR. Hardware coverage: none for
reg≠0.

### C6 /1-/7, C7 /1-/7

| | Length | Semantics |
|---|---|---|
| AV | C6: 3+D, C7: 4+D: `i_mov_bd8`/`i_mov_wd16` decode only mod and r/m, and always fetch the immediate [AV 3041-3082] | MOV r/m,imm |
| MS | 3+D / 4+D: `MoveImmediate<T>()`: ModRM, `ReadImmediate<T>()`, `SetModRm` [MS 1148-1153] | MOV r/m,imm |
| AR | 3+D / 4+D: `instructionMoveMemImm<size>` [AR instructions-move.cpp:45-48] | MOV r/m,imm |
| CT | not tested | — |

**Verdict: VERIFIED** (length and semantics) by AV, MS and AR. Hardware coverage: none.

### mod=11 effective address (shared by LEA, LES, LDS, far CALL/JMP; BOUND in AV only)

With mod=11 there is no displacement. r/m selects a new base+index mode. All four sources give
the same table:

| r/m | address | default segment |
|---|---|---|
| 0 | BX+AX | DS |
| 1 | BX+CX | DS |
| 2 | BP+DX | SS |
| 3 | BP+BX | SS |
| 4 | SI+SP | DS |
| 5 | DI+BP | DS |
| 6 | BP+SI | SS |
| 7 | BX+DI | DS |

Sources: [CT:291-305] (hardware), [AV 4310-4380] `EA_300`-`EA_307`, [MS 633-654]
`LdsLesLeaModRm`, [AR modrm.cpp:11-25] `modRM(forceAddress=true)`. A segment override replaces
the default in all three emulators. STSWS's "LEA r,r behaves like MOV" [ST:5009-5011] is
contradicted by the hardware test.

### 8D LEA, mod=11

| | Length | Semantics |
|---|---|---|
| AV | 2: `i_lea` calls the EA table for every ModRM value [AV 1878-1890] | r16 = offset of the new mode |
| MS | 2: `LEA()` → `LdsLesLeaModRm()` [MS 679-684] | same |
| AR | 2: `instructionLoadEffectiveAddressRegMem` → `modRM(true)` [AR instructions-move.cpp:66-70] | same |
| CT | `8D C8`..`8D CF`: all 8 modes checked on hardware, with the next instruction right after the 2 bytes [CTA 7646-7830] | same |

**Verdict: VERIFIED** (length and semantics); hardware-tested.

### C4 LES, C5 LDS, mod=11

| | Length | Semantics |
|---|---|---|
| AV | 2: `i_les_dw`/`i_lds_dw` → `v30ReadEAW` (EA table) [AV 3009-3039], [AVM 214-219] | r16 = word [ea]; ES/DS = word [ea+2] |
| MS | 2: `LoadSegment()` [MS 656-677] | same |
| AR | 2: `instructionLoadSegmentMem` → `modRM(true)` [AR instructions-move.cpp:72-77] | same |
| CT | `C4 D8`..`DF` and `C5 D8`..`DF`: all 8 modes on hardware [CTA 7957-8550] | same |

**Verdict: VERIFIED** (length and semantics); hardware-tested.

### FF /3 far CALL and FF /5 far JMP, mod=11 (and the FE /3, /5 aliases)

| | Length | Semantics |
|---|---|---|
| AV | 2: `callFarFFReg`/`braFarFFReg` → `v30ReadEAW` [AV 3992-4033]. FE /2-/6 go through `contFF`, so the FE forms behave the same [AV 3905-3910, 3944-3951] | far CALL/JMP through the new mode. **CALL: reads the offset, then pushes CS and IP, then reads the segment.** |
| MS | 2: `Grp45ModRm` case 3 and case 5 → `LdsLesLeaModRm()` [MS 1014-1046]. FE uses the same code [MS 2125] | same, but **CALL pushes CS and IP first, then computes the address (r/m=4 sees SP-4) and reads** |
| AR | 2: `Group4MemImm` case 3 and case 5 call plain `modRM()` [AR instructions-group.cpp:54-90] | **uses the r/m register as both the offset and the segment** |
| CT | `FF D8` (CALLF) and `FF E8` (JMPF) [CTA 8883-8963]: BX is set to `data - AX`, so only DS:[BX+AX] reaches the pass path. The return from the CALLF lands right after the 2 bytes. The source comments "some emus use AX as both ofs & seg" [CTA 8883]. | the new mode (hardware, r/m=0) |

**Verdict: VERIFIED** (length 2; new-mode semantics, from CT hardware + AV + MS). AR is
contradicted by the hardware test.
**UNRESOLVED-SEMANTICS (minor):** AV and MS differ in when the address is computed and the
pointer is read, relative to the pushes. This shows only for r/m=4 ([SI+SP]) or for a pointer
that overlaps the two pushed words. No hardware test covers it. Implemented: the address uses the
pre-push registers (AV), and the reads come after the pushes (like the hardware-tested memory
form, [CT:355-357]).

### 62 BOUND, mod=11

| | Length | Semantics |
|---|---|---|
| AV | 2: `i_chkind` → `v30ReadEAW` through the EA table [AV 1294-1310], [AVM 214-219] | bounds = words at [new mode] and [new mode + 2] |
| MS | 2: `BOUND()` uses the plain `ReadModRmByte()` / `GetModRm` (no `LdsLesLeaModRm`) [MS 580-592] | low bound = high bound = the r/m register |
| AR | 2: `instructionBound` uses `modRM()` without force; `getMemory` returns the register [AR instructions-misc.cpp:81-88], [AR modrm.cpp:55-63] | low bound = high bound = the r/m register |
| CT | not tested | — |

**Verdict:** length **VERIFIED** (2; AV, MS, AR). Semantics **CONFLICT** (AV vs MS+AR). No
hardware test covers it. Implemented as the `v30mz_undefined(0x62, reg, r/m)` placeholder.

### Related finding (not in the note): FE /7 vs FF /7

The decode of these was not changed.
- AV dispatches FE /7 straight from the ModRM byte to `undefFF`, so it consumes **no**
  displacement (2 bytes) [AV 3905-3910, 4553]. AV's FF /7 does consume it (`contFF` →
  `v30ReadEAW`) [AV 3944-3951].
- MS [MS 1050] and AR [AR instructions-group.cpp:92] consume the displacement for both, as STSWS
  says [ST:14026-14029].
- The spec keeps 2+D. This is a CONFLICT with AV only; MS, AR and STSWS agree.

## Summary

| Encoding | Length | Semantics | Sources agree? | Verdict | Hardware-tested? |
|---|---|---|---|---|---|
| F1 | 1 (MS, AR) / undefined (AV) | no-op (MS, AR) / crash (AV) / maybe BRKS (CT) | no | CONFLICT → not decoded | no |
| F6 /1 | 2+D | no-op | yes (AV MS AR) | VERIFIED | effect yes, length no |
| F7 /1 | 2+D | no-op | yes (AV MS AR) | VERIFIED | effect yes, length no |
| 8F /1-7 | 2+D | POP r/m16 | yes (AV MS AR) | VERIFIED | no |
| C6 /1-7 | 3+D | MOV r/m8,imm8 | yes (AV MS AR) | VERIFIED | no |
| C7 /1-7 | 4+D | MOV r/m16,imm16 | yes (AV MS AR) | VERIFIED | no |
| 8D mod=11 | 2 | LEA via the new modes | yes (CT AV MS AR) | VERIFIED | yes |
| C4/C5 mod=11 | 2 | LES/LDS via the new modes | yes (CT AV MS AR) | VERIFIED | yes |
| FF(FE) /3 mod=11 | 2 | CALLF via the new modes | CT AV MS yes; AR no; push/read order differs (AV vs MS) | VERIFIED (+ minor UNRESOLVED-SEMANTICS) | yes (r/m=0) |
| FF(FE) /5 mod=11 | 2 | JMPF via the new modes | CT AV MS yes; AR no | VERIFIED | yes (r/m=0) |
| 62 mod=11 | 2 | AV: new-mode bounds; MS/AR: reg/reg | length yes; semantics no | length VERIFIED, semantics CONFLICT → placeholder | no |
