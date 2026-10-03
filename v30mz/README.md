# v30mz — NEC V30MZ processor module for Ghidra 12.1.3

Language `V30MZ:LE:16:default`: the WonderSwan CPU, an 8086 + 80186 + SALC instruction set
with real-mode segmented addressing and a 20-bit bus. It is a compact standalone SLEIGH port of
the 16-bit real-mode subset of Ghidra's x86 spec (`ia.sinc`, Apache-2.0, attribution kept in
the files). Display text matches `x86:LE:16:Real Mode` so listings and the decode-diff harness
can be compared one to one. Behaviour follows `docs/V30MZ-SPEC-NOTES.md` (the brief); citations
such as `[ST:n]`, `[CT:n]` and `[DS:n]` use the brief's keys.

| File | Contents |
|---|---|
| `data/languages/v30mz.slaspec` | spaces, registers, context, tokens, operand subtables, macros, prefixes |
| `data/languages/v30mz_insn.sinc` | all defined instructions (strict decode) |
| `data/languages/v30mz_hwundef.sinc` | hardware-faithful decodes of undefined forms (`hwundef=1`) |
| `data/languages/v30mz.{ldefs,pspec,cspec}` | language definition, processor spec, compiler spec |
| `ghidra_scripts/V30MZDecodeDiff.java` | differential decode harness (opcode sweep, executed game code, csval self-test) |
| `ghidra_scripts/V30MZDecompileDemo.java` | decompiles functions of a game dump, with io labels |

`build.gradle` compiles the `.sla` (`support/sleigh -a data/languages`) before packaging, so
`./build.sh` produces a zip that ships a ready `.sla`.

## What differs from Ghidra x86 real mode

**Removed (these decode as no instruction):** the 0F map, 63 (ARPL), 64/65 (FS/GS), 66/67
(size prefixes), F1 (INT1), D8-DF x87, the 9B+x87 fused forms, C4/C5 VEX, 62 EVEX, F3 90 PAUSE
(it is `NOP` here), XABORT/XBEGIN, and the XACQUIRE/XRELEASE hints (F2/F3 are only REP here).
The Sreg field is 2 bits, so there is no FS or GS.

**Added:** SALC (D6). The 80186 set is present: PUSHA/POPA, BOUND, PUSH imm, IMUL imm,
INS/OUTS, C0/C1, ENTER/LEAVE.

**Prefixes:** only 26 2E 36 3E F0 F2 F3 are prefixes. LOCK is accepted on any instruction and
never faults. As in x86, `.LOCK` is shown only on the read-modify-write memory forms.

**Semantics:**
- PUSH SP (54, FF F4) pushes the decremented SP [CT:258-265].
- POP SP loads SP with no post-increment [CT:267-270].
- `segment()` wraps at 20 bits, and so do ptr16:16 targets [ST:331-333].
- CALLF m16:16 pushes CS:IP *before* it reads the pointer [DS:557-559], [CT:355-357].
- AAM 0 raises INT 0 and leaves AX unchanged [CT:221-225].
- **Flags follow the hardware** (WSCpuTest + its README, "[CTR]" in the SLEIGH comments): the
  V30MZ always writes the flags the manuals call undefined. AF is computed by every
  ADD/ADC/SUB/SBB/CMP/NEG/INC/DEC (incl. CMPS/SCAS) and cleared by AND/OR/XOR/TEST and the
  shifts. Rotates write OF for every count, including 0; shifts by 0 still set SF/ZF/PF from the
  result (CF is kept for a count of 0). DAA/DAS compute OF; AAA/AAS set ZF=CF=AF, SF=!AF, OF=0,
  PF=1; AAD's flags are those of the 8-bit `AL + AH*imm` addition; AAM clears AF/CF/OF.
  MUL/IMUL clear AF/PF/SF; IMUL sets ZF; MUL's ZF comes from the `colorsoc` context (below).
- **Divide error:** DIV/IDIV with a zero divisor or an out-of-range quotient (signed range
  ±(2^(n-1)-1)) and AAM 0 raise INT 0 through the `divtrap()` userop, AX/DX unchanged, with the
  hardware's flags (CF/OF of the 8-bit forms = the last multiply's overflow, held in the hidden
  `MULOV` register). IDIV 8000h/00 → 0081h and 80000000h/0000 → 8001h do **not** trap
  [CT:190,204].
- **HLT** is the `halt()` userop and falls through (after an interrupt, execution continues at
  the next instruction).
- BOUND does a signed check and raises INT 5 [ST:10264-10290].
- MOV CS (8E /1) is a no-op [ST:5136-5138].
- IRET unpacks FLAGS.
- XLAT and nested ENTER frames go through the correct segment.
- The PUSHF image has bits 15-12 and bit 1 set (F002h).
- IN/OUT/INS/OUTS use the io space (see below).

**Left to the emulator (no p-code effect):** interrupt shadows (STI/POPF/IRET/MOV SS/POP SS),
the TF single-step trap, prefix-resume rules (REP iterates with `goto inst_start`, so an
interrupt between iterations returns to the first prefix), and the HLT wait itself. `WSMachine`
implements them (`wonderswan/README.md`).

**Emulator contract (userops and state):**

| Userop / state | Emulator must |
|---|---|
| `segment(seg, off)` | return `((seg << 4) + off) & 0xFFFFF` (also defined in the pspec, `farpointer="yes"` as in Ghidra x86) |
| LES / LDS | two word loads: offset at `segment(base, off)`, segment at `segment(base, off+2)` (offset wraps in the segment). A single 4-byte load made the decompiler type a constant far pointer (e.g. C000:0000 built on the stack) as the flat ram offset 0xC0000000 and fail ("Offset must be between 0x0 and 0x10ffef"; Ghidra x86 real mode fails the same way) |
| `swi(n)` | do the interrupt entry for INT n / INT3 / INTO / BOUND (push FLAGS, CS, IP of the next instruction; IF=TF=0; load CS from vector n) and return the linear handler address; the p-code then does `call [result]` |
| `divtrap()` | do the same entry for vector 0 and redirect the PC to the handler itself (in Ghidra's emulator: `overrideCounter` + `PcodeFrame.finishAsBranch()`); the p-code falls through so static analysis sees "handler returns to the next instruction" |
| `halt()` | stop executing until an interrupt is requested (also with IF=0) |
| `LOCK()` / `UNLOCK()` | nothing |
| `v30mz_undefined(...)` | fail (only emitted for 62 mod=11 under `hwundef=1`) |
| `MULOV` register | nothing; it is CPU state (0 at reset) |
| context `hwundef`, `colorsoc` | set `hwundef=1` and `colorsoc` = the SoC (1 on a WonderSwan Color/Crystal) |

Why `divtrap()` instead of `swi(0)` + `call`: with a call, the decompiler showed every DIV as
`pcVar = swi(0); uVar = (*pcVar)();` with clobbered registers; now it reads
`if (d == 0 || 0xff < q) divtrap(); else { AL = q; AH = r; }`. AAM 0 uses it too.

## Code segment: the `csval` context

Ghidra's x86 real mode works out CS as `(inst_next >> 4) & 0xF000`, which assumes the code
segment is 64K-aligned. WonderSwan games do not follow that rule: in one commercial title half the executed blocks run
with CS=4400, and another runs some with CS=4300. This spec therefore tracks the real CS in a
16-bit **flowing context variable, `csval`**:

- **Entry points:** the loader sets `csval` (for example, to the segment of the reset vector).
  You can also set it with *Set Register Values → csval*. **An unset `csval` is 0 (CS = 0000).**
  It is not inferred.
- **Flow:** Ghidra carries `csval` unchanged to the fall-through and to near branch and call
  targets.
- **Direct far JMP/CALL ptr16:16:** `globalset()` writes `csval` = the new segment at the target.
- **RETF / IRET / INT / indirect far JMP/CALL:** the target's CS cannot be known statically. The
  target keeps whatever `csval` the program context already has there.
- **Near relative targets** are `csval*16 + ((IP_next + disp) & 0xFFFF)`, with
  `IP_next = inst_next - csval*16`. IP wraps inside the segment [ST:3012-3013].
- **CS-relative uses:** CS: overrides, PUSH CS, near indirect CALL/JMP, and the return CS:IP
  pushed by CALL/CALLF all use `csval` as a constant. After a far call, CS is restored to the
  caller's CS so the decompiler keeps it known.
- **Display:** SLEIGH cannot choose the segment Ghidra uses to print an exported address.
  Ghidra always prints `(linear >> 4) & 0xF000 : rest`, so the target `4400:0123` is shown as
  `4000:4123`. The linear value is correct.
- **Emulator:** the p-code takes CS:IP values from `csval`, so the emulator's decode context
  must keep `csval == CS`. After any RETF/IRET/INT/indirect far transfer (or before every step),
  write `csval` from the CS register into the thread's context, for example with
  `PcodeThread.overrideContext`. The PC register is the 16-bit `IP` (fixed in the pspec). The
  emulator's counter is a full linear address, so do not round-trip the counter through `IP`.

## I/O ports: the `io` space

`define space io type=ram_space size=2 wordsize=1`. IN, OUT, INS and OUTS are plain loads and
stores in `io`. A word access at port p touches p and p+1. The WonderSwan's 8-bit port decode is
**not** masked here; that belongs to the platform model.

- The pspec marks `io:0000-FFFF` **volatile**, so the decompiler keeps every access.
- The cspec puts `io` in `<global>`. Without this, the decompiler ignores labels on io addresses
  (it prints `Io00a0` instead of the label). This follows Ghidra's Z80 spec.
- A loader creates an `io` memory block (volatile, uninitialized) and puts labels and data types
  on it.
- **Emulator:** Ghidra's PcodeEmulator runs IN/OUT as ordinary loads and stores in the `io`
  space; no userop is involved. Intercept accesses whose address space is `io`. You can use
  load/store callbacks (`beforeLoad`/`afterStore`), or a state piece that overrides
  `getVar`/`setVar` for that space.
- **Display:** `IN AL,imm8` prints the port as an io address (`IN AL,0x00a0`), so references
  and labels work in the listing. Ghidra x86 prints `IN AL,0xa0`. This is the harness category
  `IO_PORT_OPERAND`.

Decompiler output for a game's hardware initialisation routine (labels `IO_xx` were created on the
touched ports):

```
  bVar1 = IO_A0;                       // in  al,0xa0
  *(byte *)0x400 = (bVar1 & 2) >> 1;
  IO_A0 = 5;                           // out 0xa0,al
  ...
    IO_60 = 0xc0;
    IO_62 = 0;
  ...
  IO_03 = 0;  IO_A2 = 3;  IO_A4 = 1;  IO_A6 = 0;  IO_B1 = 0;  IO_B3 = 0;  IO_B0 = 0x20;
```

A routine at `4400:0351` (csval=4400, a non-aligned CS):

```
LAB_ram_4000_43a3:
  Io00c6 = iVar1;      // out 0xc6,ax  (word access; only byte labels were created)
  IO_C8 = 0x40;        // out 0xc8,al
  return 0;
```

## `colorsoc` context (default 0)

MUL (F6/F7 /4) sets ZF on the colour SoC (SPHINX/SPHINX2) and clears it on the mono SoC (ASWAN)
[CT:24,148-149]; nothing else differs. `colorsoc=1` selects the colour behaviour. It is a flowing
context bit like `hwundef`: an emulator sets it from the machine model, and an analyst can set it
per range (*Set Register Values → colorsoc*). The loader leaves it at the pspec default 0; for
static analysis the value only changes the constant ZF after a MUL. (Alternatives considered: a
`v30mz_mulz()` userop would put a call on every MUL in the decompiler output.)

## `hwundef` context (default 0)

- **`hwundef=0`, strict (default):** undefined opcodes and sub-opcodes decode as no instruction,
  so disassembly of data fails fast.
- **`hwundef=1`, hardware-faithful:** decodes them with their hardware length and effect, for an
  emulator. Set it in the pspec `context_set` or per range ("hwundef" register).

| Form | `hwundef=1` decode |
|---|---|
| 0F 63 64 65 66 67 | `UNDEF`, 1-byte NOP [CT:279-285] |
| D8-DF + ModRM/disp | `ESC n,rm`, NOP with no memory access [ST:7405-7427], [DS:531] |
| FE /2-/6 | aliases of the FF word forms CALL/CALLF/JMP/JMPF/PUSH [CT:343-345] |
| FE /7, FF /7 | `UNDEF rm`, which consumes ModRM+disp [ST:14026-14029] |
| C0 C1 D0-D3 /6 | `SHL6`, which stores 0 [ST:13874-13877], [CT:311-317] |
| 8E /1 | `MOV CS,rm16`, no-op [ST:5136-5138] |
| 8C/8E with ModRM bit 5 set | aliases of ES/CS/SS/DS [CT:287-289] |
| F6/F7 /1 + ModRM/disp | `UNDEF rm`, no-op, **no immediate** (ARMV30MZ, Mesen2, ares) |
| 8F /1-7 | `POP rm16` (reg field ignored; ARMV30MZ, Mesen2, ares) |
| C6/C7 /1-7 | `MOV rm,imm` (reg field ignored; ARMV30MZ, Mesen2, ares) |
| 8D, C4, C5 with mod=11 | `LEA`/`LES`/`LDS` through the new base+index modes, 2 bytes [CT:291-305] |
| FF/FE /3, /5 with mod=11 | `CALLF`/`JMPF` through the new base+index modes, 2 bytes [CT], WSCpuTest FF D8/FF E8 |
| 62 with mod=11 | `BOUND r16,r16`, 2 bytes; effect is the `v30mz_undefined` placeholder (sources conflict) |
| F1 | stays undecoded in both modes (sources conflict) |

The mod=11 modes are 0 DS:[BX+AX], 1 DS:[BX+CX], 2 SS:[BP+DX], 3 SS:[BP+BX], 4 DS:[SI+SP],
5 DS:[DI+BP], 6 SS:[BP+SI], 7 DS:[BX+DI]; a segment override applies. The evidence, with line
citations into ARMV30MZ, Mesen2, ares and WSCpuTest, is in `docs/V30MZ-UNDEFINED-ENCODINGS.md`.
An emulator must provide the `v30mz_undefined` userop (or treat it as a fault); it is emitted only
where the sources disagree on the effect.

## Decisions

### SOURCE-CONFLICT (written as `# SOURCE-CONFLICT:` in the SLEIGH files)

Where they conflict, hardware test results ([CT]) beat the documents.

| Brief §10 | Topic | Decision |
|---|---|---|
| #1 / 2.2 | LEA (and LES/LDS/far/BOUND) with mod=11 | STSWS says it acts like MOV; [CT] and three emulators show new base+index modes. **hwundef=1 only:** LEA/LES/LDS/CALLF/JMPF use them; BOUND is a placeholder (emulators disagree). Strict mode: no constructor. |
| — | F6/F7 /1 memory access | STSWS: none [ST:13952]; the emulators read and discard. No p-code read. |
| — | FE /7 displacement | ARMV30MZ consumes none; STSWS, Mesen2 and ares consume it. 2+D kept. |
| #2 | Skip length for undefined opcodes | One-byte undefined opcodes take 1 byte (STSWS and [CT:281,285] agree). |
| #3 | POLL (9B) defined or undefined | Decoded as `WAIT`, a 1-byte NOP. The effect is the same either way. |
| #4 | Prefix limit (none vs ≤7) | Any number is decoded. It only affects interrupt resume (emulator). |
| #5 | Interrupt shadow after MOV/POP sreg | No p-code effect. `WSMachine`: SS only (datasheet, WSdev, Mesen 2, ws-test-suite `interrupt_timing`) rather than STSWS's "any sreg". |
| #6 | LOCK scope | Accepted on every instruction; never faults. |
| #7 | MULU Z flag | STSWS: always set; [CT]: set on colour, cleared on mono. Hardware wins: `colorsoc` context selects it. |
| #8 | IDIV by zero | STSWS: always traps; [CT]: 8000h/00 → 0081h and 80000000h/0000 → 0000:8001h, no trap. Hardware wins. |
| — | AAM 0 ZF | WSCpuTest README prose: set if AL > 3Fh; Mesen 2 (passes the ROM's AAM test): set if AL ≤ 3Fh. The ROM's check wins: AL ≤ 3Fh (this spec passes the AAM test). |
| — | Divide-error ZF | Not tested by [CT] ("set in some weird way"); left unchanged on the trap path (Mesen 2 does the same). |
| #9 | DAS ordering | Hardware ordering: test AL>99h first [CT:238]. |
| #10 | AX after an AAM 0 fault | Left unchanged [CT:221-225]. |
| #11 | PSW bit 15 (fixed 1 vs MD) | Constant 1; PUSHF image F002h. |
| #16 | 82 and the 83 logic forms | Decoded; nothing contradicts them. |
| — | PUSH SP "anomalous" (STSWS) | Pushes the new SP [CT:258-265]. |
| — | Sreg bit 5 | Ignored by the hardware [CT]. Accepted only under `hwundef=1`. |

### UNRESOLVED (written as `# UNRESOLVED:` / `# UNRESOLVED-SEMANTICS:`)

| Form | Status | Implemented |
|---|---|---|
| F1 (brief #12) | **CONFLICT:** Mesen2 and ares say 1-byte no-op; ARMV30MZ crashes on it; the [CT] author suggests BRKS and does not test it | not decoded in either mode |
| 62 BOUND mod=11 | length 2 settled; **effect CONFLICT** (ARMV30MZ: bounds from the new mode; Mesen2/ares: r/m register as both bounds) | `v30mz_undefined(0x62, r16, r/m16)` placeholder (hwundef=1) |
| FF/FE /3 mod=11 ordering | ARMV30MZ computes the address and reads the offset before it pushes CS:IP; Mesen2 pushes first. Visible only for r/m=4 or an overlapping pointer | address from pre-push registers, reads after the pushes |
| Group 2 /6 (#15) | flags unknown | `SHL6` leaves them unchanged |

### RESOLVED (written as `# RESOLVED (sources):`), see `docs/V30MZ-UNDEFINED-ENCODINGS.md`

- F6/F7 /1 (#13): 2+D bytes, **no immediate**, no-op (ARMV30MZ, Mesen2, ares; ares commit
  4b43bbf "fix opcode 0xF7:1 to match hardware").
- 8F /1-7 (#14): POP r/m16; C6/C7 /1-7 (#14): MOV r/m,imm (ARMV30MZ, Mesen2, ares).
- LEA/LES/LDS/CALLF/JMPF with mod=11: 2 bytes through the new base+index modes (WSCpuTest
  hardware test + ARMV30MZ + Mesen2; ares disagrees on CALLF/JMPF and is contradicted by the test).

### Deviations from the brief or the task text

- **FE /2-/6** are decoded only when `hwundef=1`, as the task asked. Brief §9.3 lists them as
  plain additions.
- **D8-DF ESC** is decoded only when `hwundef=1` (brief §9.4 suggests this as an option).
- **F6/F7 /1, 8F /1-7, C6/C7 /1-7 and the mod=11 forms** (brief §9.3/9.4: "no constructor")
  are now decoded under `hwundef=1`, after the emulator check in
  `docs/V30MZ-UNDEFINED-ENCODINGS.md`. Strict mode still has no constructor for them.
- **8E with a register operand:** Ghidra x86 prints the operands reversed (`MOV AX,ES` for
  `8E C0`, whose semantics are ES=AX). This spec prints `MOV ES,AX`. It is the only display
  text that deliberately differs (harness category `X86_DISPLAY_BUG_8E_REG`). Copying the bug
  would take a one-line change.
- **IN/OUT imm8** print the port as an io address (category `IO_PORT_OPERAND`; required by the
  io-space design).
- **`io` is in the cspec `<global>`.** The decompiler only applies labels and data types on io
  addresses when it is there.

## Test results (`ghidra_scripts/V30MZDecodeDiff.java`)

Results from 2026-10-02. Re-run after the semantics work (flags, divide trap, HLT, `MULOV`,
`colorsoc`): every count below is identical (sweep strict and `hwundef`, executed code in both
modes, lengths 55/55, csflow 5/5). Semantics are checked by the hardware test ROMs instead
(WSCpuTest 48/48 groups; ws-test-suite CPU tests: 80186 quirks 3/3, prefixes 7/7, interrupt timing
15/15; see `docs/SOURCES.md`).

**A. Sweep, x86 real mode vs V30MZ (strict):** 851,968 cases; 427,589 the same; 424,379
different; **UNEXPLAINED = 0**.

| Category | Count |
|---|---|
| FS_GS_PREFIX (64/65) | 131,444 |
| OPSIZE_ADDRSIZE_PREFIX (66/67) | 131,397 |
| LOCK_ACCEPTED (V30MZ decode = x86 decode without the F0) | 57,174 |
| TWO_BYTE_0F_MAP | 55,567 |
| IP_WRAP (rel8 at the base 1000:0000 wraps inside CS) | 18,396 |
| X87_D8_DF | 12,908 |
| IO_PORT_OPERAND (cosmetic, by design) | 7,336 |
| ARPL_63 | 1,834 |
| INT1_F1 | 1,834 |
| TSX_HLE_HINT | 1,354 |
| GRP2_6 | 1,344 |
| GRP4_FE_2_7 (x86 decodes FE /2-7 mem as INC) | 1,208 |
| SREG_FS_GS | 896 |
| GRP3_F6F7_1 | 448 |
| PAUSE_F3_90 | 267 |
| VEX_C4_C5 | 240 |
| MOV_CS | 224 |
| GRP5_FF_7 | 192 |
| X86_DISPLAY_BUG_8E_REG (cosmetic, by decision) | 168 |
| LOCK_FF_x86_INC_QUIRK | 134 |
| TSX_XABORT_XBEGIN | 14 |

Every "undefined" category is checked to be BAD on the V30MZ side.

With `hwundef=1`: 851,968 cases; 394,417 the same; 457,551 different; **UNEXPLAINED = 0**.
Only 2,104 sweep cases stay undecoded, all of them F1 (it was 10,464 before the
undefined-encoding work). Compared with the previous `hwundef=1` run, exactly 8,360 cases changed,
all from BAD to a decode, all with opcode 62/8D/8F/C4/C5/C6/C7/F6/F7/FE/FF. The categories for
the new decodes are:

| Category (hwundef=1) | Count |
|---|---|
| MOV_C6C7_1_7 (C6/C7 /1-7 = MOV) | 3,680 |
| GRP1A_8F_1_7 (8F /1-7 = POP) | 1,848 |
| VEX_C4_C5 (mod=11 LES/LDS via the new modes) | 1,024 |
| LEA_MOD3_ALT_EA (mod=11 LEA) | 512 |
| EVEX_62 (mod=11 BOUND placeholder) | 512 |
| GRP3_F6F7_1 (no-op, no immediate) | 448 |
| FAR_MOD3_ALT_EA (FF /3 /5 mod=11) | 112 |

The FE /3 /5 mod=11 forms are counted under GRP4_FE_2_7. Each new category is also in the
harness list of forms that must be BAD in strict mode.

The strict sweep after this change is identical to the one before it: every V30MZ decode is
byte-for-byte the same, with the same counts as table A.

**Targeted length test** (`lengths` corpus, 55 cases; `ghidra_scripts/V30MZDecodeDiff.java`):
each formerly unresolved encoding, with representative mod values (F6/F7 /1, 8F /1-7, C6/C7
/1-7, every mod=11 LEA mode, LES/LDS with and without an override, BOUND, and FF/FE /3 /5
mod=11), must decode under `hwundef=1` with the verified length and text. Each must also be BAD
under `hwundef=0`. F1 must be BAD in both modes. **55/55 pass.**

**B. Executed code of four commercial titles (one mono, three colour), decoded at their true CS:** every block in `coverage.json`, with
`csval` set to the block's `cs`.

| Title | Blocks (64K-aligned CS) | Instructions | V30MZ BAD | Compared with x86 | Same | Different | Near branches OK | CS-relative OK |
|---|---|---|---|---|---|---|---|---|
| A (mono) | 1472 (738) | 6604 | 0 | 3455 | 3232 | 223 | 839/839 | 6/6 |
| B | 1163 (965) | 5844 | 0 | 4773 | 4496 | 277 | 696/696 | 7/7 |
| C | 1056 (863) | 5442 | 0 | 4165 | 3897 | 268 | 600/600 | 7/7 |
| D | 1802 (1801) | 8384 | 0 | 8383 | 8144 | 239 | 989/989 | 43/43 |

- x86 is only compared on blocks where its 64K-aligned model gives the true CS.
- All 1,007 differences are cosmetic: IO_PORT_OPERAND 628 and X86_DISPLAY_BUG_8E_REG 379.
  UNEXPLAINED = 0. No instruction differs in length or mnemonic.
- Rerun after the undefined-encoding work, with `hwundef=0` and with `hwundef=1`: identical
  numbers in both modes (none of the newly decoded forms occur in executed game code).
- Near branches and CS-relative operands were checked against `cs*16 + ((ip+disp) & 0xFFFF)`
  in every block, aligned or not.

**csflow self-test:** 5/5. It checks that CALLF to 4400:0010 gives the target csval=4400, with
the pushed CS:IP = 4000:0005. It also checks that `JMP rel16` inside CS 4400 reaches linear
53FF0 (x86 would give 43FF0), that JMPF sets 5000, and that `CS:[BX]` uses segment 5000.

**C. Self-check (x86 vs x86):** the sweep gives 851,968 the same and 0 different. The four game
corpora give 0 different.
