# NEC V30MZ — opcode-level spec brief for a Ghidra SLEIGH derivative

Goal: a V30MZ (WonderSwan CPU) language derived from, and stricter than, Ghidra's
`x86:LE:16:Real Mode` (Ghidra `Processors/x86/data/languages/ia.sinc`).
Built only from the sources below (see [`SOURCES.md`](SOURCES.md) for URLs and versions). Every claim has a citation. Where the sources
disagree or say nothing, the text says so and does not guess.

## Citation keys

| Key | Source (text rendering; see `SOURCES.md`) | Cited by |
|---|---|---|
| `ST:n` | STSWS (`stsws.html` as text) | line number |
| `DS:n` | NEC V30MZ datasheet (pdftotext) | line number |
| `WI:n` | WSdev wiki `NEC_V30MZ_instruction_set` (raw wikitext) | line |
| `WN:n` | WSdev wiki `NEC_V30MZ_interrupts` | line |
| `WF:n` | WSdev wiki `NEC_V30MZ_flags` | line |
| `WM:n` | WSdev wiki `NEC_V30MZ` | line |
| `CT:n` | WSCpuTest README (results from a hardware test ROM) | line |
| `IA:n` | Ghidra 12.1.3 x86 `ia.sinc` | line |

These notes use Intel mnemonics. The NEC names are given in §9.5. In STSWS and the datasheet,
DS1=ES, PS=CS, DS0=DS, IX=SI, IY=DI, AW/BW/CW/DW=AX/BX/CX/DX and PSW=FLAGS
([ST:14045-14098]).

The WSdev page `NEC_V30MZ_undocumented_instructions` is empty. WSdev points to WSCpuTest for that
material.

---

## 0. Top-line findings

1. **ISA level.** The V30MZ is an 80186-level CPU: the 8086 set, plus 60/61, 62, 68/6A, 69/6B,
   6C-6F, C0/C1 and C8/C9, plus the undocumented D6 (SALC). It has none of the V20/V30 extensions
   (no 0F map, no REPC/REPNC, no FPO2, no 8080 mode) and no FPU. There are no 386+ prefixes or
   instructions. Sources: [WM:3], [DS:524-530], [DS:1721-1760], [ST:12433-13757].
2. **Seven fully undefined one-byte opcodes:** 0F, 63, 64, 65, 66, 67 and F1 ([ST:12517],
   [ST:12936-12952], [ST:13653]). 9B (WAIT/POLL) is effectively a NOP on WonderSwan.
3. **Undefined opcodes never trap.** There is no vector 6 or 7 ([ST:4055-4059], [ST:4372-4385],
   [WN:52-54]). An undefined *one-byte* opcode takes 1 byte ([CT:281-285], [ST:4375-4376]). An
   undefined *sub-opcode* still consumes its ModRM byte and displacement ([ST:13948-13953],
   [ST:14024-14029]). For F6/F7 /1, no source says whether the immediate is consumed — **unresolved**.
4. **Prefixes:** 26, 2E, 36, 3E, F2, F3 and F0 only ([ST:3978-3995], [ST:12391-12421],
   [DS:1739,1753]). 64, 65, 66 and 67 are one-byte NOPs, not prefixes ([ST:13742-13757], [CT:283-285]).
5. **Ghidra real mode accepts several things the V30MZ does not have.** These must be removed:
   - FS and GS prefixes, and the 66/67 size prefixes ([IA:2316-2319]);
   - the whole 0F two-byte map;
   - x87 decoding of D8-DF ([IA:5280]);
   - VEX decoding of C4/C5 when mod=11 ([IA:2441-2457]; this is not gated by real mode);
   - ARPL at 63 ([IA:2592]) and INT1 at F1 ([IA:3695]);
   - 3-bit Sreg decoding ([IA:694]);
   - the LOCK restriction ([lockable.sinc], [x86.slaspec]);
   - pushing the *old* SP for PUSH SP ([IA:1945-1948]).

---

## 1. Instruction-set level

| Class | Opcodes | Present on V30MZ? | Evidence |
|---|---|---|---|
| 8086 base set | everything in §2 not listed below | yes | [ST:12433-13726], [DS:3269-4000 App. A] |
| 80186: PUSHA / POPA | 60 / 61 | yes (PUSH R / POP R) | [ST:12920-12927], [DS:3702,3739] |
| 80186: BOUND | 62 /r (memory only) | yes (CHKIND); signed compare; INT 5 | [ST:10264-10290], [CT:273-275], [DS:3439-3442] |
| 80186: PUSH imm | 68 iw, 6A ib (sign-extended) | yes | [ST:12955-12967], [DS:3719] |
| 80186: IMUL r16,r/m16,imm | 69 /r iw, 6B /r ib (sign-extended) | yes (MUL, 3-operand form) | [ST:12960-12972], [ST:7568-7577], [DS:3633] |
| 80186: INS / OUTS | 6C, 6D, 6E, 6F | yes (INM, OUTM) | [ST:12975-12992] |
| 80186: shift/rotate by imm8 | C0 /n ib, C1 /n ib | yes; count masked to 5 bits | [ST:13407-13414], [ST:8537], [DS:547] |
| 80186: ENTER / LEAVE | C8 iw ib, C9 | yes (PREPARE, DISPOSE); level masked to 5 bits | [ST:13447-13453], [ST:10695-10727], [DS:550] |
| Undocumented 8086: SALC | D6 | yes | [ST:13517], [ST:5650-5656], [CT:327-329], [WM:3]. Missing from the datasheet (Table 3-3, App. A) and from WSdev's opcode tables. |
| Undocumented: 82 (= 80 alias) | 82 /n ib | yes per STSWS | [ST:13097-13099]. Not in the datasheet or WSdev tables. |
| AAM/AAD with any immediate | D4 ib, D5 ib | yes; the second byte is a real operand | [ST:7003-7006], [ST:7077-7081], [DS:543-545], [CT:217,230] |
| ESC / FPO1 | D8-DF + ModRM | decoded as a NOP; no coprocessor | [ST:7405-7427], [DS:531], [DS:1750-1752] |
| WAIT / POLL | 9B | a NOP in practice (POLLB is tied low) | [ST:10640-10663], [CT:307-309], [DS:770-774] |
| 286+ system instructions (0F 00/01, ARPL, LAR, LSL, CLTS, ...) | — | **absent** | 0F and 63 are undefined: [ST:12517], [ST:12936], [CT:279-285] |
| 386+ (opsize/adsize prefixes, FS/GS, 32-bit registers, 0F xx) | — | **absent** | [ST:2811] ("All registers on the V30MZ are 16-bit"), [ST:13742-13757] |
| x87 FPU | — | **absent**; "Connection to numerical operation co-processor: Not possible" | [DS:473-474] |

---

## 2. One-byte opcode map (all 256 bytes)

Legend: **P** = prefix, **U** = undefined (no exception; consumes 1 byte), **G** = group (see §2.1).
Ev/Gv are 16-bit, Eb/Gb are 8-bit, Sw is a segment register. Main source: the STSWS opcode map
[ST:12433-13726]. Byte encodings were cross-checked against datasheet App. A [DS:3269-4000].

| | x0 | x1 | x2 | x3 | x4 | x5 | x6 | x7 | x8 | x9 | xA | xB | xC | xD | xE | xF |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0x** | ADD Eb,Gb | ADD Ev,Gv | ADD Gb,Eb | ADD Gv,Ev | ADD AL,Ib | ADD AX,Iw | PUSH ES | POP ES | OR Eb,Gb | OR Ev,Gv | OR Gb,Eb | OR Gv,Ev | OR AL,Ib | OR AX,Iw | PUSH CS | **U** (0F) |
| **1x** | ADC Eb,Gb | ADC Ev,Gv | ADC Gb,Eb | ADC Gv,Ev | ADC AL,Ib | ADC AX,Iw | PUSH SS | POP SS | SBB Eb,Gb | SBB Ev,Gv | SBB Gb,Eb | SBB Gv,Ev | SBB AL,Ib | SBB AX,Iw | PUSH DS | POP DS |
| **2x** | AND Eb,Gb | AND Ev,Gv | AND Gb,Eb | AND Gv,Ev | AND AL,Ib | AND AX,Iw | **P** ES: | DAA | SUB Eb,Gb | SUB Ev,Gv | SUB Gb,Eb | SUB Gv,Ev | SUB AL,Ib | SUB AX,Iw | **P** CS: | DAS |
| **3x** | XOR Eb,Gb | XOR Ev,Gv | XOR Gb,Eb | XOR Gv,Ev | XOR AL,Ib | XOR AX,Iw | **P** SS: | AAA | CMP Eb,Gb | CMP Ev,Gv | CMP Gb,Eb | CMP Gv,Ev | CMP AL,Ib | CMP AX,Iw | **P** DS: | AAS |
| **4x** | INC AX | INC CX | INC DX | INC BX | INC SP | INC BP | INC SI | INC DI | DEC AX | DEC CX | DEC DX | DEC BX | DEC SP | DEC BP | DEC SI | DEC DI |
| **5x** | PUSH AX | PUSH CX | PUSH DX | PUSH BX | PUSH SP | PUSH BP | PUSH SI | PUSH DI | POP AX | POP CX | POP DX | POP BX | POP SP | POP BP | POP SI | POP DI |
| **6x** | PUSHA | POPA | BOUND Gv,Ma | **U** | **U** | **U** | **U** | **U** | PUSH Iw | IMUL Gv,Ev,Iw | PUSH Ib(sx) | IMUL Gv,Ev,Ib(sx) | INSB | INSW | OUTSB | OUTSW |
| **7x** | JO | JNO | JB/JC | JNB/JNC | JZ | JNZ | JBE | JA | JS | JNS | JPE | JPO | JL | JGE | JLE | JG |
| **8x** | G1 Eb,Ib | G1 Ev,Iw | G1 Eb,Ib (alias of 80) | G1 Ev,Ib(sx) | TEST Eb,Gb | TEST Ev,Gv | XCHG Eb,Gb | XCHG Ev,Gv | MOV Eb,Gb | MOV Ev,Gv | MOV Gb,Eb | MOV Gv,Ev | MOV Ew,Sw | LEA Gv,M | MOV Sw,Ew | POP Ev (G /0) |
| **9x** | NOP | XCHG AX,CX | XCHG AX,DX | XCHG AX,BX | XCHG AX,SP | XCHG AX,BP | XCHG AX,SI | XCHG AX,DI | CBW | CWD | CALL Ap | WAIT (=NOP) | PUSHF | POPF | SAHF | LAHF |
| **Ax** | MOV AL,Ob | MOV AX,Ow | MOV Ob,AL | MOV Ow,AX | MOVSB | MOVSW | CMPSB | CMPSW | TEST AL,Ib | TEST AX,Iw | STOSB | STOSW | LODSB | LODSW | SCASB | SCASW |
| **Bx** | MOV AL,Ib | MOV CL,Ib | MOV DL,Ib | MOV BL,Ib | MOV AH,Ib | MOV CH,Ib | MOV DH,Ib | MOV BH,Ib | MOV AX,Iw | MOV CX,Iw | MOV DX,Iw | MOV BX,Iw | MOV SP,Iw | MOV BP,Iw | MOV SI,Iw | MOV DI,Iw |
| **Cx** | G2 Eb,Ib | G2 Ev,Ib | RET Iw | RET | LES Gv,Mp | LDS Gv,Mp | MOV Eb,Ib (G /0) | MOV Ev,Iw (G /0) | ENTER Iw,Ib | LEAVE | RETF Iw | RETF | INT3 | INT Ib | INTO | IRET |
| **Dx** | G2 Eb,1 | G2 Ev,1 | G2 Eb,CL | G2 Ev,CL | AAM Ib | AAD Ib | SALC | XLAT | ESC (NOP+ModRM) | ESC | ESC | ESC | ESC | ESC | ESC | ESC |
| **Ex** | LOOPNE | LOOPE | LOOP | JCXZ | IN AL,Ib | IN AX,Ib | OUT Ib,AL | OUT Ib,AX | CALL Jv | JMP Jv | JMP Ap | JMP Jb | IN AL,DX | IN AX,DX | OUT DX,AL | OUT DX,AX |
| **Fx** | **P** LOCK | **U** | **P** REPNE | **P** REP/REPE | HLT | CMC | G3 Eb | G3 Ev | CLC | STC | CLI | STI | CLD | STD | G4 (FE) | G5 (FF) |

**Totals:** 7 prefixes (26 2E 36 3E F0 F2 F3), 7 undefined opcodes (0F 63 64 65 66 67 F1),
and 242 defined opcodes. Of the defined opcodes, 8 are D8-DF (an ESC NOP that takes ModRM) and
9B is effectively a NOP.

Notes on specific bytes:

| Byte | Status and notes |
|---|---|
| 0F | **Undefined** — not POP CS and not the V-series "group 3" escape. It is a 1-byte NOP taking 1 cycle ([ST:13732-13736], [ST:5355-5357] "00001111 does not correspond to POP PS", [CT:279-281]). WSdev writes the POP sreg pattern as `000xx111` with no 0F exception ([WI:1630]) — this is a WSdev omission. |
| 63 | **Undefined**, no ModRM (STSWS lists it as "Invalid" [ST:12935-12936]; [CT:283-285] says a 1-byte NOP). It is not ARPL. |
| 64, 65 | **Undefined**, *not* prefixes. On other V-series parts these are REPNC/REPC ([ST:13740-13747], [CT:283-285]). They are not FS:/GS:. |
| 66, 67 | **Undefined** with no ModRM. On other V-series parts these are FPO2 ([ST:13751-13757], [CT:283-285]). They are not operand-size or address-size prefixes. |
| 82 | Group 1 byte form, identical to 80 per the STSWS map ([ST:13097-13099]). The datasheet's AND/OR/XOR imm forms show `1000000W` with no s-bit ([DS:3321,3327]). WSdev lists 83 /1, /4 and /6 ([WI:736,1566,2200]) but no 82. **Partial disagreement: only STSWS documents 82; nothing contradicts it.** |
| 8C, 8E | The sreg field is ModRM bits 4:3. Bit 5 is ignored ([CT:287-289] hardware-tested). STSWS writes the field as `aa-rrmmm` and says bit 5 is unused but "needs research" ([ST:3957-3964], [ST:5070]). The datasheet encodes the bit as `0` ([DS:3576,3607,3609]). So reg=4..7 alias ES/CS/SS/DS. |
| 8E with CS (reg=001, or 101 via the alias) | **The move is not performed** ([ST:5136-5138]: "If PS is specified as the destination ... the operation will not be performed"). The datasheet and WSdev are silent. It is not MOV CS as on the 8086. |
| 8D | LEA. STSWS's opcode map prints this row as `10001011` ([ST:13152]), which is a typo; the instruction page has the correct `10001101` ([ST:4997]). The mod=11 form is in §2.2. |
| 9A | CALL far ptr16:16. The WSdev hex column says "CA" but its binary column is correct ([WI:774]). |
| 9B | WAIT/POLL. STSWS's opcode map lists POLL as defined ([ST:13222-13223]), and its instruction page says "No operation", 9 cycles ([ST:10640-10647]). But STSWS's exception notes say V30MZ "treats the POLL opcode as undefined" ([ST:4382-4385]). **Internal STSWS inconsistency.** The behaviour is a NOP either way: POLLB is held low ([CT:307-309], [WI:2152] ref). WSdev's WAIT row gives the opcode as `6E`/`01101110` ([WI:2152]), which is **wrong**; 6E is OUTSB ([ST:12985], [WI:1612]). |
| D4, D5 | The immediate byte is a real divisor or multiplier ([ST:7003-7006], [ST:7077-7081], [DS:543-545], [CT:217,230]). The datasheet's App. A shows the second byte fixed at 0x0A ([DS:3487,3489]) — that is notation only; see the text at [DS:543]. |
| D6 | SALC: AL = CY ? 0xFF : 0x00, with no flags changed ([ST:4763-4774], [ST:5598-5656], [CT:327-329]). It takes 8 cycles per [CT:329]; STSWS gives no cycle count in the extracted text. |
| D8-DF | ESC/FPO1: **NOP with a ModRM byte and displacement**, so 2-4 bytes, and no memory access ([ST:7405-7427], [DS:3539] "11011XXX mod YYY mem (disp)", [DS:531]). [CT:331-333] says "2 byte NOPs (1 cycle)", presumably tested only with mod=11. The sources do not conflict on length, and none says WAIT or FPU state is involved. |
| F0 | BUSLOCK prefix. It never faults (§4). |
| F1 | **Undefined** per STSWS ([ST:13652-13653]). [CT:337] says: "It doesn't look like it's a simple INT1 ... might be BRKS from NEC V25/V35 or at least that it switches the MD flag. This app doesn't test it". **Unresolved.** Behaviour is unknown and may not be a NOP. |
| F2, F3 | REPNE and REP/REPE. The low bit is the Z condition ([ST:11523-11570]). |
| FE, FF | See §2.1 (FE /2../6 alias the FF word forms). |

### 2.1 Group opcodes: sub-opcode (ModRM reg) holes

| Opcode | /0 | /1 | /2 | /3 | /4 | /5 | /6 | /7 | Source |
|---|---|---|---|---|---|---|---|---|---|
| 80, 81, 82, 83 | ADD | OR | ADC | SBB | AND | SUB | XOR | CMP | [ST:13762-13812] (all 8 defined) |
| 8F | POP Ev | ? | ? | ? | ? | ? | ? | ? | /0 per [DS:3698-3700], [WI:1624]. **/1-/7: all sources silent.** STSWS writes POP mem as `10001111 aa---mmm` ([ST:5340]), which suggests "don't care", but that notation only means "not part of the memory operand" ([ST:3560-3561]) — so this is not proof. |
| C0, C1, D0-D3 | ROL | ROR | RCL | RCR | SHL | SHR | **undefined, writes 0** | SAR | [ST:13816-13877]: /6 "still has a memory operand and produces a result of zero, which is stored". [CT:311-317] confirms for C0/C1 (/6 "zeros al/ax"). The effect of /6 on flags is **not documented** by any source. |
| C6, C7 | MOV E,I | ? | ? | ? | ? | ? | ? | ? | /0 per [DS:3568-3571], [WI:1441-1443]. **/1-/7: all sources silent.** STSWS writes `1100011W aa---mmm` ([ST:5123]); the same notation caveat as for 8F applies. Immediate consumption for /1-/7 is unknown. |
| F6, F7 | TEST E,I | **undefined** | NOT | NEG | MUL | IMUL | DIV | IDIV | [ST:13882-13953]. For /1, STSWS says it "has a memory operand and any additional bytes of instruction code required by it are present. If the memory operand specifies an offset, no memory is actually accessed" ([ST:13950-13953]). It does **not** say whether an imm8/imm16 follows. [CT:339-341] says F6 C8 / F7 C8 "doesn't seem to change flags or registers (1 cycle)" — **length unresolved.** (The Intel 8086 treats /1 as TEST, but that is not a local source.) |
| FE | INC Eb | DEC Eb | CALL Ev | CALLF Mp | JMP Ev | JMPF Mp | PUSH Ev | **undefined** | /2-/6: STSWS encodes CALL, BR and PUSH as `1111111-` with W don't-care ([ST:9875-9880], [ST:10164-10169], [ST:5515]). [CT:343-345]: "0xFE,0xD0 - 0xFE,0xF0: Does the same as 0xFF variants (CALL, BRA & PUSH)". Group 2 /7 is invalid ([ST:14015-14029]). These sources agree. |
| FF | INC Ev | DEC Ev | CALL Ev | CALLF Mp | JMP Ev | JMPF Mp | PUSH Ev | **undefined** | [ST:13958-14029]. /7 "has a memory operand ... no memory is actually accessed" ([ST:14026-14029]); [CT:347-349]: FF F8 "doesn't seem to do anything". |

### 2.2 Register-form (mod=11) encodings of memory-only operands

| Encoding | STSWS | WSCpuTest | Datasheet | Verdict |
|---|---|---|---|---|
| 8D mod=11 (LEA r,r) | "the value in that register is stored to the destination as though the instruction were MOV" ([ST:5009-5011]) | not a register move — it gives new addressing modes ([bx+ax], [bx+cx], [bp+dx], [bp+bx], [si+sp], [di+bp], [bp+si], [bx+di]) ([CT:291-305]) | silent | **CONTRADICTION** (STSWS vs. the hardware test ROM) |
| C4 / C5 mod=11 (LES/LDS) | "the offset accessed in memory will be undefined" ([ST:5197-5198]) | uses the same odd LEA-style modes ([CT:319-325]) | silent | Disagree in detail; both say the form is abnormal |
| FF /3, FF /5 mod=11 (far CALL/JMP) | "segment and offset ... are undefined" ([ST:9903-9904], [ST:10193-10194]) | LEA-style modes; tester unsure ([CT:351-361]) | silent | Unreliable |
| 62 mod=11 (BOUND) | "the offset accessed in memory will be undefined" ([ST:10290-10291]) | silent | silent | Unreliable |

---

## 3. Undefined opcodes and sub-opcodes at run time

| Question | Answer | Source |
|---|---|---|
| Is an exception raised? | **No**, for undefined opcodes or sub-opcodes. Vector 6 is unused; vector 7 is unused. | [ST:4055-4059], [ST:4360-4385], [WN:52-54] |
| Bytes consumed by an undefined one-byte opcode (0F 63 64 65 66 67, and F1 per STSWS) | **1 byte.** Execution continues "at the next byte as the start of a new instruction". | [ST:4374-4376], [CT:20], [CT:279-285] (1 cycle each) |
| Bytes consumed by an undefined sub-opcode (F6/F7 /1, FE/FF /7, C0-D3 /6) | Prefixes + opcode + ModRM + displacement ("any bytes used to supply their prefixes, opcode, sub-opcode, memory operand or immediate operand are skipped over"). | [ST:4055-4059], [ST:13950-13953], [ST:14026-14029] |
| Is the immediate consumed for F6/F7 /1? | **Unknown.** [ST:4055-4059] mentions skipping "immediate operand" bytes in general, but the group-1 note lists only the memory operand. | — |
| Wording conflict | [ST:4055-4059] (skip all operand bytes) and [ST:4374-4376] (continue at the next byte) agree only for one-byte opcodes. The vector-6 note is a simplification. | — |
| Undefined *instructions* of V20/V30 (ADD4S etc.) | Datasheet: "An undefined result is obtained by executing these instructions" ([DS:524-530], [DS:1756-1760]). Testers: 0F is a 1-byte NOP ([CT:281]). | The datasheet promises nothing. In practice, 0F <x> runs as a NOP followed by whatever <x> decodes to. |
| Is it really a "NOP"? | WSdev: "treats most unimplemented instructions as NOPs" ([WN:53]) — "most", which leaves F1 open ([CT:337]). C0-D3 /6 is **not** a NOP: it writes 0 ([ST:13874-13877]). | — |
| Cycle cost | STSWS: "Research is needed" ([ST:4062-4063]). [CT:281,285] gives 1 cycle; [CT:333] gives 1 cycle for ESC; [CT:309] gives 9 cycles for WAIT. | Emulator-only |

---

## 4. Prefixes

| Byte | Prefix | Category | Source |
|---|---|---|---|
| 26 / 2E / 36 / 3E | ES: / CS: / SS: / DS: | segment override | [ST:12391-12421], [DS:3535-3536,3715,3895] |
| F2 / F3 | REPNE(Z) / REP, REPE(Z) | repeat (Z bit = opcode bit 0) | [ST:11494-11570], [ST:13656-13665] |
| F0 | LOCK (BUSLOCK) | bus lock | [ST:9772-9801], [DS:3420] |
| 64 65 66 67 | — | **not prefixes**; 1-byte undefined NOPs | [ST:13740-13757], [CT:283-285] |

Behaviour, quirks and conflicts:

- **Categories and duplicates.** STSWS defines three mutually exclusive categories. There is "no
  hard limit" on the number of prefixes; if a category repeats, the last one wins
  ([ST:3978-4004]). The datasheet says "Up to 7 instruction prefixes can be used (for all
  instructions) ... If there are more than 7 ... the execution result ... is not guaranteed.
  Furthermore, normal recovery from interrupt processing is not possible" ([DS:532-540]).
  **Disagreement: STSWS says no limit, the datasheet says ≤7.**
- **Interrupts after a prefix.** No interrupt and no single-step trap is taken between a prefix
  and its instruction ([ST:4007-4009], [ST:4090-4092], [DS:2843-2846], [WN:44]). An NMI that
  arrives then is held until after the next instruction ([DS:2850-2852]).
- **Interrupted REP string instructions.** A hardware interrupt can be accepted mid-string. The
  saved return address is backed up by 1 for each *kind* of prefix, for up to 3 kinds. NEC
  therefore advises keeping the total prefix count before a block instruction at ≤3
  ([DS:2905-2937]). With duplicate prefixes, the resume point lands inside the prefix run. STSWS
  says nothing about resuming REP.
- **REP on a non-string instruction** has no effect ([ST:11556-11557]). REP is meaningful for
  MOVS, CMPS, SCAS, LODS, STOS, INS and OUTS ([ST:11366-11440], [DS:3741-3760]). The Z
  condition applies only to CMPS/SCAS; the other instructions repeat until CX=0
  ([ST:11556-11566]). The decrement does not change Z ([ST:11570-11571]).
- **Segment overrides on string instructions.** They apply to the SI (IX) source. They cannot
  change the ES:DI (DS1:IY) destination ([ST:2941-2948], [ST:12362]).
- **LOCK.** STSWS: "a prefix that applies to all instructions" ([ST:9778-9779]). Datasheet:
  "Only valid for instruction performing memory or I/O access, and not valid for other
  instructions" ([DS:583-587]). **Neither source mentions any fault.** POLL with BUSLOCK: "No
  problematic operations have been observed on V30MZ" ([ST:10660-10663]).
- **Interaction with undefined bytes.** Because 64-67 are not prefixes, `2E 66 8B 07` runs as
  three instructions: CS:(NOP 66), then a non-overridden `MOV AX,[BX]`. This follows from the
  1-byte rule plus "prefixes apply to the immediately following instruction" ([ST:3972-3975]);
  it is an inference and no source tests it directly.

---

## 5. NEC V20/V30 extension instructions on V30MZ

| Extension (V20/V30 / V30HL) | V30MZ | Evidence |
|---|---|---|
| 0F-prefixed group ("group 3"): TEST1, CLR1, SET1, NOT1 (bit forms), ADD4S, SUB4S, CMP4S, ROL4, ROR4, INS, EXT, BRKEM | **absent**; 0F is a 1-byte undefined NOP | [DS:524-530], [DS:1756-1760], [ST:13732-13736], [CT:279-281] |
| CLR1 CY / CLR1 DIR / SET1 CY / SET1 DIR / NOT1 CY | present = CLC/CLD/STC/STD/CMC (F8/FC/F9/FD/F5) | [DS:528 notes 1-3], [DS:1739], [ST:13689-13716] |
| REPC (65) / REPNC (64) | **absent**; undefined, and not prefixes | [ST:13740-13747], [DS:528-530], [CT:283-285] |
| FPO2 (66/67) | **absent**; undefined, with no ModRM | [ST:13751-13757], [DS:528] |
| FPO1 (D8-DF) | NOP that takes ModRM/disp | [DS:531], [ST:7405-7427] |
| RETEM, CALLN (8080-mode instructions) | **absent** | [DS:528-530] |
| µPD8080AF emulation mode / MD flag | **absent**; MD (PSW bit 15) is "invalid" | [DS:472], [DS:1203-1204], [WF:78-81], [ST:3218-3222] |
| Bit-field INS/EXT | **absent** | [DS:528] |
| Local byte encodings of the 0F sub-opcodes | **not given by any local source** — only "0F is the group-3 escape" ([ST:13734]) | — |

---

## 6. Exceptions, interrupt vectors and control flow

| Vector | Cause | Instruction / byte | Notes | Source |
|---|---|---|---|---|
| 0 | Divide error | F6/F7 /6, /7 (DIV/IDIV); D4 (AAM) when imm=0 | Signed quotient range excludes −128/−32768 (8086 rule). Registers are left unchanged on the fault (by hardware test). | [ST:4332-4336], [ST:6971-6976], [ST:7222-7271], [CT:168-212]. The datasheet lists only DIV/DIVU for vector 0 ([DS:2529]). |
| 1 | Single step (BRK/TF flag) | after each instruction while TF=1 | The trap fires after the instruction *following* the POPF that set TF ([ST:3212-3215], [WN:9-11]). It is not taken after a prefix or a MOV/POP to a segment register (§4). Priority 4: hardware interrupts are taken first ([DS:2526-2534], [DS:2779]). | [ST:3151-3157], [DS:1187-1189], [DS:2808-2829] |
| 2 | NMI | external (WonderSwan low battery via port B7h) | Rising edge; non-maskable. | [ST:4549-4627], [DS:801-805], [DS:2527] |
| 3 | Breakpoint | CC (INT3) | one byte | [ST:4348-4349], [ST:9961-10023] |
| 4 | Overflow | CE (INTO) | only when OF=1 | [ST:4352-4353], [ST:10052-10057] |
| 5 | Bound | 62 (BOUND) | signed comparison | [ST:4356-4357], [ST:10264-10287], [CT:273-275] |
| 6 | (Intel: invalid opcode) | — | **Never raised** | [ST:4372-4376], [WN:53] |
| 7 | (Intel: ESC/coprocessor; STSWS says POLL error) | — | **Never raised** | [ST:4380-4385], [WN:54] |
| 8-31 | reserved | — | | [DS:2614-2615] |
| 32-255 | INT imm8; external INT input | CD ib | WonderSwan hardware IRQs = INT_BASE (port B0h, multiple of 8) + 0..7 | [DS:2528-2533], [ST:4394-4496] |

Interrupt entry and exit, which Ghidra already models in the same way:

- **Entry:** push FLAGS; IF=0, TF=0 (and MD=1 per the datasheet); push CS; push IP; then load the
  vector (IP = word at 4n, CS = word at 4n+2) ([ST:4244-4267], [DS:2648-2656],
  [DS:2616-2631]).
- **Exit:** IRET pops IP, CS and FLAGS ([ST:4284-4301], [ST:10943-10953]).
- **Return address of a CPU exception.** STSWS states one rule for every exception: the pushed IP
  is "the offset of the first byte of the instruction that follows ... the instruction that
  raised the exception" ([ST:4271-4275]). That makes the vector 0 and vector 5 traps "after"
  traps, not restartable faults. No source has an exception-specific statement for DIV or BOUND.
- **Interrupt shadow.** STSWS says interrupts are inhibited after a MOV or POP to *any* segment
  register ([ST:4096-4100], [ST:5175-5178], [ST:5371-5378]). The datasheet and WSdev say this
  only for **SS** ([DS:2843], [WN:43]). **Disagreement.** STI, POPF or IRET that sets IF delays
  only maskable interrupts by one instruction ([ST:4104-4110], [DS:2847-2853], [WN:45]).
- **Instructions that cannot be interrupted part-way:** DIV, DIVU and PREPARE ([DS:2541-2552]).
- **HLT** resumes on any enabled interrupt request, even when IF=0, and then continues at the
  next instruction ([ST:4115-4119], [ST:10550-10570], [ST:4473-4475]). Ghidra models HLT as
  `goto inst_start` ([IA:3583]).
- **Reset** starts at FFFF:0000. CS=FFFF, DS/ES/SS=0, and the general registers are undefined.
  FLAGS = F002h (MD=1, bits 14-12 = 1, bit 1 = 1) ([DS:777-779], [DS:3112-3130]).

Things that matter for control-flow modelling:

- An undefined opcode **falls through**. It is never a terminator.
- 8E /1 (MOV CS) is a no-op, not a jump ([ST:5136-5138]).
- F1 behaviour is unknown ([CT:337]).
- FE /2-/5 are real CALL and JMP forms ([CT:343-345]).
- 9B never blocks on WonderSwan.

---

## 7. Flag differences (emulator-only — the disassembler is unaffected)

| Instruction | Documented "undefined" flags | Observed V30MZ behaviour | Source |
|---|---|---|---|
| General | V-series "unspecified" flags | **Always written, never preserved** ("never kept as they were") | [CT:19], [DS:506-508] (they may differ from V30HL/MX, "especially ... multiply and divide") |
| AND/OR/XOR/TEST | AC unspecified ([ST:8265-8268]) | AC, CF and OF cleared | [CT:28-31] |
| MUL (unsigned, F6/F7 /4) | Z, S, P, AC | S, P and AC cleared. **Z depends on the SoC:** STSWS says always set ([ST:7673]); [CT:24,148-149] says cleared on ASWAN (mono) and set on SPHINX (Color/Crystal) | **Model-dependent** |
| IMUL (F6/F7 /5, 69, 6B) | Z, S, P, AC | Z set; S, P and AC cleared | [ST:7589-7592], [CT:153-158] |
| DIV / IDIV | all | Complex and SoC-tested: Z is set "when remainder is zero and bit 0 of result is set"; S, P and AC cleared; for 8-bit, CF/OF come "from the last multiplication" | [CT:161-212]; STSWS says only "unspecified" ([ST:7226-7230]) |
| IDIV edge case | — | **0x8000 / 0x00 gives 0x0081 with no exception (8-bit); 0x80000000 / 0 gives 0x00008001** | [CT:190], [CT:204]. **Contradicts** [ST:7222-7226] (divisor 0 always traps) |
| AAM (D4) | V, CY, AC unspecified ([ST:6990-6994]) | AC, CF and OF cleared; P, S and Z from AL. On a divide fault Z = (AL > 0x3F) | [CT:214-226] |
| AAD (D5) | V, CY, AC unspecified (V-series) | Flags exactly as for an 8-bit ADD of AH*imm and AL | [ST:7058-7064], [CT:230] |
| DAA / DAS | V unspecified | DAA: same as ADD, but AF/CF never cleared. DAS: tests AL>0x99 first, then the low nibble | [CT:232-241]. STSWS's algorithm instead tests "AL > 0x9F" *after* the low-nibble adjust ([ST:6387], [ST:6497]). **Disagreement on ordering and threshold.** |
| AAA / AAS | Z, S, V, P unspecified (V-series) | V=0 and P=1 always. AF=CF=Z = (adjust taken); S = !adjust. AL is masked to 4 bits | [ST:6591-6667], [ST:6717-6803], [CT:243-256] (agree) |
| Shifts and rotates | V undefined for multi-bit shifts ([DS:1181]) | ROL/RCL: OF = CF ^ msb. ROR/RCR: OF = bit(n-1) ^ bit(n-2). SHL: OF = CF ^ msb. SHR/SAR: OF = msb ^ msb-1. AF=0 for shifts. A count of 0 (after &0x1F) leaves CF unchanged | [CT:64-142], [ST:8546-8551] |
| Shift count 0 | 8086/V30HL: no write, flags preserved | V30MZ: memory is still written, and Z/P/S are recomputed for SHL/SHR/SAR | [DS:560-569], [ST:8540-8541] |
| INC/DEC | — | CF preserved | [CT:37-40], [DS:1052] |
| Datasheet errata | The datasheet's CY text for unsigned MUL is inverted ("cleared if AH is other than 0") | Use [ST:7670] / [CT:150] instead | [DS:1057] |

---

## 8. Semantics a p-code emulator must model (differences from Ghidra's Intel model)

| Item | V30MZ behaviour | Source | Ghidra today |
|---|---|---|---|
| PUSH SP (54) | SP -= 2, then [SS:SP] = **new** SP (8086 behaviour) | [CT:258-265]; STSWS: "anomalous ... needs to be investigated" ([ST:5444-5446]) | `push22` saves the operand first, so it pushes the *old* SP ([IA:1945-1948], [IA:4342]) — **must change** |
| POP SP (5C) | SP = [SS:SP], with no post-increment visible | [CT:267-270] | `pop22` loads then adds 2 ([IA:2016-2019]); POP into SP yields loaded+2 — **must change** |
| PUSHA / POPA | PUSHA pushes the original SP. POPA reads 8 words and discards the SP slot | [ST:5541-5565], [ST:5384-5414], [DS:552] | already correct ([IA:4302]) |
| AAM / AAD imm | the immediate is used; AAM with imm=0 raises INT 0 and leaves AX unchanged | [ST:6971-6976], [CT:221-225] (STSWS says AX is undefined) | AAM divides with no zero check ([IA:2495]) — add a trap |
| SALC (D6) | AL = CF ? 0xFF : 0 | [ST:4773-4774] | **missing** — add it |
| Shift/rotate count | masked to 5 bits for CL and imm8; a memory operand is still written when the count is 0 | [ST:8537-8541], [DS:547-569] | already masked `& 0x1f` ([IA:4592-4596]); check that the zero-count write and Z/P/S update happen |
| Group 2 /6 | result = 0, stored (register or memory) | [ST:13874-13877], [CT:311-317] | no constructor — add "SHL/6" that writes 0, or decode as bad (§9) |
| ENTER | level = imm8 & 0x1F. Algorithm: push BP; temp = SP; if level > 0 { repeat level-1: BP -= 2, push [BP]; push temp }; BP = temp; SP -= imm16 | [ST:10695-10727] (nesting confirmed in `stsws.html`), [DS:550] | `low5` is already used ([IA:3312], [IA:3400-3441]) |
| BOUND | signed compare; INT 5 if out of range; the pushed IP is the next instruction (STSWS general rule) | [ST:10264-10290], [ST:4271-4275] | the body is empty ([IA:2595]) — add the check and trap |
| DIV / IDIV | quotient range excludes −2^(n-1). Divisor 0 traps (but see the [CT:190,204] anomaly). Registers are unchanged on a fault | [ST:7222-7271], [ST:7329-7374] | — |
| CALL far [mem] (FF /3) | pushes CS:IP **before** reading the target pointer | [DS:557-559], [CT:355-357] | [IA:2954] reads the pointer first — reorder (this matters for `[bp]` that overlaps the stack) |
| MOV CS, r/m (8E /1) | no operation | [ST:5136-5138] | Ghidra writes CS ([IA:4009-4010]) |
| Sreg decoding | 2-bit field (bits 4:3); bit 5 ignored | [CT:287-289], [ST:5070] | 3-bit `Sreg` with FS/GS ([IA:694]) |
| Offset wrap | Every effective address is 16-bit and wraps within the segment. A word access at offset FFFF reads offset FFFF and then offset 0000 of the *same* segment | [ST:338-345] | — |
| Physical wrap | seg*16 + off is taken mod 2^20 ("wrap back around to 0x00000") | [ST:331-333] | the real-mode `segment()` op is `(zext(base)<<4)+zext(inner)` with no 20-bit mask ([x86-16-real.pspec]); `ptr1616` likewise ([IA:1518]) — **add `& 0xFFFFF`** |
| IP wrap | IP FFFF→0000 without changing CS | [ST:3012-3013] | — |
| String SI/DI | step ±1 or ±2 by DF. 16-bit registers (wrap is implied, not stated). The destination is always ES | [ST:11306-11318], [ST:2946-2948] | already 16-bit with addrsize=0 |
| XLAT | AL = [seg:BX + zext(AL)], offset taken mod 64K | [ST:5687-5688] | — |
| CMPS order | SI operand − DI operand; reads happen IX→IY | [ST:11715-11717], [DS:554-556] | already correct ([IA:3052]) |
| IN/OUT word | the high byte goes to port+1 | [ST:4929-4931], [ST:5246-5249] | — |
| LAHF/SAHF | low 8 bits of FLAGS only | [ST:5181-5183], [DS:1033] | — |
| WAIT (9B) | NOP (9 cycles) | [CT:309] | already `{}` ([IA:5114]) |
| HLT | waits for any interrupt *request*, even with IF=0 | [ST:4115-4119], [ST:4473-4475] | `goto inst_start` |

---

## 9. SLEIGH derivation plan (restricted derivative of `x86:LE:16:Real Mode`)

### 9.1 Language and spec scaffolding

- Add a new `.ldefs` entry, e.g. `V30MZ:LE:16:default`, with its own `.slaspec`. Do not include
  `lockable.sinc` or any of the AVX/BMI/SHA/etc. `.sinc` files that `x86.slaspec` pulls in
  ([x86.slaspec]).
- Start from `x86-16-real.pspec`. Keep `segmented_address type="real"`, but change the
  `segmentop` body to `res = ((zext(base) << 4) + zext(inner)) & 0xFFFFF;` ([ST:331-333]).
  Set the reset context to CS=FFFF, IP=0 ([DS:777-779]).
- Pin the context permanently: `addrsize=0`, `opsize=0`, `protectedMode=0`, `longMode=0`. Then
  delete every constructor with `opsize=1/2`, `addrsize=1/2`, `bit64=1`, `$(LONGMODE_ON)`, `rex*`,
  `vexMode`, `evex*`, `mandover` and `protectedMode=1`. Remove the `@ifdef IA64` blocks.
- Registers: keep AX..DI with their byte halves, ES/CS/SS/DS, IP, flags and the individual flag
  bits. Drop E*/R*, R8-R15, FS/GS/FS_OFFSET/GS_OFFSET, CR/DR/TR, the
  GDTR/IDTR/LDTR/TR selectors, x87 ST/MM/XMM/YMM/ZMM, BND, MXCSR and SSP ([IA:19-510]).

### 9.2 Prefix constructors ([IA:2312-2322])

| Keep | Remove |
|---|---|
| 2E, 36, 3E, 26 (segover 1-4); F2, F3 (rep/repne); F0 (lockprefx) | 64, 65 (FS/GS), 66 (opsize), 67 (addrsize), REX (40-4F in long mode), C4/C5 VEX ([IA:2441-2457]: these match in real mode when mod=11), 62 EVEX, 0F 0F 3DNow ([IA:2484-2485]) |

- **LOCK:** Ghidra wraps every non-lockable instruction in `with : lockprefx=0`, so `F0` before
  an arbitrary instruction fails to decode ([x86.slaspec], [lockable.sinc:1-5]). The V30MZ
  accepts LOCK on any instruction ([ST:9778-9779], [DS:583-587]). Make `lockprefx` cosmetic: a
  display-only `LOCK` prefix that is valid on all opcodes. Optionally emit a `buslock()` userop.
- **REP:** keep `rep/reptail/repe/repetail` for addrsize=0 ([IA:1542-1566]). F2/F3 on a
  non-string instruction is a harmless no-op ([ST:11556-11557]). Check that legacy constructors
  do not test `mandover`/`$(PRE_NO)`; if one does, accept F2/F3 on it.
- Prefix ordering and duplicates: the last prefix of each category wins ([ST:3999-4004]). That
  is already the natural result of the context-setting chain.

### 9.3 Opcode-level edits

| Opcode(s) | Action | Reason |
|---|---|---|
| 0F xx (the entire two-byte map: BSF/BT/CMOV/CPUID/Jcc rel16/MOVZX/SETcc/PUSH FS/system/SSE...) | **Delete.** 0F becomes a 1-byte undefined opcode | [ST:13732-13736], [CT:279-281] |
| 63 (ARPL [IA:2592]), 64, 65, 66, 67, F1 (INT1 [IA:3695]) | **Delete**, then decode as undefined (see 9.4) | [ST:12935-12952], [ST:13653] |
| D8-DF (x87, from [IA:5280] on) | Replace with `ESC n, r/m16` (FPO1) that consumes ModRM+disp and has a `{}` body | [ST:7405-7427], [DS:3539] |
| D6 | **Add** `SALC` | [ST:4763-4774], [CT:327-329] |
| 82 | Keep the `$(BYTE_80_82)` alias ([IA:821-823]); in 16-bit mode it already accepts 82 | [ST:13097-13099] |
| 8C / 8E | Replace the 3-bit `Sreg` ([IA:694]) with a 2-bit sreg on ModRM bits 4:3 (`[ES CS SS DS]`), with bit 5 ignored. For `8E` with sreg=CS, either emit `MOV CS,...` with a no-op body or treat it as bad (see 9.4) | [CT:287-289], [ST:5136-5138] |
| 8D, C4, C5, FF/3, FF/5, FE/3, FE/5, 62 with mod=11 | Already unmatched in Ghidra (Mem / m16 / addr16 require mod≠3). Keep them unmatched, i.e. bad | §2.2 contradiction; compilers never emit these |
| FE /2-/6 | **Add** aliases of the FF /2-/6 word forms (CALL, CALLF, JMP, JMPF, PUSH) | [ST:9875-9880], [ST:10164-10169], [ST:5515], [CT:343-345] |
| C0/C1/D0-D3 /6 | Add a "zero-write" form, or leave it bad (see 9.4) | [ST:13874-13877] |
| AAM | Add the divide-by-zero trap (`swi(0)` when imm8==0) | [ST:6971-6976] |
| BOUND (62) | Add a signed range check plus `swi(5)` | [ST:10264-10287] |
| PUSH SP / POP SP | Special-case `row=5 & reg=SP`: push the decremented SP, and make POP SP a plain load | [CT:258-270] |
| CALLF m16:16 (FF /3) | Push CS:IP before loading the pointer | [DS:557-559], [CT:355-357] |
| ENTER / LEAVE / PUSHA / POPA / IMUL imm / PUSH imm / INS / OUTS / C0 / C1 | Keep the opsize=0, addrsize=0 variants only | §1 |
| Also delete | LOCK-only forms, XACQUIRE/XRELEASE (`xrelease`, [IA:4035]), MOVBE, CMPXCHG, BSWAP, all `*D`/`*Q` mnemonics (INSD, IRETD, POPAD ...), JMPF/CALLF ptr16:32, SYSCALL/SYSENTER etc. | §1 |

### 9.4 How to decode undefined bytes (fail fast on data, but stay faithful to hardware)

The hardware executes all of these silently ([ST:4055-4059]). A disassembler should still
**stop** on them, because real code almost never contains them and they are a strong sign that
data is being decoded.

| Bytes | Hardware | Recommended SLEIGH decode | Rationale |
|---|---|---|---|
| 0F, 63, 64, 65, 66, 67 | 1-byte NOP | **No constructor** → Ghidra "Bad Instruction" (default). Optional: behind a context/option bit, a 1-byte `UNDEF.NOP` with `{}` for emulation fidelity | These bytes are common in ASCII and tables; failing fast catches mis-flows |
| F1 | unknown ([CT:337]) | **No constructor** (bad) | Behaviour is not established |
| 9B | NOP | `WAIT` (keep it; it is legitimate in compiler output) | [ST:10640-10647] |
| D8-DF + ModRM | NOP | `ESC` constructor (consumes ModRM/disp). This is defined behaviour, but code never needs it; consider putting it behind the same option bit | [DS:531] |
| F6/F7 /1 | no-op, **length unknown** | **No constructor** (bad) | Length cannot be decoded reliably ([ST:13950-13953] vs [CT:339-341]) |
| FE /7, FF /7 | no-op, ModRM+disp | **No constructor** (bad); option bit → `UNDEF Ev` NOP | [ST:14026-14029] |
| C0-D3 /6 | writes 0 | **No constructor** (bad); option bit → `SHL6 E,cnt` storing 0 | [ST:13874-13877] |
| 8F /1-/7, C6/C7 /1-/7 | **undocumented** | **No constructor** (bad) | All sources are silent |
| 8E with CS | no-op | **No constructor** (bad); option bit → `MOV CS,Ew` with `{}` | [ST:5136-5138] |
| 8C/8E with reg bit5=1 | aliases ES..DS | Decode as the alias (it is real, tested behaviour) but flag it in the display, e.g. `MOV ES',...`, or treat it as bad if you want maximum strictness | [CT:287-289] |
| mod=11 forms in §2.2 | odd addressing / undefined | **No constructor** (bad) | Contradictory sources |

**Option bit:** a single context field, e.g. `hwUndef=(…)`, set from the `.pspec`/`.gdis`. It
switches between strict mode (bad instruction) and hardware mode, which decodes each undefined
form with its documented length and effect. This lets the p-code emulator match hardware
without weakening the default disassembly.

### 9.5 Display variant: NEC mnemonics (optional)

WSdev lists Intel ↔ NEC pairs ([WI:30-361]); STSWS has the full map ([ST:14103-14498]). A
second `.slaspec` or a display-only mnemonic table can emit:

- **Arithmetic and BCD:** ADC→ADDC, SBB→SUBC, DAA→ADJ4A, DAS→ADJ4S, AAA→ADJBA, AAS→ADJBS,
  AAM→CVTBD, AAD→CVTDB, CBW→CVTBW, CWD→CVTWL.
- **Multiply and divide:** MUL→MULU, IMUL→MUL, DIV→DIVU, IDIV→DIV.
  **Caution: the MUL and DIV names swap meaning between the two conventions.**
- **Data movement:** LEA→LDEA, XCHG→XCH, XLAT→TRANS. LES/LDS/LAHF/SAHF are all written MOV
  with explicit sreg/PSW operands.
- **Jumps and loops:** JMP→BR, Jcc→B*, with JNS→BP (sic) and JS→BN; JCXZ→BCWZ; LOOP→DBNZ,
  LOOPE→DBNZE, LOOPNE→DBNZNE.
- **Interrupts and calls:** INT→BRK, INT3→BRK 3, INTO→BRKV, IRET→RETI, BOUND→CHKIND.
- **Stack and frame:** ENTER→PREPARE, LEAVE→DISPOSE, PUSHA/POPA→PUSH R/POP R,
  PUSHF/POPF→PUSH PSW/POP PSW.
- **Flags:** CLC/STC/CMC→CLR1 CY/SET1 CY/NOT1 CY, CLD/STD→CLR1 DIR/SET1 DIR, CLI/STI→DI/EI.
- **String operations:** MOVS→MOVBK, CMPS→CMPBK, SCAS→CMPM, LODS→LDM, STOS→STM, INS→INM,
  OUTS→OUTM.
- **Other:** HLT→HALT, LOCK→BUSLOCK, WAIT→POLL, ESC→FPO1.
- **Registers:** AX→AW, BX→BW, CX→CW, DX→DW, SI→IX, DI→IY, CS→PS, DS→DS0, ES→DS1,
  IP→PC, FLAGS→PSW.

Most homebrew toolchains use Intel names ([WM:7]), so Intel should stay the default.

---

## 10. Source defects and contradictions (consolidated)

| # | Topic | Sources and positions |
|---|---|---|
| 1 | LEA with mod=11 | STSWS: acts like MOV ([ST:5009-5011]). WSCpuTest (hardware): new [base+reg] modes ([CT:291-305]). |
| 2 | Length of the vector-6 skip | STSWS skips all operand bytes ([ST:4055-4059]) vs. continues at the next byte ([ST:4374-4376]). |
| 3 | POLL (9B) | STSWS map/page: defined NOP ([ST:13222], [ST:10640]) vs. STSWS exceptions note: "treats ... as undefined" ([ST:4384-4385]). Same effect either way. |
| 4 | Prefix limit | STSWS: none ([ST:3999]) vs. datasheet: ≤7, and ≤3 kinds for REP resume ([DS:532-540], [DS:2933-2937]). |
| 5 | Interrupt shadow after MOV/POP sreg | STSWS: any sreg ([ST:4098-4100]) vs. datasheet/WSdev: SS only ([DS:2843], [WN:43]). |
| 6 | LOCK scope | STSWS: all instructions ([ST:9778]) vs. datasheet: memory/I-O instructions only ([DS:583]). Neither faults. |
| 7 | MULU Z flag | STSWS: always set ([ST:7673]) vs. WSCpuTest: clear on mono, set on Color ([CT:24,148-149]). |
| 8 | IDIV by zero | STSWS: traps ([ST:7222-7226]) vs. WSCpuTest: 8000h/0 → 0081h, no trap ([CT:190,204]). |
| 9 | DAS algorithm | STSWS: low nibble first, then AL>9Fh ([ST:6457-6497]) vs. WSCpuTest: AL>99h first ([CT:238]). |
| 10 | AW/DW after a divide fault | STSWS: "undefined" (with an editor's note saying they are unchanged) ([ST:7226-7271]) vs. WSCpuTest: unchanged ([CT:172,184,198]). |
| 11 | PSW bit 15 | STSWS figure: fixed 1 ([ST:3062-3065]) vs. datasheet: MD flag, set on interrupt entry and at reset ([DS:1029], [DS:1203-1204], [DS:2652], [DS:3127]). Both say it has no effect. |
| 12 | F1 | STSWS: undefined ([ST:13653]) vs. WSCpuTest: possibly BRKS/MD toggle, untested ([CT:337]). |
| 13 | F6/F7 /1 length | Unresolved (§2.1). |
| 14 | 8F /1-7, C6/C7 /1-7 | All sources silent. |
| 15 | Flags after group-2 /6 | All sources silent. |
| 16 | 82 and sign-extended 83 logic forms | Documented only in STSWS (82) and WSdev (83 /1,/4,/6). Absent from the datasheet. |
| 17 | WSdev typos (hex column) | WAIT=6E ([WI:2152], wrong in both columns); CALL far "CA" ([WI:774]); SUB AL "28" ([WI:2088]); OR m8,imm "80 /6" ([WI:1562]); JBE row labelled "JA" ([WI:1154]). |
| 18 | STSWS typos | 8D printed as `10001011` ([ST:13152]); the RORC header row repeats "ROLC/RCL" ([ST:8827-8830]); SUBC's Intel name is given as "SBC" ([ST:7915]). |
| 19 | Datasheet erratum | The unsigned-MUL CY text is inverted ([DS:1057]). |
