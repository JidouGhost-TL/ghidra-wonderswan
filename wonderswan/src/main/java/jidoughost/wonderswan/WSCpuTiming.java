// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * V30MZ instruction timing with the prefetch queue (cycle-timed mode of {@link WSMachine}).
 *
 * <p>Model (NEC V30MZ manual 3.3; WSdev; behaviour matched against Mesen 2 cycle traces):
 * <ul>
 * <li>Every CPU cycle is either an internal cycle, a data/port bus access, or a stall waiting for code bytes.</li>
 * <li>The prefetch queue holds up to 16 bytes. Internal cycles (and stalls) fetch: one byte after the region's wait
 *     states (1 for RAM, 1 or 2 for SRAM/ROM), plus the next byte of an aligned word on a 16-bit bus.</li>
 * <li>Each instruction byte (prefixes, opcode, ModRM, displacement, immediates) is taken from the queue; taking a
 *     byte when fewer than 2 are queued stalls until 2 are.</li>
 * <li>Data and port accesses cost one cycle each, two when split (odd address, or a byte bus / byte port) and do
 *     not fetch.</li>
 * <li>Taken branches, calls, returns and interrupts flush the queue and fetch from the new address.</li>
 * </ul>
 * Per-opcode templates give the order of internal cycles and code reads (only that order affects stalls); the
 * number of data accesses comes from what the instruction actually did.
 */
public final class WSCpuTiming {
    /** Callbacks into the machine: advance one cycle; wait states and bus width at a linear address. */
    public interface Bus {
        void cycle();
        int waitStates(long linear);
        boolean wordBus(long linear);
    }

    static final int QUEUE = 16;
    private final Bus bus;
    private long fetch;          // linear address of the next byte to fetch
    private int size;            // bytes queued
    private int wait;            // cycles since the last fetch
    public long cycles;          // cycles charged through this model
    private long instrCycles;

    public WSCpuTiming(Bus bus) { this.bus = bus; }

    /** Restart fetching at a new linear address (taken branch, far transfer, interrupt, reset). */
    public void flush(long linear) { fetch = linear & 0xFFFFF; size = 0; wait = 0; }

    private void tick() { bus.cycle(); cycles++; instrCycles++; }

    /** One internal cycle: the bus is free, so the prefetcher may fetch. */
    void idle() {
        tick();
        wait++;
        if (size >= QUEUE) return;
        if (wait < bus.waitStates(fetch)) return;
        wait = 0;
        boolean word = bus.wordBus(fetch);
        fetch = (fetch + 1) & 0xFFFFF; size++;
        if (size < QUEUE && word && (fetch & 1) != 0) { fetch = (fetch + 1) & 0xFFFFF; size++; }
    }

    void idle(int n) { for (int i = 0; i < n; i++) idle(); }

    /** Take one instruction byte from the queue (stall-fetching while fewer than 2 are queued). */
    void code() {
        while (size < 2) idle();
        size--;
    }

    void code(int n) { for (int i = 0; i < n; i++) code(); }

    /** Data or port bus cycles (no fetch). */
    void access(int n) { for (int i = 0; i < n; i++) tick(); }

    /** REP re-execution: the opcode byte is put back at the head of the queue. */
    void repeatOpcode() {
        if (size >= QUEUE) { size--; fetch = (fetch - 1) & 0xFFFFF; }
        size++;
    }

    /**
     * Charge one executed instruction.
     *
     * @param b        instruction bytes (prefixes included)
     * @param taken    control left the fall-through path (branch taken, call, return, jump)
     * @param target   linear address execution continues at (for the flush)
     * @param accesses data and port bus accesses the instruction performed (split accesses counted as 2)
     * @param repFirst for REP string instructions: true on the first iteration
     * @param repMore  for REP string instructions: another iteration follows
     * @param interrupted the instruction raised a software interrupt or a divide error (entry charged here)
     * @param entryAccesses bus accesses of the interrupt entry (3 pushes, 2 vector reads; split words count 2)
     * @return cycles charged
     */
    public long instruction(byte[] b, boolean taken, long target, int accesses, boolean repFirst, boolean repMore,
            boolean interrupted, int entryAccesses) {
        instrCycles = 0;
        int i = 0;
        boolean rep = false;
        while (i < b.length - 1 && isPrefix(b[i] & 0xFF)) { if ((b[i] & 0xF6) == 0xF2) rep = true; i++; }
        int op = b[i] & 0xFF;
        boolean string = (op >= 0xA4 && op <= 0xA7) || (op >= 0xAA && op <= 0xAF) || (op >= 0x6C && op <= 0x6F);
        if (rep && string && !repFirst) {
            code();                             // the opcode re-read from the queue (prefixes are kept)
        } else {
            code(i + 1);                        // prefixes and opcode
        }
        int read = i + 1;                       // bytes taken so far
        int modrm = read < b.length ? b[read] & 0xFF : 0xC0;
        int mod = modrm >> 6, rm = modrm & 7, reg = (modrm >> 3) & 7;
        boolean mem = mod != 3;
        int dispLen = mod == 1 ? 1 : mod == 2 ? 2 : (mod == 0 && rm == 6) ? 2 : 0;
        // ModRM byte, the base+index address cycle, then the displacement.
        Runnable modRm = () -> {
            code();
            if (mod != 3 && !(mod == 0 && rm == 6) && rm < 4) idle();
            code(dispLen);
        };
        int imm = b.length - (i + 1);           // bytes after the opcode, before any ModRM split
        boolean branchFlush = false;
        switch (op) {
            // ALU r/m forms: 1 internal, ModRM
            case 0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
                 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B, 0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B ->
                { idle(); modRm.run(); }
            // ALU accumulator, immediate
            case 0x04, 0x05, 0x0C, 0x0D, 0x14, 0x15, 0x1C, 0x1D, 0x24, 0x25, 0x2C, 0x2D, 0x34, 0x35, 0x3C, 0x3D,
                 0xA8, 0xA9 -> { idle(); code(imm); }
            case 0x06, 0x0E, 0x16, 0x1E -> idle();                   // PUSH sreg
            case 0x07, 0x17, 0x1F -> idle(2);                        // POP sreg
            case 0x27 -> idle(10);                                   // DAA
            case 0x2F -> idle(11);                                   // DAS
            case 0x37, 0x3F -> idle(9);                              // AAA, AAS
            case 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F -> idle();   // INC/DEC r16
            case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F -> { }       // PUSH/POP r16: accesses only
            case 0x60, 0x61 -> idle();                               // PUSHA, POPA
            case 0x62 -> { idle(12); modRm.run(); if (interrupted) idle(3); }   // BOUND
            case 0x68 -> code(2);                                    // PUSH imm16
            case 0x6A -> code(1);                                    // PUSH imm8
            case 0x69 -> { idle(3); modRm.run(); code(2); }          // IMUL r, r/m, imm16
            case 0x6B -> { idle(3); modRm.run(); code(1); }          // IMUL r, r/m, imm8
            case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
                 0xE3 -> { idle(); code(); if (taken) { idle(2); branchFlush = true; } }   // Jcc, JCXZ
            case 0xEB -> { idle(); code(); idle(2); branchFlush = true; }   // JMP short: unconditional, always taken (also JMP $+2)
            case 0x80, 0x81, 0x82, 0x83 -> { idle(); modRm.run(); code(op == 0x81 ? 2 : 1); }   // group 1
            case 0x84, 0x85 -> { idle(); modRm.run(); }              // TEST r/m, r
            case 0x86, 0x87 -> { idle(3); modRm.run(); }             // XCHG r/m, r
            case 0x88, 0x89, 0x8A, 0x8B -> { modRm.run(); if (!mem) idle(); }   // MOV r/m
            case 0x8C -> { idle(); modRm.run(); }                    // MOV r/m, sreg
            case 0x8E -> { idle(2); modRm.run(); }                   // MOV sreg, r/m
            case 0x8D -> { idle(); modRm.run(); }                    // LEA
            case 0x8F -> { idle(); modRm.run(); }                    // POP r/m
            case 0x90 -> idle();                                     // NOP
            case 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 -> idle(3);   // XCHG AX, r
            case 0x98, 0x99 -> idle();                               // CBW, CWD
            case 0x9A -> { code(4); idle(6); branchFlush = true; }   // CALL far
            case 0x9B -> idle(10);                                   // WAIT
            case 0x9C -> idle();                                     // PUSHF
            case 0x9D -> idle(2);                                    // POPF
            case 0x9E -> idle(4);                                    // SAHF
            case 0x9F -> idle(2);                                    // LAHF
            case 0xA0, 0xA1, 0xA2, 0xA3 -> code(2);                  // MOV acc, moffs
            case 0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0x6C, 0x6D, 0x6E, 0x6F -> {
                if (rep && repFirst) idle(5);
                int per = switch (op) {
                    case 0xA4, 0xA5 -> rep ? 5 : 3;                  // MOVS
                    case 0xA6, 0xA7 -> rep ? 8 : 4;                  // CMPS
                    case 0xAE, 0xAF -> rep ? 8 : 3;                  // SCAS
                    case 0x6C, 0x6D, 0x6E, 0x6F -> rep ? 4 : 3;      // INS, OUTS
                    default -> rep ? 5 : 2;                          // STOS, LODS
                };
                if (!(rep && accesses == 0)) idle(per);              // CX = 0: only the first-iteration setup
            }
            case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7 -> { code(1); idle(); }    // MOV r8, imm
            case 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF -> { code(2); idle(); }    // MOV r16, imm
            case 0xC0, 0xC1 -> { modRm.run(); code(1); idle(3); }    // shift r/m, imm8
            case 0xC2 -> { idle(4); code(2); branchFlush = true; }   // RET imm
            case 0xC3 -> { idle(4); branchFlush = true; }            // RET
            case 0xC4, 0xC5 -> { idle(4); modRm.run(); }             // LES, LDS
            case 0xC6, 0xC7 -> { modRm.run(); code(op == 0xC7 ? 2 : 1); }   // MOV r/m, imm
            case 0xC8 -> {                                           // ENTER
                idle(7); code(3);
                int levels = (b.length > i + 3 ? b[i + 3] & 0x1F : 0);
                if (levels > 1) idle(2 * (levels - 1));
            }
            case 0xC9 -> idle(2);                                    // LEAVE
            case 0xCA -> { idle(6); code(2); branchFlush = true; }   // RETF imm
            case 0xCB -> { idle(5); branchFlush = true; }            // RETF
            case 0xCC -> idle(5);                                    // INT3 (+ interrupt entry)
            case 0xCD -> { idle(6); code(1); }                       // INT n (+ interrupt entry)
            case 0xCE -> { idle(6); if (interrupted) idle(3); }      // INTO
            case 0xCF -> { idle(6); branchFlush = true; }            // IRET
            case 0xD0, 0xD1 -> { modRm.run(); idle(); }              // shift r/m, 1
            case 0xD2, 0xD3 -> { modRm.run(); idle(3); }             // shift r/m, CL
            case 0xD4 -> { idle(12); code(1); if (!interrupted) idle(4); }   // AAM
            case 0xD5 -> { idle(6); code(1); }                       // AAD
            case 0xD6 -> idle(8);                                    // SALC
            case 0xD7 -> idle(4);                                    // XLAT
            case 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF -> { idle(); code(1); }   // FPO1: 2-byte NOP
            case 0xE0, 0xE1 -> { idle(2); code(); if (taken) { idle(3); branchFlush = true; } }   // LOOPNZ/LOOPZ
            case 0xE2 -> { idle(); code(); if (taken) { idle(3); branchFlush = true; } }          // LOOP
            case 0xE4, 0xE5 -> { code(1); idle(5); idle(); }         // IN acc, imm (port access counted separately)
            case 0xEC, 0xED -> { idle(4); idle(); }                  // IN acc, DX
            case 0xE6, 0xE7 -> { code(1); idle(6); }                 // OUT imm, acc
            case 0xEE, 0xEF -> idle(4);                              // OUT DX, acc
            case 0xE8 -> { idle(2); code(2); branchFlush = true; }   // CALL near
            case 0xE9 -> { idle(3); code(2); branchFlush = true; }   // JMP near
            case 0xEA -> { idle(6); code(4); branchFlush = true; }   // JMP far
            case 0xF4 -> idle(12);                                   // HLT
            case 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD -> idle(4);   // flag ops
            case 0xF6, 0xF7 -> {                                     // group 3
                modRm.run(); idle();
                switch (reg) {
                    case 0 -> code(op == 0xF7 ? 2 : 1);              // TEST r/m, imm
                    case 4, 5 -> idle(2);                            // MUL, IMUL
                    case 6 -> { idle(11); if (!interrupted) idle(op == 0xF7 ? 11 : 3); }   // DIV
                    case 7 -> { idle(14); if (!interrupted) idle(op == 0xF7 ? 9 : 2); }    // IDIV
                    default -> { }
                }
            }
            case 0xFE, 0xFF -> {                                     // group 4/5
                modRm.run();
                switch (reg) {
                    case 0, 1 -> idle();                             // INC, DEC r/m
                    case 2 -> { idle(2); branchFlush = true; }       // CALL r/m
                    case 3 -> { idle(6); branchFlush = true; }       // CALL far r/m
                    case 4 -> { idle(4); branchFlush = true; }       // JMP r/m
                    case 5 -> { idle(7); branchFlush = true; }       // JMP far r/m
                    case 6 -> { }                                    // PUSH r/m
                    default -> idle();
                }
            }
            default -> idle();                                       // undefined opcodes: 1 cycle
        }
        access(accesses);
        if (interrupted) { idle(30); access(entryAccesses); flush(target); return instrCycles; }   // interrupt entry
        if (rep && string && repMore) repeatOpcode();
        if (branchFlush || (taken && !(rep && string))) flush(target);
        return instrCycles;
    }

    /** Hardware interrupt or exception entry: 30 internal cycles, then the entry bus accesses (3 pushes,
     *  2 vector reads; split words count 2), flush to the handler. */
    public long interrupt(long handler, int extraIdle, int entryAccesses) {
        instrCycles = 0;
        idle(extraIdle + 30);
        access(entryAccesses);
        flush(handler);
        return instrCycles;
    }

    /** One halted cycle (the prefetcher keeps running). */
    public void halted() { instrCycles = 0; idle(); }

    static boolean isPrefix(int b) {
        return b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0xF0 || b == 0xF2 || b == 0xF3;
    }
}
