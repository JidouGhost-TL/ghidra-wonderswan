// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;

import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Headless WonderSwan machine on Ghidra's p-code emulator.
 *
 * A deterministic probe, not a game player: runs the cartridge far enough to observe what
 * code executes, with which segment registers, what the game DMAs where, and who writes VRAM.
 *
 * Modelled: memory map + bank ports C0-C3 (ROM bytes copied into the windows on switch),
 * general DMA (40-48), the interrupt controller (B0 vector base / request read-back, B2 enable,
 * B4 status latch, B6 acknowledge; edge and level sources per WSdev Interrupts), the CPU side of
 * interrupts (IF, one-instruction shadow after STI/POPF/IRET that set IF and after MOV/POP SS,
 * HLT halted state, TF single-step trap, divide-error trap via the language's swi(0)), line
 * counter (02) with line-match and VBlank IRQs, HBlank/VBlank timers (A2-AB), the UART
 * send-ready level IRQ (B1/B3; bytes sent instantly, nothing received), scripted keypad (B5),
 * the internal (BA-BE) and cartridge (C4-C8) serial EEPROMs ({@link WSEeprom}), cartridge SRAM in the
 * 1000:0000 window (bank port C1, mirrored to its size), with load/save of all three images. Every
 * other port stores writes and reads back the last value. Not modelled: sound, sound DMA, RTC,
 * cycle timing.
 *
 * Requires the V30MZ language. These games run code with CS not 64 KiB-aligned (e.g. 4400:xxxx);
 * Ghidra's x86 real mode derives CS from the linear address ((linear >> 4) & 0xF000), which is
 * wrong for that code (CS-relative tables, PUSH CS, interrupt return addresses). The machine reads
 * the CS register as the CPU state; it is only trustworthy with a language that tracks real CS.
 */
public class WSMachine {
    public final Language lang;
    public final AddressSpace ram;
    public final byte[] rom;
    public final int[] ports = new int[256];
    public final PcodeEmulator emu;
    public final PcodeThread<byte[]> thread;
    public final boolean color;

    public int buttons;             // bit1 Start, bit2 A, bit3 B; bits 4-7 X pad; 8-11 Y pad
    public static final int LINES = 159, VISIBLE = 144;
    /** Display ports as they were at the start of each visible line of the last frame (raster state). */
    public final int[][] linePorts = new int[VISIBLE][];
    private int currentLine;
    public long instructions;
    /** Stores into the SRAM window. */
    public long sramWrites;
    /** Internal EEPROM (16 Kbit on colour hardware, 1 Kbit on mono). */
    public final WSEeprom internalEeprom;
    /** Cartridge EEPROM, or null when the footer declares none. */
    public final WSEeprom cartEeprom;
    /** Cartridge SRAM contents, or null when the footer declares none. */
    public final byte[] sram;

    /** Executed instruction linear address -> observed (DS, ES, SS) triples. */
    public final Map<Long, Set<Integer>> executed = new TreeMap<>();
    /** Executed instruction linear address -> (C0, C2, C3) at execution time, packed. */
    public final Map<Long, Integer> executedBanks = new HashMap<>();
    /** Executed ROM0/ROM1 window address (linear 20000-3FFFF) -> every bank value (16-bit, incl. 2003-mapper high byte) it executed under. */
    public final Map<Long, Set<Integer>> windowBanks = new TreeMap<>();
    public final List<String> dmaLog = new ArrayList<>();
    /** Last 64 executed instructions: "linear  text", newest last. Filled when run() returns or throws
     *  (formatting every step is expensive; the steps are kept in a ring meanwhile). */
    public final ArrayDeque<String> trace = new ArrayDeque<>();
    private final long[] ringLin = new long[64];
    private final Instruction[] ringIns = new Instruction[64];
    private long ringCount;
    /** Stop (throw) when this linear PC is about to execute; -1 = never. */
    public long stopAt = -1;
    public volatile boolean stopped;
    public final Map<String, Integer> bankWrites = new TreeMap<>();
    public final Map<Long, Long> vramFirstWriter = new HashMap<>();
    public final Map<Long, Long> vramWriterBytes = new TreeMap<>();

    private final Register rCS, rDS, rES, rSS, rSP, rCsval, rIF, rTF;
    /** I/O port space of the V30MZ language (IN/OUT are loads/stores there); null on other languages. */
    public final AddressSpace io;
    private long lastCsval = -1;
    /** Set after an instruction that can change CS; the next step re-syncs csval. */
    private boolean csMayHaveChanged = true;
    private static final List<Integer> PREFIXES = List.of(0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3);
    private static final Set<String> CS_WRITERS = Set.of("CALLF", "JMPF", "RETF", "IRET", "INT", "INT3", "INTO");
    /** Executed linear address -> CS seen at first execution (needed to disassemble it with the right csval). */
    public final Map<Long, Integer> csAt = new HashMap<>();
    /**
     * Observed control-flow edges whose target is not encoded in the instruction: computed JMP/CALL
     * (kind "jump"/"call"), software interrupts ("int") and injected hardware interrupts ("irq").
     * Key "from,to,targetCS,kind" (linear hex; from = -1 for irq) -> count.
     */
    public final Map<String, Integer> edges = new TreeMap<>();
    private long pendingFrom = -1;
    private String pendingKind;
    /** Visits per executed address; DS/ES sets are sampled for the first 64 visits (as the Mesen trace does). */
    private final Map<Long, Integer> visits = new HashMap<>();

    // ---- CPU interrupt state (see run()) -----------------------------------------------------
    /** HLT executed: no instruction runs until an interrupt is requested (B4 != 0), even with IF=0. */
    public boolean halted;
    /** Lines (or remainders of lines) spent halted. */
    public long haltedLines;
    /** Set by the instruction just executed: no maskable interrupt at the next boundary
     *  (STI/POPF/IRET that set IF, POPF/IRET that set TF, MOV/POP SS). */
    private boolean suppressIrq;
    /** Set by the instruction just executed: no single-step trap after it (POPF/IRET that set TF, MOV/POP SS). */
    private boolean suppressTrap;
    private boolean ifBefore, tfBefore;
    /** Interrupt status latch (port B4). */
    private int irqStatus;
    /** Timer counters (ports A8/A9 and AA/AB). */
    private int hTimer, vTimer;
    /** Bytes written to the UART transmit port B1 (sent instantly; there is no peer). */
    public final java.io.ByteArrayOutputStream serialOut = new java.io.ByteArrayOutputStream();

    // ---- hooks for test harnesses -------------------------------------------------------------
    /** Called before every instruction (after interrupt entry, so the PC is the instruction about to run). */
    public java.util.function.Consumer<WSMachine> beforeStep;
    /** Called when stepping throws; return true to continue with the next step (the handler fixed the
     *  state), false to rethrow. */
    public java.util.function.BiPredicate<WSMachine, RuntimeException> onFault;

    /** Observer of CPU data accesses to the ram space (loads before they read, stores after they write). */
    public interface MemoryWatch {
        /** @param store true for a store; value = stored bytes little-endian (loads: the bytes about to be read)
         *  @param pc linear address of the executing instruction */
        void access(WSMachine m, boolean store, long linear, int size, long value, long pc);
    }

    /** Optional memory-access observer; null = none (no cost). */
    public MemoryWatch memoryWatch;

    public WSMachine(Program program, boolean color) {
        this.lang = program.getLanguage();
        this.ram = lang.getDefaultSpace();
        this.color = color;
        List<FileBytes> fbs = program.getMemory().getAllFileBytes();
        if (fbs.isEmpty()) throw new IllegalStateException("program has no stored ROM bytes (import with the WonderSwan loader)");
        FileBytes fb = fbs.get(0);
        rom = new byte[(int) fb.getSize()];
        try { fb.getOriginalBytes(0, rom); } catch (Exception e) { throw new IllegalStateException(e); }
        rCS = lang.getRegister("CS"); rDS = lang.getRegister("DS"); rES = lang.getRegister("ES");
        rSS = lang.getRegister("SS"); rSP = lang.getRegister("SP");
        rCsval = lang.getRegister("csval");
        rIF = lang.getRegister("IF"); rTF = lang.getRegister("TF");
        io = lang.getAddressFactory().getAddressSpace("io");
        if (rCsval == null || io == null)
            throw new IllegalStateException("WSMachine requires the V30MZ language (csval context + io space); program uses " + lang.getLanguageID());
        WSHeader hdr = WSHeader.parse(rom);
        internalEeprom = new WSEeprom(true, color ? 0x800 : 0x80);
        int eep = WSHardware.cartEepromBytes(hdr.saveCode), sr = WSHardware.sramBytes(hdr.saveCode);
        cartEeprom = eep > 0 ? new WSEeprom(false, eep) : null;
        sram = sr > 0 ? new byte[sr] : null;
        ports[0xC0] = WSHardware.RESET_C0; ports[0xC2] = WSHardware.RESET_C2; ports[0xC3] = WSHardware.RESET_C3;
        ports[0xC1] = 0xFF; ports[0xCF] = ports[0xD0] = ports[0xD2] = ports[0xD4] = 0xFF;
        ports[0xA0] = WSHardware.systemControlAtEntry(hdr);
        for (int[] pv : WSHardware.PORTS_AT_ENTRY) ports[pv[0]] = pv[1];

        emu = new PcodeEmulator(lang, new Callbacks());
        thread = emu.newThread();
        mapLinear(); mapBank(0xC2, 0x20000); mapBank(0xC3, 0x30000);
        if (color) {   // WSC palette RAM reads 0xFF at cartridge entry
            byte[] ff = new byte[0x200];
            Arrays.fill(ff, (byte) 0xFF);
            write(0xFE00, ff);
        }
        // Cartridge entry state (boot ROM skipped): CS:IP = FFFF:0000 executes the footer JMP FAR.
        int[] r = WSHardware.registersAtEntry(hdr);
        String[] names = { "AX", "BX", "CX", "DX", "SI", "DI", "SP", "BP", "DS", "ES", "SS", "CS" };
        for (int i = 0; i < names.length; i++) {
            Register reg = lang.getRegister(names[i]);
            if (reg != null) setReg(reg, r[i]);
        }
        unpackFlags(r[13]);
        thread.overrideCounter(addr(((long) r[11] << 4) + r[12]));
        // Decode context: hardware-faithful undefined opcodes (hwundef=1, v30mz README) and the SoC
        // (colorsoc: MUL's ZF is set on the colour SoC, cleared on the mono one).
        RegisterValue ctx = thread.getContext();
        Register rHw = lang.getRegister("hwundef"), rSoc = lang.getRegister("colorsoc");
        if (rHw != null) ctx = ctx.assign(rHw, BigInteger.ONE);
        if (rSoc != null) ctx = ctx.assign(rSoc, color ? BigInteger.ONE : BigInteger.ZERO);
        thread.overrideContext(ctx);
        syncCsval();
    }

    // ------------------------------------------------------------------ memory
    public Address addr(long linear) { return ram.getAddress(linear & 0xFFFFF); }

    public byte[] read(long linear, int n) {
        return emu.getSharedState().getVar(addr(linear), n, false, Reason.INSPECT);
    }

    public void write(long linear, byte[] b) {
        emu.getSharedState().setVar(addr(linear), b.length, false, b);
    }

    private byte[] romSlice(long off, int n) {
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = rom[(int) ((off + i) & (rom.length - 1))];
        return out;
    }

    private void mapLinear() {
        for (int seg = 4; seg < 16; seg++) {
            long lin = (long) seg << 16;
            write(lin, romSlice(WSHardware.linearToRom(lin, ports[0xC0], rom.length), 0x10000));
        }
    }

    /** Current 16-bit bank number for C1/C2/C3 (2003 mapper high bytes in D1/D3/D5). */
    public int bank(int port) {
        int hi = port == 0xC1 ? 0xD1 : port == 0xC2 ? 0xD3 : 0xD5;
        return ports[port] | ports[hi] << 8;
    }

    private void mapBank(int port, long window) {
        write(window, romSlice(WSHardware.bankToRom(bank(port), rom.length), 0x10000));
    }

    /** ROM offset of a linear address under the current bank registers, or -1 for RAM/SRAM. */
    public long romOffset(long linear) {
        if (linear >= 0x40000) return WSHardware.linearToRom(linear, ports[0xC0], rom.length);
        if (linear >= 0x30000) return WSHardware.bankToRom(bank(0xC3), rom.length) | (linear & 0xFFFF);
        if (linear >= 0x20000) return WSHardware.bankToRom(bank(0xC2), rom.length) | (linear & 0xFFFF);
        return -1;
    }

    // ------------------------------------------------------------------ registers
    public long reg(Register r) {
        byte[] v = thread.getState().getVar(r, Reason.INSPECT);
        long x = 0;
        for (int i = v.length - 1; i >= 0; i--) x = (x << 8) | (v[i] & 0xff);   // little-endian
        return x;
    }

    public void setReg(Register r, long value) {
        byte[] v = new byte[r.getMinimumByteSize()];
        for (int i = 0; i < v.length; i++) v[i] = (byte) (value >> (8 * i));
        thread.getState().setVar(r, v);
    }

    private static final String[] FLAG_BITS = { "CF", null, "PF", null, "AF", null, "ZF", "SF", "TF", "IF", "DF", "OF" };

    public int packFlags() {
        int f = 0xF002;   // V30MZ: reserved bits read as 1 except bit 1 set
        for (int b = 0; b < FLAG_BITS.length; b++) {
            if (FLAG_BITS[b] == null) continue;
            Register r = lang.getRegister(FLAG_BITS[b]);
            if (r != null && reg(r) != 0) f |= 1 << b;
        }
        return f;
    }

    public void unpackFlags(int f) {
        for (int b = 0; b < FLAG_BITS.length; b++) {
            if (FLAG_BITS[b] == null) continue;
            Register r = lang.getRegister(FLAG_BITS[b]);
            if (r != null) setReg(r, (f >> b) & 1);
        }
    }

    public long linearPC() { return thread.getCounter().getOffset(); }

    /** Keep the decoder's csval context equal to the CS register (the language derives CS:IP
     *  arithmetic from csval; far transfers write the CS register). */
    public void syncCsval() {
        long cs = reg(rCS);
        // No "unchanged" shortcut: the decoder's flowing csval can change without a sync (JMPF/CALLF
        // ptr16:16 globalset), so a cached last value can be stale.
        RegisterValue ctx = thread.getContext().assign(rCsval, BigInteger.valueOf(cs));
        thread.overrideContext(ctx);
        lastCsval = cs;
    }

    // ------------------------------------------------------------------ ports
    int portIn(int port, int size) {
        int v;
        switch (port) {
            case 0x02: return currentLine;
            case 0xB5: {
                int sel = ports[0xB5] & 0x70, k = 0;
                if ((sel & 0x40) != 0) k |= buttons & 0x0F;
                if ((sel & 0x20) != 0) k |= (buttons >> 4) & 0x0F;
                if ((sel & 0x10) != 0) k |= (buttons >> 8) & 0x0F;
                return (ports[0xB5] & 0xF0) | k;
            }
            case 0xA8: case 0xA9: case 0xAA: case 0xAB: {   // timer counters
                int c = port < 0xAA ? hTimer : vTimer;
                v = (port & 1) == 0 ? c & 0xFF : c >> 8;
                if (size == 2 && (port & 1) == 0) v |= (c & 0xFF00);
                return v;
            }
            case 0xB0: {                                  // vector base | highest requested level
                int act = activeIrqs(), hi = 0;
                for (int l = 7; l >= 0; l--) if ((act >> l & 1) != 0) { hi = l; break; }
                return (ports[0xB0] & 0xF8) | hi;
            }
            case 0xB1: return 0;                         // UART receive buffer (nothing is received)
            case 0xB3:                                    // UART status: enable, speed, TX empty
                return (ports[0xB3] & 0xC0) | ((ports[0xB3] & 0x80) != 0 ? 0x04 : 0);
            case 0xB4: return activeIrqs();
            case 0xB6: return 0;
            case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE:
                v = internalEeprom.read(port - 0xBA, instructions);
                if (size == 2 && port < 0xBE) v |= internalEeprom.read(port - 0xBA + 1, instructions) << 8;
                return v;
            case 0xC4: case 0xC5: case 0xC6: case 0xC7: case 0xC8:
                if (cartEeprom == null) return 0xFF;      // no cartridge EEPROM: open bus
                v = cartEeprom.read(port - 0xC4, instructions);
                if (size == 2 && port < 0xC8) v |= cartEeprom.read(port - 0xC4 + 1, instructions) << 8;
                return v;
            default:
                v = ports[port & 0xFF];
                if (size == 2) v |= ports[(port + 1) & 0xFF] << 8;
                return v;
        }
    }

    void portOut(int port, int size, int value) {
        for (int k = 0; k < size; k++) {
            int p = (port + k) & 0xFF;
            int b = (value >> (8 * k)) & 0xFF;
            if (p == 0xB4) continue;                              // read-only status
            if (p == 0xB6) { irqStatus &= ~b; continue; }         // acknowledge
            if (p == 0xB1) serialOut.write(b);                    // UART transmit (instant)
            ports[p] = b;
            for (int[] al : WSHardware.MAPPER_ALIASES) {           // 2003-mapper mirrors, both directions
                if (p == al[0]) ports[al[1]] = ports[p];
                else if (p == al[1]) ports[al[0]] = ports[p];
            }
            if ((p >= 0xC0 && p <= 0xC3) || (p >= 0xCF && p <= 0xD5))
                bankWrites.merge(String.format("%02X=%02X", p, ports[p]), 1, Integer::sum);
        }
        boolean touches = false;
        for (int k = 0; k < size; k++) {
            int p = (port + k) & 0xFF;
            if (p == 0xC0 || p == 0xCF) mapLinear();
            if (p == 0xC2 || p == 0xD2 || p == 0xD3) mapBank(0xC2, 0x20000);
            if (p == 0xC3 || p == 0xD4 || p == 0xD5) mapBank(0xC3, 0x30000);
            if (p == 0x48) touches = true;
            if (p >= 0xBA && p <= 0xBE)
                internalEeprom.write(p - 0xBA, ports[p], instructions, colorMode(), linearPC());
            if (p >= 0xC4 && p <= 0xC8 && cartEeprom != null)
                cartEeprom.write(p - 0xC4, ports[p], instructions, colorMode(), linearPC());
            if (p == 0xA4 || p == 0xA5) hTimer = ports[0xA4] | ports[0xA5] << 8;   // reload -> counter
            if (p == 0xA6 || p == 0xA7) vTimer = ports[0xA6] | ports[0xA7] << 8;
        }
        if (touches && (ports[0x48] & 0x80) != 0) dma();
    }

    /** Colour mode (port 60 bit 7) on colour hardware. */
    public boolean colorMode() { return color && (ports[0x60] & 0x80) != 0; }

    /** SRAM offset of an address in the 1000:0000 window under the current C1 bank (SRAM mirrors to its size). */
    private int sramOffset(long linear) {
        return (int) ((((long) bank(0xC1) << 16) | (linear & 0xFFFF)) & (sram.length - 1));
    }

    // ------------------------------------------------------------------ save images
    public static final String INTERNAL_EEPROM_FILE = "internal.eeprom", CART_EEPROM_FILE = "cart.eeprom", SRAM_FILE = "cart.sram";

    /** Load whichever save images exist in dir (sizes must match); returns the files loaded. */
    public List<String> loadSaves(java.nio.file.Path dir) throws java.io.IOException {
        List<String> got = new ArrayList<>();
        java.nio.file.Path f = dir.resolve(INTERNAL_EEPROM_FILE);
        if (java.nio.file.Files.exists(f)) { internalEeprom.load(java.nio.file.Files.readAllBytes(f)); got.add(INTERNAL_EEPROM_FILE); }
        f = dir.resolve(CART_EEPROM_FILE);
        if (java.nio.file.Files.exists(f)) {
            if (cartEeprom == null) throw new IllegalArgumentException(f + ": this cartridge has no EEPROM");
            cartEeprom.load(java.nio.file.Files.readAllBytes(f)); got.add(CART_EEPROM_FILE);
        }
        f = dir.resolve(SRAM_FILE);
        if (java.nio.file.Files.exists(f)) {
            if (sram == null) throw new IllegalArgumentException(f + ": this cartridge has no SRAM");
            byte[] b = java.nio.file.Files.readAllBytes(f);
            if (b.length != sram.length) throw new IllegalArgumentException(f + ": " + b.length + " bytes, SRAM is " + sram.length);
            System.arraycopy(b, 0, sram, 0, b.length); got.add(SRAM_FILE);
        }
        return got;
    }

    /** Write the save images this machine has (internal EEPROM always; cartridge EEPROM / SRAM if present). */
    public void writeSaves(java.nio.file.Path dir) throws java.io.IOException {
        java.nio.file.Files.createDirectories(dir);
        java.nio.file.Files.write(dir.resolve(INTERNAL_EEPROM_FILE), internalEeprom.data);
        if (cartEeprom != null) java.nio.file.Files.write(dir.resolve(CART_EEPROM_FILE), cartEeprom.data);
        if (sram != null) java.nio.file.Files.write(dir.resolve(SRAM_FILE), sram);
    }

    private void dma() {
        long src = ports[0x40] | ports[0x41] << 8 | (long) (ports[0x42] & 0x0F) << 16;
        long dst = ports[0x44] | ports[0x45] << 8;
        int n = ports[0x46] | ports[0x47] << 8;
        if (n > 0) write(dst, read(src, n));
        dmaLog.add(String.format("{\"src\":%d,\"rom_off\":%d,\"dst\":%d,\"len\":%d,\"at\":%d,\"insns\":%d}",
            src, romOffset(src), dst, n, linearPC(), instructions));
        ports[0x46] = ports[0x47] = 0;
        ports[0x48] &= 0x7F;
    }

    // ------------------------------------------------------------------ interrupts
    /** Inject a hardware interrupt at `level` (6 = VBlank) if enabled; returns true if taken. */
    public final Map<String, Integer> irqStats = new TreeMap<>();
    public final Map<String, Integer> accessStats = new TreeMap<>();
    /** Full register trace of the first traceLimit instructions, Mesen trace.tsv format. */
    public int traceLimit = 20000;
    public final List<String> firstTrace = new ArrayList<>();
    private long lastTraced = -1;

    /**
     * Request an edge-triggered hardware interrupt (WSdev Interrupts): the status bit in B4 is set
     * only if the level is enabled in B2 at this moment. The CPU takes it at the next instruction
     * boundary where IF=1 (see {@link #run}); it stays requested until acknowledged through B6.
     * Returns true if the request was latched.
     */
    public boolean raiseIrq(int level) {
        if (((ports[0xB2] >> level) & 1) == 0) { irqStats.merge("masked", 1, Integer::sum); return false; }
        irqStatus |= 1 << level;
        irqStats.merge("requested", 1, Integer::sum);
        return true;
    }

    /** Interrupt status (B4) including the level-triggered sources (UART send ready, level 0: the
     *  transmit buffer is always empty, so it is requested whenever the UART and level 0 are enabled). */
    public int activeIrqs() {
        if ((ports[0xB3] & 0x80) != 0 && (ports[0xB2] & 1) != 0) irqStatus |= 1;
        return irqStatus;
    }

    private boolean flag(Register r) { return reg(r) != 0; }

    /** Interrupt entry: push FLAGS, CS, IP (IP = ipLinear relative to CS), clear IF and TF, jump through
     *  vector `vec`. Used for hardware interrupts and the single-step trap (CPU exceptions raised by
     *  instructions go through the language's swi userop). */
    private void enterInterrupt(int vec, long ipLinear, String kind) {
        int cs = (int) reg(rCS);
        int ip = (int) ((ipLinear - ((long) cs << 4)) & 0xFFFF);
        int sp = (int) reg(rSP), ss = (int) reg(rSS);
        for (int w : new int[] { packFlags(), cs, ip }) {
            sp = (sp - 2) & 0xFFFF;
            write(((long) ss << 4) + sp, new byte[] { (byte) w, (byte) (w >> 8) });
        }
        setReg(rSP, sp);
        setReg(rIF, 0);
        setReg(rTF, 0);
        byte[] v = read(vec * 4L, 4);
        int off = (v[0] & 0xff) | (v[1] & 0xff) << 8, seg = (v[2] & 0xff) | (v[3] & 0xff) << 8;
        setReg(rCS, seg);
        thread.overrideCounter(addr(((long) seg << 4) + off));
        syncCsval();
        csMayHaveChanged = false;
        edges.merge(String.format("%x,%x,%x,%s", -1L & 0xFFFFF, (((long) seg << 4) + off) & 0xFFFFF, seg, kind), 1, Integer::sum);
    }

    /**
     * Instruction boundary: leave the halted state when an interrupt is requested (also with IF=0,
     * then execution just continues after the HLT), and take the highest requested hardware interrupt
     * when IF=1 and the previous instruction did not open an interrupt shadow. Returns false while
     * halted with nothing requested.
     */
    private boolean boundary() {
        int act = activeIrqs();
        if (halted) {
            if (act == 0) return false;
            halted = false;
        }
        if (act != 0 && !suppressIrq && flag(rIF)) {
            int hi = 7;
            while ((act >> hi & 1) == 0) hi--;
            irqStats.merge("taken", 1, Integer::sum);
            enterInterrupt((ports[0xB0] & 0xF8) + hi, linearPC(), "irq");
        }
        suppressIrq = false;
        return true;
    }

    /** After an instruction: single-step trap (INT 1, pushed IP = next instruction) when TF is set,
     *  unless the instruction just set TF (POPF/IRET) or loaded SS. */
    private void afterStep() {
        if (!suppressTrap && flag(rTF)) {
            irqStats.merge("trap", 1, Integer::sum);
            enterInterrupt(1, linearPC(), "trap");
        }
        suppressTrap = false;
    }

    private void tickTimers(boolean vblank) {
        int ctl = ports[0xA2];
        // WSdev Timers: the IRQ fires when the counter is 1 at the tick (even if counting is disabled);
        // an enabled counter then counts down and, in repeat mode, reloads on reaching 0.
        if (hTimer == 1) raiseIrq(7);
        if ((ctl & 1) != 0 && hTimer != 0 && --hTimer == 0 && (ctl & 2) != 0) hTimer = ports[0xA4] | ports[0xA5] << 8;
        if (!vblank) return;
        if (vTimer == 1) raiseIrq(5);
        if ((ctl & 4) != 0 && vTimer != 0 && --vTimer == 0 && (ctl & 8) != 0) vTimer = ports[0xA6] | ports[0xA7] << 8;
    }

    /**
     * Run `frames` frames of `slice` instructions each, split evenly over 159 lines (144 visible).
     * Port 02 reports the current line; at the start of each line the HBlank timer ticks, the
     * line-match interrupt (level 4) is requested at line LINE_CMP (port 03), VBlank (level 6) and the
     * VBlank timer tick at line 144 (WSdev Display#Interrupts, Timers). Display ports are snapshotted
     * at the start of each visible line for the renderer. While the CPU is halted the rest of the
     * line is skipped (no instructions run, `instructions` does not advance).
     */
    public void run(int frames, int slice, java.util.function.IntConsumer onFrame) {
        try {
            runFrames(frames, slice, onFrame);
        } finally {
            trace.clear();
            for (long k = Math.max(0, ringCount - 64); k < ringCount; k++) {
                int ri = (int) (k & 63);
                trace.addLast(String.format("%05x %s", ringLin[ri], ringIns[ri]));
            }
        }
    }

    private void runFrames(int frames, int slice, java.util.function.IntConsumer onFrame) {
        int perLine = Math.max(1, slice / LINES);
        for (int f = 0; f < frames; f++) {
            if (onFrame != null) onFrame.accept(f);
            for (int ln = 0; ln < LINES; ln++) {
                currentLine = ln;
                tickTimers(ln == VISIBLE);
                if (ln == ports[0x03]) raiseIrq(4);
                if (ln == VISIBLE) raiseIrq(6);
                if (ln < VISIBLE) linePorts[ln] = ports.clone();
                for (int i = 0; i < perLine; i++) {
                    if (!boundary()) { haltedLines++; break; }
                    if (csMayHaveChanged) { syncCsval(); csMayHaveChanged = false; }
                    if (beforeStep != null) beforeStep.accept(this);
                    try {
                        thread.stepInstruction();
                    } catch (RuntimeException e) {
                        if (onFault == null || !onFault.test(this, e)) throw e;
                        suppressIrq = suppressTrap = false;
                        continue;
                    }
                    instructions++;
                    afterStep();
                    if (stopped) throw new IllegalStateException(String.format("stopAt %05x reached", stopAt));
                }
            }
        }
    }

    // ------------------------------------------------------------------ callbacks
    private class Callbacks implements PcodeEmulationCallbacks<byte[]> {
        /** io varnodes the current instruction writes directly (constant port numbers compile to
         *  plain varnodes in the io space, not LOAD/STORE ops, so the load/store callbacks miss them). */
        private final List<Varnode> pendingIoWrites = new ArrayList<>();

        @Override
        public void beforeExecuteInstruction(PcodeThread<byte[]> t, Instruction ins, PcodeProgram program) {
            pendingIoWrites.clear();
            ifBefore = flag(rIF);
            tfBefore = flag(rTF);
            for (PcodeOp op : program.getCode()) {
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode in = op.getInput(i);
                    if (in.getAddress().getAddressSpace() == io) {
                        int port = (int) in.getOffset() & 0xFF;
                        int v = portIn(port, in.getSize());
                        byte[] b = new byte[in.getSize()];
                        for (int k = 0; k < b.length; k++) b[k] = (byte) (v >> (8 * k));
                        emu.getSharedState().setVar(in.getAddress(), b.length, false, b);
                        accessStats.merge("in:direct", 1, Integer::sum);
                    }
                }
                Varnode out = op.getOutput();
                if (out != null && out.getAddress().getAddressSpace() == io) pendingIoWrites.add(out);
            }
            long lin = ins.getAddress().getOffset();
            boolean repIteration = lin == lastTraced && ins.getMnemonicString().contains(".REP");
            lastTraced = lin;
            if (firstTrace.size() < traceLimit && !repIteration) {
                firstTrace.add(String.format("%d\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x\t%04x",
                    firstTrace.size() + 1, reg(rCS), (lin - (reg(rCS) << 4)) & 0xFFFF,
                    reg(lang.getRegister("AX")), reg(lang.getRegister("BX")), reg(lang.getRegister("CX")), reg(lang.getRegister("DX")),
                    reg(lang.getRegister("SI")), reg(lang.getRegister("DI")), reg(lang.getRegister("BP")), reg(rSP),
                    reg(rDS), reg(rES), reg(rSS), packFlags()));
            }
            int ri = (int) (ringCount++ & 63);
            ringLin[ri] = lin;
            ringIns[ri] = ins;
            if (lin == stopAt) stopped = true;
            if (pendingFrom >= 0) {
                edges.merge(String.format("%x,%x,%x,%s", pendingFrom, lin, reg(rCS), pendingKind), 1, Integer::sum);
                pendingFrom = -1;
            }
            if (ins.getFlowType().isComputed() && (ins.getFlowType().isJump() || ins.getFlowType().isCall())) {
                pendingFrom = lin;
                pendingKind = ins.getFlowType().isCall() ? "call" : "jump";
            }
            if (lin >= 0x20000 && lin < 0x40000)    // B1: every ROM bank a window address executes under
                windowBanks.computeIfAbsent(lin, k -> new TreeSet<>()).add(bank(lin < 0x30000 ? 0xC2 : 0xC3));
            int v = visits.merge(lin, 1, Integer::sum);
            if (v == 1) csAt.put(lin, (int) reg(rCS));
            if (v <= 64) {
                Set<Integer> s = executed.get(lin);
                if (s == null) { s = new HashSet<>(); executed.put(lin, s); executedBanks.put(lin, ports[0xC0] << 16 | ports[0xC2] << 8 | ports[0xC3]); }
                s.add((int) (reg(rDS) << 16 | reg(rES)));
            }
        }

        @Override
        public void afterExecuteInstruction(PcodeThread<byte[]> t, Instruction ins) {
            String mn = ins.getMnemonicString();
            if (CS_WRITERS.contains(mn)) csMayHaveChanged = true;
            // Interrupt shadow (WSdev NEC V30MZ interrupts, datasheet [DS:2843-2853]; ws-test-suite
            // interrupt_timing): STI/POPF/IRET that set IF delay maskable interrupts by one instruction;
            // POPF/IRET that set TF delay both; a load of SS (MOV SS / POP SS) delays both.
            // SOURCE-CONFLICT (brief 10 #5): STSWS says any segment register; datasheet/WSdev/Mesen 2
            // say SS only -> SS only.
            boolean ifSet = !ifBefore && flag(rIF), tfSet = !tfBefore && flag(rTF);
            boolean ssLoad = ("MOV".equals(mn) || "POP".equals(mn)) && loadsSS(ins);
            suppressIrq = ifSet || tfSet || ssLoad;
            suppressTrap = tfSet || ssLoad;
            for (Varnode out : pendingIoWrites) {
                byte[] b = emu.getSharedState().getVar(out.getAddress(), out.getSize(), false, Reason.INSPECT);
                portOut((int) out.getOffset() & 0xFF, out.getSize(), (int) le(b));
                accessStats.merge("out:direct", 1, Integer::sum);
            }
            pendingIoWrites.clear();
        }

        @Override
        public void beforeLoad(PcodeThread<byte[]> t, PcodeOp op, AddressSpace space, byte[] offset, int size) {
            accessStats.merge("load:" + space.getName(), 1, Integer::sum);
            if (space == ram && memoryWatch != null) {
                long a = le(offset);
                byte[] cur = emu.getSharedState().getVar(ram.getAddress(a), size, false, Reason.INSPECT);
                memoryWatch.access(WSMachine.this, false, a, size, le(cur), t.getCounter().getOffset());
            }
            if (space == ram && sram != null) {
                long a = le(offset);
                if (a >= 0x10000 && a < 0x20000) {
                    byte[] b = new byte[size];
                    for (int i = 0; i < size; i++) b[i] = sram[sramOffset(a + i)];
                    emu.getSharedState().setVar(ram.getAddress(a), size, false, b);
                }
                return;
            }
            if (space != io) return;
            int port = (int) le(offset) & 0xFF;            // the SoC decodes the low 8 bits
            int v = portIn(port, size);
            byte[] b = new byte[size];
            for (int i = 0; i < size; i++) b[i] = (byte) (v >> (8 * i));
            emu.getSharedState().setVar(io.getAddress(le(offset)), size, false, b);
        }

        @Override
        public void afterStore(PcodeThread<byte[]> t, PcodeOp op, AddressSpace space, byte[] offset, int size, byte[] value) {
            accessStats.merge("store:" + space.getName(), 1, Integer::sum);
            if (space == io) {
                portOut((int) le(offset) & 0xFF, size, (int) le(value));
                return;
            }
            if (space != ram) return;
            long a = le(offset);
            if (memoryWatch != null) memoryWatch.access(WSMachine.this, true, a, size, le(value), t.getCounter().getOffset());
            if (sram != null && a >= 0x10000 && a < 0x20000) {
                for (int i = 0; i < size; i++) sram[sramOffset(a + i)] = value[i];
                sramWrites++;
                return;
            }
            if (a < 0x2000 || a >= 0xFE00) return;
            long pc = t.getCounter().getOffset();
            for (int i = 0; i < size; i++) vramFirstWriter.putIfAbsent(a + i, pc);
            vramWriterBytes.merge(pc, (long) size, Long::sum);
        }

        @Override
        public boolean handleMissingUserop(PcodeThread<byte[]> t, PcodeOp op, PcodeFrame frame, String name,
                PcodeUseropLibrary<byte[]> library) {
            ThreadPcodeExecutorState<byte[]> st = t.getState();
            switch (name) {
                case "segment": {
                    long base = val(st, op.getInput(1)), inner = val(st, op.getInput(2));
                    put(st, op.getOutput(), ((base << 4) + inner) & 0xFFFFF);
                    return true;
                }
                case "swi": {                                  // INT n / INT3 / INTO / BOUND: returns the handler
                    long target = instructionInterrupt(t, (int) val(st, op.getInput(1)) & 0xFF);
                    if (op.getOutput() != null) put(st, op.getOutput(), target);   // p-code then does call [target]
                    return true;
                }
                case "divtrap": {                              // DIV/IDIV/AAM 0 divide error: INT 0, branch now
                    long target = instructionInterrupt(t, 0);
                    irqStats.merge("divtrap", 1, Integer::sum);
                    t.overrideCounter(addr(target));
                    frame.finishAsBranch();
                    return true;
                }
                case "halt":                                  // HLT: wait for an interrupt request (run())
                    halted = true;
                    return true;
                case "LOCK": case "UNLOCK":
                    return true;
                default:
                    return false;
            }
        }

        /** Interrupt entry raised by the executing instruction: push FLAGS, CS and the IP of the NEXT
         *  instruction, IF=TF=0, CS from vector `vec`; returns the linear handler address. */
        private long instructionInterrupt(PcodeThread<byte[]> t, int vec) {
            Instruction ins = t.getInstruction();
            long next = ins.getAddress().getOffset() + ins.getLength();
            int cs = (int) reg(rCS);
            int ip = (int) ((next - ((long) cs << 4)) & 0xFFFF);
            int sp = (int) reg(rSP), ss = (int) reg(rSS);
            for (int w : new int[] { packFlags(), cs, ip }) {
                sp = (sp - 2) & 0xFFFF;
                write(((long) ss << 4) + sp, new byte[] { (byte) w, (byte) (w >> 8) });
            }
            setReg(rSP, sp);
            setReg(rIF, 0);
            setReg(rTF, 0);
            byte[] v = read(vec * 4L, 4);
            int off = (v[0] & 0xff) | (v[1] & 0xff) << 8, seg = (v[2] & 0xff) | (v[3] & 0xff) << 8;
            setReg(rCS, seg);
            csMayHaveChanged = true;          // BOUND / divide traps are not in CS_WRITERS
            long target = (((long) seg << 4) + off) & 0xFFFFF;
            edges.merge(String.format("%x,%x,%x,int", ins.getAddress().getOffset(), target, seg), 1, Integer::sum);
            return target;
        }

        /** POP SS (17) or MOV SS,r/m (8E with ModRM sreg field 2; bit 5 ignored), after any prefixes. */
        private boolean loadsSS(Instruction ins) {
            try {
                byte[] b = ins.getParsedBytes();
                int i = 0;
                while (i < b.length - 1 && PREFIXES.indexOf(b[i] & 0xFF) >= 0) i++;
                int op = b[i] & 0xFF;
                return op == 0x17 || (op == 0x8E && i + 1 < b.length && ((b[i + 1] >> 3) & 3) == 2);
            } catch (ghidra.program.model.mem.MemoryAccessException e) {
                return false;
            }
        }

        private long le(byte[] b) {
            long x = 0;
            for (int i = b.length - 1; i >= 0; i--) x = (x << 8) | (b[i] & 0xff);
            return x;
        }

        private long val(ThreadPcodeExecutorState<byte[]> st, Varnode vn) {
            byte[] b = st.getVar(vn, Reason.EXECUTE_READ);
            long x = 0;
            for (int i = b.length - 1; i >= 0; i--) x = (x << 8) | (b[i] & 0xff);
            return x;
        }

        private void put(ThreadPcodeExecutorState<byte[]> st, Varnode vn, long v) {
            byte[] b = new byte[vn.getSize()];
            for (int i = 0; i < b.length; i++) b[i] = (byte) (v >> (8 * i));
            st.setVar(vn, b);
        }
    }
}
