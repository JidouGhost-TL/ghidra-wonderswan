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
 * general DMA (40-48: word alignment masks, 20-bit source, SRAM/slow-ROM refusal, direction),
 * sound DMA registers (4A-52: 20-bit source/length, shadows, hold/repeat/rate) with transfers
 * and sound channel-3 sweep as cycle counters when {@link #cycleTiming} is set, the interrupt
 * controller (B0 vector base / request read-back, B2 enable, B4 status latch, B6 acknowledge;
 * edge and level sources per WSdev Interrupts), the CPU side of interrupts (IF, one-instruction
 * shadow after STI/POPF/IRET that set IF and after MOV/POP SS, HLT halted state, TF single-step
 * trap, divide-error trap via the language's swi(0)), line counter (02) with line-match and
 * VBlank IRQs, HBlank/VBlank timers (A2-AB), the UART send-ready level IRQ (B1/B3; bytes sent
 * instantly, nothing received), scripted keypad (B5), the internal (BA-BE) and cartridge (C4-C8)
 * serial EEPROMs ({@link WSEeprom}), cartridge SRAM in the 1000:0000 window (bank port C1,
 * mirrored to its size; direct machine accesses such as IRQ pushes and GDMA go through it too),
 * with load/save of all three images,
 * the 2003-mapper RTC (CA/CB, {@link WSRtc}; deterministic fixed clock by default), the self-flash
 * window ($CE; on flash cartridges a NOR flash, {@link WSFlash}, otherwise the ROM read-only) and
 * the KARNAK ADPCM decoder and timer (D6/D8/D9, {@link WSKarnak}) on Pocket Challenge V2 images.
 * Every other port stores writes and reads back the last value. Not modelled: sound output; cycle
 * timing unless {@link #cycleTiming} is set.
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
    /** Detected cartridge (mapper, save hardware, image geometry). */
    public final WSCartridge cartridge;
    /** Cartridge RTC, or null unless the mapper is 2003-family. */
    public final WSRtc rtc;
    /** Cartridge NOR flash (shares the {@link #rom} array), or null unless WonderWitch-style. */
    public final WSFlash flash;
    /** KARNAK ADPCM/timer, or null unless the image is Pocket Challenge V2. */
    public final WSKarnak karnak;
    /** Writes to the self-flash window ignored on masked-ROM cartridges (writes are flash commands). */
    public long selfFlashIgnored;
    /** SHA-256 of the ROM as imported (flash writes mutate {@link #rom}, so this is kept). */
    private final byte[] initialDigest;

    /**
     * Detect the cartridge for a program: the loader's stored Mapper option when present (it saw
     * the real file name), else fresh detection from the bytes and the program name.
     */
    private static WSCartridge cartridgeFromProgram(Program program, byte[] file) {
        try {
            WSCartridge.Mapper m = WSCartridge.parseMapper(
                program.getOptions(WonderSwanLoader.OPTIONS_CATEGORY).getString("Mapper", null));
            if (m != null) return WSCartridge.detectAs(file, m);
        } catch (Exception e) { /* fall through to detection */ }
        return WSCartridge.detect(file, program.getName());
    }

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
     * Rule E0b: a computed edge resolves in the same interrupt context (see {@link WSComputedEdges}).
     */
    public final Map<String, Integer> edges = new TreeMap<>();
    /** Pending computed-branch edges and interrupt-nesting depth (rule E0b). */
    public final WSComputedEdges computedEdges = new WSComputedEdges();
    /** Visits per executed address; DS/ES sets are sampled for the first 64 visits (as the Mesen trace does). */
    private final Map<Long, Integer> visits = new HashMap<>();

    /**
     * Addresses that cannot be trusted after a run ends in an error: those among the last 64 executed
     * instructions whose every execution falls inside that window, i.e. first reached just before the failure
     * (typically the run has left real code and is decoding data). Earlier addresses were executed on a path that
     * kept running and are kept as evidence.
     */
    public Set<Long> untrustedTail() {
        Map<Long, Integer> inTail = new HashMap<>();
        for (long k = Math.max(0, ringCount - 64); k < ringCount; k++) inTail.merge(ringLin[(int) (k & 63)], 1, Integer::sum);
        Set<Long> out = new TreeSet<>();
        for (Map.Entry<Long, Integer> e : inTail.entrySet())
            if (visits.getOrDefault(e.getKey(), 0) <= e.getValue()) out.add(e.getKey());
        return out;
    }

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

    // ---- Accuracy: cycle timing and DMA (option + state; see run/runCycle) --------------------
    // Kept in one block so save-state and mapper work elsewhere merges cleanly: the visible DMA
    // and sweep registers live in ports[] (already snapshotted); only the shadow/counter fields
    // below are appended to snapshots (see saveState/restoreState tail).
    /** When true, instructions cost V30MZ cycles; lines, timers, sweep and SDMA run by cycles. */
    public boolean cycleTiming = false;
    /** Total CPU cycles (including DMA stalls) when cycleTiming; else 0. */
    public long cycles = 0;
    /** PPU cycle within the line (0-255) and APU 128-cycle phase, for cycleTiming. */
    private int cycleInLine = 0, apuCycle = 0;
    /** Sound DMA shadow reloads (written with the visible 4A-4C/4E-50) and rate timer. */
    private int sdmaSrcReload = 0, sdmaLenReload = 0, sdmaTimer = 0, sdmaFreq = 0;
    private boolean sdmaEnabled = false, sdmaRepeat = false, sdmaHold = false;
    private boolean sdmaDec = false, sdmaHyper = false;
    /** Channel-3 sweep counters (visible freq in 84/85, value 8C, period 8D, ctrl 90, test 95). */
    private int sweepTimer = 0, sweepScaler = 0;
    /** Cycles of the current IN before its port read (6 imm / 5 DX) for sweep read-early. */
    private int curInBefore = 0;
    /** Split word accesses (odd or 8-bit bus) seen during the current instruction. */
    private int curSplitWords = 0;
    /** Current instruction bytes/length (captured in callbacks; no disassembly with -noanalysis). */
    private byte[] curBytes = new byte[0];
    private int curLen = 1;
    /** Per-instruction enable snapshot: HW enables change at the end of OUT, so its own cycles tick
     *  with the before state (otherwise sweep/SDMA overcount the enabling OUT by 7). */
    private boolean tickOverride = false, sweepWas = false, sdmaWas = false;

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

    /**
     * Optional trace-recording sink for Debugger integration (null = standalone, no cost).
     * When set (see WSDebuggerEmulator), every state write and uninitialized-state read is
     * forwarded to it, so the Debugger's trace writer can record the run. Attach after
     * construction: the constructor's own state setup (memory map, entry registers) is the
     * initial state, not recorded history.
     */
    public PcodeEmulationCallbacks<byte[]> traceCallbacks;

    public WSMachine(Program program, boolean color) {
        this(program, color, null);
    }

    /**
     * @param threadName name of the machine's thread, or null for the default. The Debugger
     * binds emulator threads to trace threads by name, so the debugger integration passes the
     * trace thread's path here; standalone users pass null.
     */
    public WSMachine(Program program, boolean color, String threadName) {
        this.lang = program.getLanguage();
        this.ram = lang.getDefaultSpace();
        this.color = color;
        List<FileBytes> fbs = program.getMemory().getAllFileBytes();
        if (fbs.isEmpty()) throw new IllegalStateException("program has no stored ROM bytes (import with the WonderSwan loader)");
        FileBytes fb = fbs.get(0);
        byte[] file = new byte[(int) fb.getSize()];
        try { fb.getOriginalBytes(0, file); } catch (Exception e) { throw new IllegalStateException(e); }
        cartridge = cartridgeFromProgram(program, file);
        // Effective ROM: the file at the end, start padding (a no-op for power-of-two images).
        long pad = cartridge.effectiveSize - file.length;
        rom = new byte[(int) cartridge.effectiveSize];
        java.util.Arrays.fill(rom, 0, (int) pad, (byte) WSHardware.PAD_BYTE);
        System.arraycopy(file, 0, rom, (int) pad, file.length);
        initialDigest = digest(rom);
        rtc = cartridge.hasRtc() ? new WSRtc() : null;
        flash = cartridge.hasFlash() ? new WSFlash(rom) : null;
        karnak = cartridge.hasKarnak() ? new WSKarnak() : null;
        rCS = lang.getRegister("CS"); rDS = lang.getRegister("DS"); rES = lang.getRegister("ES");
        rSS = lang.getRegister("SS"); rSP = lang.getRegister("SP");
        rCsval = lang.getRegister("csval");
        rIF = lang.getRegister("IF"); rTF = lang.getRegister("TF");
        io = lang.getAddressFactory().getAddressSpace("io");
        if (rCsval == null || io == null)
            throw new IllegalStateException("WSMachine requires the V30MZ language (csval context + io space); program uses " + lang.getLanguageID());
        WSHeader hdr = cartridge.header;
        internalEeprom = new WSEeprom(true, color ? 0x800 : 0x80);
        int eep = WSHardware.cartEepromBytes(hdr.saveCode), sr = WSHardware.sramBytes(hdr.saveCode);
        cartEeprom = eep > 0 ? new WSEeprom(false, eep) : null;
        sram = sr > 0 ? new byte[sr] : null;
        ports[0xC0] = WSHardware.RESET_C0; ports[0xC2] = WSHardware.RESET_C2; ports[0xC3] = WSHardware.RESET_C3;
        ports[0xC1] = 0xFF; ports[0xCF] = ports[0xD0] = ports[0xD2] = ports[0xD4] = 0xFF;
        ports[0xA0] = WSHardware.systemControlAtEntry(hdr, color);
        for (int[] pv : WSHardware.PORTS_AT_ENTRY) ports[pv[0]] = pv[1];

        emu = new WSDebuggerEmulator(lang, new Callbacks());
        thread = threadName == null ? emu.newThread() : emu.newThread(threadName);
        // Internal RAM starts zeroed. Reads of never-written bytes already returned 0 (with an emulator
        // "uninitialized state" warning per access); filling it removes that log flood without changing behaviour.
        write(0, new byte[color ? WSHardware.RAM_COLOR : WSHardware.RAM_MONO]);
        mapLinear(); mapBank(0xC2, 0x20000); mapBank(0xC3, 0x30000);
        if (color) {   // WSC palette RAM reads 0xFF at cartridge entry
            byte[] ff = new byte[0x200];
            Arrays.fill(ff, (byte) 0xFF);
            write(0xFE00, ff);
        }
        // Cartridge entry state (boot ROM skipped): CS:IP = FFFF:0000 executes the footer JMP FAR.
        int[] r = WSHardware.registersAtEntry(hdr, color);
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

    /** Direct (non-p-code) memory read. Bytes in the SRAM window come from the cartridge SRAM under the
     *  current C1 bank, exactly as a p-code load sees them (beforeLoad), so machine-made accesses such as
     *  IRQ pushes, GDMA and inspection agree with the program's own loads. */
    public byte[] read(long linear, int n) {
        byte[] b = emu.getSharedState().getVar(addr(linear), n, false, Reason.INSPECT);
        if (sram != null)
            for (int i = 0; i < n; i++) if (inSramWindow(linear + i)) b[i] = sram[sramOffset(linear + i)];
        return b;
    }

    /** Direct (non-p-code) memory write. Bytes in the SRAM window also go to the cartridge SRAM, as a
     *  p-code store does (afterStore); otherwise the next load of them would reread stale SRAM. */
    public void write(long linear, byte[] b) {
        emu.getSharedState().setVar(addr(linear), b.length, false, b);
        if (sram != null)
            for (int i = 0; i < b.length; i++) if (inSramWindow(linear + i)) sram[sramOffset(linear + i)] = b[i];
    }

    private static boolean inSramWindow(long linear) {
        return linear >= 0x10000 && linear < 0x20000;
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

    /** Current 16-bit bank number for C1/C2/C3 (2003 mapper high bytes in D1/D3/D5; KARNAK has none). */
    public int bank(int port) {
        if (karnak != null) return ports[port];
        int hi = port == 0xC1 ? 0xD1 : port == 0xC2 ? 0xD3 : 0xD5;
        return ports[port] | ports[hi] << 8;
    }

    /** True when the SRAM window shows the self-flash chip instead of SRAM ($CE bit 0, 2003-family only). */
    public boolean flashMode() {
        return (ports[0xCE] & 1) != 0 && (cartridge.mapper == WSCartridge.Mapper.M2003
            || cartridge.mapper == WSCartridge.Mapper.WONDERWITCH);
    }

    private void mapBank(int port, long window) {
        write(window, romSlice(WSHardware.bankToRom(bank(port), rom.length), 0x10000));
    }

    /** Effective-ROM offset of a linear address under the current bank registers, or -1 for RAM/SRAM
     *  (for non-power-of-two images translate to a file offset with {@link WSHardware#fileOffset}). */
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
    /** Write an I/O port from outside the emulation (bank switches remap, as the hardware does). */
    public void setPort(int port, int size, int value) { portOut(port, size, value); }

    int portIn(int port, int size) {
        int v;
        // Cartridge peripherals (absent ones keep the last-value behaviour in the switch below).
        if (rtc != null && port == 0xCA) {
            v = rtc.readStatus();
            if (size == 2) v |= rtc.readData() << 8;
            return v;
        }
        if (rtc != null && port == 0xCB) {
            v = rtc.readData();
            if (size == 2) v |= rtc.readData() << 8;
            return v;
        }
        if (karnak != null && port == 0xD9) {
            v = karnak.readAdpcm();
            if (size == 2) v |= karnak.readAdpcm() << 8;
            return v;
        }
        switch (port) {
            case 0x02: return currentLine;
            case 0x43: case 0x4D: case 0x51: case 0x53: return 0;   // DMA gaps read 0
            case 0x84: case 0x85: {   // CH3 freq: sweep counts cycles; IN reads a cycle early
                int f = (ports[0x84] | ports[0x85] << 8) & 0xFFF;
                if (cycleTiming && curInBefore > 0 && sweepCounting())
                    f = (f + sweepPending(curInBefore)) & 0xFFF;
                if (size == 2) return f & 0xFFF;
                return port == 0x84 ? f & 0xFF : (f >> 8) & 0xFF;
            }
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
        if (rtc != null && port == 0xCA && size == 2) {
            // Word store to the RTC ports (OUT 0CAh,AX: command in AL, data in AH): the data byte
            // is valid before the interface clocks it out, so it latches first.
            ports[0xCA] = value & 0xFF;
            ports[0xCB] = (value >> 8) & 0xFF;
            rtc.writeData((value >> 8) & 0xFF);
            rtc.writeCommand(value & 0xFF);
            return;
        }
        for (int k = 0; k < size; k++) {
            int p = (port + k) & 0xFF;
            int b = (value >> (8 * k)) & 0xFF;
            if (p == 0xB4) continue;                              // read-only status
            if (p == 0xB6) { irqStatus &= ~b; continue; }         // acknowledge
            if (p == 0x43 || p == 0x4D || p == 0x51 || p == 0x53) continue;   // DMA gaps ignore writes
            if (p == 0xB1) serialOut.write(b);                    // UART transmit (instant)
            // Accuracy: DMA word-alignment and 20-bit masks (ws-test-suite alignment_access/sound_dma).
            if (p == 0x40 || p == 0x44 || p == 0x46) b &= 0xFE;
            else if (p == 0x42 || p == 0x4C || p == 0x50) b &= 0x0F;
            else if (p == 0x48) b &= 0xC0;
            else if (p == 0x52) {
                if (sdmaLen() == 0) b &= ~0x80;                  // enable fails when length is 0
                b &= 0xDF;                                       // bit 5 reserved
            } else if (p == 0x85) b &= 0x07;                     // CH3 freq high is 3 bits
            else if (p == 0x8D) b &= 0x1F;                       // sweep period is 5 bits
            ports[p] = b;
            if (p >= 0x4A && p <= 0x4C) sdmaSrcReload = sdmaSrc();   // shadows follow every write
            if (p >= 0x4E && p <= 0x50) sdmaLenReload = sdmaLen();
            if (p == 0x52) sdmaControl(b);
            if (karnak == null) for (int[] al : WSHardware.MAPPER_ALIASES) {   // 2003-mapper mirrors, both directions
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
            if (p == 0xCA && rtc != null) rtc.writeCommand(ports[p]);
            if (p == 0xCB && rtc != null) rtc.writeData(ports[p]);
            if (p == 0xD6 && karnak != null) karnak.writeControl(ports[p]);
            if (p == 0xD8 && karnak != null) karnak.writeAdpcm(ports[p]);
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

    /** ROM/flash offset of an address in the 1000:0000 window in self-flash mode (same banking as C2/C3). */
    private int flashOffset(long linear) {
        return (int) WSHardware.bankToRom(bank(0xC1), rom.length) | (int) (linear & 0xFFFF);
    }

    // ---- Accuracy: DMA helpers (masks above; timing in dma/tick) -------------------------------
    /** 20-bit GDMA source from 40-42 (40/42 already masked on write). */
    private int gdmaSrc() { return ports[0x40] | ports[0x41] << 8 | (ports[0x42] & 0x0F) << 16; }
    private int gdmaDst() { return ports[0x44] | ports[0x45] << 8; }
    private int gdmaLen() { return ports[0x46] | ports[0x47] << 8; }
    private int sdmaSrc() { return ports[0x4A] | ports[0x4B] << 8 | (ports[0x4C] & 0x0F) << 16; }
    private int sdmaLen() { return ports[0x4E] | ports[0x4F] << 8 | (ports[0x50] & 0x0F) << 16; }
    private void sdmaSetSrc(int s) {
        ports[0x4A] = s & 0xFF; ports[0x4B] = (s >> 8) & 0xFF; ports[0x4C] = (s >> 16) & 0x0F;
    }
    private void sdmaSetLen(int l) {
        ports[0x4E] = l & 0xFF; ports[0x4F] = (l >> 8) & 0xFF; ports[0x50] = (l >> 16) & 0x0F;
    }
    /** Decode SDMA control (52) into enable/rate/hold/repeat/target/direction. */
    private void sdmaControl(int b) {
        sdmaEnabled = (b & 0x80) != 0;
        sdmaDec = (b & 0x40) != 0;
        sdmaHyper = (b & 0x10) != 0;
        sdmaRepeat = (b & 0x08) != 0;
        sdmaHold = (b & 0x04) != 0;
        sdmaFreq = switch (b & 0x03) { case 0 -> 5; case 1 -> 3; case 2 -> 1; default -> 0; };
    }
    /** 16-bit bus with no wait: IRAM always, SRAM never (8-bit), ROM from A0 bits 2-3. */
    private boolean isWordBus(long linear) {
        if (linear < 0x10000) return true;
        if (linear < 0x20000) return false;
        return (ports[0xA0] & 0x04) != 0;
    }
    private int waitStates(long linear) {
        if (linear < 0x10000) return 1;
        if (linear < 0x20000) return ((ports[0x60] & 0x02) != 0) ? 2 : 1;
        return ((ports[0xA0] & 0x08) != 0) ? 2 : 1;
    }
    /** GDMA refuses SRAM, slow ROM and 8-bit ROM, at start and mid-transfer (WSdev DMA). */
    private boolean gdmaRefused(long linear) { return !isWordBus(linear) || waitStates(linear) > 1; }
    private boolean sweepCounting() {
        return (ports[0x90] & 0x04) != 0 && (ports[0x90] & 0x40) != 0;
    }
    /** Sweep increments over n cycles without updating state (for IN read-early). */
    private int sweepPending(int n) {
        int f = ports[0x84] | ports[0x85] << 8;
        int t = sweepTimer, s = sweepScaler;
        int per = ports[0x8D] & 0x1F, add = (byte) ports[0x8C];
        boolean fast = (ports[0x95] & 0x02) != 0;
        int d = 0;
        for (int i = 0; i < n; i++) {
            if (++s >= 0x2000 || fast) {
                s = 0;
                if (t == 0) { t = per; d += add; } else t--;
            }
        }
        return d;
    }

    // ------------------------------------------------------------------ save images
    public static final String INTERNAL_EEPROM_FILE = "internal.eeprom", CART_EEPROM_FILE = "cart.eeprom", SRAM_FILE = "cart.sram",
        FLASH_FILE = "cart.flash", RTC_FILE = "cart.rtc";

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
        f = dir.resolve(FLASH_FILE);
        if (java.nio.file.Files.exists(f)) {
            if (flash == null) throw new IllegalArgumentException(f + ": this cartridge has no flash");
            flash.load(java.nio.file.Files.readAllBytes(f)); got.add(FLASH_FILE);
            mapLinear();
            mapBank(0xC2, 0x20000);
            mapBank(0xC3, 0x30000);
        }
        f = dir.resolve(RTC_FILE);
        if (java.nio.file.Files.exists(f)) {
            if (rtc == null) throw new IllegalArgumentException(f + ": this cartridge has no RTC");
            try (java.io.DataInputStream in = new java.io.DataInputStream(
                    new java.io.BufferedInputStream(java.nio.file.Files.newInputStream(f)))) {
                rtc.restoreState(in);
            }
            got.add(RTC_FILE);
        }
        return got;
    }

    /** Write the save images this machine has (internal EEPROM always; cartridge EEPROM / SRAM / flash / RTC if present). */
    public void writeSaves(java.nio.file.Path dir) throws java.io.IOException {
        java.nio.file.Files.createDirectories(dir);
        java.nio.file.Files.write(dir.resolve(INTERNAL_EEPROM_FILE), internalEeprom.data);
        if (cartEeprom != null) java.nio.file.Files.write(dir.resolve(CART_EEPROM_FILE), cartEeprom.data);
        if (sram != null) java.nio.file.Files.write(dir.resolve(SRAM_FILE), sram);
        if (flash != null) java.nio.file.Files.write(dir.resolve(FLASH_FILE), flash.contents);
        if (rtc != null) {
            try (java.io.DataOutputStream out = new java.io.DataOutputStream(
                    new java.io.BufferedOutputStream(java.nio.file.Files.newOutputStream(dir.resolve(RTC_FILE))))) {
                rtc.saveState(out);
            }
        }
    }

    // ------------------------------------------------------------------ snapshots
    /** Magic ("WSST") and version of the snapshot format below (v2 appends RTC/flash/KARNAK state, v3 the cycle
     *  timing and DMA counters; older versions still read, with defaults for the missing parts). */
    public static final int STATE_MAGIC = 0x57535354, STATE_VERSION = 3;

    /**
     * Save the full machine state: CPU registers and program counter, the 64 KiB RAM (work RAM,
     * VRAM, palette RAM), all I/O port registers, both EEPROMs (contents and control state),
     * cartridge SRAM, the timer counters and the interrupt controller state, the cartridge RTC,
     * flash and KARNAK state if present, plus the line-port snapshots of the last frame.
     * The ROM windows (0x20000 and above) are derived from the ROM
     * and the bank registers, so they are rebuilt on restore; the snapshot records a ROM digest
     * and refuses to restore onto a different ROM. Diagnostics (executed maps, DMA log, traces)
     * and the serial output log are not part of the state. Call only at an instruction boundary
     * (between {@link #run} calls), never from inside a callback.
     */
    public void saveState(java.nio.file.Path file) throws java.io.IOException {
        try (java.io.DataOutputStream o = new java.io.DataOutputStream(
                new java.io.BufferedOutputStream(java.nio.file.Files.newOutputStream(file)))) {
            saveState(o);
        }
    }

    public void saveState(java.io.DataOutputStream o) throws java.io.IOException {
        o.writeInt(STATE_MAGIC);
        o.writeInt(STATE_VERSION);
        o.writeInt(rom.length);
        o.write(initialDigest);
        o.writeBoolean(color);
        o.writeInt(buttons);
        o.writeLong(instructions);
        o.writeLong(haltedLines);
        o.writeBoolean(halted);
        o.writeInt(currentLine);
        o.writeInt(irqStatus);
        o.writeInt(hTimer);
        o.writeInt(vTimer);
        o.writeBoolean(suppressIrq);
        o.writeBoolean(suppressTrap);
        o.writeBoolean(ifBefore);
        o.writeBoolean(tfBefore);
        for (int p : ports) o.writeInt(p);
        o.write(read(0, 0x10000));
        if (sram == null) o.writeInt(-1);
        else { o.writeInt(sram.length); o.write(sram); }
        internalEeprom.saveState(o);
        o.writeBoolean(cartEeprom != null);
        if (cartEeprom != null) cartEeprom.saveState(o);
        List<Register> regs = new ArrayList<>();
        for (Register r : lang.getRegisters()) if (r.isBaseRegister() && !r.isProcessorContext()) regs.add(r);
        o.writeInt(regs.size());
        for (Register r : regs) {
            byte[] v = thread.getState().getVar(r, Reason.INSPECT);
            o.writeUTF(r.getName());
            o.writeInt(v.length);
            o.write(v);
        }
        o.writeLong(linearPC());
        for (int ln = 0; ln < VISIBLE; ln++) {
            int[] p = linePorts[ln];
            o.writeBoolean(p != null);
            if (p != null) for (int v : p) o.writeByte(v);
        }
        // v2: cartridge peripherals (absent peripherals write a false flag only).
        o.writeBoolean(rtc != null);
        if (rtc != null) rtc.saveState(o);
        o.writeBoolean(flash != null);
        if (flash != null) flash.saveState(o);
        o.writeBoolean(karnak != null);
        if (karnak != null) karnak.saveState(o);
        // v3: cycle timing and DMA counters.
        o.writeBoolean(cycleTiming);
        o.writeLong(cycles);
        o.writeInt(cycleInLine);
        o.writeInt(apuCycle);
        o.writeInt(sdmaSrcReload);
        o.writeInt(sdmaLenReload);
        o.writeInt(sdmaTimer);
        o.writeInt(sdmaFreq);
        o.writeInt(sweepTimer);
        o.writeInt(sweepScaler);
    }

    /** Restore state written by {@link #saveState}; the ROM and hardware model must match. */
    public void restoreState(java.nio.file.Path file) throws java.io.IOException {
        try (java.io.DataInputStream o = new java.io.DataInputStream(
                new java.io.BufferedInputStream(java.nio.file.Files.newInputStream(file)))) {
            restoreState(o);
        }
    }

    public void restoreState(java.io.DataInputStream o) throws java.io.IOException {
        if (o.readInt() != STATE_MAGIC) throw new IllegalArgumentException("not a machine snapshot");
        int version = o.readInt();
        if (version < 1 || version > STATE_VERSION) throw new IllegalArgumentException("unsupported snapshot version");
        int romLen = o.readInt();
        byte[] digest = new byte[32];
        o.readFully(digest);
        if (romLen != rom.length || !Arrays.equals(digest, initialDigest))
            throw new IllegalArgumentException("snapshot is for a different ROM");
        if (o.readBoolean() != color) throw new IllegalArgumentException("snapshot hardware model differs");
        buttons = o.readInt();
        instructions = o.readLong();
        haltedLines = o.readLong();
        halted = o.readBoolean();
        currentLine = o.readInt();
        irqStatus = o.readInt();
        hTimer = o.readInt();
        vTimer = o.readInt();
        suppressIrq = o.readBoolean();
        suppressTrap = o.readBoolean();
        ifBefore = o.readBoolean();
        tfBefore = o.readBoolean();
        for (int i = 0; i < 256; i++) ports[i] = o.readInt();
        byte[] ramBytes = new byte[0x10000];
        o.readFully(ramBytes);
        write(0, ramBytes);
        int sr = o.readInt();
        if (sr < 0) {
            if (sram != null) throw new IllegalArgumentException("snapshot has no SRAM, this cartridge has SRAM");
        } else {
            if (sram == null) throw new IllegalArgumentException("snapshot has SRAM, this cartridge has none");
            if (sr != sram.length) throw new IllegalArgumentException("snapshot SRAM size differs");
            o.readFully(sram);
        }
        internalEeprom.restoreState(o);
        boolean hasCart = o.readBoolean();
        if (hasCart != (cartEeprom != null)) throw new IllegalArgumentException("snapshot cartridge EEPROM differs");
        if (hasCart) cartEeprom.restoreState(o);
        mapLinear();
        mapBank(0xC2, 0x20000);
        mapBank(0xC3, 0x30000);
        int nRegs = o.readInt();
        for (int i = 0; i < nRegs; i++) {
            String name = o.readUTF();
            byte[] v = new byte[o.readInt()];
            o.readFully(v);
            Register r = lang.getRegister(name);
            if (r == null) throw new IllegalArgumentException("snapshot register unknown: " + name);
            thread.getState().setVar(r, v);
        }
        thread.overrideCounter(addr(o.readLong()));
        RegisterValue ctx = thread.getContext();
        Register rHw = lang.getRegister("hwundef"), rSoc = lang.getRegister("colorsoc");
        if (rHw != null) ctx = ctx.assign(rHw, BigInteger.ONE);
        if (rSoc != null) ctx = ctx.assign(rSoc, color ? BigInteger.ONE : BigInteger.ZERO);
        thread.overrideContext(ctx);
        syncCsval();
        csMayHaveChanged = false;
        for (int ln = 0; ln < VISIBLE; ln++) {
            if (!o.readBoolean()) { linePorts[ln] = null; continue; }
            int[] p = new int[256];
            for (int i = 0; i < 256; i++) p[i] = o.readByte() & 0xFF;
            linePorts[ln] = p;
        }
        if (version >= 2) {
            boolean hasRtc = o.readBoolean();
            if (hasRtc != (rtc != null)) throw new IllegalArgumentException("snapshot cartridge RTC differs");
            if (hasRtc) rtc.restoreState(o);
            boolean hasFlash = o.readBoolean();
            if (hasFlash != (flash != null)) throw new IllegalArgumentException("snapshot cartridge flash differs");
            if (hasFlash) {
                flash.restoreState(o);
                mapLinear();
                mapBank(0xC2, 0x20000);
                mapBank(0xC3, 0x30000);
            }
            boolean hasKarnak = o.readBoolean();
            if (hasKarnak != (karnak != null)) throw new IllegalArgumentException("snapshot KARNAK state differs");
            if (hasKarnak) karnak.restoreState(o);
        }
        if (version >= 3) {
            cycleTiming = o.readBoolean();
            cycles = o.readLong();
            cycleInLine = o.readInt();
            apuCycle = o.readInt();
            sdmaSrcReload = o.readInt();
            sdmaLenReload = o.readInt();
            sdmaTimer = o.readInt();
            sdmaFreq = o.readInt();
            sweepTimer = o.readInt();
            sweepScaler = o.readInt();
        } else {
            cycleTiming = false; cycles = 0; cycleInLine = 0; apuCycle = 0;
            sdmaSrcReload = sdmaSrc(); sdmaLenReload = sdmaLen(); sdmaTimer = 0;
            sdmaFreq = 0; sweepTimer = 0; sweepScaler = 0;
        }
        sdmaControl(ports[0x52]);
        curInBefore = 0; curSplitWords = 0;
        computedEdges.reset();
        stopped = false;
    }

    private static byte[] digest(byte[] bytes) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void dma() {
        int src0 = gdmaSrc(), dst0 = gdmaDst(), n0 = gdmaLen();
        int off = (ports[0x48] & 0x40) != 0 ? -2 : 2;
        // Quick failure: length 0 or refused start takes no cycles, registers unchanged but for
        // the enable bit (WSdev DMA; ws-test-suite alignment_access/gdma_timing).
        if (n0 == 0 || gdmaRefused(src0 & 0xFFFFF)) {
            dmaLog.add(String.format("{\"src\":%d,\"rom_off\":%d,\"dst\":%d,\"len\":%d,\"at\":%d,\"insns\":%d,\"refused\":true}",
                src0, romOffset(src0), dst0, n0, linearPC(), instructions));
            ports[0x48] &= 0x40;
            return;
        }
        int src = src0, dst = dst0, n = n0, words = 0;
        while (n > 0) {
            if (gdmaRefused(src & 0xFFFFF)) break;   // slow failure: stop mid-transfer
            byte[] w = read(src & 0xFFFFF, 2);
            write(dst & 0xFFFF, w);
            src = (src + off) & 0xFFFFF;
            dst = (dst + off) & 0xFFFF;
            n -= 2;
            words++;
        }
        ports[0x40] = src & 0xFF; ports[0x41] = (src >> 8) & 0xFF; ports[0x42] = (src >> 16) & 0x0F;
        ports[0x44] = dst & 0xFE; ports[0x45] = (dst >> 8) & 0xFF;
        ports[0x46] = n & 0xFE; ports[0x47] = (n >> 8) & 0xFF;
        ports[0x48] &= 0x40;
        dmaLog.add(String.format("{\"src\":%d,\"rom_off\":%d,\"dst\":%d,\"len\":%d,\"at\":%d,\"insns\":%d,\"words\":%d}",
            src0, romOffset(src0), dst0, n0, linearPC(), instructions, words));
        if (cycleTiming && words > 0) tickCycles(5 + 2 * words);   // CPU stall (WSdev DMA)
    }

    // ---- Accuracy: cycle tick (sweep, SDMA, lines/timers) ------------------------------------
    static final int CYCLES_PER_LINE = 256, CYCLES_PER_FRAME = LINES * CYCLES_PER_LINE;
    private void tickSweep() {
        if (tickOverride ? !sweepWas : !sweepCounting()) return;
        if (++sweepScaler >= 0x2000 || (ports[0x95] & 0x02) != 0) {
            sweepScaler = 0;
            if (sweepTimer == 0) {
                sweepTimer = ports[0x8D] & 0x1F;
                int f = ((ports[0x84] | ports[0x85] << 8) + (byte) ports[0x8C]) & 0xFFF;
                ports[0x84] = f & 0xFF; ports[0x85] = (f >> 8) & 0xFF;
            } else sweepTimer--;
        }
    }
    private int sdmaRead(long linear) {
        long a = linear & 0xFFFFF;
        if (a >= 0x10000 && a < 0x20000) {
            if (sram == null) return 0x90;
            return sram[sramOffset(a)] & 0xFF;
        }
        return read(a, 1)[0] & 0xFF;
    }
    /** One 128-cycle SDMA slot (at apu phase 116): rate timer, 7-cycle steal, one byte. */
    private void sdmaSlot() {
        if (tickOverride ? !sdmaWas : !sdmaEnabled) return;
        if (sdmaTimer != 0) { sdmaTimer--; return; }
        sdmaTimer = sdmaFreq;
        int sample = sdmaRead(sdmaSrc());
        if (sdmaHold) sample = 0;
        else {
            int s = sdmaSrc(), l = sdmaLen();
            s = (s + (sdmaDec ? -1 : 1)) & 0xFFFFF;
            l = (l - 1) & 0xFFFFF;
            sdmaSetSrc(s); sdmaSetLen(l);
            if (l == 0) {
                if (sdmaRepeat) { sdmaSetSrc(sdmaSrcReload); sdmaSetLen(sdmaLenReload); }
                else { sdmaEnabled = false; ports[0x52] &= 0x7F; }
            }
        }
        // 6+N steal (N=1 here): advance lines/sweep but not nested SDMA slots.
        for (int i = 0; i < 7; i++) { cycles++; tickSweep(); tickLine(); }
        if (!sdmaHyper) ports[0x89] = sample & 0xFF;
    }
    private void tickLine() {
        apuCycle = (apuCycle + 1) & 0x7F;
        if (apuCycle == 116) sdmaSlot();
        if (++cycleInLine >= CYCLES_PER_LINE) {
            cycleInLine = 0;
            if (halted) haltedLines++;
            currentLine++;
            if (currentLine >= LINES) currentLine = 0;
            if (currentLine < VISIBLE) linePorts[currentLine] = ports.clone();
            if (currentLine == VISIBLE) {
                tickTimers(true);
                raiseIrq(6);
            }
            if (currentLine == ports[0x03]) raiseIrq(4);
        } else if (cycleInLine == 224) tickTimers(false);
    }
    private void tickCycles(int n) {
        for (int i = 0; i < n; i++) { cycles++; tickSweep(); tickLine(); }
    }

    // ---- Accuracy: V30MZ cycle costs (NEC/WSdev base + bus/branch extras) -----------------------
    // Base table covers the DMA-test paths exactly (NOP/MOV/OUT/IN/LOOP) and common ops from the
    // NEC V30MZ manual Appendix A / WSdev instruction set; rare ops fall back to 4. IN/OUT use 7/6
    // (Mesen/HW, one more than the NEC 6) so the sweep-measured gdma_timing values match.
    private int cyclesFor(byte[] b, boolean branchTaken, boolean repFirst) {
        int i = 0;
        while (i < b.length && PREFIXES.contains(b[i] & 0xFF)) i++;
        if (i >= b.length) return 1;
        int op = b[i] & 0xFF;
        int modrm = (i + 1 < b.length) ? b[i + 1] & 0xFF : 0xC0;
        boolean modMem = (modrm >> 6) != 3;
        boolean w = (op & 1) != 0;
        // String ops with REP: first iteration pays the 5-cycle setup, then per-iteration cost.
        boolean rep = false;
        for (int k = 0; k < i; k++) { int p = b[k] & 0xFF; if (p == 0xF2 || p == 0xF3) rep = true; }
        if (rep && ((op >= 0xA4 && op <= 0xAF) || (op >= 0x6C && op <= 0x6F))) {
            int per = switch (op) {
                case 0xA4, 0xA5 -> 7;   // MOVS
                case 0xA6, 0xA7 -> 9;   // CMPS
                case 0xAA, 0xAB, 0xAC, 0xAD -> 6;        // STOS/LODS
                case 0xAE, 0xAF -> 6;                    // SCAS
                default -> 6;                           // INS/OUTS
            };
            return (repFirst ? 5 : 0) + per;
        }
        return switch (op) {
            case 0x90 -> 1;                                   // NOP
            case 0xF4 -> 9;                                   // HLT
            case 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD -> 4; // flag ops
            case 0xE4, 0xE5 -> 7;                             // IN imm (5+1+1, read-early)
            case 0xEC, 0xED -> 6;                             // IN DX (4+1+1)
            case 0xE6, 0xE7 -> 7;                             // OUT imm (6+1)
            case 0xEE, 0xEF -> 5;                             // OUT DX (4+1)
            case 0xE2 -> branchTaken ? 5 : 2;                 // LOOP
            case 0xE0, 0xE1 -> branchTaken ? 6 : 3;           // LOOPNE/LOOPE
            case 0xE3 -> branchTaken ? 4 : 1;                 // JCXZ
            case 0xEB -> 4;                                   // JMP short
            case 0xE9 -> 4;                                   // JMP near
            case 0xEA -> 7;                                   // JMP far
            case 0xE8 -> 5;                                   // CALL near
            case 0x9A -> 10;                                  // CALL far
            case 0xC3 -> 6; case 0xC2 -> 6;                   // RET near
            case 0xCB -> 8; case 0xCA -> 9;                   // RET far
            case 0xCF -> 10;                                  // IRET
            case 0xCC -> 9; case 0xCD -> 10;                  // INT3/INT
            case 0xCE -> 6;                                   // INTO (taken adds more; rare)
            case 0x60 -> 9; case 0x61 -> 8;                   // PUSHA/POPA
            case 0x9C -> 2; case 0x9D -> 3;                   // PUSHF/POPF
            case 0x9E -> 4; case 0x9F -> 2;                   // SAHF/LAHF
            case 0x98, 0x99 -> 1;                             // CBW/CWD
            case 0x37, 0x3F -> 9;                             // AAA/AAS
            case 0x27, 0x2F -> 10;                            // DAA/DAS
            case 0xD4 -> 17; case 0xD5 -> 6;                  // AAM/AAD
            case 0xD6 -> 8;                                   // SALC
            case 0xD7 -> 5;                                   // XLAT
            case 0xC8 -> 14; case 0xC9 -> 2;                  // ENTER (imm8>1 adds; approx)/LEAVE
            case 0x62 -> 13;                                  // BOUND (no trap; trap adds)
            case 0x69, 0x6B -> modMem ? 4 : 3;                // IMUL imm
            case 0xF6, 0xF7 -> {                              // GRP3: TEST/NOT/NEG/MUL/DIV
                int r = (modrm >> 3) & 7;
                if (r == 0) yield modMem ? 2 : 1;             // TEST
                if (r == 2 || r == 3) yield modMem ? 3 : 1;   // NOT/NEG
                if (r == 4 || r == 5) yield modMem ? 4 : 3;   // MUL/IMUL
                if (r == 7) {                                // IDIV (signed costs 2 more)
                    if (!w) yield modMem ? 18 : 17;
                    yield modMem ? 25 : 24;
                }
                if (!w) yield modMem ? 16 : 15;               // DIV 8-bit
                yield modMem ? 24 : 23;                       // DIV 16-bit
            }
            case 0xFE, 0xFF -> {                              // GRP4/5: INC/DEC/CALL/JMP/PUSH
                int r = (modrm >> 3) & 7;
                yield switch (r) {
                    case 0, 1 -> modMem ? 3 : 1;               // INC/DEC
                    case 2 -> modMem ? 6 : 5;                 // CALL near indirect
                    case 3 -> 12;                             // CALL far indirect
                    case 4 -> modMem ? 5 : 4;                 // JMP near indirect
                    case 5 -> 10;                             // JMP far indirect
                    case 6 -> modMem ? 2 : 1;                 // PUSH
                    default -> 1;
                };
            }
            case 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3 -> {       // shifts/rotates
                boolean byCL = op == 0xD2 || op == 0xD3;
                boolean byImm = op == 0xC0 || op == 0xC1;
                if (modMem) yield (byCL || byImm) ? 5 : 3;
                yield (byCL || byImm) ? 3 : 1;
            }
            case 0x80, 0x81, 0x82, 0x83 -> modMem ? 3 : 1;    // GRP1 ALU imm (CMP mem,imm is 2; approx 3)
            case 0x84, 0x85 -> modMem ? 2 : 1;                // TEST modrm
            case 0x86, 0x87 -> modMem ? 5 : 3;                // XCHG
            case 0x88, 0x89, 0x8A, 0x8B -> {                 // MOV modrm
                if (!modMem) yield 1;
                yield (op == 0x8A || op == 0x8B) ? 2 : 1;     // reg,mem=2 else 1
            }
            case 0x8C -> modMem ? 3 : 1;                      // MOV mem/sreg
            case 0x8E -> modMem ? 3 : 2;                      // MOV sreg,...
            case 0x8D -> 1;                                   // LEA
            case 0x8F -> 3;                                   // POP mem
            case 0xC4, 0xC5 -> 6;                             // LES/LDS
            case 0xC6, 0xC7 -> 1;                             // MOV mem,imm
            case 0xA0, 0xA1, 0xA2, 0xA3 -> 1;                 // MOV acc,mem
            case 0xA4, 0xA5 -> 5;                             // MOVS (no REP)
            case 0xA6, 0xA7 -> 6;                             // CMPS
            case 0xA8, 0xA9 -> 1;                             // TEST acc,imm
            case 0xAA, 0xAB, 0xAC, 0xAD -> 3;                 // STOS/LODS
            case 0xAE, 0xAF -> 4;                             // SCAS
            case 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF -> 1; // MOV reg,imm
            default -> {
                if (op >= 0x70 && op <= 0x7F) yield branchTaken ? 4 : 1;  // Jcc
                if (op >= 0x40 && op <= 0x4F) yield 1;        // INC/DEC reg
                if (op >= 0x50 && op <= 0x57) yield 1;        // PUSH reg
                if (op >= 0x58 && op <= 0x5F) yield 1;        // POP reg
                if (op >= 0x91 && op <= 0x97) yield 3;        // XCHG AX,reg
                if ((op & 0xFC) == 0x04 || (op & 0xFC) == 0x0C || (op & 0xFC) == 0x14
                    || (op & 0xFC) == 0x1C || (op & 0xFC) == 0x24 || (op & 0xFC) == 0x2C
                    || (op & 0xFC) == 0x34 || (op & 0xFC) == 0x3C) yield 1; // ALU acc,imm
                if (op <= 0x3B && (op & 0xC6) != 0x06) {      // ALU modrm 00-3B except PUSH/POP seg
                    int dir = (op & 0x02) != 0 ? 1 : 0;
                    boolean isCmp = (op & 0x38) == 0x38;
                    if (!modMem) yield 1;
                    if (isCmp) yield 2;
                    yield dir == 1 ? 2 : 3;                   // reg,mem=2 else 3
                }
                if (op == 0x06 || op == 0x0E || op == 0x16 || op == 0x1E) yield 2; // PUSH seg
                if (op == 0x07 || op == 0x17 || op == 0x1F) yield 3;               // POP seg
                if (op == 0x26 || op == 0x2E || op == 0x36 || op == 0x3E) yield 1; // seg prefix alone
                if (op == 0xF0) yield 1;                      // LOCK
                yield 4;                                     // fallback (rare/undefined: 1-2 on HW)
            }
        };
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
        computedEdges.noteInterruptEntry();   // E0b: handler flow is a deeper context, not a branch target
        edges.merge(String.format("%x,%x,%x,%s", -1L & 0xFFFFF, (((long) seg << 4) + off) & 0xFFFFF, seg, kind), 1, Integer::sum);
    }

    /**
     * Instruction boundary: leave the halted state when an interrupt is requested (also with IF=0,
     * then execution just continues after the HLT), and take the highest requested hardware interrupt
     * when IF=1 and the previous instruction did not open an interrupt shadow. Returns false while
     * halted with nothing requested.
     */
    boolean boundary() {
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
    void afterStep() {
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
        if (cycleTiming) { runCycleFrames(frames, onFrame); return; }
        int perLine = Math.max(1, slice / LINES);
        for (int f = 0; f < frames; f++) {
            if (onFrame != null) onFrame.accept(f);
            if (rtc != null) rtc.advanceFrames(1);
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
                    if (karnak != null && karnak.tick(1)) raiseIrq(WSKarnak.TIMER_IRQ_LEVEL);
                    afterStep();
                    if (stopped) throw new IllegalStateException(String.format("stopAt %05x reached", stopAt));
                }
            }
        }
    }

    /** Cycle-timed frames (40704 cycles): lines/timers/sweep/SDMA advance per cycle. */
    private void runCycleFrames(int frames, java.util.function.IntConsumer onFrame) {
        long prevPc = -1;
        for (int f = 0; f < frames; f++) {
            if (onFrame != null) onFrame.accept(f);
            long frameStart = cycles;
            // Safety: even with all-HLT frames must end; HLT still ticks cycles below.
            while (cycles - frameStart < CYCLES_PER_FRAME) {
                if (!boundary()) { tickCycles(1); continue; }   // halted: burn cycles to IRQ
                if (csMayHaveChanged) { syncCsval(); csMayHaveChanged = false; }
                if (beforeStep != null) beforeStep.accept(this);
                long pcBefore = linearPC();
                sweepWas = sweepCounting();
                sdmaWas = sdmaEnabled;
                boolean repFirst = pcBefore != prevPc;
                try {
                    thread.stepInstruction();
                } catch (RuntimeException e) {
                    if (onFault == null || !onFault.test(this, e)) throw e;
                    suppressIrq = suppressTrap = false;
                    prevPc = -1;
                    continue;
                }
                instructions++;
                afterStep();
                long pcAfter = linearPC();
                boolean taken = pcAfter != pcBefore + curLen;
                int c = cyclesFor(curBytes, taken, repFirst) + curSplitWords;
                if (taken && (pcAfter & 1) != 0) c++;   // odd branch target costs one more
                // HLT's own 9 cycles were counted above; the halted wait burns in boundary().
                tickOverride = true;
                try { tickCycles(Math.max(1, c)); } finally { tickOverride = false; }
                prevPc = pcBefore;
                if (stopped) throw new IllegalStateException(String.format("stopAt %05x reached", stopAt));
                // Guard against pathological zero-cycle loops (should not happen).
                if (instructions > (long) frames * CYCLES_PER_FRAME * 2) break;
            }
        }
    }

    // ------------------------------------------------------------------ debugger hooks
    /**
     * Mirror of runFrames' per-instruction prologue (csval re-sync when a far transfer, CPU
     * exception or injected interrupt may have changed CS). Used by WSDebuggerEmulator, which
     * steps outside runFrames; keep the two in sync.
     */
    void debuggerPreStep() {
        if (csMayHaveChanged) { syncCsval(); csMayHaveChanged = false; }
    }

    /**
     * Mirror of runFrames' per-line prologue (line counter, timer ticks, line-match and VBlank
     * interrupt requests, display-port snapshot for the renderer). Used by WSDebuggerEmulator,
     * which advances lines outside runFrames; keep the two in sync.
     */
    void debuggerLinePrologue(int ln) {
        currentLine = ln;
        tickTimers(ln == VISIBLE);
        if (ln == ports[0x03]) raiseIrq(4);
        if (ln == VISIBLE) raiseIrq(6);
        if (ln < VISIBLE) linePorts[ln] = ports.clone();
    }

    /** Current display line (port 02 reads this). */
    public int getCurrentLine() {
        return currentLine;
    }

    // ------------------------------------------------------------------ callbacks
    private class Callbacks implements PcodeEmulationCallbacks<byte[]> {
        @Override
        public void emulatorCreated(PcodeMachine<byte[]> emu) {
            if (traceCallbacks != null) traceCallbacks.emulatorCreated(emu);
        }

        @Override
        public void threadCreated(PcodeThread<byte[]> t) {
            if (traceCallbacks != null) traceCallbacks.threadCreated(t);
        }

        @Override
        public <A, U> void dataWritten(PcodeThread<byte[]> t, PcodeExecutorStatePiece<A, U> piece,
                Address address, int length, U value) {
            if (traceCallbacks != null) traceCallbacks.dataWritten(t, piece, address, length, value);
        }

        @Override
        public <A, U> void dataWritten(PcodeThread<byte[]> t, PcodeExecutorStatePiece<A, U> piece,
                AddressSpace space, A offset, int length, U value) {
            if (traceCallbacks != null) traceCallbacks.dataWritten(t, piece, space, offset, length, value);
        }

        @Override
        public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> t,
                PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
            if (traceCallbacks != null) return traceCallbacks.readUninitialized(t, piece, set, reason);
            return set;
        }

        @Override
        public <A, U> int readUninitialized(PcodeThread<byte[]> t, PcodeExecutorStatePiece<A, U> piece,
                AddressSpace space, A offset, int length, Reason reason) {
            if (traceCallbacks != null) return traceCallbacks.readUninitialized(t, piece, space, offset, length, reason);
            return 0;
        }

        /** io varnodes the current instruction writes directly (constant port numbers compile to
         *  plain varnodes in the io space, not LOAD/STORE ops, so the load/store callbacks miss them). */
        private final List<Varnode> pendingIoWrites = new ArrayList<>();

        @Override
        public void beforeExecuteInstruction(PcodeThread<byte[]> t, Instruction ins, PcodeProgram program) {
            pendingIoWrites.clear();
            ifBefore = flag(rIF);
            tfBefore = flag(rTF);
            curSplitWords = 0;
            curInBefore = 0;
            try {
                curBytes = ins.getParsedBytes();
                curLen = ins.getLength();
            } catch (Exception e) { curBytes = new byte[0]; curLen = 1; }
            if (cycleTiming) {
                int q = 0;
                while (q < curBytes.length - 1 && PREFIXES.contains(curBytes[q] & 0xFF)) q++;
                int o = q < curBytes.length ? curBytes[q] & 0xFF : -1;
                if (o == 0xE4 || o == 0xE5) curInBefore = 6;
                else if (o == 0xEC || o == 0xED) curInBefore = 5;
            }
            for (PcodeOp op : program.getCode()) {
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode in = op.getInput(i);
                    if (in.getAddress().getAddressSpace() == io) {
                        int port = (int) in.getOffset() & 0xFF;
                        if (cycleTiming && in.getSize() == 2 && ((port & 1) != 0 || port >= 0xC0)) curSplitWords++;
                        int v = portIn(port, in.getSize());
                        byte[] b = new byte[in.getSize()];
                        for (int k = 0; k < b.length; k++) b[k] = (byte) (v >> (8 * k));
                        emu.getSharedState().setVar(in.getAddress(), b.length, false, b);
                        accessStats.merge("in:direct", 1, Integer::sum);
                    }
                }
                Varnode out = op.getOutput();
                if (out != null && out.getAddress().getAddressSpace() == io) {
                    if (cycleTiming && out.getSize() == 2) {
                        int port = (int) out.getOffset() & 0xFF;
                        if ((port & 1) != 0 || port >= 0xC0) curSplitWords++;
                    }
                    pendingIoWrites.add(out);
                }
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
            // E0b: a computed branch resolves to the next instruction in its own interrupt
            // context; edges pre-empted by an interrupt stay pending across the handler flow.
            computedEdges.resolveAt(lin, (int) reg(rCS), (from, to, cs, kind) ->
                edges.merge(String.format("%x,%x,%x,%s", from, to, cs, kind), 1, Integer::sum));
            if (ins.getFlowType().isComputed() && (ins.getFlowType().isJump() || ins.getFlowType().isCall())) {
                computedEdges.noteComputedBranch(lin, ins.getFlowType().isCall() ? "call" : "jump");
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
            if ("IRET".equals(mn)) computedEdges.noteIret();   // E0b: the interrupted context resumes
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
            if (cycleTiming && size == 2) {
                long a = le(offset);
                if (space == ram) { if ((a & 1) != 0 || !isWordBus(a & 0xFFFFF)) curSplitWords++; }
                else if (space == io) { int p = (int) a & 0xFF; if ((p & 1) != 0 || p >= 0xC0) curSplitWords++; }
            }
            if (space == ram && memoryWatch != null) {
                long a = le(offset);
                byte[] cur = emu.getSharedState().getVar(ram.getAddress(a), size, false, Reason.INSPECT);
                memoryWatch.access(WSMachine.this, false, a, size, le(cur), t.getCounter().getOffset());
            }
            if (space == ram && (sram != null || flashMode())) {
                long a = le(offset);
                if (a >= 0x10000 && a < 0x20000) {
                    byte[] b = new byte[size];
                    for (int i = 0; i < size; i++) {
                        if (flashMode()) {
                            int off = flashOffset(a + i);
                            b[i] = flash != null ? (byte) flash.read(off) : rom[off];
                        } else b[i] = sram[sramOffset(a + i)];
                    }
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
            if (cycleTiming && size == 2) {
                long a = le(offset);
                if (space == ram) { if ((a & 1) != 0 || !isWordBus(a & 0xFFFFF)) curSplitWords++; }
                else if (space == io) { int p = (int) a & 0xFF; if ((p & 1) != 0 || p >= 0xC0) curSplitWords++; }
            }
            if (space == io) {
                portOut((int) le(offset) & 0xFF, size, (int) le(value));
                return;
            }
            if (space != ram) return;
            long a = le(offset);
            if (memoryWatch != null) memoryWatch.access(WSMachine.this, true, a, size, le(value), t.getCounter().getOffset());
            if (flashMode() && a >= 0x10000 && a < 0x20000) {
                for (int i = 0; i < size; i++) {
                    if (flash != null) flash.write(flashOffset(a + i), value[i] & 0xFF);
                    else selfFlashIgnored++;
                }
                if (flash != null) sramWrites++;   // stores into the window, as counted for SRAM
                return;
            }
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
            computedEdges.noteInterruptEntry();   // E0b: the INT handler is a deeper context
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
