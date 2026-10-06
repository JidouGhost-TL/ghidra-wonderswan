// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Objects;
import java.util.function.IntConsumer;
import java.util.function.LongConsumer;

import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.AbstractPcodeTraceDataAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceMemoryAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * WonderSwan-aware p-code emulator for Ghidra's Debugger.
 *
 * <p>
 * Every {@link WSMachine} runs on one of these (see its constructor); standalone runs never
 * enable the debugger stepping and behave exactly like a plain {@link PcodeEmulator}. When bound
 * to its machine ({@link #bind}) each instruction step also performs the machine's
 * instruction-boundary work (interrupt entry, single-step trap) and advances the display line,
 * timers and VBlank/line-match interrupts by instruction count, exactly mirroring
 * {@link WSMachine#run} over the same steps. That is what lets the Debugger's own stepping,
 * breakpoints and run actions drive WonderSwan hardware behaviour: the emulation service steps
 * threads through {@link PcodeThread#stepInstruction}, which lands here.
 *
 * <p>
 * Trace recording flows through {@link WSMachine#traceCallbacks} (set by {@link #attachTrace}):
 * register and memory writes are forwarded to the Debugger's trace writer, so those views
 * show the run. Unique-space temporaries stay in the emulator. The machine's peripheral state (ports, timers, interrupt latch, EEPROMs) is not
 * part of the trace; when the service re-emulates from a mid-trace snapshot with a fresh machine,
 * {@link #attachTrace} restores a best-effort approximation (registers, RAM, bank windows and
 * ports read back from the trace, timers and interrupt state reset). Stepping back in time always
 * shows recorded history; stepping forward again after stepping back re-emulates and may drift
 * from the recorded run where the approximation differs.
 */
public class WSDebuggerEmulator extends PcodeEmulator {
    /** Machine this emulator belongs to; null until {@link #bind}. */
    public WSMachine ws;
    private WSMachine owner;
    /** Debugger stepping (boundary + line advance per step); false = plain PcodeEmulator. */
    public boolean steppingEnabled;
    /** Nominal instructions per frame; lines advance by instruction count like WSMachine.run. */
    public int slice = 40000;

    private int line;
    private int lineCount;
    private boolean needPrologue = true;
    /** Prologues applied since bind (diagnostic). */
    public long linesAdvanced;
    /** Frame wraps (line 158 -> 0) since bind. */
    public long framesAdvanced;

    /** Thread with debugger stepping: each step runs the machine boundary around the real step. */
    public static class WSThread extends BytesPcodeThread {
        private static final boolean CHECK_CONTEXT = Boolean.getBoolean("wonderswan.checkContextMemo");
        private Object lastContextSink;
        private boolean contextWritten;
        public WSThread(String name, AbstractPcodeMachine<byte[]> machine) {
            super(name, machine);
        }

        @Override
        protected SleighInstructionDecoder createInstructionDecoder(PcodeExecutorState<byte[]> sharedState) {
            return new WSInstructionDecoder(language, sharedState);
        }

        private RegisterValue finishedContext(RegisterValue commits) {
            return new RegisterValue(contextreg, BigInteger.ZERO)
                .combineValues(defaultContext.getDefaultValue(contextreg, getCounter()))
                .combineValues(defaultContext.getFlowValue(getContext()))
                .combineValues(commits);
        }

        /** Preserve DefaultPcodeThread's finish order, including injects, commits and callbacks. */
        @Override
        protected void advanceAfterFinished() {
            if (!(instruction instanceof WSInstructionDecoder.MemoInstruction memo)) {
                super.advanceAfterFinished();
                return;
            }
            if (frame.isFallThrough()) writeCounter(getCounter().addWrap(decoder.getLastLengthWithDelays()));
            if (contextreg != Register.NO_CONTEXT) {
                // Commits and defaults can depend on the destination of a dynamic branch.
                if (!Objects.equals(memo.finishInput, getContext()) || !Objects.equals(memo.finishCounter, getCounter())) {
                    memo.finishOutput = finishedContext(memo.committedContext(getCounter().getOffset()));
                    memo.finishBytes = arithmetic.fromConst(memo.finishOutput.getUnsignedValueIgnoreMask(),
                        contextreg.getMinimumByteSize(), true);
                    memo.finishInput = getContext();
                    memo.finishCounter = getCounter();
                } else if (CHECK_CONTEXT) {
                    RegisterValue computed = finishedContext(memo.freshCommittedContext(getCounter().getOffset()));
                    if (!memo.finishOutput.equals(computed)) {
                        throw new AssertionError("Context memo differs from the framework formula: " +
                            instruction.getAddress() + " to " + getCounter() + ": cached=" + memo.finishOutput +
                            ", computed=" + computed + ", input=" + getContext());
                    }
                }
                WSDebuggerEmulator emulator = (WSDebuggerEmulator) getMachine();
                Object sink = emulator.owner == null ? emulator.cb : emulator.owner.traceCallbacks;
                boolean bytesMatch = state.getLocalState() instanceof WSArrayState flat &&
                    flat.matches(contextreg.getAddress(), memo.finishBytes);
                // A new recorder needs its first context write. Raw p-code writes must also be repaired.
                if (!contextWritten || lastContextSink != sink || !getContext().equals(memo.finishOutput) || !bytesMatch) {
                    writeContext(memo.finishOutput);
                    contextWritten = true;
                    lastContextSink = sink;
                }
            }
            postExecuteInstruction();
            ((WSDebuggerEmulator) getMachine()).instructionFinished(this, instruction);
            frame = null;
            instruction = null;
        }

        @Override
        public void stepInstruction() {
            WSDebuggerEmulator e = (WSDebuggerEmulator) getMachine();
            if (e.ws == null || !e.steppingEnabled) {
                super.stepInstruction();
                return;
            }
            e.debuggerStep(this);
        }

        void plainStep() {
            super.stepInstruction();
        }

        @Override
        public void finishInstruction() {
            WSDebuggerEmulator emulator = (WSDebuggerEmulator) getMachine();
            if (emulator.ws == null || !emulator.steppingEnabled) super.finishInstruction();
            else emulator.debuggerFinish(this);
        }

        void plainFinish() { super.finishInstruction(); }
    }

    public WSDebuggerEmulator(Language language, PcodeEmulationCallbacks<byte[]> cb) {
        super(language, cb);
    }

    public WSDebuggerEmulator(Language language) {
        super(language);
    }

    @Override
    protected BytesPcodeThread createThread(String name) {
        return new WSThread(name, this);
    }

    @Override
    protected PcodeExecutorState<byte[]> createSharedState() {
        return new WSArrayState(language, cb.wrapFor(null));
    }

    @Override
    protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
        return super.createUseropLibrary().compose(new WSSegmentLibrary(), true);
    }

    @Override
    protected PcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> thread) {
        return new WSArrayState(language, cb.wrapFor(thread));
    }

    void setOwner(WSMachine owner) {
        this.owner = owner;
    }

    private void instructionFinished(WSThread thread, Instruction instruction) {
        cb.afterExecuteInstruction(thread, instruction);
    }

    /** Build a program-bound emulator for headless use (no trace); stepping is enabled. */
    public static WSDebuggerEmulator forProgram(Program program, boolean color, String threadName) {
        WSMachine ws = new WSMachine(program, color, threadName);
        WSDebuggerEmulator emu = (WSDebuggerEmulator) ws.emu;
        emu.bind(ws);
        return emu;
    }

    /** Bind to the machine (enables debugger stepping from the frame start). */
    public void bind(WSMachine ws) {
        this.ws = ws;
        this.owner = ws;
        this.steppingEnabled = true;
        this.line = 0;
        this.lineCount = 0;
        this.needPrologue = true;
        this.linesAdvanced = 0;
        this.framesAdvanced = 0;
        resolveShadow();
    }

    /** Instructions per display line under the current slice (mirrors WSMachine.run). */
    public int perLine() {
        return Math.max(1, slice / WSMachine.LINES);
    }

    /**
     * Register-space scratch holding the full linear program counter. The PC register itself is
     * only the 16-bit IP, which cannot restore the 20-bit counter when CS is not 64 KiB-aligned
     * (common on WonderSwan), so each debugger step also records the linear counter here; the
     * trace records it through the normal register channel and restore reads it back. Far from
     * any V30MZ register; bind() disables the shadow if anything ever overlaps it.
     */
    static final long SHADOW_PC = 0x4000;
    private Address shadowAddr;

    /** Resolve the shadow address, disabling it if a register overlaps the scratch. */
    private void resolveShadow() {
        shadowAddr = null;
        Register cs = ws.lang.getRegister("CS");
        if (cs == null) return;
        AddressSpace regSpace = cs.getAddress().getAddressSpace();
        Address base = regSpace.getAddress(SHADOW_PC);
        Address end = base.addWrap(3);
        for (Register r : ws.lang.getRegisters()) {
            Address lo = r.getAddress(), hi = lo.addWrap(r.getNumBytes() - 1);
            if (lo.getAddressSpace() == regSpace && lo.compareTo(end) <= 0 && hi.compareTo(base) >= 0)
                return;
        }
        shadowAddr = base;
    }

    /**
     * Attach trace recording for Debugger-driven emulation: restores a best-effort state when
     * re-emulating from a mid-trace snapshot (a no-op on a fresh trace), then forwards all state
     * writes and uninitialized reads to the writer. The writer's emulator handle is registered
     * last so a failed attach leaves the writer clean for the default emulator fallback.
     */
    public void attachTrace(PcodeDebuggerAccess access, Writer writer) {
        restoreFromTrace(access);
        ws.traceCallbacks = writer.callbacks();
        ws.traceCallbacks.emulatorCreated(ws.emu);
        // NB. threadCreated is deliberately not forwarded for the pre-existing thread: its
        // context is already the cartridge-entry state, while the trace writer would overwrite
        // it from static context. Threads created later are forwarded by the callbacks.
    }

    /**
     * One instruction step outside WSMachine.run: the line prologue (lazily, so the first step
     * of each line sees it exactly like runFrames), the interrupt boundary, the real step, the
     * trap check and the line advance. Mirrors runFrames step for step; faults propagate (the
     * Debugger stops on them) and onFault is not consulted.
     */
    void debuggerStep(WSThread t) {
        if (t != ws.thread)
            throw new IllegalStateException(
                "WonderSwan has one CPU; emulator thread " + t.getName() + " cannot step it");
        if (needPrologue) enterLine();
        if (!ws.boundary()) {
            ws.haltedLines++;
            advanceLine();
            return;
        }
        ws.debuggerPreStep();
        if (ws.beforeStep != null) ws.beforeStep.accept(this.ws);
        t.plainStep();
        completeDebuggerStep();
    }

    private void debuggerFinish(WSThread thread) {
        if (thread != ws.thread) throw new IllegalStateException("WonderSwan has one CPU");
        thread.plainFinish();
        completeDebuggerStep();
    }

    private void completeDebuggerStep() {
        ws.instructions++;
        ws.afterStep();
        if (shadowAddr != null) {
            long pc = ws.linearPC();
            ws.thread.getState().setVar(shadowAddr, 4, false, new byte[] {
                (byte) pc, (byte) (pc >> 8), (byte) (pc >> 16), (byte) (pc >> 24) });
        }
        if (++lineCount >= perLine()) advanceLine();
        if (ws.stopped) throw new IllegalStateException(String.format("stopAt %05x reached", ws.stopAt));
    }

    private void advanceLine() {
        lineCount = 0;
        line++;
        if (line >= WSMachine.LINES) {
            line = 0;
            framesAdvanced++;
        }
        needPrologue = true;
    }

    /**
     * Run the given thread of this machine until the next entry into the VBlank line (144),
     * i.e. one frame step, and apply that line's prologue (so VBlank is raised when this
     * returns). Already at a VBlank entry completes the entry without stepping (0 steps);
     * mid-VBlank runs to the next frame's VBlank. Returns the instructions stepped.
     */
    public int stepFrame(PcodeThread<byte[]> thread) {
        try { return stepFrame(thread, TaskMonitor.DUMMY); }
        catch (CancelledException e) { throw new AssertionError(e); }
    }

    /** Cancellable frame step; cancellation is checked at every instruction boundary. */
    public int stepFrame(PcodeThread<byte[]> thread, TaskMonitor monitor) throws CancelledException {
        return stepFrame(thread, monitor, ignored -> {});
    }

    int stepFrame(PcodeThread<byte[]> thread, TaskMonitor monitor, LongConsumer completed)
            throws CancelledException {
        if (thread.getMachine() != this)
            throw new IllegalArgumentException("stepFrame needs a thread of this machine");
        monitor.checkCancelled();
        if (line == WSMachine.VISIBLE && needPrologue) {
            enterLine();
            return 0;
        }
        int steps = 0, cap = perLine() * (WSMachine.LINES + 2);
        while (steps < cap) {
            monitor.checkCancelled();
            int before = line;
            if (thread.getFrame() != null) thread.finishInstruction();
            else thread.stepInstruction();
            steps++;
            completed.accept(1);
            if (line == WSMachine.VISIBLE && before != WSMachine.VISIBLE) {
                enterLine();
                return steps;
            }
        }
        return steps;
    }

    private void enterLine() {
        ws.debuggerLinePrologue(line);
        needPrologue = false;
        linesAdvanced++;
    }

    /**
     * Run whole frames like WSMachine.run(frames, slice, onFrame): onFrame fires once per frame
     * before that frame's first line, frames end at the line wrap. From a fresh bind this steps
     * identically to run().
     */
    public void emulateFrames(int frames, IntConsumer onFrame) {
        if (frames <= 0) return;
        long end = framesAdvanced + frames;
        if (onFrame != null) onFrame.accept((int) framesAdvanced);
        PcodeThread<byte[]> main = ws.thread;
        while (framesAdvanced < end) {
            long before = framesAdvanced;
            main.stepInstruction();
            if (framesAdvanced != before && framesAdvanced < end && onFrame != null)
                onFrame.accept((int) framesAdvanced);
        }
    }

    // ------------------------------------------------------------------ trace restore
    static long snapOf(PcodeDebuggerAccess access) {
        if (access.getDataForSharedState() instanceof AbstractPcodeTraceDataAccess a) return a.getSnap();
        return -1;
    }

    /**
     * Best-effort state restore for re-emulation from a mid-trace snapshot: reads back what the
     * trace recorded (known bytes only, so this is a no-op on a fresh trace): RAM, the bank
     * windows, the I/O ports (bank ports through portOut so the windows remap, others verbatim;
     * computed ports skipped), the display line, and — unless this is the initial snapshot, whose
     * registers are the launcher's placeholders — CPU registers, PC and decode context. Timer
     * counters, the interrupt latch, EEPROM internals and the halted state reset; SRAM bytes are
     * placed under the restored C1 bank, which misplaces bytes recorded under other banks.
     */
    void restoreFromTrace(PcodeDebuggerAccess access) {
        PcodeTraceMemoryAccess mem = access.getDataForSharedState();
        restorePorts(mem);
        restoreRange(mem, 0x00000, 0x10000);
        restoreRange(mem, 0x10000, 0x10000);
        restoreRange(mem, 0x20000, 0x20000);
        restoreSram();
        restoreLine(mem);
        if (snapOf(access) > 0) restoreRegisters(access);
    }

    /** Computed/read-only ports, never restored (values are derived, or restoring re-triggers effects). */
    private static boolean isComputedPort(int p) {
        return p == 0x02 || p == 0xB0 || p == 0xB1 || p == 0xB3 || p == 0xB4 || p == 0xB6
            || (p >= 0xA8 && p <= 0xAB) || (p >= 0xBA && p <= 0xBE) || (p >= 0xC4 && p <= 0xC8);
    }

    private static boolean isBankPort(int p) {
        return (p >= 0xC0 && p <= 0xC3) || p == 0xCF || (p >= 0xD0 && p <= 0xD5);
    }

    private void restorePorts(PcodeTraceMemoryAccess mem) {
        if (ws.io == null) return;
        AddressSetView known =
            mem.intersectViewKnown(new AddressSet(ws.io.getAddress(0), ws.io.getAddress(0xFF)), true);
        for (AddressRange r : known) {
            long base = r.getMinAddress().getOffset();
            byte[] b = getKnownBytes(mem, r);
            for (int i = 0; i < b.length; i++) {
                int p = (int) (base + i) & 0xFF;
                if (isComputedPort(p)) continue;
                if (isBankPort(p)) ws.portOut(p, 1, b[i] & 0xFF);
                else ws.ports[p] = b[i] & 0xFF;
            }
        }
    }

    private void restoreRange(PcodeTraceMemoryAccess mem, long start, int len) {
        AddressSetView known = mem.intersectViewKnown(
            new AddressSet(ws.ram.getAddress(start), ws.ram.getAddress(start + len - 1)), true);
        for (AddressRange r : known) ws.write(r.getMinAddress().getOffset(), getKnownBytes(mem, r));
    }

    private static byte[] getKnownBytes(PcodeTraceDataAccess mem, AddressRange r) {
        ByteBuffer buf = ByteBuffer.allocate((int) r.getLength());
        mem.getBytes(r.getMinAddress(), buf);
        return buf.array();
    }

    /** Place the restored SRAM-window bytes into the SRAM image under the restored C1 bank. */
    private void restoreSram() {
        if (ws.sram == null) return;
        byte[] win = ws.read(0x10000, 0x10000);
        int bank = ws.bank(0xC1);
        for (int i = 0; i < win.length; i++)
            ws.sram[(int) ((((long) bank << 16) | i) & (ws.sram.length - 1))] = win[i];
    }

    private void restoreLine(PcodeTraceMemoryAccess mem) {
        if (ws.io == null) return;
        AddressSetView known =
            mem.intersectViewKnown(new AddressSet(ws.io.getAddress(2)), true);
        if (known.isEmpty()) return;
        ByteBuffer buf = ByteBuffer.allocate(1);
        if (mem.getBytes(ws.io.getAddress(2), buf) < 1) return;
        line = Math.min(buf.array()[0] & 0xFF, WSMachine.LINES - 1);
        lineCount = 0;
        needPrologue = true;
    }

    private void restoreRegisters(PcodeDebuggerAccess access) {
        // The machine's thread is named for the trace thread (see the factory); resolve the
        // register access through it so recording stays bound to the same thread.
        PcodeTraceRegistersAccess regs = null;
        try {
            regs = access.getDataForLocalState(ws.thread, 0);
        }
        catch (RuntimeException e) {
            regs = null;
        }
        if (regs == null) {
            Collection<? extends TraceThread> threads = null;
            try {
                if (access.getDataForSharedState() instanceof AbstractPcodeTraceDataAccess a)
                    threads = a.getPlatform().getTrace().getThreadManager().getAllThreads();
            }
            catch (RuntimeException e) {
                threads = null;
            }
            if (threads == null || threads.isEmpty()) return;
            try {
                regs = access.getDataForLocalState(threads.iterator().next(), 0);
            }
            catch (RuntimeException e) {
                return;
            }
        }
        if (regs == null) return;
        Register pc = ws.lang.getProgramCounter();
        for (Register r : ws.lang.getRegisters()) {
            if (!r.isBaseRegister() || r.isProcessorContext() || r.equals(pc)) continue;
            byte[] v = knownBytes(regs, r.getAddress(), r.getNumBytes());
            if (v != null) ws.thread.getState().setVar(r, v);
        }
        // Counter from the shadow (full linear PC); IP applied after, since overrideCounter
        // re-derives it as low16(linear), which differs for unaligned CS. Without a shadow
        // (trace recorded no steps) fall back to the CS:IP formula.
        byte[] ipBytes = pc == null ? null : knownBytes(regs, pc.getAddress(), pc.getNumBytes());
        Long linear = shadowAddr == null ? null : shadowLinear(regs);
        if (linear == null && ipBytes != null) {
            Register cs = ws.lang.getRegister("CS");
            if (cs != null) {
                long ip = 0;
                for (int i = ipBytes.length - 1; i >= 0; i--) ip = (ip << 8) | (ipBytes[i] & 0xFF);
                linear = ((ws.reg(cs) << 4) + ip) & 0xFFFFF;
            }
        }
        if (linear != null) ws.thread.overrideCounter(ws.addr(linear));
        if (ipBytes != null) ws.thread.getState().setVar(pc, ipBytes);
        Register ctx = ws.lang.getContextBaseRegister();
        if (ctx != null && ctx != Register.NO_CONTEXT) {
            byte[] b = knownBytes(regs, ctx.getAddress(), ctx.getNumBytes());
            if (b != null) {
                byte[] be = new byte[b.length + 1];
                for (int i = 0; i < b.length; i++) be[be.length - 1 - i] = b[i];
                ws.thread.overrideContext(ws.thread.getContext().assign(ctx, new BigInteger(be)));
            }
        }
    }

    /** Fully-known bytes at an address, or null. */
    private static byte[] knownBytes(PcodeTraceRegistersAccess regs, Address addr, int size) {
        AddressSetView range = new AddressSet(addr, addr.addWrap(size - 1));
        if (!regs.intersectViewKnown(range, true).equals(range)) return null;
        ByteBuffer buf = ByteBuffer.allocate(size);
        if (regs.getBytes(addr, buf) < size) return null;
        return buf.array();
    }

    /** Linear counter from the shadow scratch, or null when not recorded. */
    private Long shadowLinear(PcodeTraceRegistersAccess regs) {
        byte[] b = knownBytes(regs, shadowAddr, 4);
        if (b == null) return null;
        return ((b[3] & 0xFFL) << 24 | (b[2] & 0xFF) << 16 | (b[1] & 0xFF) << 8 | (b[0] & 0xFF))
            & 0xFFFFF;
    }
}
