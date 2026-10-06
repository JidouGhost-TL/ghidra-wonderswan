// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;


import ghidra.app.util.PseudoInstruction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.base.project.GhidraProject;
import ghidra.pcode.exec.BytesPcodeExecutorState;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import db.Transaction;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Synthetic code exercises cache reuse, memory changes, decode context and the bank-switch queue. */
final class WSEmulationChecks {
    private static Language language;

    static void run(Language lang) throws Exception {
        language = lang;
        cacheValidatesBytesAndWholeContext();
        flatStateCopiesForksAndClears();
        contextMemoRepairsRawWrites();
        cachedFarTransferReplaysContextCommits();
        segmentLibraryWrapsThePhysicalAddress();
        bankSwitchRetainsPrefetchedCodeThenUsesNewBytes();
        System.out.println("WSEmulationChecks: PASS (cache, flat state, context, self-modifying code and prefetch)");
    }

    private static void cachedFarTransferReplaysContextCommits() {
        var emulator = new WSDebuggerEmulator(language);
        var thread = emulator.newThread();
        var address = language.getDefaultSpace().getAddress(0x1000);
        emulator.getSharedState().setVar(address, 16, false, new byte[16]);
        emulator.getSharedState().setVar(address, 5, false,
            new byte[] {(byte) 0xEA, 0x00, 0x01, 0x00, 0x02});
        RegisterValue input = new RegisterValue(language.getContextBaseRegister(), BigInteger.ZERO);
        for (int i = 0; i < 3; i++) {
            thread.overrideCounter(address);
            thread.overrideContext(input);
            thread.stepInstruction();
            assertEquals(0x2100, thread.getCounter().getOffset());
            assertEquals(BigInteger.valueOf(0x200), thread.getContext()
                .getRegisterValue(language.getRegister("csval")).getUnsignedValueIgnoreMask());
        }
    }

    private static void segmentLibraryWrapsThePhysicalAddress() {
        var emulator = new WSDebuggerEmulator(language);
        assertTrue(emulator.getUseropLibrary().getUserops().containsKey("segment"));
        var thread = emulator.newThread();
        var memory = emulator.getSharedState();
        var start = language.getDefaultSpace().getAddress(0x1000);
        memory.setVar(start, 16, false, new byte[16]);
        memory.setVar(start, 2, false, new byte[] {(byte) 0x8B, 0x07});
        memory.setVar(language.getDefaultSpace().getAddress(2), 2, false, new byte[] {0x34, 0x12});
        thread.getState().setVar(language.getRegister("DS"), new byte[] {(byte) 0xFF, (byte) 0xFF});
        thread.getState().setVar(language.getRegister("BX"), new byte[] {0x12, 0});
        thread.overrideCounter(start);
        thread.overrideContext(new RegisterValue(language.getContextBaseRegister(), BigInteger.ZERO));
        thread.stepInstruction();
        assertArrayEquals(new byte[] {0x34, 0x12}, thread.getState().getVar(language.getRegister("AX"), Reason.INSPECT));
    }

    private static WSDebuggerEmulator loopingMachine(Program program, String threadName) {
        var emulator = WSDebuggerEmulator.forProgram(program, false, threadName);
        var machine = emulator.ws;
        machine.traceLimit = 0;
        machine.setReg(language.getRegister("CS"), 0);
        machine.syncCsval();
        machine.write(0x1000, new byte[] {(byte) 0x90, (byte) 0xEB, (byte) 0xFD});
        machine.thread.overrideCounter(machine.addr(0x1000));
        return emulator;
    }

    private static byte[] savedState(WSMachine machine) throws Exception {
        var bytes = new java.io.ByteArrayOutputStream();
        machine.saveState(new java.io.DataOutputStream(bytes));
        return bytes.toByteArray();
    }

    private static void frameRunsPreserveProgressAndCancellation(Program program) throws Exception {
        Trace trace = new DBTrace("frame-check", program.getCompilerSpec(), WSEmulationChecks.class);
        try {
            TraceThread traceThread;
            try (Transaction transaction = trace.openTransaction("CPU")) {
                ProgramEmulationUtils.createObjects(trace);
                traceThread = trace.getThreadManager().createThread("Threads[cpu]", 0);
            }
            var batch = loopingMachine(program, traceThread.getPath());
            var reference = loopingMachine(program, traceThread.getPath());
            var result = new WSFrameScheduler(3).run(trace, traceThread, batch, TaskMonitor.DUMMY);
            assertNull(result.error());
            long ticks = 0;
            for (int i = 0; i < 3; i++) ticks += reference.stepFrame(reference.ws.thread);
            assertEquals(ticks, result.schedule().totalTickCount());
            assertEquals(reference.ws.instructions, batch.ws.instructions);
            assertArrayEquals(savedState(reference.ws), savedState(batch.ws));

            var cancelled = loopingMachine(program, traceThread.getPath());
            var monitor = new TaskMonitorAdapter(true) {
                int checks;
                @Override public void checkCancelled() throws CancelledException {
                    if (++checks == 1000) cancel();
                    super.checkCancelled();
                }
            };
            var partial = new WSFrameScheduler(3).run(trace, traceThread, cancelled, monitor);
            assertTrue(partial.error() instanceof CancelledException);
            long completed = partial.schedule().totalTickCount();
            assertTrue(completed > 0 && completed < cancelled.perLine() * WSMachine.VISIBLE);
            assertEquals(completed, cancelled.ws.instructions);
            var partialReference = loopingMachine(program, traceThread.getPath());
            for (long i = 0; i < completed; i++) partialReference.ws.thread.stepInstruction();
            assertArrayEquals(savedState(partialReference.ws), savedState(cancelled.ws));

            var untouched = loopingMachine(program, traceThread.getPath());
            byte[] before = savedState(untouched.ws);
            var alreadyCancelled = new TaskMonitorAdapter(true);
            alreadyCancelled.cancel();
            var empty = new WSFrameScheduler(2).run(trace, traceThread, untouched, alreadyCancelled);
            assertTrue(empty.error() instanceof CancelledException);
            assertEquals(0, empty.schedule().totalTickCount());
            assertArrayEquals(before, savedState(untouched.ws));

            var stopped = loopingMachine(program, traceThread.getPath());
            stopped.inject(stopped.ws.addr(0x1001), "emu_swi();");
            var breakpoint = new WSFrameScheduler(3).run(trace, traceThread, stopped, TaskMonitor.DUMMY);
            assertTrue(breakpoint.error() instanceof PcodeExecutionException);
            assertEquals(1, breakpoint.schedule().totalTickCount());
            assertEquals(1, stopped.ws.instructions);
            assertNull(stopped.ws.thread.getFrame());
            stopped.clearInject(stopped.ws.addr(0x1001));
            var resumed = new WSFrameScheduler().run(trace, traceThread, stopped, TaskMonitor.DUMMY);
            assertNull(resumed.error());
            var stoppedReference = loopingMachine(program, traceThread.getPath());
            stoppedReference.stepFrame(stoppedReference.ws.thread);
            assertArrayEquals(savedState(stoppedReference.ws), savedState(stopped.ws));

            var pending = loopingMachine(program, traceThread.getPath());
            pending.inject(pending.ws.addr(0x1001),
                "local saved:2 = AX; emu_swi(); AX = saved; emu_exec_decoded();");
            var interrupted = new WSFrameScheduler(3).run(trace, traceThread, pending, TaskMonitor.DUMMY);
            assertTrue(interrupted.error() instanceof PcodeExecutionException);
            assertEquals(1, interrupted.schedule().tickCount());
            assertTrue(interrupted.schedule().pTickCount() > 0);
            assertNotNull(pending.ws.thread.getFrame());
            pending.ws.thread.skipPcodeOp(); // resume past the breakpoint's userop
            pending.clearInject(pending.ws.addr(0x1001));
            var finished = new WSFrameScheduler().run(trace, traceThread, pending, TaskMonitor.DUMMY);
            assertNull(finished.error());
            assertArrayEquals(savedState(stoppedReference.ws), savedState(pending.ws));

            int[] writes = new int[4];
            stopped.ws.traceCallbacks = new PcodeEmulationCallbacks<byte[]>() {
                @Override public <A, T> void dataWritten(PcodeThread<byte[]> thread,
                        PcodeExecutorStatePiece<A, T> piece, Address address, int length, T value) {
                    AddressSpace space = address.getAddressSpace();
                    writes[space.isUniqueSpace() ? 0 : space.isRegisterSpace() ? 1 :
                        space == stopped.ws.io ? 2 : 3]++;
                }
            };
            var unique = language.getAddressFactory().getUniqueSpace().getAddress(0x100);
            stopped.ws.thread.getState().setVar(unique, 1, false, new byte[] {1});
            stopped.ws.setReg(language.getRegister("AX"), 1);
            stopped.getSharedState().setVar(stopped.ws.io.getAddress(0), 1, false, new byte[] {1});
            stopped.ws.write(0x2000, new byte[] {1});
            assertArrayEquals(new int[] {0, 1, 1, 1}, writes);
            assertArrayEquals(new byte[] {1}, stopped.ws.thread.getState().getVar(unique, 1, false, Reason.INSPECT));
        } finally { trace.release(WSEmulationChecks.class); }
    }

    private static void contextMemoRepairsRawWrites() {
        int[] writes = {0};
        var contextRegister = language.getContextBaseRegister();
        var callbacks = new PcodeEmulationCallbacks<byte[]>() {
            @Override
            public <A, T> void dataWritten(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, T> piece,
                    Address address, int length, T value) {
                if (address.equals(contextRegister.getAddress())) writes[0]++;
            }
        };
        var emulator = new WSDebuggerEmulator(language, callbacks);
        var thread = emulator.newThread();
        var address = language.getDefaultSpace().getAddress(0x1000);
        emulator.getSharedState().setVar(address, 16, false,
            new byte[] {(byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90,
                (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90,
                (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90,
                (byte) 0x90, (byte) 0x90, (byte) 0x90, (byte) 0x90});
        thread.overrideContext(new RegisterValue(contextRegister, BigInteger.ZERO));
        thread.overrideCounter(address);
        writes[0] = 0;
        thread.stepInstruction();
        assertEquals(1, writes[0]);
        RegisterValue expectedContext = thread.getContext();
        byte[] expectedBytes = thread.getState().getVar(contextRegister, Reason.INSPECT);
        thread.overrideCounter(address);
        thread.stepInstruction();
        assertEquals(1, writes[0]);
        byte[] damaged = expectedBytes.clone();
        damaged[0] ^= 1;
        thread.getState().setVar(contextRegister, damaged);
        thread.overrideCounter(address);
        thread.stepInstruction();
        assertEquals(expectedContext, thread.getContext());
        assertArrayEquals(expectedBytes, thread.getState().getVar(contextRegister, Reason.INSPECT));
        assertEquals(3, writes[0]); // the raw write and its repair
    }

    private static void flatStateCopiesForksAndClears() {
        int[] events = new int[2];
        var callbacks = new PcodeStateCallbacks() {
            @Override
            public <A, T> void dataWritten(PcodeExecutorStatePiece<A, T> piece,
                    Address address, int length, T value) {
                events[0]++;
            }

            @Override
            public <A, T> AddressSetView readUninitialized(PcodeExecutorStatePiece<A, T> piece,
                    AddressSetView set, Reason reason) {
                events[1]++;
                return set;
            }
        };
        WSArrayState state = new WSArrayState(language, callbacks);
        Address address = language.getDefaultSpace().getAddress(0x1234);
        assertArrayEquals(new byte[4], state.getVar(address, 4, false, Reason.EXECUTE_READ));
        assertArrayEquals(new byte[4], state.getVar(address, 4, false, Reason.EXECUTE_DECODE));
        byte[] value = {1, 2, 3, 4};
        state.setVar(address, 4, false, value);
        value[0] = 9;
        byte[] read = state.getVar(address, 4, false, Reason.INSPECT);
        assertArrayEquals(new byte[] {1, 2, 3, 4}, read);
        read[1] = 9;
        assertTrue(state.matches(address, new byte[] {1, 2, 3, 4}));
        assertFalse(state.matches(address, new byte[] {1, 9, 3, 4}));
        var unique = language.getAddressFactory().getUniqueSpace();
        Address grown = unique.getAddress(0x80000);
        Address crossing = unique.getAddress(16 * 1024 * 1024 - 2);
        Address sparse = unique.getAddress(32 * 1024 * 1024);
        for (Address target : new Address[] {grown, crossing, sparse}) {
            state.setVar(target, 4, false, new byte[] {5, 6, 7, 8});
            assertArrayEquals(new byte[] {5, 6, 7, 8}, state.getVar(target, 4, false, Reason.INSPECT));
        }
        WSArrayState fork = state.fork(PcodeStateCallbacks.NONE);
        state.setVar(sparse, 4, false, new byte[4]);
        state.clear();
        assertArrayEquals(new byte[4], state.getVar(address, 4, false, Reason.INSPECT));
        assertArrayEquals(new byte[4], state.getVar(crossing, 4, false, Reason.INSPECT));
        for (Address target : new Address[] {grown, crossing, sparse}) {
            assertArrayEquals(new byte[] {5, 6, 7, 8}, fork.getVar(target, 4, false, Reason.INSPECT));
        }
        assertTrue(fork.matches(address, new byte[] {1, 2, 3, 4}));
        assertEquals(5, events[0]);
        assertEquals(0, events[1]);
        try {
            state.getVar(language.getDefaultSpace().getMaxAddress(), 2, false, Reason.INSPECT);
            fail("An access beyond the address space must be rejected");
        } catch (IllegalArgumentException expected) {
            // Keep the framework's range checking on unusual accesses.
        }
    }

    private static void cacheValidatesBytesAndWholeContext() throws Exception {
        var state = new BytesPcodeExecutorState(language, PcodeStateCallbacks.NONE);
        var address = language.getDefaultSpace().getAddress(0);
        state.setVar(address, 16, false, new byte[16]);
        state.setVar(address, 3, false, new byte[] {(byte) 0xB8, 1, 0});
        var decoder = new WSInstructionDecoder(language, state);
        RegisterValue context = new RegisterValue(language.getContextBaseRegister(), BigInteger.ZERO);
        PseudoInstruction first = decoder.decodeInstruction(address, context);
        decoder.branched(address);
        assertSame(first, decoder.decodeInstruction(address, context));
        assertSame(first.getPcode(), first.getPcode());
        state.setVar(address.add(1), 1, false, new byte[] {2});
        PseudoInstruction changed = decoder.decodeInstruction(address, context);
        assertNotSame(first, changed);
        assertArrayEquals(new byte[] {(byte) 0xB8, 2, 0}, changed.getParsedBytes());
        RegisterValue other = context.assign(language.getRegister("csval"), BigInteger.ONE);
        assertNotSame(changed, decoder.decodeInstruction(address, other));
        // Equal numeric values with different context masks must also be distinct.
        RegisterValue partial = new RegisterValue(language.getRegister("csval"), BigInteger.ZERO);
        assertNotSame(decoder.decodeInstruction(address, context), decoder.decodeInstruction(address, partial));
    }

    private static void bankSwitchRetainsPrefetchedCodeThenUsesNewBytes() throws Exception {
        byte[] rom = WSGuiSmoke.syntheticRom();
        java.util.Arrays.fill(rom, 0, rom.length - 16, (byte) 0x90);
        rom[1] = rom[0x10001] = (byte) 0xB8; // MOV AX, immediate after the first NOP
        rom[2] = rom[3] = 0x22;
        rom[0x10002] = rom[0x10003] = 0x11;
        Path dir = Files.createTempDirectory("ws-cache");
        Path file = dir.resolve("synthetic.ws");
        Files.write(file, rom);
        GhidraProject project = GhidraProject.createProject(dir.toString(), "Cache", true);
        try {
            Program program = project.importProgram(file.toFile(), WonderSwanLoader.class,
                language, language.getDefaultCompilerSpec());
            WSMachine machine = new WSMachine(program, false);
            machine.setReg(language.getRegister("CS"), 0x2000);
            machine.thread.overrideCounter(machine.addr(0x20000));
            machine.thread.overrideContext(machine.thread.getContext().assign(
                language.getRegister("csval"), BigInteger.valueOf(0x2000)));
            machine.thread.stepInstruction();
            machine.portOut(0xC2, 1, 0);
            assertEquals(1, machine.prefetchHolds);
            machine.thread.stepInstruction();
            assertEquals(0x1111, machine.reg(language.getRegister("AX")));
            machine.thread.overrideCounter(machine.addr(0x20020));
            machine.thread.stepInstruction(); // leave the held range, releasing it
            machine.thread.overrideCounter(machine.addr(0x20001));
            machine.thread.stepInstruction();
            assertEquals(0x2222, machine.reg(language.getRegister("AX")));
            // A subsequent self-modifying RAM write must replace both decoded bytes and p-code.
            machine.write(0x20001, new byte[] {(byte) 0xB8, 0x33, 0x33});
            machine.thread.overrideCounter(machine.addr(0x20001));
            machine.thread.stepInstruction();
            assertEquals(0x3333, machine.reg(language.getRegister("AX")));
            machine.setReg(language.getRegister("CS"), 0);
            machine.thread.overrideContext(machine.thread.getContext().assign(
                language.getRegister("csval"), BigInteger.ZERO));
            machine.write(0x1000, new byte[] {(byte) 0xB8, 0x44, 0x44});
            machine.thread.overrideCounter(machine.addr(0x1000));
            machine.thread.stepInstruction();
            assertEquals(0x4444, machine.reg(language.getRegister("AX")));
            machine.write(0x1001, new byte[] {0x55, 0x55});
            machine.thread.overrideCounter(machine.addr(0x1000));
            machine.thread.stepInstruction();
            assertEquals(0x5555, machine.reg(language.getRegister("AX")));
            // Rewriting a bank repairs modified window bytes even when the bank value is unchanged.
            machine.portOut(0xC2, 1, 0);
            assertArrayEquals(new byte[] {(byte) 0xB8, 0x22, 0x22}, machine.read(0x20001, 3));
            int[] remaps = {0};
            machine.traceCallbacks = new PcodeEmulationCallbacks<byte[]>() {
                @Override
                public <A, T> void dataWritten(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, T> piece,
                        Address address, int length, T value) {
                    if (address.equals(machine.addr(0x20000)) && length == 0x10000) remaps[0]++;
                }
            };
            machine.portOut(0xC2, 1, 0);
            assertEquals(1, remaps[0]); // a newly attached recorder still observes the mapping
            machine.write(0x20010, new byte[] {0x33});
            machine.portOut(0xC2, 1, 0);
            assertEquals(2, remaps[0]);
            assertEquals((byte) 0x90, machine.read(0x20010, 1)[0]);
            int[] contextWrites = {0};
            var recorder = new PcodeEmulationCallbacks<byte[]>() {
                @Override
                public <A, T> void dataWritten(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, T> piece,
                        Address address, int length, T value) {
                    if (address.equals(language.getContextBaseRegister().getAddress())) contextWrites[0]++;
                }
            };
            machine.traceCallbacks = recorder;
            machine.thread.overrideCounter(machine.addr(0x1000));
            machine.thread.stepInstruction();
            assertEquals(1, contextWrites[0]);
            machine.thread.overrideCounter(machine.addr(0x1000));
            machine.thread.stepInstruction();
            assertEquals(1, contextWrites[0]);
            frameRunsPreserveProgressAndCancellation(program);
        } finally {
            project.close();
            try (var files = Files.walk(dir)) {
                for (Path path : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }
}
