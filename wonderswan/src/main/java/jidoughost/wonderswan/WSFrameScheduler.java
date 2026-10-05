// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Collection;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.TickStep;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Scheduler that runs until the next VBlank (frame step) for use with the Debugger emulation
 * service's run actions. Breakpoints still win: a breakpoint hit stops the run with its error,
 * like any other run.
 */
public class WSFrameScheduler implements Scheduler {
    /** Fallback step count when the machine is not a WonderSwan emulator. */
    public static final int FALLBACK_STEPS = 40000;

    @Override
    public TickStep nextSlice(Trace trace) {
        return new TickStep(-1, 1000);
    }

    @Override
    public RunResult run(Trace trace, TraceThread eventThread, PcodeMachine<?> machine,
            TaskMonitor monitor) {
        TraceThreadManager tm = trace.getThreadManager();
        TraceThread thread = eventThread;
        if (thread == null) {
            Collection<? extends TraceThread> all = tm.getAllThreads();
            if (all.isEmpty()) return new RecordRunResult(TraceSchedule.snap(0), null);
            thread = all.iterator().next();
        }
        PcodeThread<?> emuThread = machine.getThread(thread.getPath(), true);
        int steps = 0;
        try {
            if (machine instanceof WSDebuggerEmulator wsemu) {
                @SuppressWarnings("unchecked")
                PcodeThread<byte[]> typed = (PcodeThread<byte[]>) emuThread;
                steps = wsemu.stepFrame(typed);
            }
            else {
                for (; steps < FALLBACK_STEPS; steps++) {
                    monitor.checkCancelled();
                    emuThread.stepInstruction();
                }
            }
        }
        catch (PcodeExecutionException e) {
            return new RecordRunResult(
                TraceSchedule.snap(0).steppedForward(thread, steps).assumeRecorded(), e);
        }
        catch (CancelledException e) {
            return new RecordRunResult(
                TraceSchedule.snap(0).steppedForward(thread, steps).assumeRecorded(), e);
        }
        return new RecordRunResult(
            TraceSchedule.snap(0).steppedForward(thread, steps).assumeRecorded(), null);
    }
}
