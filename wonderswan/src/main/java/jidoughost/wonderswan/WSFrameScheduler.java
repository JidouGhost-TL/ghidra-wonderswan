// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Collection;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.exec.PcodeFrame;
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
    private final int frames;

    public WSFrameScheduler() { this(1); }

    /** Run consecutive frame steps in one debugger task and one trace write-down. */
    public WSFrameScheduler(int frames) {
        if (frames <= 0) throw new IllegalArgumentException("Frame count must be positive");
        this.frames = frames;
    }

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
        long[] steps = {0};
        try {
            monitor.initialize(frames);
            for (int frame = 0; frame < frames; frame++) {
                monitor.checkCancelled();
                monitor.setMessage("Running frame " + (frame + 1) + " of " + frames);
                if (machine instanceof WSDebuggerEmulator wsemu) {
                    @SuppressWarnings("unchecked")
                    PcodeThread<byte[]> typed = (PcodeThread<byte[]>) emuThread;
                    wsemu.stepFrame(typed, monitor, count -> steps[0] += count);
                }
                else {
                    for (int i = 0; i < FALLBACK_STEPS; i++) {
                        monitor.checkCancelled();
                        if (emuThread.getFrame() != null) emuThread.finishInstruction();
                        else emuThread.stepInstruction();
                        steps[0]++;
                    }
                }
                monitor.setProgress(frame + 1);
            }
        }
        catch (PcodeExecutionException e) {
            TraceSchedule completed = TraceSchedule.snap(0).steppedForward(thread, steps[0]);
            PcodeFrame frame = emuThread.getFrame();
            if (frame == null) return new RecordRunResult(completed.assumeRecorded(), e);
            // Follow Ghidra's scheduler: retry the failing op and retain completed p-code steps.
            frame.stepBack();
            int count = frame.resetCount();
            if (count == 0) {
                emuThread.dropInstruction();
                return new RecordRunResult(completed, e);
            }
            return new RecordRunResult(completed.steppedPcodeForward(thread, count + 1).assumeRecorded(), e);
        }
        catch (CancelledException e) {
            return new RecordRunResult(
                TraceSchedule.snap(0).steppedForward(thread, steps[0]).assumeRecorded(), e);
        }
        return new RecordRunResult(
            TraceSchedule.snap(0).steppedForward(thread, steps[0]).assumeRecorded(), null);
    }
}
