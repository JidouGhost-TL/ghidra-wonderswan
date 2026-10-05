// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Collection;

import ghidra.app.plugin.core.debug.service.emulation.data.InternalPcodeDebuggerDataAccess;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.AbstractPcodeTraceDataAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

/**
 * Emulator factory that makes the Debugger's "Emulate" actions run WonderSwan programs with real
 * hardware behaviour: I/O ports, interrupts, timers, DMA, banking and EEPROMs from
 * {@link WSMachine}, trace-recorded.
 *
 * <p>
 * The factory resolves the WonderSwan program behind the trace through the static mappings (the
 * program's whole ROM is needed for bank switching; the trace only maps the fixed windows),
 * builds a {@link WSMachine} for it and returns its trace-attached emulator. Anything else —
 * other languages, unresolvable programs, any failure — falls back to the default concrete
 * emulator, so this factory is safe to select globally.
 */
public class WSEmulatorFactory implements EmulatorFactory {
    @Override
    public String getTitle() {
        return "WonderSwan Concrete P-code Emulator";
    }

    @Override
    public PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer) {
        try {
            return createOrDefault(access, writer);
        }
        catch (Throwable t) {
            Msg.warn(this, "WonderSwan emulator setup failed, using default: " + t);
            return new PcodeEmulator(access.getLanguage(), writer.callbacks());
        }
    }

    private PcodeMachine<?> createOrDefault(PcodeDebuggerAccess access, Writer writer) {
        Program program = resolveProgram(access);
        if (program == null || !isWonderSwan(program))
            return new PcodeEmulator(access.getLanguage(), writer.callbacks());
        boolean color = program.getOptions("WonderSwan").getBoolean("Color", true);
        WSMachine ws = new WSMachine(program, color, firstThreadPath(access));
        WSDebuggerEmulator emu = (WSDebuggerEmulator) ws.emu;
        emu.bind(ws);
        emu.attachTrace(access, writer);
        return emu;
    }

    /** True for programs imported by the WonderSwan loader (V30MZ + io space + stored ROM). */
    static boolean isWonderSwan(Program program) {
        Language lang = program.getLanguage();
        if (!"V30MZ".equals(lang.getProcessor().toString())) return false;
        if (lang.getAddressFactory().getAddressSpace("io") == null) return false;
        return !program.getMemory().getAllFileBytes().isEmpty();
    }

    static Trace traceOf(PcodeDebuggerAccess access) {
        if (access.getDataForSharedState() instanceof AbstractPcodeTraceDataAccess a)
            return a.getPlatform().getTrace();
        return null;
    }

    /** Path of the first live trace thread (the emulator thread is named for it). */
    static String firstThreadPath(PcodeDebuggerAccess access) {
        Trace trace = traceOf(access);
        if (trace == null) return null;
        long snap = WSDebuggerEmulator.snapOf(access);
        Collection<? extends TraceThread> threads = snap < 0
            ? trace.getThreadManager().getAllThreads()
            : trace.getThreadManager().getLiveThreads(snap);
        if (threads.isEmpty()) threads = trace.getThreadManager().getAllThreads();
        return threads.isEmpty() ? null : threads.iterator().next().getPath();
    }

    /**
     * The open program mapped to this trace, via the entry address (always mapped for
     * WonderSwan programs), or null when there is none (no tool, no mapping service, no match).
     */
    static Program resolveProgram(PcodeDebuggerAccess access) {
        if (!(access.getDataForSharedState() instanceof InternalPcodeDebuggerDataAccess data))
            return null;
        ServiceProvider provider = data.getServiceProvider();
        DebuggerStaticMappingService maps =
            provider == null ? null : provider.getService(DebuggerStaticMappingService.class);
        Trace trace = traceOf(access);
        if (maps == null || trace == null) return null;
        Address entry = access.getLanguage().getDefaultSpace().getAddress(0xFFFF0);
        TraceLocation loc = new DefaultTraceLocation(trace, null,
            Lifespan.at(Math.max(0, WSDebuggerEmulator.snapOf(access))), entry);
        ProgramLocation progLoc;
        try {
            progLoc = maps.getOpenMappedLocation(loc);
        }
        catch (Exception e) {
            return null;
        }
        return progLoc == null ? null : progLoc.getProgram();
    }
}
