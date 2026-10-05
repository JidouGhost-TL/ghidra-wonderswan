// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Map;
import java.util.WeakHashMap;

import javax.swing.SwingUtilities;

import docking.action.builder.ActionBuilder;
import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerEmulationService.CachedEmulator;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.time.schedule.TraceSchedule;

/**
 * WonderSwan debugging in the Debugger (and CodeBrowser) tool: a screen view, a controller input
 * panel and a run-to-VBlank (frame step) action, all driven by the {@link WSDebuggerEmulator} the
 * emulation service caches for the current trace.
 *
 * <p>
 * Setup: open a WonderSwan program, pick "WonderSwan Concrete P-code Emulator" under Debugger →
 * Configure Emulator, then Emulate Program (or any emulate/step action). The screen refreshes
 * whenever emulation stops; the input panel feeds the emulated key port live.
 */
@PluginInfo(
    shortDescription = "WonderSwan Debugger",
    description = "Screen, controller input and frame stepping for WonderSwan emulation.",
    category = PluginCategoryNames.DEBUGGER,
    packageName = DebuggerPluginPackage.NAME,
    status = PluginStatus.RELEASED,
    servicesRequired = {
        DebuggerTraceManagerService.class,
        DebuggerEmulationService.class
    })
public class WSDebuggerPlugin extends Plugin implements DebuggerEmulationService.EmulatorStateListener {
    @AutoServiceConsumed
    private DebuggerTraceManagerService traceManager;
    @AutoServiceConsumed
    private DebuggerEmulationService emulationService;
    @SuppressWarnings("unused")
    private AutoService.Wiring autoServiceWiring;

    private final Map<Trace, WSDebuggerEmulator> byTrace = new WeakHashMap<>();
    private WSScreenProvider screen;
    private WSInputProvider input;
    private DockingAction actionStepFrame;

    public WSDebuggerPlugin(PluginTool tool) {
        super(tool);
        autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
    }

    @Override
    protected void init() {
        super.init();
        screen = new WSScreenProvider(this);
        input = new WSInputProvider(this);
        tool.addComponentProvider(screen, false);
        tool.addComponentProvider(input, false);
        actionStepFrame = new ActionBuilder("Step Frame (VBlank)", getName())
            .description("Run the WonderSwan emulation to the next VBlank")
            .menuPath(DebuggerPluginPackage.NAME, "Step Frame (VBlank)")
            .menuGroup("Debugger")
            .popupMenuPath("Step Frame (VBlank)")
            .popupMenuGroup("Debugger")
            .enabledWhen(ctx -> getCurrentTrace() != null && isWonderSwanTrace(getCurrentTrace()))
            .onAction(ctx -> stepFrame())
            .buildAndInstall(tool);
        emulationService.addStateListener(this);
    }

    @Override
    protected void dispose() {
        // Services may already be gone at tool close; providers/actions may be
        // absent if init() never ran. Guard everything so dispose never throws.
        if (emulationService != null) emulationService.removeStateListener(this);
        if (screen != null) tool.removeComponentProvider(screen);
        if (input != null) tool.removeComponentProvider(input);
        if (actionStepFrame != null) tool.removeAction(actionStepFrame);
        super.dispose();
    }

    Trace getCurrentTrace() {
        return traceManager == null ? null : traceManager.getCurrentTrace();
    }

    static boolean isWonderSwanTrace(Trace trace) {
        return trace != null
            && "V30MZ".equals(trace.getBaseLanguage().getProcessor().toString());
    }

    /** The WonderSwan emulator running the current trace, or null. */
    synchronized WSDebuggerEmulator getCurrentEmulator() {
        Trace trace = getCurrentTrace();
        if (trace == null) return null;
        WSDebuggerEmulator emu = byTrace.get(trace);
        if (emu == null && emulationService != null) {
            try {
                DebuggerCoordinates current = traceManager.getCurrent();
                TraceSchedule time = current.getTime();
                PcodeMachine<?> cached = emulationService.getCachedEmulator(trace, time);
                if (cached instanceof WSDebuggerEmulator w) {
                    emu = w;
                    byTrace.put(trace, w);
                }
            }
            catch (RuntimeException e) {
                // No cached emulator for this view; providers show their idle state.
            }
        }
        return emu;
    }

    private void stepFrame() {
        DebuggerCoordinates current = traceManager.getCurrent();
        Trace trace = current.getTrace();
        TracePlatform platform = current.getPlatform();
        TraceSchedule time = current.getTime();
        if (trace == null || platform == null || time == null) return;
        emulationService.backgroundRun(platform, time, new WSFrameScheduler());
    }

    @Override
    public void running(CachedEmulator ce) {
    }

    @Override
    public void stopped(CachedEmulator ce) {
        if (ce.emulator() instanceof WSDebuggerEmulator w) {
            synchronized (this) {
                byTrace.put(ce.trace(), w);
            }
            SwingUtilities.invokeLater(() -> {
                screen.refresh();
                input.refresh();
            });
        }
    }
}
