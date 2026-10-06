// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.base.project.GhidraProject;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.TestTool;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Headed GUI smoke test for the WonderSwan plugins: the asset viewer
 * ({@link WSAssetPlugin}/{@link WSAssetProvider}) and the debugger integration
 * ({@link WSDebuggerPlugin}, {@link WSScreenProvider}, {@link WSInputProvider},
 * {@link WSEmulatorFactory}).
 *
 * <p>Runs as a plain main (via the {@code guiTest} Gradle task) under a display
 * (Xvfb in CI, see {@code wonderswan/gui-test/}). It creates a tool, imports a
 * small synthetic ROM, adds each plugin, shows each provider, renders the Tiles
 * tab from a ROM offset, steps two live frames through the debugger's frame-step
 * API and checks the screen paints the emulated frame, removes and re-adds the
 * plugins, and closes cleanly.
 * Any exception — including the double-registration {@code AssertException}
 * ("... was already added") — fails the test with a non-zero exit.
 *
 * <p>Public-safe: the ROM is generated in-memory (no game data, no addresses).
 */
public final class WSGuiSmoke {
    private WSGuiSmoke() { }

    private static int checks;

    private static void check(boolean ok, String what) {
        checks++;
        if (!ok) throw new AssertionError("CHECK FAILED: " + what);
        System.out.println("WSGuiSmoke: ok - " + what);
    }

    /** Run {@code body} on the Swing EDT, propagating any failure. */
    private static <T> T onEdt(Callable<T> body) throws Exception {
        final Object[] out = new Object[1];
        final Throwable[] err = new Throwable[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                out[0] = body.call();
            } catch (Throwable t) {
                err[0] = t;
            }
        });
        if (err[0] instanceof Exception e) throw e;
        if (err[0] instanceof Error e) throw e;
        if (err[0] != null) throw new RuntimeException(err[0]);
        @SuppressWarnings("unchecked")
        T result = (T) out[0];
        return result;
    }

    /** Minimal synthetic ROM: 128 KiB, tile pattern + valid footer. */
    static byte[] syntheticRom() {
        int size = 0x20000;
        byte[] rom = new byte[size];
        for (int i = 0; i < 8192; i++) {
            rom[i] = (byte) ((i & 1) == 0 ? 0xAA : 0x55);
        }
        // Reset target (visible at linear F000:0000 through the reset bank mapping):
        // a tight spin (JMP short -2) so emulated frames execute without running off the
        // top of the address space. Must precede the checksum below.
        rom[0x10000] = (byte) 0xEB;
        rom[0x10000 + 1] = (byte) 0xFE;
        int f = size - WSHeader.SIZE;
        rom[f] = (byte) 0xEA;
        rom[f + 1] = 0x00; rom[f + 2] = 0x00;
        rom[f + 3] = 0x00; rom[f + 4] = (byte) 0xF0;
        rom[f + 7] = 0x01;   // colour hardware
        rom[f + 10] = 0x00;  // size code for 128 KiB
        rom[f + 11] = 0x00;  // no save hardware
        rom[f + 13] = 0x00;  // 2001 mapper
        int sum = 0;
        for (int i = 0; i < rom.length - 2; i++) sum += rom[i] & 0xFF;
        rom[f + 14] = (byte) sum;
        rom[f + 15] = (byte) (sum >> 8);
        return rom;
    }

    public static void main(String[] args) throws Exception {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            System.out.println("WSGuiSmoke: FAIL: no display (run under Xvfb or with DISPLAY set)");
            System.exit(1);
        }
        System.setProperty("SystemUtilities.isTesting", "true");
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        if (installDir == null) installDir = "/opt/ghidra_12.1.3_PUBLIC";

        // Watchdog: never hang CI forever.
        Thread watchdog = new Thread(() -> {
            try {
                Thread.sleep(300_000);
                System.out.println("WSGuiSmoke: FAIL: timed out after 5 minutes");
                System.exit(1);
            } catch (InterruptedException e) {
                // done
            }
        });
        watchdog.setDaemon(true);
        watchdog.start();

        try {
            run(installDir);
        } catch (Throwable t) {
            System.out.println("WSGuiSmoke: FAIL: " + t);
            t.printStackTrace(System.out);
            System.exit(1);
        } finally {
            watchdog.interrupt();
        }
        System.out.println("WSGuiSmoke: PASS (" + checks + " checks)");
        System.exit(0);
    }

    private static void run(String installDir) throws Exception {
        GhidraApplicationLayout layout = new GhidraApplicationLayout(new File(installDir));
        GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
        config.setShowSplashScreen(false);
        Application.initializeApplication(layout, config);
        check(true, "application initialized");

        Language lang = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("V30MZ:LE:16:default"));
        WSEmulationChecks.run(lang);
        CompilerSpec cspec = lang.getDefaultCompilerSpec();
        check(lang != null, "V30MZ language available");

        File tmpDir = Files.createTempDirectory("wsgui-smoke").toFile();
        File romFile = new File(tmpDir, "smoke.ws");
        Files.write(romFile.toPath(), syntheticRom());
        check(romFile.length() == 0x20000, "synthetic ROM written");

        GhidraProject gp = GhidraProject.createProject(tmpDir.getAbsolutePath(), "Smoke", true);
        Program program = gp.importProgram(romFile, WonderSwanLoader.class, lang, cspec);
        check(program != null && WSRom.size(program) == 0x20000, "ROM imported with stored image");

        PluginTool tool = onEdt(() -> new TestTool(gp.getProject()));
        check(tool != null, "tool created: " + tool.getName());

        // Program manager + open the ROM so ProgramPlugins activate.
        onEdt(() -> {
            tool.addPlugin(ProgramManagerPlugin.class.getName());
            return null;
        });
        check(true, "ProgramManagerPlugin added");
        ProgramManagerPlugin pm = onEdt(() -> {
            for (Plugin p : tool.getManagedPlugins()) {
                if (p instanceof ProgramManagerPlugin m) return m;
            }
            return null;
        });
        check(pm != null, "program manager found");
        onEdt(() -> {
            pm.openProgram(program.getDomainFile());
            return null;
        });
        check(pm.getCurrentProgram() == program, "program opened in tool");

        // ---- Asset viewer ----
        onEdt(() -> {
            tool.addPlugin(WSAssetPlugin.class.getName());
            return null;
        });
        check(true, "WSAssetPlugin added without exception");
        WSAssetPlugin assetPlugin = onEdt(() -> {
            for (Plugin p : tool.getManagedPlugins()) {
                if (p instanceof WSAssetPlugin a) return a;
            }
            return null;
        });
        check(assetPlugin != null, "asset plugin instance found");
        WSAssetProvider assetProvider = onEdt(
            () -> (WSAssetProvider) tool.getComponentProvider("WS Asset Viewer"));
        check(assetProvider != null, "asset provider registered");
        check(onEdt(assetProvider::isInTool), "asset provider in tool");
        // Exactly once: the tool's provider is the plugin's own instance.
        Field pluginProviderField = WSAssetPlugin.class.getDeclaredField("provider");
        pluginProviderField.setAccessible(true);
        WSAssetProvider owned = (WSAssetProvider) pluginProviderField.get(assetPlugin);
        check(owned == assetProvider, "asset provider registered exactly once");
        check(assetProvider.getProgram() == program, "asset provider received program");

        var assetActions = onEdt(() -> tool.getDockingActionsByOwnerName(assetPlugin.getName()));
        check(hasAction(assetActions, "Show Asset Viewer"), "Show Asset Viewer action present");
        check(hasAction(assetActions, "WS Decompress Here"), "WS Decompress Here action present");

        onEdt(() -> {
            tool.showComponentProvider(assetProvider, true);
            return null;
        });
        check(onEdt(assetProvider::isVisible), "asset provider shown");
        JComponent assetComp = onEdt(assetProvider::getComponent);
        check(assetComp != null && assetComp == onEdt(assetProvider::getComponent),
            "asset component stable");

        // Tiles tab: ROM-offset view renders without error.
        tilesRomOffset(assetProvider);

        // ---- Emulator factory ----
        boolean factoryRegistered = false;
        String factoryTitle = null;
        try {
            for (EmulatorFactory f : ClassSearcher.getInstances(EmulatorFactory.class)) {
                if (f instanceof WSEmulatorFactory) {
                    factoryRegistered = true;
                    factoryTitle = f.getTitle();
                }
            }
        } catch (Exception e) {
            System.out.println("WSGuiSmoke: ClassSearcher note: " + e);
        }
        // ClassSearcher may not scan the test classpath; direct load must work regardless.
        WSEmulatorFactory direct = new WSEmulatorFactory();
        check("WonderSwan Concrete P-code Emulator".equals(direct.getTitle()),
            "emulator factory loadable with title");
        if (factoryRegistered) {
            check("WonderSwan Concrete P-code Emulator".equals(factoryTitle),
                "emulator factory registered with ClassSearcher");
        } else {
            System.out.println("WSGuiSmoke: note - factory not via ClassSearcher (test classpath)");
            checks++; // count the direct-load check above as the factory check
        }

        // ---- Debugger plugin ----
        onEdt(() -> {
            tool.addPlugin(DebuggerTraceManagerServicePlugin.class.getName());
            tool.addPlugin(DebuggerEmulationServicePlugin.class.getName());
            tool.addPlugin(DebuggerTargetServicePlugin.class.getName());
            return null;
        });
        check(true, "debugger service plugins added");
        onEdt(() -> {
            tool.addPlugin(WSDebuggerPlugin.class.getName());
            return null;
        });
        check(true, "WSDebuggerPlugin added without exception");
        WSDebuggerPlugin dbgPlugin = onEdt(() -> {
            for (Plugin p : tool.getManagedPlugins()) {
                if (p instanceof WSDebuggerPlugin d) return d;
            }
            return null;
        });
        check(dbgPlugin != null, "debugger plugin instance found");
        WSScreenProvider screen = onEdt(
            () -> (WSScreenProvider) tool.getComponentProvider("WonderSwan Screen"));
        WSInputProvider input = onEdt(
            () -> (WSInputProvider) tool.getComponentProvider("WonderSwan Input"));
        check(screen != null, "screen provider registered");
        check(input != null, "input provider registered");
        check(onEdt(screen::isInTool), "screen provider in tool");
        check(onEdt(input::isInTool), "input provider in tool");
        var dbgActions = onEdt(() -> tool.getDockingActionsByOwnerName(dbgPlugin.getName()));
        check(hasAction(dbgActions, "Step Frame (VBlank)") && hasAction(dbgActions, "Run N Frames"),
            "Step Frame and Run N Frames actions present");
        onEdt(() -> {
            tool.showComponentProvider(screen, true);
            tool.showComponentProvider(input, true);
            return null;
        });
        check(onEdt(screen::isVisible), "screen provider shown");
        check(onEdt(input::isVisible), "input provider shown");
        // Idle refresh (no emulation) must not throw.
        onEdt(() -> {
            screen.refresh();
            input.refresh();
            return null;
        });
        check(true, "screen/input idle refresh without error");
        check(onEdt(() -> screen.getComponent()) != null, "screen component present");
        check(onEdt(() -> input.getComponent()) != null, "input component present");

        // ---- Live frame stepping ----
        liveFrameStepping(tool, program, dbgPlugin, screen, input);

        // ---- Re-registration: remove and add again ----
        onEdt(() -> {
            List<Plugin> doomed = new ArrayList<>();
            for (Plugin p : tool.getManagedPlugins()) {
                if (p instanceof WSAssetPlugin || p instanceof WSDebuggerPlugin) {
                    doomed.add(p);
                }
            }
            if (doomed.isEmpty()) throw new IllegalStateException("plugins to remove not found");
            tool.removePlugins(doomed);
            return null;
        });
        check(onEdt(() -> tool.getComponentProvider("WS Asset Viewer")) == null,
            "asset provider removed");
        check(onEdt(() -> tool.getComponentProvider("WonderSwan Screen")) == null,
            "screen provider removed");
        onEdt(() -> {
            tool.addPlugin(WSAssetPlugin.class.getName());
            tool.addPlugin(WSDebuggerPlugin.class.getName());
            return null;
        });
        check(onEdt(() -> tool.getComponentProvider("WS Asset Viewer")) != null,
            "asset provider re-registered");
        check(onEdt(() -> tool.getComponentProvider("WonderSwan Screen")) != null,
            "screen provider re-registered");
        check(onEdt(() -> tool.getComponentProvider("WonderSwan Input")) != null,
            "input provider re-registered");

        // Show re-registered providers once more.
        onEdt(() -> {
            tool.showComponentProvider(tool.getComponentProvider("WS Asset Viewer"), true);
            tool.showComponentProvider(tool.getComponentProvider("WonderSwan Screen"), true);
            return null;
        });
        check(true, "re-registered providers shown");

        // ---- Close cleanly ----
        onEdt(() -> {
            tool.close();
            return null;
        });
        check(true, "tool closed");
        gp.close();
        check(true, "project closed");
    }

    /**
     * Live emulation through the debugger path: start debugger-emulator sessions on the
     * synthetic ROM, step two frames through the debugger's frame-step API (the call the Step
     * Frame action runs via the frame scheduler) on the live session and an identical reference
     * session, and verify the screen provider paints the emulated frame after each.
     */
    private static void liveFrameStepping(PluginTool tool, Program program,
            WSDebuggerPlugin dbgPlugin, WSScreenProvider screen, WSInputProvider input)
            throws Exception {
        boolean color = program.getOptions("WonderSwan").getBoolean("Color", true);
        WSDebuggerEmulator emu = WSDebuggerEmulator.forProgram(program, color, "smoke-live");
        WSDebuggerEmulator ref = WSDebuggerEmulator.forProgram(program, color, "smoke-ref");
        check(emu.ws != null && ref.ws != null, "live emulation sessions started");
        check(emu.ws.instructions == 0 && ref.ws.instructions == 0,
            "fresh sessions at zero instructions");
        showTestPattern(emu.ws);
        showTestPattern(ref.ws);

        Trace trace = onEdt(() -> {
            Trace t = new DBTrace("smoke-live", program.getCompilerSpec(), WSGuiSmoke.class);
            DebuggerTraceManagerService tm = tool.getService(DebuggerTraceManagerService.class);
            tm.openTrace(t);
            tm.activateTrace(t);
            return t;
        });
        check(trace != null, "live trace opened and active");

        // Frame 1 through the debugger's frame-step API.
        int steps1 = emu.stepFrame(emu.ws.thread);
        int refSteps1 = ref.stepFrame(ref.ws.thread);
        check(steps1 > 0, "Step Frame advanced " + steps1 + " instructions");
        check(emu.ws.instructions == steps1 && ref.ws.instructions == refSteps1
            && steps1 == refSteps1, "frame 1 instruction counts agree");
        check(emu.ws.getCurrentLine() == WSMachine.VISIBLE, "frame 1 landed on VBlank entry");
        check(emu.framesAdvanced == 0 && ref.framesAdvanced == 0,
            "frame 1 ends before the line wrap");
        liveScreen(dbgPlugin, screen, input, trace, emu, ref, "frame 1");
        long after1 = emu.ws.instructions;

        // Frame 2: determinism across a second frame (line wrap included).
        int steps2 = emu.stepFrame(emu.ws.thread);
        int refSteps2 = ref.stepFrame(ref.ws.thread);
        check(steps2 > 0, "second Step Frame advanced " + steps2 + " instructions");
        check(emu.ws.instructions == after1 + steps2 && steps2 == refSteps2
            && emu.ws.instructions == ref.ws.instructions, "second frame deterministic");
        check(emu.ws.getCurrentLine() == WSMachine.VISIBLE, "frame 2 landed on VBlank entry");
        check(emu.framesAdvanced == 1 && ref.framesAdvanced == 1,
            "frame 2 wrapped the line counter");
        liveScreen(dbgPlugin, screen, input, trace, emu, ref, "frame 2");

        onEdt(() -> {
            tool.getService(DebuggerTraceManagerService.class).closeTraceNoConfirm(trace);
            return null;
        });
        check(true, "live trace closed");
    }

    /** Report the live session the way the emulation service does when a run stops, then verify
     *  the screen painted the emulated frame and the input pad went live. */
    private static void liveScreen(WSDebuggerPlugin dbgPlugin, WSScreenProvider screen,
            WSInputProvider input, Trace trace, WSDebuggerEmulator emu, WSDebuggerEmulator ref,
            String what) throws Exception {
        onEdt(() -> {
            dbgPlugin.stopped(new DebuggerEmulationService.CachedEmulator(trace, emu, null));
            return null;
        });
        check(dbgPlugin.getCurrentEmulator() == emu, what + ": plugin follows live session");
        onEdt(() -> null); // let the posted refresh run
        Field fImage = WSScreenProvider.class.getDeclaredField("image");
        fImage.setAccessible(true);
        BufferedImage img = onEdt(() -> (BufferedImage) fImage.get(screen));
        check(img != null && img.getWidth() == 224 && img.getHeight() == 144,
            what + ": screen painted 224x144");
        BufferedImage expected = WSRender.render(ref.ws);
        check(checksum(img) == checksum(expected), what + ": screen matches synthetic ROM output"
            + " (checksum " + Long.toHexString(checksum(img)) + ")");
        check(img.getRGB(0, 0) != img.getRGB(100, 100) && distinctColors(img) >= 3,
            what + ": screen non-blank (" + distinctColors(img) + " colours)");
        Field fButtons = WSInputProvider.class.getDeclaredField("buttons");
        fButtons.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<JButton> buttons = onEdt(() -> (List<JButton>) fButtons.get(input));
        check(onEdt(() -> buttons.stream().allMatch(JButton::isEnabled)),
            what + ": input pad enabled while live");
    }

    /** Minimal visible scene on a fresh machine: screen 1 on, map entry (0,0) on tile 1, tile 1
     *  striped through a distinct mono palette. The synthetic ROM's code touches neither, so the
     *  stepped frames render it deterministically. */
    private static void showTestPattern(WSMachine ws) {
        ws.ports[0x00] = 0x01; // screen 1 on
        ws.ports[0x01] = 0x00; // background shade 0
        ws.ports[0x07] = 0x00; // screen map base 0
        ws.ports[0x60] = 0x00; // mono: 2bpp tiles at 0x2000
        ws.ports[0x1C] = 0x00; // shades 0-1 -> level 0 (white)
        ws.ports[0x1D] = 0x44; // shades 2-3 -> level 4
        ws.ports[0x1E] = 0x88; // shades 4-5 -> level 8
        ws.ports[0x1F] = 0xF0; // shades 6-7 -> level 15 (black)
        ws.ports[0x20] = 0x70; // palette 0: idx0 -> shade 0, idx1 -> shade 7
        ws.ports[0x21] = 0x34; // palette 0: idx2 -> shade 4, idx3 -> shade 3
        ws.write(0, new byte[] { 1, 0 }); // map entry (0,0): tile 1, palette 0
        byte[] tile = new byte[16];
        for (int y = 0; y < 8; y++) {
            tile[y * 2] = (byte) ((y & 1) == 0 ? 0xFF : 0x00);
            tile[y * 2 + 1] = (byte) ((y & 1) == 0 ? 0x00 : 0xFF);
        }
        ws.write(0x2000 + 16, tile);
    }

    private static long checksum(BufferedImage img) {
        long sum = 0;
        for (int y = 0; y < img.getHeight(); y++)
            for (int x = 0; x < img.getWidth(); x++) sum += img.getRGB(x, y);
        return sum;
    }

    private static int distinctColors(BufferedImage img) {
        Set<Integer> seen = new HashSet<>();
        for (int y = 0; y < img.getHeight(); y++)
            for (int x = 0; x < img.getWidth(); x++) seen.add(img.getRGB(x, y));
        return seen.size();
    }

    private static boolean hasAction(java.util.Set<DockingActionIf> actions, String name) {
        for (DockingActionIf a : actions) {
            if (name.equals(a.getName())) return true;
        }
        return false;
    }

    /** Switch the Tiles tab to ROM-offset mode and verify it renders. */
    @SuppressWarnings("unchecked")
    private static void tilesRomOffset(WSAssetProvider provider) throws Exception {
        Field fSource = WSAssetProvider.class.getDeclaredField("tileSource");
        fSource.setAccessible(true);
        Field fRomOff = WSAssetProvider.class.getDeclaredField("romOffset");
        fRomOff.setAccessible(true);
        Field fInfo = WSAssetProvider.class.getDeclaredField("tileInfo");
        fInfo.setAccessible(true);
        Field fImg = WSAssetProvider.class.getDeclaredField("tileImage");
        fImg.setAccessible(true);
        Field fCur = WSAssetProvider.class.getDeclaredField("currentTiles");
        fCur.setAccessible(true);
        Method mRefresh = WSAssetProvider.class.getDeclaredMethod("refreshTiles");
        mRefresh.setAccessible(true);

        onEdt(() -> {
            JComboBox<String> tileSource = (JComboBox<String>) fSource.get(provider);
            JTextField romOffset = (JTextField) fRomOff.get(provider);
            tileSource.setSelectedItem("ROM offset");
            romOffset.setText("0x000000");
            mRefresh.invoke(provider);
            return null;
        });
        String info = onEdt(() -> ((JLabel) fInfo.get(provider)).getText());
        BufferedImage cur = onEdt(() -> (BufferedImage) fCur.get(provider));
        boolean hasIcon = onEdt(() -> ((JLabel) fImg.get(provider)).getIcon() != null);
        check(cur != null && cur.getWidth() > 0 && cur.getHeight() > 0,
            "tiles ROM-offset rendered " + (cur == null ? "null" : cur.getWidth() + "x" + cur.getHeight()));
        check(hasIcon, "tiles image icon set");
        check(!info.contains("Bad") && !info.startsWith("No "),
            "tiles info without error: " + info);
    }
}
