// SPDX-License-Identifier: MIT OR Apache-2.0
// Smoke test for the asset viewer plugin. Runs every check that can run
// headless (class loading, plugin metadata, codec registry, ROM read and
// arranged render), then attempts real tool instantiation and documents its
// headless boundary: PluginTool always builds a DockingWindowManager (a
// JFrame), so it throws HeadlessException without a display. Any other
// failure throws.
// @category WonderSwan
import docking.ComponentProvider;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import jidoughost.wonderswan.WSAssetPlugin;
import jidoughost.wonderswan.WSAssetProvider;
import jidoughost.wonderswan.WSAssets;
import jidoughost.wonderswan.WSCodec;
import jidoughost.wonderswan.WSCodecRegistry;
import jidoughost.wonderswan.WSRom;
import jidoughost.wonderswan.WSTileArrangement;
import jidoughost.wonderswan.WSTileFormat;

public class WSViewerSmoke extends GhidraScript {
    @Override public void run() throws Exception {
        // 1. Plugin + provider classes load; @PluginInfo metadata intact.
        PluginInfo info = WSAssetPlugin.class.getAnnotation(PluginInfo.class);
        if (info == null) throw new IllegalStateException("WSAssetPlugin lacks @PluginInfo");
        println("WSViewerSmoke: plugin=" + WSAssetPlugin.class.getName()
            + " package=" + info.packageName() + " status=" + info.status());
        if (!ComponentProvider.class.isAssignableFrom(WSAssetProvider.class)) {
            throw new IllegalStateException("WSAssetProvider is not a ComponentProvider");
        }
        println("WSViewerSmoke: provider=" + WSAssetProvider.class.getName());

        // 2. Codec registry round-trip (fake codec, removed afterwards).
        WSCodec fake = new WSCodec() {
            @Override public String id() { return "smoke-fake"; }
            @Override public String description() { return "smoke"; }
            @Override public Result decode(byte[] src, int off, int avail) {
                return new Result(new byte[] { src[off] }, 1);
            }
        };
        WSCodecRegistry.register(fake);
        try {
            if (WSCodecRegistry.get("smoke-fake") != fake) {
                throw new IllegalStateException("registry round-trip failed");
            }
        } finally {
            WSCodecRegistry.unregister("smoke-fake");
        }
        println("WSViewerSmoke: registry ok, shipped codecs=" + WSCodecRegistry.all().size());

        // 3. ROM read + arranged render against the current program.
        long size = WSRom.size(currentProgram);
        if (size <= 0) throw new IllegalStateException("program has no stored ROM");
        byte[] src = WSRom.read(currentProgram, 0, 64);
        if (src.length != 64) throw new IllegalStateException("short ROM read: " + src.length);
        int[] grey = { 0x000000, 0x555555, 0xAAAAAA, 0xFFFFFF };
        java.awt.image.BufferedImage img = WSAssets.renderArrangedAtlas(src, 0,
            WSAssets.tileCount(src.length, WSTileFormat.BPP2), WSTileFormat.BPP2, grey,
            WSTileArrangement.GLYPH_16X16_COLUMN, 2, 1);
        if (img.getWidth() != 32 || img.getHeight() != 16) {
            throw new IllegalStateException("unexpected render size");
        }
        println("WSViewerSmoke: rom_size=" + size + " render ok");

        // 4. Real tool instantiation: needs a display; anything else is a bug.
        try {
            new PluginTool(state.getProject(), "WSViewerSmoke", false, false, true) { };
            println("WSViewerSmoke: tool instantiation unexpectedly worked (display present?)");
        } catch (java.awt.HeadlessException e) {
            println("WSViewerSmoke: tool needs a display, as expected headless "
                + "(PluginTool builds a DockingWindowManager/JFrame)");
        }
        println("WSViewerSmoke: PASS");
    }
}
