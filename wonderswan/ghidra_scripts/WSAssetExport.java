// SPDX-License-Identifier: MIT OR Apache-2.0
// Headless asset export: run the current WonderSwan program in WSMachine, then
// export the composed screen, VRAM tile atlases, full screen layers, palette
// swatches and the sprite table to PNG. Verifies the asset core against WSRender.
// Args: <outdir> [frames=300] [slice=15000]
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.WSAssets;
import jidoughost.wonderswan.WSMachine;
import jidoughost.wonderswan.WSSnapshot;
import jidoughost.wonderswan.WSTileFormat;
import java.awt.image.BufferedImage;
import java.io.PrintWriter;
import java.nio.file.*;

public class WSAssetExport extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        Path out = Paths.get(a[0]);
        Files.createDirectories(out);
        int frames = a.length > 1 ? Integer.parseInt(a[1]) : 300;
        int slice = a.length > 2 ? Integer.parseInt(a[2]) : 15000;
        boolean colorHw = currentProgram.getOptions("WonderSwan").getBoolean("Color", true);
        WSMachine m = new WSMachine(currentProgram, colorHw);
        m.run(frames, slice, null);
        WSSnapshot s = WSSnapshot.fromMachine(m);

        // Screen via both paths; they must be pixel-identical (shared WSRender core).
        BufferedImage viaMachine = WSAssets.renderScreen(m);
        BufferedImage viaSnapshot = WSAssets.renderScreen(s);
        int diff = countDiff(viaMachine, viaSnapshot);
        WSAssets.writePng(viaSnapshot, out.resolve("screen.png"));

        // Tile atlases from VRAM (palette 0 of the active mode).
        int[] p = s.ports;
        boolean color = s.colorMode(p);
        boolean bpp4 = color && (p[0x60] & 0x40) != 0;
        boolean packed = bpp4 && (p[0x60] & 0x20) != 0;
        int[] pal0 = color ? WSAssets.colorPalette(s.ram, 0) : WSAssets.monoPalette(s.ports, 0);
        byte[] v2 = new byte[512 * 16];
        System.arraycopy(s.ram, 0x2000, v2, 0, v2.length);
        WSAssets.writePng(WSAssets.renderAtlas(v2, 0, 512, WSTileFormat.BPP2, pal0, 16, 2),
            out.resolve("tiles_2bpp.png"));
        if (colorHw) {
            byte[] v4 = new byte[512 * 32];
            System.arraycopy(s.ram, 0x4000, v4, 0, v4.length);
            int[] pal16 = WSAssets.colorPalette(s.ram, 0);
            WSAssets.writePng(WSAssets.renderAtlas(v4, 0, 512,
                packed ? WSTileFormat.BPP4_PACKED : WSTileFormat.BPP4_PLANAR, pal16, 16, 2),
                out.resolve("tiles_4bpp.png"));
        }

        // Full screen layers without scroll (asset inspection).
        WSAssets.writePng(WSAssets.renderLayer(s, p[0x07] & 0x0F), out.resolve("layer_scr1.png"));
        WSAssets.writePng(WSAssets.renderLayer(s, p[0x07] >> 4), out.resolve("layer_scr2.png"));

        // Palette swatches.
        int cols = color ? 16 : 4, cell = 16;
        BufferedImage sw = new BufferedImage(cols * cell, 16 * cell, BufferedImage.TYPE_INT_RGB);
        for (int pal = 0; pal < 16; pal++) {
            int[] rgb = color ? WSAssets.colorPalette(s.ram, pal) : WSAssets.monoPalette(s.ports, pal);
            for (int i = 0; i < rgb.length; i++) {
                for (int y = 0; y < cell; y++) {
                    for (int x = 0; x < cell; x++) {
                        sw.setRGB(i * cell + x, pal * cell + y, rgb[i]);
                    }
                }
            }
        }
        WSAssets.writePng(sw, out.resolve("palettes.png"));

        // Sprite table.
        try (PrintWriter w = new PrintWriter(out.resolve("sprites.tsv").toFile())) {
            w.println("index\tx\ty\ttile\tpalette\thflip\tvflip\thigh\tinside");
            for (WSAssets.Sprite sp : WSAssets.decodeSprites(s.ram, s.ports)) {
                w.printf("%d\t%d\t%d\t%d\t%d\t%b\t%b\t%b\t%b%n", sp.index(), sp.x(), sp.y(),
                    sp.tile(), sp.palette(), sp.hFlip(), sp.vFlip(), sp.highPriority(), sp.insideWindow());
            }
        }

        String summary = String.format(
            "frames=%d slice=%d colorHw=%b colorMode=%b bpp4=%b packed=%b screen_diff=%d sprites=%d",
            frames, slice, colorHw, color, bpp4, packed, diff,
            WSAssets.decodeSprites(s.ram, s.ports).size());
        Files.writeString(out.resolve("summary.txt"), summary + "\n");
        println("WSAssetExport: " + summary);
        if (diff != 0) throw new IllegalStateException("screen paths differ in " + diff + " pixels");
    }

    static int countDiff(BufferedImage a, BufferedImage b) {
        if (a.getWidth() != b.getWidth() || a.getHeight() != b.getHeight()) return -1;
        int n = 0;
        for (int y = 0; y < a.getHeight(); y++) {
            for (int x = 0; x < a.getWidth(); x++) {
                if (a.getRGB(x, y) != b.getRGB(x, y)) n++;
            }
        }
        return n;
    }
}
