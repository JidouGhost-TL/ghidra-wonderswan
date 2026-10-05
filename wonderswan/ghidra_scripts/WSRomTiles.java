// SPDX-License-Identifier: MIT OR Apache-2.0
// Render tiles from a ROM file offset (program FileBytes) through a tile
// arrangement to PNG. ROM banks need not be mapped.
// Args: <outdir> <offsetHex> [format=2bpp] [arrangement=plain] [bytes=4096] [cols=16] [scale=2]
//   format: 2bpp | 4bpp-planar | 4bpp-packed
//   arrangement: plain | 8x16 | 16x16row | 16x16col | WxH:row | WxH:col
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.WSAssets;
import jidoughost.wonderswan.WSRom;
import jidoughost.wonderswan.WSTileArrangement;
import jidoughost.wonderswan.WSTileFormat;
import java.awt.image.BufferedImage;
import java.nio.file.*;

public class WSRomTiles extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 2) throw new IllegalArgumentException(
            "usage: WSRomTiles <outdir> <offsetHex> [format] [arrangement] [bytes] [cols] [scale]");
        Path out = Paths.get(a[0]);
        Files.createDirectories(out);
        long off = WSRom.parseOffset(a[1]);
        if (off < 0) throw new IllegalArgumentException("bad offset: " + a[1]);
        WSTileFormat fmt = a.length > 2 ? parseFormat(a[2]) : WSTileFormat.BPP2;
        WSTileArrangement arr = a.length > 3 ? WSTileArrangement.parse(a[3]) : WSTileArrangement.PLAIN;
        int bytes = a.length > 4 ? Integer.parseInt(a[4]) : 4096;
        int cols = a.length > 5 ? Integer.parseInt(a[5]) : 16;
        int scale = a.length > 6 ? Integer.parseInt(a[6]) : 2;

        long size = WSRom.size(currentProgram);
        byte[] src = WSRom.read(currentProgram, off, bytes);
        int count = WSAssets.tileCount(src.length, fmt);
        if (count == 0) throw new IllegalStateException("no whole " + fmt + " tiles at " + a[1]);
        int n = fmt.bitsPerPixel == 2 ? 4 : 16;
        int[] grey = new int[n];
        for (int i = 0; i < n; i++) {
            int g = 255 - i * 255 / (n - 1);
            grey[i] = g << 16 | g << 8 | g;
        }
        BufferedImage img = WSAssets.renderArrangedAtlas(src, 0, count, fmt, grey, arr, cols, scale);
        Path png = out.resolve("tiles.png");
        WSAssets.writePng(img, png);
        int cells = (count + arr.tilesPerCell() - 1) / arr.tilesPerCell();
        String summary = String.format(
            "program=%s rom_size=%d offset=%s bytes=%d format=%s arrangement=%s tiles=%d cells=%d cols=%d scale=%d png=%s",
            currentProgram.getName(), size, WSRom.formatOffset(off), src.length, fmt, arr.label,
            count, cells, cols, scale, png);
        Files.writeString(out.resolve("info.txt"), summary + "\n");
        println("WSRomTiles: " + summary);
    }

    static WSTileFormat parseFormat(String s) {
        switch (s.trim().toLowerCase()) {
            case "2bpp": case "bpp2": return WSTileFormat.BPP2;
            case "4bpp-planar": case "4bppplanar": case "bpp4": return WSTileFormat.BPP4_PLANAR;
            case "4bpp-packed": case "4bpppacked": return WSTileFormat.BPP4_PACKED;
            default: throw new IllegalArgumentException("bad format: " + s);
        }
    }
}
