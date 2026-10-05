// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.imageio.ImageIO;

/**
 * Headless asset core: decode and image helpers for WonderSwan tiles,
 * tilemaps, palettes and sprites (general hardware; WSdev Display pages).
 *
 * <p>Screen composition reuses {@link WSRender}: {@link #renderScreen(WSMachine)}
 * calls it directly, and {@link #renderScreen(WSSnapshot)} calls the same shared
 * raster implementation, so both stay pixel-identical by construction. The
 * per-pixel tile and palette lookups below are the single implementation that
 * {@link WSRender} itself calls; nothing here duplicates its logic.
 *
 * <p>All methods are GUI-free and unit-testable with synthetic arrays.
 */
public final class WSAssets {
    private WSAssets() { }

    // ------------------------------------------------------------------ tiles

    /** Pixel index of a 2bpp VRAM tile (tiles at 0x2000, 9-bit index). */
    public static int tilePixel2bpp(byte[] ram, int tile, int x, int y) {
        int o = 0x2000 + (tile & 0x1FF) * 16 + y * 2;
        return (((ram[o] & 0xFF) >> (7 - x)) & 1) | ((((ram[o + 1] & 0xFF) >> (7 - x)) & 1) << 1);
    }

    /** Pixel index of a 4bpp VRAM tile (tiles at 0x4000). */
    public static int tilePixel4bpp(byte[] ram, int tile, int x, int y, boolean packed) {
        int o = 0x4000 + tile * 32 + y * 4;
        if (packed) {
            return ((ram[o + x / 2] & 0xFF) >> (((x & 1) == 0) ? 4 : 0)) & 15;
        }
        int v = 0;
        for (int k = 0; k < 4; k++) {
            v |= (((ram[o + k] & 0xFF) >> (7 - x)) & 1) << k;
        }
        return v;
    }

    /**
     * Decode one 8x8 tile from arbitrary bytes (ROM, selection, decompressed
     * output) into 64 row-major colour indices (0-3 for 2bpp, 0-15 for 4bpp).
     */
    public static int[] decodeTile(byte[] src, int off, WSTileFormat fmt) {
        if (off < 0 || off + fmt.bytesPerTile > src.length) throw new IllegalArgumentException("tile outside buffer");
        int[] px = new int[64];
        switch (fmt) {
            case BPP2 -> {
                for (int y = 0; y < 8; y++) {
                    int lo = src[off + y * 2] & 0xFF, hi = src[off + y * 2 + 1] & 0xFF;
                    for (int x = 0; x < 8; x++) {
                        px[y * 8 + x] = ((lo >> (7 - x)) & 1) | (((hi >> (7 - x)) & 1) << 1);
                    }
                }
            }
            case BPP4_PLANAR -> {
                for (int y = 0; y < 8; y++) {
                    int b0 = src[off + y * 4] & 0xFF, b1 = src[off + y * 4 + 1] & 0xFF;
                    int b2 = src[off + y * 4 + 2] & 0xFF, b3 = src[off + y * 4 + 3] & 0xFF;
                    for (int x = 0; x < 8; x++) {
                        px[y * 8 + x] = (((b0 >> (7 - x)) & 1) << 0) | (((b1 >> (7 - x)) & 1) << 1)
                            | (((b2 >> (7 - x)) & 1) << 2) | (((b3 >> (7 - x)) & 1) << 3);
                    }
                }
            }
            case BPP4_PACKED -> {
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        px[y * 8 + x] = ((src[off + y * 4 + x / 2] & 0xFF) >> (((x & 1) == 0) ? 4 : 0)) & 15;
                    }
                }
            }
        }
        return px;
    }

    /** How many whole tiles of a format fit in a byte range. */
    public static int tileCount(int bytes, WSTileFormat fmt) {
        return bytes / fmt.bytesPerTile;
    }

    // ------------------------------------------------------------------ palettes

    /**
     * True when colour index 0 of a palette is transparent: always in 16-colour
     * mode, otherwise for palettes 4-7 and 12-15 (opaque for 0-3 and 8-11).
     */
    public static boolean transparent(int pal, int idx, boolean bpp4) {
        if (idx != 0) return false;
        if (bpp4) return true;
        return (pal & 4) != 0;
    }

    /** Colour palette entry as sRGB: palettes at 0xFE00, RGB444 expanded per nibble. */
    public static int rgb444(byte[] ram, int pal, int idx) {
        int o = 0xFE00 + pal * 32 + idx * 2;
        int v = (ram[o] & 0xFF) | (ram[o + 1] & 0xFF) << 8;
        return (((v >> 8) & 15) * 17) << 16 | (((v >> 4) & 15) * 17) << 8 | (v & 15) * 17;
    }

    /** Full colour palette (16 entries) as sRGB. */
    public static int[] colorPalette(byte[] ram, int pal) {
        int[] out = new int[16];
        for (int i = 0; i < 16; i++) out[i] = rgb444(ram, pal, i);
        return out;
    }

    /** Mono shade (0-7) as grey sRGB through the pool at ports 1C-1F. */
    public static int monoLevel(int[] ports, int shade) {
        int level = (ports[0x1C + shade / 2] >> (4 * (shade & 1))) & 15;
        int g = 255 - level * 17;
        return g << 16 | g << 8 | g;
    }

    /** Mono palette entry as grey sRGB through the LUT at ports 20-3F. */
    public static int monoShade(int[] ports, int pal, int idx) {
        return monoLevel(ports, (ports[0x20 + pal * 2 + idx / 2] >> (4 * (idx & 1))) & 7);
    }

    /** Full mono palette (4 entries) as grey sRGB. */
    public static int[] monoPalette(int[] ports, int pal) {
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) out[i] = monoShade(ports, pal, i);
        return out;
    }

    /** Background colour as sRGB (port 01: colour index or mono shade). */
    public static int background(int[] ports, byte[] ram, boolean color) {
        return color ? rgb444(ram, (ports[0x01] >> 4) & 15, ports[0x01] & 15) : monoLevel(ports, ports[0x01] & 7);
    }

    // ------------------------------------------------------------------ tilemaps

    /** Decoded screen-map entry: tile index, palette, flips. */
    public record MapEntry(int tile, int palette, boolean hFlip, boolean vFlip) { }

    /**
     * Decode one 16-bit screen entry. Bit layout (WSdev Display): bits 0-8 tile,
     * 9-12 palette, 13 tile bit 9 in colour mode, 14 H flip, 15 V flip.
     */
    public static MapEntry decodeMapEntry(int word, boolean color) {
        int tile = (word & 0x1FF) | (color ? ((word >> 13) & 1) << 9 : 0);
        return new MapEntry(tile, (word >> 9) & 15, (word & 0x4000) != 0, (word & 0x8000) != 0);
    }

    /** Decode {@code count} little-endian screen entries from bytes. */
    public static List<MapEntry> decodeMap(byte[] src, int off, int count, boolean color) {
        if (off < 0 || off + count * 2 > src.length) throw new IllegalArgumentException("map outside buffer");
        List<MapEntry> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            out.add(decodeMapEntry((src[off + i * 2] & 0xFF) | (src[off + i * 2 + 1] & 0xFF) << 8, color));
        }
        return out;
    }

    // ------------------------------------------------------------------ sprites

    /** Decoded sprite-table entry (4 bytes: attribute word, Y, X). */
    public record Sprite(int index, int x, int y, int tile, int palette,
        boolean hFlip, boolean vFlip, boolean highPriority, boolean insideWindow) { }

    /** Sprite table base from port 04 (units of 0x200). */
    public static int spriteBase(int[] ports) {
        return (ports[0x04] & 0x3F) * 0x200;
    }

    /** Decode one sprite entry; attribute layout per WSdev Display (sprite window side bit 12, priority bit 13). */
    public static Sprite decodeSprite(byte[] ram, int tableBase, int index) {
        int o = tableBase + index * 4;
        int attr = (ram[o] & 0xFF) | (ram[o + 1] & 0xFF) << 8;
        return new Sprite(index, ram[o + 3] & 0xFF, ram[o + 2] & 0xFF, attr & 0x1FF,
            8 + ((attr >> 9) & 7), (attr & 0x4000) != 0, (attr & 0x8000) != 0,
            (attr & 0x2000) != 0, (attr & 0x1000) == 0);
    }

    /** Active sprite range from ports 05 (first) and 06 (count), at most 128 entries. */
    public static List<Sprite> decodeSprites(byte[] ram, int[] ports) {
        int base = spriteBase(ports);
        int first = ports[0x05] & 0x7F;
        int last = Math.min(127, first + ports[0x06] - 1);
        List<Sprite> out = new ArrayList<>();
        for (int s = first; s <= last; s++) out.add(decodeSprite(ram, base, s));
        return out;
    }

    // ------------------------------------------------------------------ compose

    /** Compose the 224x144 screen from a live emulator machine (via WSRender). */
    public static BufferedImage renderScreen(WSMachine m) {
        return WSRender.render(m);
    }

    /** Compose the 224x144 screen from a snapshot (same WSRender implementation). */
    public static BufferedImage renderScreen(WSSnapshot s) {
        return WSRender.renderSnapshot(s.ram, s.ports, s.linePorts, s.colorHardware);
    }

    // ------------------------------------------------------------------ images

    /** Render 64 colour indices as an 8x8 image through an sRGB palette. */
    public static BufferedImage renderTileImage(int[] indices, int[] paletteRgb) {
        BufferedImage img = new BufferedImage(8, 8, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 8; y++) {
            for (int x = 0; x < 8; x++) {
                img.setRGB(x, y, paletteRgb[indices[y * 8 + x] % paletteRgb.length]);
            }
        }
        return img;
    }

    /** Decode and render one tile from bytes. */
    public static BufferedImage renderTileBytes(byte[] src, int off, WSTileFormat fmt, int[] paletteRgb) {
        return renderTileImage(decodeTile(src, off, fmt), paletteRgb);
    }

    /**
     * Render an atlas of consecutive tiles: {@code cols} tiles per row, each
     * tile scaled by {@code scale}. Unfilled cells stay black.
     */
    public static BufferedImage renderAtlas(byte[] src, int off, int count, WSTileFormat fmt,
            int[] paletteRgb, int cols, int scale) {
        return renderArrangedAtlas(src, off, count, fmt, paletteRgb,
            WSTileArrangement.PLAIN, cols, scale);
    }

    /**
     * Render consecutive tiles grouped into cells ({@code arr}): {@code cols}
     * cells per row, each pixel scaled by {@code scale}. Tiles past the end of
     * the buffer leave their sub-cell black.
     */
    public static BufferedImage renderArrangedAtlas(byte[] src, int off, int count, WSTileFormat fmt,
            int[] paletteRgb, WSTileArrangement arr, int cols, int scale) {
        if (cols < 1 || scale < 1) throw new IllegalArgumentException("cols and scale must be >= 1");
        int tpc = arr.tilesPerCell();
        int cells = (count + tpc - 1) / tpc;
        int rows = (cells + cols - 1) / cols;
        int cw = arr.tilesWide * 8 * scale, ch = arr.tilesHigh * 8 * scale;
        BufferedImage img = new BufferedImage(Math.max(1, cols * cw), Math.max(1, rows * ch),
            BufferedImage.TYPE_INT_RGB);
        for (int c = 0; c < cells; c++) {
            for (int i = 0; i < tpc; i++) {
                int t = c * tpc + i;
                if (t >= count) break;
                int[] px;
                try {
                    px = decodeTile(src, off + t * fmt.bytesPerTile, fmt);
                } catch (IllegalArgumentException e) {
                    break;
                }
                int tx = (c % cols) * cw + arr.cellX(i) * 8 * scale;
                int ty = (c / cols) * ch + arr.cellY(i) * 8 * scale;
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        int rgb = paletteRgb[px[y * 8 + x] % paletteRgb.length];
                        for (int sy = 0; sy < scale; sy++) {
                            for (int sx = 0; sx < scale; sx++) {
                                img.setRGB(tx + x * scale + sx, ty + y * scale + sy, rgb);
                            }
                        }
                    }
                }
            }
        }
        return img;
    }

    /**
     * Render one full 256x256 screen layer from a snapshot without scroll, for
     * asset inspection (not raster-accurate: uses the current ports for every
     * line). Transparent pixels show as magenta.
     */
    public static BufferedImage renderLayer(WSSnapshot s, int mapNibble) {
        int[] p = s.ports;
        boolean color = s.colorMode(p);
        boolean bpp4 = color && (p[0x60] & 0x40) != 0;
        boolean packed = bpp4 && (p[0x60] & 0x20) != 0;
        int base = (mapNibble & 15) * 0x800;
        BufferedImage img = new BufferedImage(256, 256, BufferedImage.TYPE_INT_RGB);
        int magenta = 0xFF00FF;
        for (int ty = 0; ty < 32; ty++) {
            for (int tx = 0; tx < 32; tx++) {
                int ea = base + (ty * 32 + tx) * 2;
                MapEntry e = decodeMapEntry((s.ram[ea] & 0xFF) | (s.ram[ea + 1] & 0xFF) << 8, color);
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        int sx = e.hFlip() ? 7 - x : x, sy = e.vFlip() ? 7 - y : y;
                        int idx = bpp4 ? tilePixel4bpp(s.ram, e.tile(), sx, sy, packed)
                            : tilePixel2bpp(s.ram, e.tile(), sx, sy);
                        int rgb = transparent(e.palette(), idx, bpp4) ? magenta
                            : color ? rgb444(s.ram, e.palette(), idx) : monoShade(p, e.palette(), idx);
                        img.setRGB(tx * 8 + x, ty * 8 + y, rgb);
                    }
                }
            }
        }
        return img;
    }

    /**
     * Render an arbitrary tilemap from decoded entries and a tile provider.
     * Transparent pixels show as magenta; out-of-range tiles stay black.
     */
    public static BufferedImage renderMap(List<MapEntry> entries, int cols,
            java.util.function.IntFunction<int[]> tileIndices, java.util.function.IntFunction<int[]> paletteFor,
            boolean bpp4) {
        if (cols < 1) throw new IllegalArgumentException("cols must be >= 1");
        int rows = (entries.size() + cols - 1) / cols;
        BufferedImage img = new BufferedImage(Math.max(1, cols * 8), Math.max(1, rows * 8), BufferedImage.TYPE_INT_RGB);
        int magenta = 0xFF00FF;
        for (int i = 0; i < entries.size(); i++) {
            MapEntry e = entries.get(i);
            int[] px = null;
            try {
                px = tileIndices.apply(e.tile());
            } catch (RuntimeException ex) {
                px = null;
            }
            int[] pal = paletteFor.apply(e.palette());
            int tx = (i % cols) * 8, ty = (i / cols) * 8;
            for (int y = 0; y < 8; y++) {
                for (int x = 0; x < 8; x++) {
                    int sx = e.hFlip() ? 7 - x : x, sy = e.vFlip() ? 7 - y : y;
                    int idx = px == null ? -1 : px[sy * 8 + sx];
                    int rgb = idx < 0 ? 0 : transparent(e.palette(), idx, bpp4) ? magenta
                        : pal[idx % pal.length];
                    img.setRGB(tx + x, ty + y, rgb);
                }
            }
        }
        return img;
    }

    /** Write an image as PNG, creating parent directories. */
    public static void writePng(BufferedImage img, Path file) throws IOException {
        if (file.getParent() != null) java.nio.file.Files.createDirectories(file.getParent());
        ImageIO.write(img, "png", file.toFile());
    }
}
