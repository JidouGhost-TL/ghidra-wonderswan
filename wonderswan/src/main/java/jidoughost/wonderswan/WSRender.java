// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.awt.image.BufferedImage;

/**
 * Renders the WonderSwan screen (224x144) from a machine's RAM and ports, following WSdev
 * (WSdev wiki, Display pages; see docs/SOURCES.md):
 *
 * <pre>
 * front  sprites, high priority  (sprite window)
 *        screen 2                (screen 2 window, scroll)
 *        sprites, low priority   (sprite window)
 *        screen 1                (scroll)
 * back   background colour (port 01)
 * </pre>
 *
 * Port 60 (colour models): bit 7 colour, bit 6 4bpp (16-colour), bit 5 packed 4bpp. 2bpp tiles at
 * 0x2000, 4bpp tiles at 0x4000; colour palettes at 0xFE00 (RGB444), mono shades via ports 1C-3F.
 * Colour 0 is opaque for palettes 0-3 and 8-11 in 4-colour modes and always transparent in 16-colour
 * mode. Earlier sprites draw over later ones. Windows use inclusive coordinates.
 *
 * Raster effects: each line uses the port snapshot WSMachine took at the start of that line (palette and
 * map RAM are taken from the end of the frame). Not modelled (diagnostic renderer, not an accurate PPU):
 * mid-line changes, the 32-sprites-per-line limit, the frame-delayed sprite table copy, LCD icons and LCD colour response.
 */
public final class WSRender {
    private WSRender() { }

    /** Render using each line's port snapshot from the last frame (raster effects), else current ports. */
    public static BufferedImage render(WSMachine m) {
        return renderSnapshot(m.read(0, 0x10000), m.ports, m.linePorts, m.color);
    }

    /**
     * Render from a RAM dump, port row and per-line port snapshots: the same
     * implementation {@link #render(WSMachine)} uses, shared with the asset
     * core ({@link WSAssets#renderScreen(WSSnapshot)}) so both stay
     * pixel-identical by construction.
     */
    public static BufferedImage renderSnapshot(byte[] ram, int[] ports, int[][] linePorts, boolean colorHardware) {
        BufferedImage img = new BufferedImage(224, 144, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 144; y++) {
            int[] p = linePorts != null && linePorts[y] != null ? linePorts[y] : ports;
            renderLine(img, ram, p, y, colorHardware);
        }
        return img;
    }

    static void renderLine(BufferedImage img, byte[] ram, int[] p, int y, boolean colorHardware) {
        boolean color = (p[0x60] & 0x80) != 0 && colorHardware;
        boolean bpp4 = color && (p[0x60] & 0x40) != 0;
        boolean packed = bpp4 && (p[0x60] & 0x20) != 0;
        int ctrl = p[0x00];
        Ctx c = new Ctx(ram, p, color, bpp4, packed);
        int bg = color ? c.rgb((p[0x01] >> 4) & 15, p[0x01] & 15) : c.shadeValue(p[0x01] & 7);
        {
            for (int x = 0; x < 224; x++) {
                int out = bg;
                if ((ctrl & 0x01) != 0) {
                    int px = c.screenPixel(p[0x07] & 0x0F, p[0x10], p[0x11], x, y);
                    if (px >= 0) out = px;
                }
                if ((ctrl & 0x04) != 0) {
                    int px = c.spritePixel(x, y, false);
                    if (px >= 0) out = px;
                }
                if ((ctrl & 0x02) != 0 && screen2Visible(p, ctrl, x, y)) {
                    int px = c.screenPixel(p[0x07] >> 4, p[0x12], p[0x13], x, y);
                    if (px >= 0) out = px;
                }
                if ((ctrl & 0x04) != 0) {
                    int px = c.spritePixel(x, y, true);
                    if (px >= 0) out = px;
                }
                img.setRGB(x, y, out);
            }
        }
    }

    static boolean inside(int[] p, int base, int x, int y) {
        return x >= p[base] && x <= p[base + 2] && y >= p[base + 1] && y <= p[base + 3];
    }

    static boolean screen2Visible(int[] p, int ctrl, int x, int y) {
        if ((ctrl & 0x20) == 0) return true;                 // screen 2 window disabled
        boolean in = inside(p, 0x08, x, y);
        return (ctrl & 0x10) == 0 ? in : !in;
    }

    private static final class Ctx {
        final byte[] ram;
        final int[] p;
        final boolean color, bpp4, packed;
        final int spriteBase, first, last;

        Ctx(byte[] ram, int[] p, boolean color, boolean bpp4, boolean packed) {
            this.ram = ram; this.p = p; this.color = color; this.bpp4 = bpp4; this.packed = packed;
            spriteBase = (p[0x04] & 0x3F) * 0x200;
            first = p[0x05] & 0x7F;
            last = Math.min(127, first + p[0x06] - 1);
        }

        /** Colour index of tile pixel (x,y), 0..3 or 0..15. */
        int tilePixel(int tile, int x, int y) {
            return bpp4 ? WSAssets.tilePixel4bpp(ram, tile, x, y, packed)
                : WSAssets.tilePixel2bpp(ram, tile, x, y);
        }

        boolean transparent(int pal, int idx) {
            return WSAssets.transparent(pal, idx, bpp4);
        }

        int colour(int pal, int idx) { return color ? rgb(pal, idx) : shade(pal, idx); }

        int rgb(int pal, int idx) {
            return WSAssets.rgb444(ram, pal, idx);
        }

        int shade(int pal, int idx) {
            return WSAssets.monoShade(p, pal, idx);
        }

        int shadeValue(int v) {
            return WSAssets.monoLevel(p, v);
        }

        /** Screen pixel as RGB, or -1 if transparent. */
        int screenPixel(int mapNibble, int sx, int sy, int x, int y) {
            int base = mapNibble * 0x800;
            int X = (x + sx) & 255, Y = (y + sy) & 255;
            int ea = base + ((Y >> 3) * 32 + (X >> 3)) * 2;
            int e = (ram[ea] & 0xff) | (ram[ea + 1] & 0xff) << 8;
            int tile = (e & 0x1FF) | (color ? ((e >> 13) & 1) << 9 : 0);
            int pal = (e >> 9) & 15;
            int tx = X & 7, ty = Y & 7;
            if ((e & 0x4000) != 0) tx = 7 - tx;
            if ((e & 0x8000) != 0) ty = 7 - ty;
            int idx = tilePixel(tile, tx, ty);
            return transparent(pal, idx) ? -1 : colour(pal, idx);
        }

        /** Topmost sprite pixel of the given priority at (x,y) as RGB, or -1. */
        int spritePixel(int x, int y, boolean high) {
            boolean windowOn = (p[0x00] & 0x08) != 0;
            for (int s = first; s <= last; s++) {             // earlier sprites are on top
                int o = spriteBase + s * 4;
                int attr = (ram[o] & 0xff) | (ram[o + 1] & 0xff) << 8;
                if (((attr & 0x2000) != 0) != high) continue;
                int sy = ram[o + 2] & 0xff, sx = ram[o + 3] & 0xff;
                int dx = (x - sx) & 255, dy = (y - sy) & 255;
                if (dx > 7 || dy > 7) continue;
                if (windowOn) {
                    boolean in = inside(p, 0x0C, x, y);
                    if ((attr & 0x1000) == 0 ? !in : in) continue;
                }
                int tx = (attr & 0x4000) != 0 ? 7 - dx : dx, ty = (attr & 0x8000) != 0 ? 7 - dy : dy;
                int pal = 8 + ((attr >> 9) & 7);
                int idx = tilePixel(attr & 0x1FF, tx, ty);
                if (!transparent(pal, idx)) return colour(pal, idx);
            }
            return -1;
        }
    }
}
