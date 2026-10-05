// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import static org.junit.Assert.*;

import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.Test;

/** Synthetic-data unit tests for the asset core (no ROM, no GUI). */
public class WSAssetsTest {

    // ------------------------------------------------------------------ tiles

    @Test
    public void decode2bpp() {
        byte[] src = new byte[16];
        src[0] = (byte) 0b10000001;
        src[1] = (byte) 0b01000010;
        int[] px = WSAssets.decodeTile(src, 0, WSTileFormat.BPP2);
        // x=0: lo bit7=1, hi bit7=0 -> 1; x=1: lo=0, hi=1 -> 2; x=6: 0; x=7: lo=1,hi=0? bit0: lo=1,hi=0 -> 1? check: lo bit0=1, hi bit0=0 -> 1
        assertEquals(1, px[0]);
        assertEquals(2, px[1]);
        assertEquals(0, px[3]);
        assertEquals(1, px[7]);
        for (int i = 8; i < 64; i++) assertEquals(0, px[i]);
    }

    @Test
    public void decode4bppPlanar() {
        byte[] src = new byte[32];
        src[0] = (byte) 0x80;
        src[1] = (byte) 0x80;
        src[2] = (byte) 0x80;
        src[3] = (byte) 0x80;
        int[] px = WSAssets.decodeTile(src, 0, WSTileFormat.BPP4_PLANAR);
        assertEquals(15, px[0]);
        for (int i = 1; i < 64; i++) assertEquals(0, px[i]);
    }

    @Test
    public void decode4bppPacked() {
        byte[] src = new byte[32];
        src[0] = (byte) 0xAB;
        int[] px = WSAssets.decodeTile(src, 0, WSTileFormat.BPP4_PACKED);
        assertEquals(0xA, px[0]);
        assertEquals(0xB, px[1]);
        for (int i = 2; i < 8; i++) assertEquals(0, px[i]);
    }

    @Test
    public void tileCount() {
        assertEquals(2, WSAssets.tileCount(32, WSTileFormat.BPP2));
        assertEquals(1, WSAssets.tileCount(32, WSTileFormat.BPP4_PLANAR));
        assertEquals(0, WSAssets.tileCount(15, WSTileFormat.BPP2));
    }

    @Test(expected = IllegalArgumentException.class)
    public void decodeTileOutOfRange() {
        WSAssets.decodeTile(new byte[15], 0, WSTileFormat.BPP2);
    }

    @Test
    public void vramTileHelpersMatchOffsetDecode() {
        byte[] ram = new byte[0x10000];
        ram[0x2000] = (byte) 0x81;
        ram[0x2001] = (byte) 0x42;
        assertEquals(1, WSAssets.tilePixel2bpp(ram, 0, 0, 0));
        assertEquals(2, WSAssets.tilePixel2bpp(ram, 0, 1, 0));
        // 9-bit wrap: tile 0x200 aliases tile 0.
        assertEquals(WSAssets.tilePixel2bpp(ram, 0, 0, 0), WSAssets.tilePixel2bpp(ram, 0x200, 0, 0));
        ram[0x4000] = (byte) 0xAB;
        assertEquals(0xA, WSAssets.tilePixel4bpp(ram, 0, 0, 0, true));
        assertEquals(0xB, WSAssets.tilePixel4bpp(ram, 0, 1, 0, true));
    }

    // ------------------------------------------------------------------ maps

    @Test
    public void mapEntry() {
        WSAssets.MapEntry e = WSAssets.decodeMapEntry(0xC125, false);
        assertEquals(0x125, e.tile());
        assertEquals(0, e.palette());
        assertTrue(e.hFlip());
        assertTrue(e.vFlip());
        WSAssets.MapEntry f = WSAssets.decodeMapEntry((3 << 9) | 0x1AB | 0x4000 | 0x8000, false);
        assertEquals(0x1AB, f.tile());
        assertEquals(3, f.palette());
        assertTrue(f.hFlip());
        assertTrue(f.vFlip());
    }

    @Test
    public void mapEntryBankBit() {
        int word = (1 << 13) | 0x1FF;
        assertEquals(0x3FF, WSAssets.decodeMapEntry(word, true).tile());
        assertEquals(0x1FF, WSAssets.decodeMapEntry(word, false).tile());
    }

    @Test
    public void decodeMapBytes() {
        byte[] src = { 0x34, 0x12, (byte) 0xFF, 0x7F };
        List<WSAssets.MapEntry> list = WSAssets.decodeMap(src, 0, 2, false);
        assertEquals(2, list.size());
        assertEquals(WSAssets.decodeMapEntry(0x1234, false), list.get(0));
        assertEquals(WSAssets.decodeMapEntry(0x7FFF, false), list.get(1));
    }

    // ------------------------------------------------------------------ palettes

    @Test
    public void transparency() {
        assertFalse(WSAssets.transparent(0, 1, false));
        assertFalse(WSAssets.transparent(0, 0, false));
        assertFalse(WSAssets.transparent(11, 0, false));
        assertTrue(WSAssets.transparent(4, 0, false));
        assertTrue(WSAssets.transparent(15, 0, false));
        assertTrue(WSAssets.transparent(0, 0, true));
        assertFalse(WSAssets.transparent(0, 5, true));
    }

    @Test
    public void rgb444() {
        byte[] ram = new byte[0x10000];
        ram[0xFE00] = 0x34;
        ram[0xFE01] = 0x12;
        assertEquals(0x223344, WSAssets.rgb444(ram, 0, 0));
        int[] pal = WSAssets.colorPalette(ram, 0);
        assertEquals(16, pal.length);
        assertEquals(0x223344, pal[0]);
    }

    @Test
    public void monoPalette() {
        int[] p = new int[256];
        p[0x1C] = 0x10;
        p[0x20] = 0x10;
        assertEquals(0xFFFFFF, WSAssets.monoLevel(p, 0));
        assertEquals(0xEEEEEE, WSAssets.monoLevel(p, 1));
        assertEquals(0xFFFFFF, WSAssets.monoShade(p, 0, 0));
        assertEquals(0xEEEEEE, WSAssets.monoShade(p, 0, 1));
        int[] pal = WSAssets.monoPalette(p, 0);
        assertEquals(4, pal.length);
        assertEquals(0xFFFFFF, pal[0]);
    }

    @Test
    public void background() {
        int[] p = new int[256];
        byte[] ram = new byte[0x10000];
        p[0x1C] = 0x10;
        p[0x01] = 1;
        assertEquals(0xEEEEEE, WSAssets.background(p, ram, false));
        ram[0xFE00 + 2 * 32 + 3 * 2] = 0x00;
        ram[0xFE00 + 2 * 32 + 3 * 2 + 1] = 0x0F;
        p[0x01] = 0x23;
        assertEquals(0xFF0000, WSAssets.background(p, ram, true));
    }

    // ------------------------------------------------------------------ sprites

    @Test
    public void spriteBase() {
        int[] p = new int[256];
        p[0x04] = 0x3F;
        assertEquals(0x7E00, WSAssets.spriteBase(p));
    }

    @Test
    public void decodeSprite() {
        byte[] ram = new byte[0x10000];
        ram[0] = 0x05;
        ram[1] = 0x26;
        ram[2] = 20;
        ram[3] = 10;
        WSAssets.Sprite s = WSAssets.decodeSprite(ram, 0, 0);
        assertEquals(0, s.index());
        assertEquals(10, s.x());
        assertEquals(20, s.y());
        assertEquals(5, s.tile());
        assertEquals(11, s.palette());
        assertFalse(s.hFlip());
        assertFalse(s.vFlip());
        assertTrue(s.highPriority());
        assertTrue(s.insideWindow());
    }

    @Test
    public void decodeSpriteRange() {
        byte[] ram = new byte[0x10000];
        int[] p = new int[256];
        p[0x04] = 0;
        p[0x05] = 126;
        p[0x06] = 10; // clamps at 127
        List<WSAssets.Sprite> list = WSAssets.decodeSprites(ram, p);
        assertEquals(2, list.size());
        assertEquals(126, list.get(0).index());
        assertEquals(127, list.get(1).index());
        p[0x06] = 0;
        assertTrue(WSAssets.decodeSprites(ram, p).isEmpty());
    }

    // ------------------------------------------------------------------ images

    @Test
    public void renderTileImage() {
        int[] px = new int[64];
        px[0] = 1;
        px[63] = 3;
        int[] pal = { 0x000000, 0xFF0000, 0x00FF00, 0x0000FF };
        BufferedImage img = WSAssets.renderTileImage(px, pal);
        assertEquals(8, img.getWidth());
        assertEquals(8, img.getHeight());
        assertEquals(0xFFFF0000, img.getRGB(0, 0));
        assertEquals(0xFF000000, img.getRGB(1, 0));
        assertEquals(0xFF0000FF, img.getRGB(7, 7));
    }

    @Test
    public void renderAtlasSize() {
        byte[] src = new byte[3 * 16];
        int[] pal = { 0, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF };
        BufferedImage img = WSAssets.renderAtlas(src, 0, 3, WSTileFormat.BPP2, pal, 2, 2);
        assertEquals(2 * 8 * 2, img.getWidth());
        assertEquals(2 * 8 * 2, img.getHeight());
    }

    // ------------------------------------------------------------------ arrangements

    /** 2bpp tile filled with one colour index. */
    private static void solid2bpp(byte[] src, int tile, int idx) {
        int o = tile * 16;
        byte lo = (byte) (((idx & 1) != 0) ? 0xFF : 0x00);
        byte hi = (byte) (((idx & 2) != 0) ? 0xFF : 0x00);
        for (int y = 0; y < 8; y++) { src[o + y * 2] = lo; src[o + y * 2 + 1] = hi; }
    }

    private static final int[] PAL4 = { 0x000000, 0xFF0000, 0x00FF00, 0x0000FF };

    private static void assertSolidCell(BufferedImage img, int cellX, int cellY) {
        // Every pixel of the 8x8 sub-cell at (cellX, cellY) equals its top-left pixel.
        int rgb = img.getRGB(cellX * 8, cellY * 8);
        for (int y = 0; y < 8; y++) {
            for (int x = 0; x < 8; x++) {
                assertEquals("pixel " + x + "," + y, rgb, img.getRGB(cellX * 8 + x, cellY * 8 + y));
            }
        }
    }

    @Test
    public void arrangePlainMatchesAtlas() {
        byte[] src = new byte[4 * 16];
        for (int t = 0; t < 4; t++) solid2bpp(src, t, t);
        BufferedImage a = WSAssets.renderAtlas(src, 0, 4, WSTileFormat.BPP2, PAL4, 2, 1);
        BufferedImage b = WSAssets.renderArrangedAtlas(src, 0, 4, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.PLAIN, 2, 1);
        assertEquals(a.getWidth(), b.getWidth());
        assertEquals(a.getHeight(), b.getHeight());
        assertEquals(0xFF000000, b.getRGB(0, 0));
        assertEquals(0xFFFF0000, b.getRGB(8, 0));
        assertEquals(0xFF00FF00, b.getRGB(0, 8));
        assertEquals(0xFF0000FF, b.getRGB(8, 8));
    }

    @Test
    public void arrangeTallStacksTwoTiles() {
        byte[] src = new byte[2 * 16];
        solid2bpp(src, 0, 1);
        solid2bpp(src, 1, 2);
        BufferedImage img = WSAssets.renderArrangedAtlas(src, 0, 2, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.TALL_8X16, 1, 1);
        assertEquals(8, img.getWidth());
        assertEquals(16, img.getHeight());
        assertEquals(0xFFFF0000, img.getRGB(0, 0));
        assertEquals(0xFF00FF00, img.getRGB(0, 8));
        assertSolidCell(img, 0, 0);
        assertSolidCell(img, 0, 1);
    }

    @Test
    public void arrangeGlyphRowMajor() {
        byte[] src = new byte[4 * 16];
        for (int t = 0; t < 4; t++) solid2bpp(src, t, t);
        BufferedImage img = WSAssets.renderArrangedAtlas(src, 0, 4, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.GLYPH_16X16_ROW, 1, 1);
        assertEquals(16, img.getWidth());
        assertEquals(16, img.getHeight());
        // TL, TR, BL, BR.
        assertEquals(0xFF000000, img.getRGB(0, 0));
        assertEquals(0xFFFF0000, img.getRGB(8, 0));
        assertEquals(0xFF00FF00, img.getRGB(0, 8));
        assertEquals(0xFF0000FF, img.getRGB(8, 8));
    }

    @Test
    public void arrangeGlyphColumnMajor() {
        byte[] src = new byte[4 * 16];
        for (int t = 0; t < 4; t++) solid2bpp(src, t, t);
        BufferedImage img = WSAssets.renderArrangedAtlas(src, 0, 4, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.GLYPH_16X16_COLUMN, 1, 1);
        assertEquals(16, img.getWidth());
        assertEquals(16, img.getHeight());
        // TL, BL, TR, BR.
        assertEquals(0xFF000000, img.getRGB(0, 0));
        assertEquals(0xFF00FF00, img.getRGB(8, 0));
        assertEquals(0xFFFF0000, img.getRGB(0, 8));
        assertEquals(0xFF0000FF, img.getRGB(8, 8));
    }

    @Test
    public void arrangeCustomRowAndColumn() {
        byte[] src = new byte[6 * 16];
        for (int t = 0; t < 6; t++) solid2bpp(src, t, t % 4);
        BufferedImage row = WSAssets.renderArrangedAtlas(src, 0, 6, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.custom(3, 2, WSTileArrangement.Order.ROW_MAJOR), 1, 1);
        assertEquals(24, row.getWidth());
        assertEquals(16, row.getHeight());
        // Row-major: tile 3 starts the second row.
        assertEquals(0xFF0000FF, row.getRGB(0, 8));
        assertEquals(0xFF000000, row.getRGB(8, 8));
        BufferedImage col = WSAssets.renderArrangedAtlas(src, 0, 6, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.custom(3, 2, WSTileArrangement.Order.COLUMN_MAJOR), 1, 1);
        assertEquals(24, col.getWidth());
        assertEquals(16, col.getHeight());
        // Column-major: tile 1 is below tile 0, tile 2 starts the second column.
        assertEquals(0xFFFF0000, col.getRGB(0, 8));
        assertEquals(0xFF00FF00, col.getRGB(8, 0));
        assertEquals(0xFF000000, col.getRGB(16, 0));
    }

    @Test
    public void arrangePartialCellStaysBlack() {
        byte[] src = new byte[3 * 16];
        for (int t = 0; t < 3; t++) solid2bpp(src, t, 1);
        BufferedImage img = WSAssets.renderArrangedAtlas(src, 0, 3, WSTileFormat.BPP2, PAL4,
            WSTileArrangement.GLYPH_16X16_ROW, 1, 1);
        assertEquals(0xFFFF0000, img.getRGB(0, 0));
        assertEquals(0xFF000000, img.getRGB(8, 8));
    }

    @Test
    public void arrangeParse() {
        assertSame(WSTileArrangement.PLAIN, WSTileArrangement.parse("plain"));
        assertSame(WSTileArrangement.TALL_8X16, WSTileArrangement.parse("8x16"));
        assertSame(WSTileArrangement.GLYPH_16X16_ROW, WSTileArrangement.parse("16x16row"));
        assertSame(WSTileArrangement.GLYPH_16X16_COLUMN, WSTileArrangement.parse("16x16col"));
        WSTileArrangement c = WSTileArrangement.parse("3x2:col");
        assertEquals(3, c.tilesWide);
        assertEquals(2, c.tilesHigh);
        assertEquals(WSTileArrangement.Order.COLUMN_MAJOR, c.order);
        assertEquals(1, WSTileArrangement.custom(2, 3, WSTileArrangement.Order.ROW_MAJOR).cellX(3));
        assertEquals(1, WSTileArrangement.custom(2, 3, WSTileArrangement.Order.ROW_MAJOR).cellY(3));
        assertEquals(1, WSTileArrangement.custom(3, 2, WSTileArrangement.Order.COLUMN_MAJOR).cellX(3));
        assertEquals(1, WSTileArrangement.custom(3, 2, WSTileArrangement.Order.COLUMN_MAJOR).cellY(3));
    }

    @Test(expected = IllegalArgumentException.class)
    public void arrangeParseRejectsGarbage() {
        WSTileArrangement.parse("diagonal");
    }

    @Test
    public void renderMapSmoke() {
        List<WSAssets.MapEntry> entries = List.of(
            new WSAssets.MapEntry(0, 0, false, false), new WSAssets.MapEntry(1, 0, true, true));
        int[] zeros = new int[64];
        int[] ones = new int[64];
        java.util.Arrays.fill(ones, 1);
        int[] pal = { 0x000000, 0xFFFFFF, 0, 0 };
        BufferedImage img = WSAssets.renderMap(entries, 2, t -> t == 0 ? zeros : ones, palx -> pal, false);
        assertEquals(16, img.getWidth());
        assertEquals(8, img.getHeight());
        // Palette 0 index 0 is opaque in 4-colour mode, so tile 0 shows black.
        assertEquals(0xFF000000, img.getRGB(0, 0));
        assertEquals(0xFFFFFFFF, img.getRGB(8, 0));
    }

    // ------------------------------------------------------------------ compose

    private static WSSnapshot monoScreen() {
        byte[] ram = new byte[0x10000];
        int[] p = new int[256];
        p[0x00] = 0x01;      // screen 1 on
        p[0x01] = 2;         // bg shade 2
        p[0x07] = 0x00;      // map base 0
        p[0x60] = 0x00;      // mono 2bpp
        p[0x1C] = 0x10;      // levels 0,1
        p[0x1D] = 0x02;      // level 2
        p[0x20] = 0x10;      // pal 0: idx0->shade0, idx1->shade1
        // Map entry (0,0): tile 1, pal 0.
        ram[0] = 0x01;
        ram[1] = 0x00;
        // Map entry (1,0): tile 0, pal 4 (transparent index 0).
        ram[2] = 0x00;
        ram[3] = 0x08;
        // Tile 1 row 0: pixel (0,0) index 1.
        ram[0x2000 + 16] = (byte) 0x80;
        ram[0x2000 + 17] = 0x00;
        return new WSSnapshot(ram, p, null, false);
    }

    @Test
    public void composeMonoScreen() {
        WSSnapshot s = monoScreen();
        BufferedImage img = WSAssets.renderScreen(s);
        assertEquals(224, img.getWidth());
        assertEquals(144, img.getHeight());
        assertEquals(0xFFEEEEEE, img.getRGB(0, 0));
        // Entry (1,0) is transparent, so the background shade shows.
        assertEquals(0xFFDDDDDD, img.getRGB(8, 0));
    }

    @Test
    public void composeMatchesWSRender() {
        WSSnapshot s = monoScreen();
        BufferedImage a = WSAssets.renderScreen(s);
        BufferedImage b = WSRender.renderSnapshot(s.ram, s.ports, s.linePorts, s.colorHardware);
        assertEquals(a.getWidth(), b.getWidth());
        assertEquals(a.getHeight(), b.getHeight());
        for (int y = 0; y < a.getHeight(); y += 7) {
            for (int x = 0; x < a.getWidth(); x += 11) {
                assertEquals("pixel " + x + "," + y, a.getRGB(x, y), b.getRGB(x, y));
            }
        }
    }

    @Test
    public void composeColorScreen() {
        byte[] ram = new byte[0x10000];
        int[] p = new int[256];
        p[0x00] = 0x01;
        p[0x01] = 0x00;
        p[0x07] = 0x00;
        p[0x60] = 0x80; // colour 2bpp
        ram[0] = 0x01;
        ram[1] = 0x00;
        ram[0x2000 + 16] = (byte) 0x80;
        ram[0x2000 + 17] = 0x00;
        ram[0xFE00 + 1 * 2] = 0x34;
        ram[0xFE00 + 1 * 2 + 1] = 0x12;
        WSSnapshot s = new WSSnapshot(ram, p, null, true);
        assertEquals(0xFF223344, WSAssets.renderScreen(s).getRGB(0, 0));
    }

    @Test
    public void renderLayerSize() {
        BufferedImage img = WSAssets.renderLayer(monoScreen(), 0);
        assertEquals(256, img.getWidth());
        assertEquals(256, img.getHeight());
        assertEquals(0xFFEEEEEE, img.getRGB(0, 0));
    }

    // ------------------------------------------------------------------ snapshot

    @Test(expected = IllegalArgumentException.class)
    public void snapshotRejectsShortRam() {
        new WSSnapshot(new byte[0x4000], new int[256], null, false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void snapshotRejectsShortPorts() {
        new WSSnapshot(new byte[0x10000], new int[128], null, false);
    }

    @Test
    public void snapshotFromFiles() throws Exception {
        Path dir = Files.createTempDirectory("wsasset");
        byte[] ram = new byte[0x10000];
        ram[123] = 7;
        byte[] pb = new byte[256];
        pb[9] = 11;
        Files.write(dir.resolve("ram_00000.bin"), ram);
        Files.write(dir.resolve("ports_00000.bin"), pb);
        WSSnapshot s = WSSnapshot.fromFiles(dir.resolve("ram_00000.bin"), dir.resolve("ports_00000.bin"), true);
        assertEquals(7, s.ram[123]);
        assertEquals(11, s.ports[9]);
        assertTrue(s.colorHardware);
    }

    // ------------------------------------------------------------------ codecs

    @Test
    public void codecRegistry() {
        WSCodec fake = new WSCodec() {
            @Override public String id() { return "test-fake"; }
            @Override public String description() { return "fake"; }
            @Override public Result decode(byte[] src, int off, int avail) {
                return new Result(new byte[] { src[off] }, 1);
            }
        };
        WSCodecRegistry.register(fake);
        try {
            assertSame(fake, WSCodecRegistry.get("test-fake"));
            assertTrue(WSCodecRegistry.all().stream().anyMatch(c -> c.id().equals("test-fake")));
            WSCodec.Result r = WSCodecRegistry.get("test-fake").decode(new byte[] { 5, 6 }, 1, 1);
            assertArrayEquals(new byte[] { 6 }, r.data());
            assertEquals(1, r.consumed());
        } finally {
            WSCodecRegistry.unregister("test-fake");
        }
        assertNull(WSCodecRegistry.get("test-fake"));
    }
}
