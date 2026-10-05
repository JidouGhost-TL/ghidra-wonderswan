// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * How consecutive 8x8 tiles group into cells for display: plain tiles, 8x16
 * pairs, 16x16 four-tile glyphs, or a custom WxH cell in row- or column-major
 * sub-tile order.
 */
public final class WSTileArrangement {
    /** Sub-tile order within a cell. */
    public enum Order {
        ROW_MAJOR("row-major"),
        COLUMN_MAJOR("column-major");

        public final String label;

        Order(String label) { this.label = label; }

        @Override public String toString() { return label; }
    }

    /** Plain 8x8 tiles (1x1 cell). */
    public static final WSTileArrangement PLAIN =
        new WSTileArrangement("8x8 tiles", 1, 1, Order.ROW_MAJOR);
    /** 8x16 cells of 2 stacked tiles. */
    public static final WSTileArrangement TALL_8X16 =
        new WSTileArrangement("8x16 cells", 1, 2, Order.ROW_MAJOR);
    /** 16x16 glyphs, sub-tiles TL, TR, BL, BR. */
    public static final WSTileArrangement GLYPH_16X16_ROW =
        new WSTileArrangement("16x16 glyphs, row-major", 2, 2, Order.ROW_MAJOR);
    /** 16x16 glyphs, sub-tiles TL, BL, TR, BR. */
    public static final WSTileArrangement GLYPH_16X16_COLUMN =
        new WSTileArrangement("16x16 glyphs, column-major", 2, 2, Order.COLUMN_MAJOR);

    /** Preset list for UI combos (custom arrangements are built, not listed). */
    public static WSTileArrangement[] presets() {
        return new WSTileArrangement[] { PLAIN, TALL_8X16, GLYPH_16X16_ROW, GLYPH_16X16_COLUMN };
    }

    public final String label;
    public final int tilesWide;
    public final int tilesHigh;
    public final Order order;

    private WSTileArrangement(String label, int tilesWide, int tilesHigh, Order order) {
        if (tilesWide < 1 || tilesHigh < 1) throw new IllegalArgumentException("cell dimensions must be >= 1");
        this.label = label;
        this.tilesWide = tilesWide;
        this.tilesHigh = tilesHigh;
        this.order = order;
    }

    /** Custom WxH cell in the given sub-tile order. */
    public static WSTileArrangement custom(int tilesWide, int tilesHigh, Order order) {
        return new WSTileArrangement(tilesWide + "x" + tilesHigh + " custom, " + order.label,
            tilesWide, tilesHigh, order);
    }

    /** Tiles per cell. */
    public int tilesPerCell() { return tilesWide * tilesHigh; }

    /** Horizontal sub-tile position of the i-th tile in a cell. */
    public int cellX(int i) {
        return order == Order.ROW_MAJOR ? i % tilesWide : i / tilesHigh;
    }

    /** Vertical sub-tile position of the i-th tile in a cell. */
    public int cellY(int i) {
        return order == Order.ROW_MAJOR ? i / tilesWide : i % tilesHigh;
    }

    /**
     * Parse an arrangement: {@code plain}, {@code 8x16}, {@code 16x16row},
     * {@code 16x16col}, or {@code WxH:row} / {@code WxH:col} for custom cells.
     */
    public static WSTileArrangement parse(String text) {
        String t = text.trim().toLowerCase();
        switch (t) {
            case "plain": case "8x8": case "1x1": return PLAIN;
            case "8x16": case "1x2": return TALL_8X16;
            case "16x16row": case "2x2row": case "2x2:row": return GLYPH_16X16_ROW;
            case "16x16col": case "2x2col": case "2x2:col": return GLYPH_16X16_COLUMN;
            default: break;
        }
        String[] parts = t.split(":");
        if (parts.length != 2) throw new IllegalArgumentException("bad arrangement: " + text);
        String[] wh = parts[0].split("x");
        if (wh.length != 2) throw new IllegalArgumentException("bad arrangement: " + text);
        Order o;
        switch (parts[1]) {
            case "row": case "row-major": o = Order.ROW_MAJOR; break;
            case "col": case "column-major": case "column": o = Order.COLUMN_MAJOR; break;
            default: throw new IllegalArgumentException("bad arrangement order: " + text);
        }
        try {
            return custom(Integer.parseInt(wh[0]), Integer.parseInt(wh[1]), o);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad arrangement: " + text);
        }
    }

    @Override public String toString() { return label; }
}
