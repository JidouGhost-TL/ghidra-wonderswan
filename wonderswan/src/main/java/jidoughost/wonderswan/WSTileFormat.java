// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * WonderSwan tile pixel formats (general hardware; WSdev Display pages).
 *
 * <p>The display hardware reads 8x8 tiles from work RAM. 2bpp tiles occupy
 * 16 bytes (2 bytes per row, one bit per plane); 4bpp tiles occupy 32 bytes,
 * either planar (4 bytes per row) or packed (4 bytes per row, two 4-bit pixels
 * per byte, high nibble first). Mono and colour 2bpp share the bit layout and
 * differ only in palette lookup.
 */
public enum WSTileFormat {
    /** 2bpp planar, 16 bytes per tile (mono shades or colour palettes 0-15). */
    BPP2("2bpp", 2, 16),
    /** 4bpp planar, 32 bytes per tile (colour mode). */
    BPP4_PLANAR("4bpp planar", 4, 32),
    /** 4bpp packed, 32 bytes per tile (colour mode, port 60 bit 5). */
    BPP4_PACKED("4bpp packed", 4, 32);

    public final String label;
    public final int bitsPerPixel;
    public final int bytesPerTile;

    WSTileFormat(String label, int bitsPerPixel, int bytesPerTile) {
        this.label = label;
        this.bitsPerPixel = bitsPerPixel;
        this.bytesPerTile = bytesPerTile;
    }

    @Override public String toString() { return label; }
}
