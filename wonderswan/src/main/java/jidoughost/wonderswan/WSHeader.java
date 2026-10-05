// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * WonderSwan cartridge footer (last 16 bytes of the ROM).
 *
 * <pre>
 * +0  EA off16 seg16   far JMP reset vector
 * +5  maintenance      +6 publisher  +7 colour flag (bit0)  +8 game id  +9 version
 * +A  ROM size code    +B save code  +C flags  +D mapper  +E checksum (u16, sum of all bytes but these two)
 * </pre>
 *
 * Byte +D is the mapper (WSdev ROM_header: $00 = 2001 or KARNAK, $01 = 2003); older documents
 * (WSMan) call the same byte "RTC present", which amounts to the same detection: the RTC interface
 * exists exactly on 2003-family cartridges. There is no footer flag for the S-3511A chip itself;
 * some 2003 boards leave it unpopulated (their reads return $FF), but no footer byte distinguishes
 * them, so the emulator provides the RTC on every 2003-family cartridge.
 */
public final class WSHeader {
    public static final int SIZE = 16;
    /** Largest cartridge the 2003 mapper addresses (WSdev ROM_header). */
    public static final long MAX_SIZE = 0x4000000L;

    public final int resetOffset, resetSegment;
    public final int maintenance, publisher, gameId, version, romSizeCode, saveCode, flags, mapperCode;
    public final boolean color, rtc;
    public final int checksum, computedChecksum;

    private WSHeader(byte[] rom) {
        int f = rom.length - SIZE;
        resetOffset = u16(rom, f + 1);
        resetSegment = u16(rom, f + 3);
        maintenance = u8(rom, f + 5);
        publisher = u8(rom, f + 6);
        color = (u8(rom, f + 7) & 1) != 0;
        gameId = u8(rom, f + 8);
        version = u8(rom, f + 9);
        romSizeCode = u8(rom, f + 10);
        saveCode = u8(rom, f + 11);
        flags = u8(rom, f + 12);
        mapperCode = u8(rom, f + 13);
        rtc = mapperCode == 0x01;
        checksum = u16(rom, f + 14);
        int sum = 0;
        for (int i = 0; i < rom.length - 2; i++) sum += rom[i] & 0xff;
        computedChecksum = sum & 0xffff;
    }

    /**
     * True when the bytes are shaped like a WonderSwan cartridge: at least one 64 KiB bank, at
     * most 64 MiB, with a JMP FAR footer. Non-power-of-two images are accepted: hardware decodes a
     * power-of-two ROM, so the image is padded at the start (see {@link WSHardware#effectiveSize}).
     */
    public static boolean plausible(long length, byte[] footer) {
        if (length < 0x10000 || length > MAX_SIZE) return false;
        return footer.length == SIZE && (footer[0] & 0xff) == 0xEA;
    }

    public static WSHeader parse(byte[] rom) {
        if (!plausible(rom.length, java.util.Arrays.copyOfRange(rom, rom.length - SIZE, rom.length)))
            throw new IllegalArgumentException("not a WonderSwan ROM: bad size or footer");
        return new WSHeader(rom);
    }

    public boolean checksumOk() { return checksum == computedChecksum; }

    public long resetLinear() { return ((long) resetSegment << 4) + resetOffset; }

    /**
     * Declared ROM size in bytes for a footer ROM-size code (WSdev ROM_header, including the
     * unofficial/inferred rows), or -1 for an unknown code. Informational only: banking always
     * uses the file size, since released footers mispredict it.
     */
    public static long declaredSize(int romSizeCode) {
        return switch (romSizeCode) {
            case 0x00 -> 0x20000; case 0x01 -> 0x40000; case 0x02 -> 0x80000; case 0x03 -> 0x100000;
            case 0x04 -> 0x200000; case 0x05 -> 0x300000; case 0x06 -> 0x400000; case 0x07 -> 0x600000;
            case 0x08 -> 0x800000; case 0x09 -> 0x1000000; case 0x0A -> 0x2000000; case 0x0B -> 0x4000000;
            default -> -1;
        };
    }

    static int u8(byte[] b, int o) { return b[o] & 0xff; }
    static int u16(byte[] b, int o) { return (b[o] & 0xff) | (b[o + 1] & 0xff) << 8; }
}
