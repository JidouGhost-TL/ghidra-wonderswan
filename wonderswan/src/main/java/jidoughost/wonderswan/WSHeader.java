// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * WonderSwan cartridge footer (last 16 bytes of the ROM).
 *
 * <pre>
 * +0  EA off16 seg16   far JMP reset vector
 * +5  maintenance      +6 publisher  +7 colour flag (bit0)  +8 game id  +9 version
 * +A  ROM size code    +B save code  +C flags  +D RTC present  +E checksum (u16, sum of all bytes but these two)
 * </pre>
 */
public final class WSHeader {
    public static final int SIZE = 16;

    public final int resetOffset, resetSegment;
    public final int maintenance, publisher, gameId, version, romSizeCode, saveCode, flags;
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
        rtc = u8(rom, f + 13) != 0;
        checksum = u16(rom, f + 14);
        int sum = 0;
        for (int i = 0; i < rom.length - 2; i++) sum += rom[i] & 0xff;
        computedChecksum = sum & 0xffff;
    }

    /** True when the bytes are shaped like a WonderSwan cartridge (power-of-two size, JMP FAR footer). */
    public static boolean plausible(long length, byte[] footer) {
        if (length < 0x10000 || Long.bitCount(length) != 1 || length > 0x1000000) return false;
        return footer.length == SIZE && (footer[0] & 0xff) == 0xEA;
    }

    public static WSHeader parse(byte[] rom) {
        if (!plausible(rom.length, java.util.Arrays.copyOfRange(rom, rom.length - SIZE, rom.length)))
            throw new IllegalArgumentException("not a WonderSwan ROM: bad size or footer");
        return new WSHeader(rom);
    }

    public boolean checksumOk() { return checksum == computedChecksum; }

    public long resetLinear() { return ((long) resetSegment << 4) + resetOffset; }

    static int u8(byte[] b, int o) { return b[o] & 0xff; }
    static int u16(byte[] b, int o) { return (b[o] & 0xff) | (b[o + 1] & 0xff) << 8; }
}
