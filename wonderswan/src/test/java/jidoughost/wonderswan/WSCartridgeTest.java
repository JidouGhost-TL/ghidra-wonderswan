// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * Unit tests for {@link WSCartridge} detection and the {@link WSHardware} padding/mirroring rules,
 * on synthetic footers (no ROM data).
 */
public final class WSCartridgeTest {
    private WSCartridgeTest() { }

    /** Synthetic image of `size` bytes with a footer; checksum fixed up unless `badChecksum`. */
    private static byte[] image(int size, int mapper, int save, int romSize, int version, boolean badChecksum) {
        byte[] rom = new byte[size];
        int f = size - WSHeader.SIZE;
        rom[f] = (byte) 0xEA;
        rom[f + 3] = (byte) 0xF0;   // reset F000:0000
        rom[f + 9] = (byte) version;
        rom[f + 10] = (byte) romSize;
        rom[f + 11] = (byte) save;
        rom[f + 13] = (byte) mapper;
        int sum = 0;
        for (int i = 0; i < rom.length - 2; i++) sum += rom[i] & 0xFF;
        if (badChecksum) sum += 1;
        rom[f + 14] = (byte) sum;
        rom[f + 15] = (byte) (sum >> 8);
        return rom;
    }

    public static void run() {
        detect2001();
        detect2003();
        detectWonderWitch();
        detectKarnak();
        unknownMapper();
        unknownSave();
        sizeMismatch();
        paddingRules();
        bankMath();
        System.out.println("WSCartridgeTest: PASS");
    }

    private static void detect2001() {
        WSCartridge c = WSCartridge.detect(image(0x400000, 0x00, 0x20, 0x06, 0x00, false), "game.wsc");
        Check.eq("2001", c.mapperName(), "2001 name");
        Check.isFalse(c.hasRtc(), "2001 no RTC");
        Check.isFalse(c.hasFlash(), "2001 no flash");
        Check.eq(0x800, c.eepromBytes, "16Kbit EEPROM");
        Check.eq(0, c.sramBytes, "no SRAM");
        Check.isTrue(c.warnings.isEmpty(), "clean image warns nothing, got " + c.warnings);
    }

    private static void detect2003() {
        WSCartridge c = WSCartridge.detect(image(0x200000, 0x01, 0x02, 0x04, 0x00, false), "game.wsc");
        Check.eq("2003", c.mapperName(), "2003 name");
        Check.isTrue(c.hasRtc(), "2003 RTC");
        Check.isFalse(c.hasFlash(), "2003 no flash");
        Check.eq(0x8000, c.sramBytes, "256Kbit SRAM");
        Check.isTrue(c.warnings.isEmpty(), "clean 2003 warns nothing, got " + c.warnings);
    }

    private static void detectWonderWitch() {
        // WonderWitch markers: mapper $01, zero checksum field, version bit 7, 512 KiB.
        byte[] rom = image(0x80000, 0x01, 0x04, 0x02, 0x80, false);
        rom[rom.length - 2] = 0;
        rom[rom.length - 1] = 0;
        WSCartridge c = WSCartridge.detect(rom, "flash.ws");
        Check.eq("WonderWitch", c.mapperName(), "WonderWitch name");
        Check.isTrue(c.hasRtc(), "WW RTC");
        Check.isTrue(c.hasFlash(), "WW flash");
        Check.isFalse(c.warnings.isEmpty(), "WW rule always logged");
        // Same markers at a masked-ROM size: 2003, with a note (never silent).
        byte[] big = image(0x200000, 0x01, 0x04, 0x02, 0x80, false);
        big[big.length - 2] = 0;
        big[big.length - 1] = 0;
        WSCartridge c2 = WSCartridge.detect(big, "masked.wsc");
        Check.eq("2003", c2.mapperName(), "WW markers at 2 MiB stay 2003");
        Check.isFalse(c2.hasFlash(), "no flash on masked ROM");
        Check.isFalse(c2.warnings.isEmpty(), "WW-style metadata noted");
    }

    private static void detectKarnak() {
        WSCartridge c = WSCartridge.detect(image(0xC0000, 0x00, 0x00, 0x03, 0x00, false), "test.pc2");
        Check.eq("KARNAK", c.mapperName(), "pc2 name");
        Check.isTrue(c.hasKarnak(), "hasKarnak");
        Check.isFalse(c.hasRtc(), "KARNAK no RTC");
        Check.eq(0x100000L, c.effectiveSize, "768 KiB -> 1 MiB effective");
        Check.isFalse(c.warnings.isEmpty(), "non-pow2 noted");
        // Same bytes without the extension: plain 2001.
        WSCartridge c2 = WSCartridge.detect(image(0xC0000, 0x00, 0x00, 0x03, 0x00, false), "test.ws");
        Check.eq("2001", c2.mapperName(), ".ws stays 2001");
    }

    private static void unknownMapper() {
        WSCartridge c = WSCartridge.detect(image(0x100000, 0x02, 0x00, 0x03, 0x00, false), "x.ws");
        Check.eq("2001", c.mapperName(), "unknown mapper falls back to 2001");
        Check.isFalse(c.warnings.isEmpty(), "unknown mapper warned loudly");
        Check.isTrue(c.warnings.get(0).contains("$02"), "warning names the value: " + c.warnings);
    }

    private static void unknownSave() {
        WSCartridge c = WSCartridge.detect(image(0x100000, 0x00, 0x09, 0x03, 0x00, false), "x.ws");
        Check.eq(0, c.sramBytes, "unknown save: no SRAM");
        Check.eq(0, c.eepromBytes, "unknown save: no EEPROM");
        Check.isFalse(c.warnings.isEmpty(), "unknown save warned");
    }

    private static void sizeMismatch() {
        // Declared 4 Mbit but the file is 2 MiB: file wins, loudly.
        WSCartridge c = WSCartridge.detect(image(0x200000, 0x00, 0x00, 0x02, 0x00, false), "x.ws");
        Check.isFalse(c.warnings.isEmpty(), "size mismatch warned");
        // Bad checksum on an ordinary image: warned.
        WSCartridge c2 = WSCartridge.detect(image(0x100000, 0x00, 0x00, 0x03, 0x00, true), "x.ws");
        Check.isFalse(c2.warnings.isEmpty(), "bad checksum warned");
    }

    private static void paddingRules() {
        Check.eq(0x100000L, WSHardware.effectiveSize(0xC0000), "768K effective");
        Check.eq(0x40000L, WSHardware.padSize(0xC0000), "768K pad");
        Check.eq(0L, WSHardware.padSize(0x200000), "pow2 has no pad");
        Check.eq(0x100000L, WSHardware.effectiveSize(0x100000), "pow2 effective == size");
        // The file sits at the END: effective 0x40000 == file 0, footer at the top.
        Check.eq(-1L, WSHardware.fileOffset(0x3FFFF, 0xC0000), "offset in padding");
        Check.eq(0L, WSHardware.fileOffset(0x40000, 0xC0000), "first file byte");
        Check.eq(0xBFFF0L, WSHardware.fileOffset(0xFFFF0, 0xC0000), "footer offset");
        Check.eq(WSHeader.SIZE, 0xC0000 - WSHardware.fileOffset(0xFFFF0, 0xC0000), "footer at file end");
    }

    private static void bankMath() {
        // 2 MiB, C0 reset FF: linear window shows the top of the ROM.
        Check.eq(0x1F0000L, WSHardware.linearToRom(0xF0000, 0xFF, 0x200000), "linear top bank");
        Check.eq(0x140000L, WSHardware.linearToRom(0x40000, 0xFF, 0x200000), "linear bottom bank");
        Check.eq(0x10000L, WSHardware.bankToRom(0x01, 0x200000), "bank 1");
        Check.eq(0x00000L, WSHardware.bankToRom(0x20, 0x200000), "bank mirrors past the end");
        // 768 KiB-as-1 MiB: bank 0 is padding, bank 4 is the file start.
        Check.eq(0x00000L, WSHardware.bankToRom(0x00, 0x100000), "pad bank offset");
        Check.eq(-1L, WSHardware.fileOffset(WSHardware.bankToRom(0x00, 0x100000), 0xC0000), "pad bank has no file");
        Check.eq(0L, WSHardware.fileOffset(WSHardware.bankToRom(0x04, 0x100000), 0xC0000), "bank 4 is the file start");
        // 2003 high bytes are 16-bit values; masking to the size keeps them sane.
        Check.eq(0x1F0000L, WSHardware.bankToRom(0xFF1F, 0x200000), "high byte masked by size");
    }

    public static void main(String[] args) {
        run();
    }
}
