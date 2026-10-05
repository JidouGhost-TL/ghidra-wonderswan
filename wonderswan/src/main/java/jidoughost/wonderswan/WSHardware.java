// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Map;
import java.util.TreeMap;

/** WonderSwan memory map and I/O port names: the single source of truth for this module. */
public final class WSHardware {
    private WSHardware() { }

    public static final int SEG_RAM = 0x0000, SEG_SRAM = 0x1000, SEG_ROM0 = 0x2000, SEG_ROM1 = 0x3000;
    public static final int SEG_LINEAR_FIRST = 0x4000;   // 0x40000-0xFFFFF: twelve 64 KiB segments
    public static final int RAM_COLOR = 0x10000, RAM_MONO = 0x4000;
    /** Bank register values after reset (C0 linear, C2 ROM0, C3 ROM1). */
    public static final int RESET_C0 = 0xFF, RESET_C2 = 0xFF, RESET_C3 = 0xFF;

    /** Cartridge EEPROM size in bytes for a footer save-type byte (WSdev ROM header), 0 if none. */
    public static int cartEepromBytes(int saveCode) {
        return switch (saveCode) { case 0x10 -> 0x80; case 0x20 -> 0x800; case 0x50 -> 0x400; default -> 0; };
    }

    /** Cartridge SRAM size in bytes for a footer save-type byte (WSdev ROM header), 0 if none. */
    public static int sramBytes(int saveCode) {
        return switch (saveCode) { case 0x01, 0x02 -> 0x8000; case 0x03 -> 0x20000; case 0x04 -> 0x40000; case 0x05 -> 0x80000; default -> 0; };
    }

    /**
     * Effective ROM size for a file image of `fileLength` bytes: the smallest power of two that
     * holds it. The cartridge bus decodes a power-of-two ROM; a short image is padded at the START
     * so the footer stays at the top (WSdev ROM_header; Mesen 2 and ares pad the same way), e.g. a
     * 768 KiB image is read as a 1 MiB ROM whose first 256 KiB is padding. All address masking in
     * this class uses the effective size.
     */
    public static long effectiveSize(long fileLength) {
        long e = 0x10000;
        while (e < fileLength) e <<= 1;
        return e;
    }

    /** Padding bytes before the file image inside the effective ROM (0 for power-of-two sizes). */
    public static long padSize(long fileLength) {
        return effectiveSize(fileLength) - fileLength;
    }

    /**
     * File offset of an effective-ROM offset, or -1 when the offset is in the start padding
     * (reads there return {@link #PAD_BYTE}). Mirroring past the end of the chip is the caller's
     * masking ({@link #linearToRom}, {@link #bankToRom}); this only places the file at the end.
     */
    public static long fileOffset(long effectiveOffset, long fileLength) {
        long f = effectiveOffset - padSize(fileLength);
        return f < 0 ? -1 : f;
    }

    /** Fill byte of the start padding and of erased flash. */
    public static final int PAD_BYTE = 0xFF;

    /**
     * Effective-ROM offset shown at a linear CPU address (>= 0x40000) under linear bank register
     * `c0`. `romLength` is the EFFECTIVE size ({@link #effectiveSize}); translate to a file offset
     * with {@link #fileOffset} when the image is not a power of two. The C0 mask (6 bits) covers
     * the 2003 mapper; on a 2001 (4 bits) the extra bits are masked away for every ROM up to
     * 16 MiB, so one formula serves both.
     */
    public static long linearToRom(long linear, int c0, long romLength) {
        return ((((long) (c0 & 0x3F)) << 20) | linear) & (romLength - 1);
    }

    /**
     * Effective-ROM offset of 64 KiB bank number `bank` (bank windows C1/C2/C3, 16-bit values on
     * the 2003 mapper). Only the low 10 bits can address the largest (64 MiB) cartridge, but
     * masking to 10 first is a no-op under the size mask, so the full value is used directly.
     */
    public static long bankToRom(int bank, long romLength) {
        return (((long) bank) << 16) & (romLength - 1);
    }

    /** Port A0 (System Control) at cartridge entry: bit7 bus test OK, bits 3:2 copied from footer flags
     *  bits 3:2 (ROM wait state, ROM width), bit1 colour model, bit0 boot ROM locked out.
     *  WSdev SoC + ROM_header ("Flag bits 2 and 3 correspond to System Control bits 2 and 3").
     *  `color` is the console model running the cartridge (the loader's hardware decision: footer flag or
     *  .wsc), not the footer flag: bit 1 reports the hardware, and colour games whose footer says mono read
     *  it to choose their colour path. */
    public static int systemControlAtEntry(WSHeader h, boolean color) {
        return 0x80 | (h.flags & 0x0C) | (color ? 0x02 : 0x00) | 0x01;
    }

    /** CPU registers at cartridge entry (WSdev Boot_ROM, measured on SwanCrystal). DX is undocumented
     *  ("?") and left 0. Order: AX BX CX DX SI DI SP BP DS ES SS CS IP FLAGS. AX low byte = port A0.
     *  SOURCE-CONFLICT: Mesen 2 (b9fa69d, WsConsole::InitPostBootRomState) uses CX=0004, DX=0001,
     *  SI=0435 on colour and DS=FE00 on both models. ws-test-suite's startup_state_custom_crt0 only
     *  displays the state, so it settles this only when run on real hardware. WSdev kept (measured).
     *  The boot ROM, and so this state, belongs to the console model `color`, not to the cartridge. */
    public static int[] registersAtEntry(WSHeader h, boolean color) {
        int a0 = systemControlAtEntry(h, color);
        return color
            ? new int[] { 0xFF00 | a0, 0x0043, 0, 0, 0x0457, 0x040B, 0x2000, 0, 0xFE00, 0, 0, 0xFFFF, 0x0000, 0xF086 }
            : new int[] { 0xFF00 | a0, 0x0040, 0, 0, 0x023D, 0x040D, 0x2000, 0, 0xFF00, 0, 0, 0xFFFF, 0x0000, 0xF082 };
    }

    /** Non-zero I/O ports at cartridge entry besides A0 and the bank registers (WSdev Boot_ROM, LINK-SURVEY). */
    public static final int[][] PORTS_AT_ENTRY = { { 0x60, 0x0A }, { 0xB5, 0x40 }, { 0xBE, 0x80 }, { 0x14, 0x01 }, { 0x9E, 0x03 } };

    /** 2003-mapper aliases (WSdev, ares, Bandai2003): port -> primary register it mirrors. D1/D3/D5 are the
     *  high bytes of the SRAM/ROM0/ROM1 bank registers whose low bytes are C1/C2/C3. */
    public static final int[][] MAPPER_ALIASES = { { 0xCF, 0xC0 }, { 0xD0, 0xC1 }, { 0xD2, 0xC2 }, { 0xD4, 0xC3 } };

    /** Ports accessed as 16-bit words (low byte address); labelled as words in the io space. */
    public static final int[] WORD_PORTS = { 0x40, 0x44, 0x46, 0x4A, 0x4E, 0x80, 0x82, 0x84, 0x86,
        0xA4, 0xA6, 0xA8, 0xAA, 0xBA, 0xBC, 0xBE, 0xC4, 0xC6, 0xC8 };

    public static final Map<Integer, String> PORTS = new TreeMap<>();
    static {
        String[][] p = {
            {"00", "DISP_CTRL"}, {"01", "BACK_COLOR"}, {"02", "LINE_CUR"}, {"03", "LINE_CMP"},
            {"04", "SPR_BASE"}, {"05", "SPR_FIRST"}, {"06", "SPR_COUNT"}, {"07", "MAP_BASE"},
            {"08", "SCR2_WIN_X0"}, {"09", "SCR2_WIN_Y0"}, {"0A", "SCR2_WIN_X1"}, {"0B", "SCR2_WIN_Y1"},
            {"0C", "SPR_WIN_X0"}, {"0D", "SPR_WIN_Y0"}, {"0E", "SPR_WIN_X1"}, {"0F", "SPR_WIN_Y1"},
            {"10", "SCR1_X"}, {"11", "SCR1_Y"}, {"12", "SCR2_X"}, {"13", "SCR2_Y"},
            {"14", "LCD_CTRL"}, {"15", "LCD_ICON"}, {"16", "LCD_VTOTAL"}, {"17", "LCD_VSYNC"},
            {"1C", "PAL_MONO_POOL_0"}, {"1D", "PAL_MONO_POOL_1"}, {"1E", "PAL_MONO_POOL_2"}, {"1F", "PAL_MONO_POOL_3"},
            {"40", "DMA_SRC_L"}, {"41", "DMA_SRC_M"}, {"42", "DMA_SRC_H"}, {"44", "DMA_DST_L"}, {"45", "DMA_DST_H"},
            {"46", "DMA_LEN_L"}, {"47", "DMA_LEN_H"}, {"48", "DMA_CTRL"},
            {"4A", "SDMA_SRC_L"}, {"4B", "SDMA_SRC_M"}, {"4C", "SDMA_SRC_H"}, {"4E", "SDMA_LEN_L"},
            {"4F", "SDMA_LEN_M"}, {"50", "SDMA_LEN_H"}, {"52", "SDMA_CTRL"},
            {"60", "DISP_MODE"}, {"62", "WSC_SYSTEM"},
            {"80", "SND_CH1_PITCH"}, {"82", "SND_CH2_PITCH"}, {"84", "SND_CH3_PITCH"}, {"86", "SND_CH4_PITCH"},
            {"88", "SND_CH1_VOL"}, {"89", "SND_CH2_VOL"}, {"8A", "SND_CH3_VOL"}, {"8B", "SND_CH4_VOL"},
            {"8C", "SND_SWEEP_VAL"}, {"8D", "SND_SWEEP_TIME"}, {"8E", "SND_NOISE"}, {"8F", "SND_WAVE_BASE"},
            {"90", "SND_CTRL"}, {"91", "SND_OUTPUT"}, {"92", "SND_RANDOM"}, {"94", "SND_VOICE_CTRL"},
            {"A0", "HW_FLAGS"}, {"A2", "TMR_CTRL"}, {"A4", "HTMR_FREQ"}, {"A6", "VTMR_FREQ"},
            {"A8", "HTMR_CTR"}, {"AA", "VTMR_CTR"},
            {"B0", "INT_BASE"}, {"B1", "SER_DATA"}, {"B2", "INT_ENABLE"}, {"B3", "SER_STATUS"},
            {"B4", "INT_STATUS"}, {"B5", "KEYPAD"}, {"B6", "INT_ACK"},
            {"BA", "IEEP_DATA"}, {"BC", "IEEP_ADDR"}, {"BE", "IEEP_CMD"},
            {"C0", "BANK_LINEAR"}, {"C1", "BANK_SRAM"}, {"C2", "BANK_ROM0"}, {"C3", "BANK_ROM1"},
            {"C4", "EEP_DATA"}, {"C6", "EEP_ADDR"}, {"C8", "EEP_CMD"}, {"CA", "RTC_CMD"}, {"CB", "RTC_DATA"},
            {"CC", "GPO_EN"}, {"CD", "GPO_DATA"}, {"CE", "FLASH_ENABLE"}, {"CF", "BANK_LINEAR_ALIAS"},
            {"D0", "BANK_SRAM_L"}, {"D1", "BANK_SRAM_H"}, {"D2", "BANK_ROM0_L"}, {"D3", "BANK_ROM0_H"},
            {"D4", "BANK_ROM1_L"}, {"D5", "BANK_ROM1_H"},
            {"D6", "KARNAK_CTRL"}, {"D8", "KARNAK_ADPCM_IN"}, {"D9", "KARNAK_ADPCM_OUT"},
        };
        for (String[] e : p) PORTS.put(Integer.parseInt(e[0], 16), e[1]);
    }
}
