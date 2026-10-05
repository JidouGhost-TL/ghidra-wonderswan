// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/**
 * Cartridge detection shared by the loader and the emulator: mapper, save hardware and image
 * geometry from the footer, with every unknown or contradictory value reported loudly in
 * {@link #warnings} instead of defaulted silently.
 *
 * <ul>
 * <li>Mapper byte $00 = 2001, or KARNAK when the file is a Pocket Challenge V2 image ({@code .pc2});
 *   $01 = 2003. Anything else is unknown: loading proceeds as 2001 (the bank windows are the same
 *   common subset on all mappers) and the raw value is kept in the report.
 * <li>WonderWitch: a 2003-family flash cartridge has no footer flag of its own; its images carry
 *   mapper $01 with a zero checksum field (a writable flash cannot carry a checksum) and the
 *   internal-EEPROM write protection disabled (version bit 7). When those markers coincide with
 *   the 512 KiB flash size, the image is treated as a WonderWitch flash cartridge: the ROM window
 *   contents are flash-backed and writable through the command sequences. The rule is necessarily
 *   heuristic (a masked-ROM image with the same markers would match too) and is always logged.
 * <li>The RTC interface exists on every 2003-family cartridge; the S-3511A chip itself has no
 *   footer flag (see {@link WSHeader}), so it is always provided there.
 * <li>Banking always uses the file size, never the footer's ROM-size code: released footers
 *   mispredict it, and non-power-of-two images are padded at the start
 *   (see {@link WSHardware#effectiveSize}).
 * </ul>
 */
public final class WSCartridge {

    /** Mapper families the loader and emulator distinguish. */
    public enum Mapper { M2001, M2003, KARNAK, WONDERWITCH }

    /** Flash chip size identifying a WonderWitch image (Fujitsu 29DL400TC, 4 Mbit). */
    public static final int WONDERWITCH_FLASH_BYTES = 0x80000;

    public final Mapper mapper;
    public final WSHeader header;
    /** File size in bytes (as stored); banking uses {@link #effectiveSize}. */
    public final long fileSize;
    public final long effectiveSize;
    public final int eepromBytes, sramBytes;
    /** Human-readable detection report, one line per fact or warning; never empty. */
    public final List<String> warnings = new ArrayList<>();

    private WSCartridge(Mapper mapper, WSHeader header, long fileSize) {
        this.mapper = mapper;
        this.header = header;
        this.fileSize = fileSize;
        this.effectiveSize = WSHardware.effectiveSize(fileSize);
        this.eepromBytes = WSHardware.cartEepromBytes(header.saveCode);
        this.sramBytes = WSHardware.sramBytes(header.saveCode);
    }

    public boolean hasRtc() { return mapper == Mapper.M2003 || mapper == Mapper.WONDERWITCH; }
    public boolean hasFlash() { return mapper == Mapper.WONDERWITCH; }
    public boolean hasKarnak() { return mapper == Mapper.KARNAK; }

    /** Short mapper name for options and reports. */
    public String mapperName() {
        return switch (mapper) {
            case M2001 -> "2001";
            case M2003 -> "2003";
            case KARNAK -> "KARNAK";
            case WONDERWITCH -> "WonderWitch";
        };
    }

    /**
     * Describe a file image with an already-decided mapper (the loader stored its decision in the
     * program options, so the emulator need not re-guess from a possibly renamed program).
     */
    public static WSCartridge detectAs(byte[] rom, Mapper mapper) {
        return new WSCartridge(mapper, WSHeader.parse(rom), rom.length);
    }

    /** Parse a stored mapper name back, or null when unknown. */
    public static Mapper parseMapper(String name) {
        if (name == null) return null;
        return switch (name) {
            case "2001" -> Mapper.M2001;
            case "2003" -> Mapper.M2003;
            case "KARNAK" -> Mapper.KARNAK;
            case "WonderWitch" -> Mapper.WONDERWITCH;
            default -> null;
        };
    }

    /**
     * Detect the cartridge from a file image and its name (the extension disambiguates KARNAK and
     * the colour model hint; {@code null} names are allowed).
     */
    public static WSCartridge detect(byte[] rom, String fileName) {
        WSHeader h = WSHeader.parse(rom);
        String name = fileName == null ? "" : fileName.toLowerCase();
        boolean pc2 = name.endsWith(".pc2");
        Mapper m;
        WSCartridge c;
        if (pc2) {
            m = Mapper.KARNAK;
            c = new WSCartridge(m, h, rom.length);
            if (h.mapperCode != 0x00)
                c.warnings.add(String.format("Pocket Challenge V2 image (.pc2) with mapper byte $%02X, expected $00 (2001/KARNAK); KARNAK assumed", h.mapperCode));
        } else if (h.mapperCode == 0x00) {
            c = new WSCartridge(Mapper.M2001, h, rom.length);
        } else if (h.mapperCode == 0x01 && h.checksum == 0 && (h.version & 0x80) != 0 && rom.length == WONDERWITCH_FLASH_BYTES) {
            c = new WSCartridge(Mapper.WONDERWITCH, h, rom.length);
            c.warnings.add("WonderWitch-style markers (mapper $01, zero checksum, version bit 7, 512 KiB flash size): flash-backed ROM assumed");
        } else if (h.mapperCode == 0x01) {
            c = new WSCartridge(Mapper.M2003, h, rom.length);
            if (h.checksum == 0 && (h.version & 0x80) != 0)
                c.warnings.add("WonderWitch-style metadata (zero checksum, version bit 7) on a masked-ROM-sized image: 2003 assumed, self-flash window is read-only");
        } else {
            c = new WSCartridge(Mapper.M2001, h, rom.length);
            c.warnings.add(String.format("Unknown mapper byte $%02X (known: $00 = 2001/KARNAK, $01 = 2003); 2001 bank windows assumed", h.mapperCode));
        }
        if (h.saveCode != 0 && c.eepromBytes == 0 && c.sramBytes == 0)
            c.warnings.add(String.format("Unknown save-type byte $%02X (known: $00-$05 SRAM, $10/$20/$50 EEPROM); no save hardware assumed", h.saveCode));
        long declared = WSHeader.declaredSize(h.romSizeCode);
        if (declared < 0)
            c.warnings.add(String.format("Unknown ROM-size code $%02X; file size used for banking", h.romSizeCode));
        else if (declared != rom.length)
            c.warnings.add(String.format("Footer ROM-size code $%02X declares %d bytes but the file has %d; file size used for banking",
                h.romSizeCode, declared, rom.length));
        if (c.effectiveSize != rom.length)
            c.warnings.add(String.format("Non-power-of-two image (%d bytes): read as a %d-byte ROM with %d padding bytes at the start",
                rom.length, c.effectiveSize, c.effectiveSize - rom.length));
        if (!h.checksumOk() && !(h.checksum == 0 && (c.mapper == Mapper.WONDERWITCH || c.mapper == Mapper.M2003)))
            c.warnings.add(String.format("Footer checksum %04X != computed %04X", h.checksum, h.computedChecksum));
        return c;
    }

    /** One-line summary for logs and reports. */
    public String summary() {
        return String.format("mapper=%s rtc=%s flash=%s karnak=%s sram=%d eeprom=%d size=%d(eff %d)",
            mapperName(), hasRtc(), hasFlash(), hasKarnak(), sramBytes, eepromBytes, fileSize, effectiveSize);
    }
}
