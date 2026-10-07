// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.AddressSpace;
import java.math.BigInteger;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;

/**
 * Bandai WonderSwan / WonderSwan Color cartridge loader.
 *
 * Memory map (CPU linear address = seg*16 + off, 20-bit):
 *   0000:0000  RAM          64 KiB on Colour, 16 KiB on mono (initialised to zero; the game fills it)
 *   1000:0000  SRAM         uninitialised, bank-dependent (port C1)
 *   2000:0000  ROM0 window  uninitialised, bank-dependent (port C2) -- not executable until resolved
 *   3000:0000  ROM1 window  uninitialised, bank-dependent (port C3)
 *   4000:0000 .. F000:0000  fixed linear window, twelve 64 KiB blocks mapped through the reset value
 *                           of the linear bank register (C0 = 0xFF); small ROMs mirror.
 *   ROM_xx     data overlays, one 64 KiB read-only non-executable overlay block per ROM bank not
 *              already visible in the fixed linear window, overlaying 0000:0000 (each in its own
 *              overlay address space named after the block, e.g. ROM_3A:0000:0100). Any ROM offset
 *              is reachable via Go-To-Address, labels and references. Bank overlays for executed
 *              window code (rule B2, ROM0_BANK_XXXX / ROM1_BANK_XXXX at 2000:0000 / 3000:0000) are
 *              executable views at the window address; these are data views (see {@link #isDataOverlay}).
 * The whole ROM is kept as FileBytes so analyzers can add ROM banks as overlays later.
 */
public class WonderSwanLoader extends AbstractProgramWrapperLoader {

    public static final String NAME = "WonderSwan Cartridge";
    public static final String LANG_V30MZ = "V30MZ:LE:16:default";
    public static final String LANG_X86_REAL = "x86:LE:16:Real Mode";
    public static final String OPTIONS_CATEGORY = "WonderSwan";
    /** Loader option: map every non-linear ROM bank as a read-only data overlay (default on). */
    public static final String OPT_MAP_BANKS = "Map all ROM banks as data overlays";

    /**
     * True for a loader-created ROM data overlay block (name {@code ROM_XX}, hex bank number,
     * e.g. {@code ROM_3A}): a read-only non-executable FileBytes-backed overlay of 0000:0000.
     * Rule-B2 window overlays ({@code ROM0_BANK_XXXX}/{@code ROM1_BANK_XXXX}) are executable
     * views at the window address and do not match.
     */
    public static boolean isDataOverlay(MemoryBlock b) {
        return b != null && isDataOverlayName(b.getName());
    }

    /** Name test behind {@link #isDataOverlay}, pure for unit tests (no framework). */
    public static boolean isDataOverlayName(String n) {
        if (n == null || !n.startsWith("ROM_") || n.length() <= 4) return false;
        for (int i = 4; i < n.length(); i++) {
            char c = n.charAt(i);
            if ((c < '0' || c > '9') && (c < 'A' || c > 'F')) return false;
        }
        return true;
    }

    /** ROM bank number of a data overlay block, or -1 when {@link #isDataOverlay} is false. */
    public static int dataOverlayBank(MemoryBlock b) {
        return b == null ? -1 : dataOverlayBankName(b.getName());
    }

    /** Bank number behind {@link #dataOverlayBank}, pure for unit tests. */
    public static int dataOverlayBankName(String n) {
        if (!isDataOverlayName(n)) return -1;
        try {
            return Integer.parseInt(n.substring(4), 16);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Data overlay block name for a ROM bank (e.g. bank {@code 0x3A} → {@code ROM_3A}). */
    public static String dataOverlayName(int bank) {
        return String.format("ROM_%02X", bank);
    }

    /** Banks visible in the fixed linear window (4000–F000) for an effective ROM size. */
    public static Set<Integer> linearBanks(long romLen) {
        Set<Integer> out = new HashSet<>();
        for (int seg = WSHardware.SEG_LINEAR_FIRST; seg <= 0xF000; seg += 0x1000) {
            out.add((int) (WSHardware.linearToRom(((long) seg) << 4, WSHardware.RESET_C0, romLen) >> 16));
        }
        return out;
    }

    /** Banks needing data overlays: every 64 KiB bank not in {@link #linearBanks}. */
    public static List<Integer> dataOverlayBanks(long romLen) {
        Set<Integer> lin = linearBanks(romLen);
        List<Integer> out = new ArrayList<>();
        int total = (int) (romLen / 0x10000);
        for (int b = 0; b < total; b++) if (!lin.contains(b)) out.add(b);
        return out;
    }

    @Override
    public String getName() { return NAME; }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> specs = new ArrayList<>();
        long len = provider.length();
        if (len < WSHeader.SIZE) return specs;
        byte[] footer = provider.readBytes(len - WSHeader.SIZE, WSHeader.SIZE);
        if (!WSHeader.plausible(len, footer)) return specs;
        // Preferred only when the footer checksum verifies; homebrew with a bad sum still loads.
        boolean ok = WSHeader.parse(provider.readBytes(0, len)).checksumOk();
        specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANG_V30MZ, "default"), ok));
        specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANG_X86_REAL, "default"), false));
        return specs;
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
        ByteProvider provider = settings.provider();
        byte[] rom = provider.readBytes(0, provider.length());
        WSHeader hdr = WSHeader.parse(rom);
        WSCartridge cart = WSCartridge.detect(rom, provider.getName());
        boolean mapBanks = true;
        for (Option opt : settings.options()) {
            if (!OPT_MAP_BANKS.equals(opt.getName())) continue;
            Object v = opt.getValue();
            if (v instanceof Boolean b) mapBanks = b;
            else if (v instanceof String s) mapBanks = Boolean.parseBoolean(s);
        }
        // Hardware model: colour when the footer says so, or when the cartridge was released for the
        // WonderSwan Color (.wsc). Some colour releases leave the footer flag 0 and diverge from Mesen within
        // ~10 instructions when run on the mono model.
        String name = provider.getName() == null ? "" : provider.getName().toLowerCase();
        boolean colorHw = hdr.color || name.endsWith(".wsc");
        String colorSource = hdr.color ? "footer" : colorHw ? "file extension .wsc (footer flag 0)" : "footer (mono)";
        long romLen = cart.effectiveSize;
        settings.log().appendMsg("WonderSwan cartridge: " + cart.summary());
        for (String w : cart.warnings) settings.log().appendMsg("WonderSwan: " + w);
        Memory mem = program.getMemory();
        SegmentedAddressSpace space = (SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
        FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, settings.monitor());
        try {
            int ramSize = colorHw ? WSHardware.RAM_COLOR : WSHardware.RAM_MONO;
            MemoryBlock ram = mem.createInitializedBlock("RAM", space.getAddress(WSHardware.SEG_RAM, 0), ramSize,
                (byte) 0, settings.monitor(), false);
            ram.setPermissions(true, true, true);
            ram.setComment("Work RAM, tile data, maps, palettes; contents set by the game at run time");

            MemoryBlock sram = mem.createUninitializedBlock("SRAM", space.getAddress(WSHardware.SEG_SRAM, 0), 0x10000, false);
            sram.setPermissions(true, true, false);
            sram.setVolatile(true);
            sram.setComment("Cartridge SRAM window, bank-dependent (port C1)");

            for (int[] w : new int[][] { { WSHardware.SEG_ROM0, 0xC2 }, { WSHardware.SEG_ROM1, 0xC3 } }) {
                MemoryBlock b = mem.createUninitializedBlock(w[0] == WSHardware.SEG_ROM0 ? "ROM0_WINDOW" : "ROM1_WINDOW",
                    space.getAddress(w[0], 0), 0x10000, false);
                b.setPermissions(true, false, false);
                b.setVolatile(true);
                b.setComment(String.format("ROM bank window, contents depend on port %02X; resolved banks are added as overlays", w[1]));
            }

            boolean padded = romLen != rom.length;
            for (int seg = WSHardware.SEG_LINEAR_FIRST; seg <= 0xF000; seg += 0x1000) {
                long linear = ((long) seg) << 4;
                long off = WSHardware.linearToRom(linear, WSHardware.RESET_C0, romLen);
                MemoryBlock b;
                String comment;
                if (!padded) {
                    b = mem.createInitializedBlock(String.format("LIN_%04X", seg), space.getAddress(seg, 0),
                        fb, off, 0x10000, false);
                    comment = String.format("Fixed linear window, ROM bank 0x%02X (file offset 0x%06X)", off >> 16, off);
                } else {
                    // Non-power-of-two image: materialise the window (file bytes at the end, start padding).
                    byte[] win = new byte[0x10000];
                    long pad = romLen - rom.length;
                    for (int i = 0; i < win.length; i++) {
                        long f = off + i - pad;
                        win[i] = f < 0 ? (byte) WSHardware.PAD_BYTE : rom[(int) f];
                    }
                    b = mem.createInitializedBlock(String.format("LIN_%04X", seg), space.getAddress(seg, 0),
                        new java.io.ByteArrayInputStream(win), 0x10000, settings.monitor(), false);
                    comment = String.format("Fixed linear window, ROM bank 0x%02X (effective offset 0x%06X; image padded at the start)", off >> 16, off);
                }
                b.setPermissions(true, false, true);
                b.setComment(comment);
            }

            if (mapBanks) mapDataOverlays(mem, space, fb, rom, romLen, padded, settings);
        }
        catch (Exception e) {
            throw new IOException("WonderSwan memory map: " + e.getMessage(), e);
        }

        SymbolTable st = program.getSymbolTable();
        try {
            Address reset = space.getAddress(hdr.resetSegment, hdr.resetOffset);
            st.addExternalEntryPoint(reset);
            // A named entry point is skipped by Ghidra's entry-point analyzer; a one-address function
            // at the entry is the loader convention: the analyzer disassembles it and fixes the body.
            program.getFunctionManager().createFunction("reset", reset, new ghidra.program.model.address.AddressSet(reset), SourceType.IMPORTED);
            String[][] labels = { { "0", "0", "IVT" }, { "0", "2000", "TILES_2BPP" }, { "0", "4000", "TILES_4BPP" },
                { "0", "fe00", "PALETTES" } };
            for (String[] l : labels) {
                Address a = space.getAddress(Integer.parseInt(l[0], 16), Integer.parseInt(l[1], 16));
                if (mem.contains(a)) st.createLabel(a, l[2], SourceType.IMPORTED);
            }
            Address footer = space.getAddress(0xF000, 0xFFF0);
            if (mem.contains(footer)) {
                st.createLabel(footer, "cartridge_footer", SourceType.IMPORTED);
                program.getListing().createData(footer, footerType());
            }
        }
        catch (Exception e) {
            settings.log().appendMsg("WonderSwan labels/footer: " + e.getMessage());
        }

        if (program.getLanguage().getProcessor().toString().equals("V30MZ")) setupV30MZ(program, hdr, colorHw, settings);

        // Default analysis policy: Ghidra's discovered-non-returning heuristic flags routines that execution
        // shows returning (e.g. a loader routine with 113 call sites, 22 observed fall-throughs) and its flow
        // repair then removes executed code, re-triggering after any later disassembly. Off by default for
        // WonderSwan programs; WSEvidenceRepairAnalyzer rule N1 still clears contradicted flags. Users can
        // re-enable it in Analysis Options.
        program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("Non-Returning Functions - Discovered", false);

        Options o = program.getOptions(OPTIONS_CATEGORY);
        o.setBoolean("Color", colorHw);               // hardware model used by WSMachine and the analyzers
        o.setString("Color source", colorSource);
        o.setBoolean("Footer color flag", hdr.color);
        o.setInt("Publisher", hdr.publisher);
        o.setInt("Game ID", hdr.gameId);
        o.setInt("Version", hdr.version);
        o.setInt("ROM size code", hdr.romSizeCode);
        o.setInt("Save code", hdr.saveCode);
        o.setInt("Flags", hdr.flags);
        o.setInt("Mapper code", hdr.mapperCode);
        o.setString("Mapper", cart.mapperName());
        o.setBoolean("RTC", cart.hasRtc());
        o.setBoolean("Flash", cart.hasFlash());
        o.setBoolean("Checksum OK", hdr.checksumOk());
        o.setString("Reset", String.format("%04X:%04X", hdr.resetSegment, hdr.resetOffset));
        o.setBoolean("Map data overlays", mapBanks);
    }

    /**
     * Map every 64 KiB ROM bank not already visible in the fixed linear window as a read-only,
     * non-executable overlay block of 0000:0000, one per bank in its own overlay space
     * (e.g. {@code ROM_3A} for bank 0x3A, addressable as {@code ROM_3A:0000:0100}).
     * Non-executable, so Ghidra's code-finding analyzers (entry points, aggressive instruction
     * finder, function starts) and the WS evidence rules F/G/U/J (all gated on executable) leave
     * them as pure data; the decompiler only sees functions, of which none are created here.
     */
    private void mapDataOverlays(Memory mem, SegmentedAddressSpace space, FileBytes fb, byte[] rom,
            long romLen, boolean padded, ImporterSettings settings) throws Exception {
        Address base = space.getAddress(WSHardware.SEG_RAM, 0);
        int mapped = 0;
        for (int bank : dataOverlayBanks(romLen)) {
            String blockName = dataOverlayName(bank);
            if (mem.getBlock(blockName) != null) continue;
            long off = ((long) bank) << 16;
            MemoryBlock b;
            String comment;
            if (!padded) {
                b = mem.createInitializedBlock(blockName, base, fb, off, 0x10000, true);
                comment = String.format("ROM bank 0x%02X (file offset 0x%06X): read-only data view overlaying 0000:0000; "
                    + "executable window views (evidence rule B2) are ROM0_BANK_XXXX/ROM1_BANK_XXXX at 2000:0000/3000:0000", bank, off);
            } else {
                byte[] win = new byte[0x10000];
                long pad = romLen - rom.length;
                for (int i = 0; i < win.length; i++) {
                    long f = off + i - pad;
                    win[i] = f < 0 ? (byte) WSHardware.PAD_BYTE : rom[(int) f];
                }
                b = mem.createInitializedBlock(blockName, base,
                    new java.io.ByteArrayInputStream(win), 0x10000, settings.monitor(), true);
                comment = String.format("ROM bank 0x%02X (effective offset 0x%06X; image padded at the start): "
                    + "read-only data view overlaying 0000:0000; executable window views (evidence rule B2) are "
                    + "ROM0_BANK_XXXX/ROM1_BANK_XXXX at 2000:0000/3000:0000", bank, off);
            }
            b.setPermissions(true, false, false);
            b.setComment(comment);
            mapped++;
        }
        settings.log().appendMsg("WonderSwan: mapped " + mapped + " ROM banks as data overlays (ROM_xx at 0000:0000, read-only, non-executable)");
    }

    /**
     * V30MZ-language specifics: the language tracks the real code segment in the flowing context
     * field `csval` (unset = 0, which would mis-resolve every near branch), and models I/O ports
     * as the `io` address space. Set csval at the reset entry and create the labelled IO block.
     */
    private void setupV30MZ(Program program, WSHeader hdr, boolean colorHw, ImporterSettings settings) {
        SegmentedAddressSpace space = (SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
        Register csval = program.getProgramContext().getRegister("csval");
        if (csval == null) {
            settings.log().appendMsg("WonderSwan: V30MZ language has no csval context field; near branches will resolve with CS=0");
        } else {
            try {
                Address reset = space.getAddress(hdr.resetSegment, hdr.resetOffset);
                program.getProgramContext().setValue(csval, reset, reset, BigInteger.valueOf(hdr.resetSegment));
            } catch (Exception e) {
                settings.log().appendMsg("WonderSwan: could not set csval at reset: " + e.getMessage());
            }
        }
        // DS = SS = 0 default context over the ROM code (measured on commercial titles: reset code sets
        // DS=ES=SS=0; 86-96 % of executed code runs with DS=0; ROM data is reached by temporarily loading DS,
        // which the decompiler tracks within a function). Evidence overrides it: rule D0 (WSCompilerRules) replaces
        // the default when execution shows another DS or SS dominating the title (e.g. 1000 = SRAM in titles
        // whose stack lives there), always stamps the resolved defaults on the bank overlays too (they do not
        // exist at load time), and rule D1 sets the DS/SS observed at function entries.
        try {
            Register ds = program.getProgramContext().getRegister("DS"), ss = program.getProgramContext().getRegister("SS");
            for (MemoryBlock b : program.getMemory().getBlocks()) {
                if (!b.getName().startsWith("LIN_")) continue;
                program.getProgramContext().setValue(ds, b.getStart(), b.getEnd(), BigInteger.ZERO);
                program.getProgramContext().setValue(ss, b.getStart(), b.getEnd(), BigInteger.ZERO);
            }
        } catch (Exception e) {
            settings.log().appendMsg("WonderSwan: could not set DS/SS default context: " + e.getMessage());
        }
        // colorsoc (MUL's ZF) is NOT stored here as a context range over the ROM: a stored context-field range
        // over not-yet-disassembled bytes overrides the flowing context (csval) that later disassembly relies
        // on (in one title Ghidra's switch analysis then lost every case of a 177-function dispatch). The
        // evidence analyzer sets colorsoc with csval at each executed address instead, and it flows from there.
        AddressSpace io = program.getAddressFactory().getAddressSpace("io");
        if (io == null) {
            settings.log().appendMsg("WonderSwan: V30MZ language has no io space; ports are not labelled");
            return;
        }
        try {
            MemoryBlock b = program.getMemory().createUninitializedBlock("IO", io.getAddress(0), 0x100, false);
            b.setPermissions(true, true, false);
            b.setVolatile(true);
            b.setComment("I/O ports (the SoC decodes the low 8 bits of the port address)");
            SymbolTable st = program.getSymbolTable();
            java.util.Set<Integer> words = new java.util.HashSet<>();
            for (int w : WSHardware.WORD_PORTS) words.add(w);
            for (java.util.Map.Entry<Integer, String> e : WSHardware.PORTS.entrySet()) {
                Address a = io.getAddress(e.getKey());
                st.createLabel(a, e.getValue(), SourceType.IMPORTED);
                if (words.contains(e.getKey())) program.getListing().createData(a, WordDataType.dataType);
                else if (!words.contains(e.getKey() - 1)) program.getListing().createData(a, ByteDataType.dataType);
            }
        } catch (Exception e) {
            settings.log().appendMsg("WonderSwan: IO block: " + e.getMessage());
        }
    }

    static DataType footerType() {
        StructureDataType s = new StructureDataType("WSCartridgeFooter", 0);
        s.add(ByteDataType.dataType, "jmp_opcode", "0xEA far JMP");
        s.add(WordDataType.dataType, "reset_offset", null);
        s.add(WordDataType.dataType, "reset_segment", null);
        s.add(ByteDataType.dataType, "maintenance", null);
        s.add(ByteDataType.dataType, "publisher", null);
        s.add(ByteDataType.dataType, "color", "bit0: WonderSwan Color");
        s.add(ByteDataType.dataType, "game_id", null);
        s.add(ByteDataType.dataType, "version", null);
        s.add(ByteDataType.dataType, "rom_size", null);
        s.add(ByteDataType.dataType, "save_type", null);
        s.add(ByteDataType.dataType, "flags", null);
        s.add(ByteDataType.dataType, "mapper", "$00 = 2001/KARNAK, $01 = 2003 (older docs: RTC present)");
        s.add(WordDataType.dataType, "checksum", "sum of all ROM bytes except these two");
        return s;
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
            boolean isLoadIntoProgram, boolean mirrorFsLayout) {
        List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram, mirrorFsLayout);
        list.add(new Option(OPT_MAP_BANKS, Boolean.TRUE, Boolean.class, "MapDataOverlays"));
        return list;
    }
}
