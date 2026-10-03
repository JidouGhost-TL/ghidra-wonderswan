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
 * The whole ROM is kept as FileBytes so analyzers can add ROM banks as overlays later.
 */
public class WonderSwanLoader extends AbstractProgramWrapperLoader {

    public static final String NAME = "WonderSwan Cartridge";
    public static final String LANG_V30MZ = "V30MZ:LE:16:default";
    public static final String LANG_X86_REAL = "x86:LE:16:Real Mode";
    public static final String OPTIONS_CATEGORY = "WonderSwan";

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
        // Hardware model: colour when the footer says so, or when the cartridge was released for the
        // WonderSwan Color (.wsc). Some colour releases leave the footer flag 0 and diverge from Mesen within
        // ~10 instructions when run on the mono model.
        String name = provider.getName() == null ? "" : provider.getName().toLowerCase();
        boolean colorHw = hdr.color || name.endsWith(".wsc");
        String colorSource = hdr.color ? "footer" : colorHw ? "file extension .wsc (footer flag 0)" : "footer (mono)";
        long romLen = rom.length;
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

            for (int seg = WSHardware.SEG_LINEAR_FIRST; seg <= 0xF000; seg += 0x1000) {
                long linear = ((long) seg) << 4;
                long off = WSHardware.linearToRom(linear, WSHardware.RESET_C0, romLen);
                MemoryBlock b = mem.createInitializedBlock(String.format("LIN_%04X", seg), space.getAddress(seg, 0),
                    fb, off, 0x10000, false);
                b.setPermissions(true, false, true);
                b.setComment(String.format("Fixed linear window, ROM bank 0x%02X (file offset 0x%06X)", off >> 16, off));
            }
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
        o.setBoolean("RTC", hdr.rtc);
        o.setBoolean("Checksum OK", hdr.checksumOk());
        o.setString("Reset", String.format("%04X:%04X", hdr.resetSegment, hdr.resetOffset));
        if (!hdr.checksumOk())
            settings.log().appendMsg(String.format("WonderSwan: footer checksum %04X != computed %04X", hdr.checksum, hdr.computedChecksum));
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
        // the default when execution shows another DS dominating the title (e.g. 1000 = SRAM in LSI C-86 titles),
        // and rule D1 sets the DS observed at function entries.
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
        s.add(ByteDataType.dataType, "rtc", null);
        s.add(WordDataType.dataType, "checksum", "sum of all ROM bytes except these two");
        return s;
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
            boolean isLoadIntoProgram, boolean mirrorFsLayout) {
        return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram, mirrorFsLayout);
    }
}
