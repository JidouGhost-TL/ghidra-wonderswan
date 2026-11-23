// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.File;
import java.nio.file.*;
import java.util.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.WonderSwanLoader;

/**
 * Rules J1u and C on synthetic cartridges, through the real import and default auto-analysis (WSMachine evidence,
 * stock Decompiler Switch Analysis, both evidence phases). Each dispatcher is reached only through a CALL behind a
 * branch that does not execute, so execution evidence observes none of its targets.
 *
 * proven:     IN AL,0B5h; SHL AL,1; MOV BL,AL; MOV BH,0; ADD BX,tbl; JMP CS:[BX] with 7 slots followed
 *             directly by the first handler. J1 proves the end (OWN_TARGET) before stock switch analysis reads
 *             the handler bytes as 121 more slots.
 * unprovable: the same dispatcher, but the word after the 7 slots points at erased bytes (a weak stop): J1 cannot
 *             prove an end; the site is tagged (rule C) and preserved, and no table end is invented.
 * guarded:    CMP AL,6; JA out before the scaling: stock switch recovery bounds it itself and keeps it (unchanged).
 *
 * Usage: headless post script on any program (it imports its own cartridges into a temporary project).
 */
public class WSSwitchOrderFixtures extends GhidraScript {
    int checks, failures;
    final List<String> lines = new ArrayList<>();

    void check(String fixture, boolean ok, String message) {
        checks++;
        if (!ok) failures++;
        String line = (ok ? "ok   " : "FAIL ") + fixture + ": " + message;
        lines.add(line);
        if (ok) println(line); else printerr(line);
    }

    static void put(byte[] rom, int off, String hex) {
        byte[] v = HexFormat.of().parseHex(hex);
        System.arraycopy(v, 0, rom, 0x10000 + off, v.length);
    }

    static String word(int v) { return String.format("%02x%02x", v & 0xff, (v >> 8) & 0xff); }

    static final int SITE_PROVEN = 0x50, TABLE = 0x60, SITE_GUARDED = 0x54;
    static final int[] ADJACENT = {0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98};
    static final int[] DETACHED = {0x100, 0x107, 0x10e, 0x115, 0x11c, 0x123, 0x12a};

    /** 128 KiB cartridge: code at F000:0000 (file 0x10000), everything else erased (FF). */
    static byte[] rom(String variant) {
        byte[] rom = new byte[0x20000];
        Arrays.fill(rom, (byte) 0xff);
        // reset: CLI; XOR AX,AX; MOV DS,AX; MOV AL,[0100h]; CMP AL,5Ah; JNZ spin; CALL 0040h; spin: JMP spin
        put(rom, 0x00, "fa31c08ed8a000013c5a7503e83100ebfe");
        int[] handlers = variant.equals("unprovable") ? DETACHED : ADJACENT;
        if (variant.equals("guarded")) {
            // IN AL,0B5h; NOP x4; CMP AL,6; JA 0057h; SHL AL,1; MOV BL,AL; MOV BH,0; ADD BX,0060h;
            // JMP CS:[BX]; RET
            put(rom, 0x40, "e4b5909090903c06770dd0e088c3b70081c360002eff27c3");
        } else {
            // IN AL,0B5h (keypad: no constant); NOP x4; SHL AL,1; MOV BL,AL; MOV BH,0; ADD BX,0060h; JMP CS:[BX]
            put(rom, 0x40, "e4b590909090d0e088c3b70081c360002eff27");
        }
        StringBuilder table = new StringBuilder();
        for (int h : handlers) table.append(word(h));
        if (variant.equals("unprovable")) table.append(word(0x400));   // next word: erased bytes
        put(rom, TABLE, table.toString());
        for (int k = 0; k < handlers.length; k++)
            put(rom, handlers[k], "b8" + word(k) + "a30003c3");        // MOV AX,k; MOV [0300h],AX; RET
        int f = rom.length - 16;
        Arrays.fill(rom, f, rom.length, (byte) 0);
        rom[f] = (byte) 0xea; rom[f + 4] = (byte) 0xf0;                 // JMP F000:0000
        rom[f + 7] = 0x01;                                              // colour
        int sum = 0;
        for (int i = 0; i < rom.length - 2; i++) sum += rom[i] & 0xff;
        rom[f + 14] = (byte) sum; rom[f + 15] = (byte) (sum >> 8);
        return rom;
    }

    Address at(Program p, int off) {
        return ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(0xf000, off);
    }

    Set<Address> computedTargets(Program p, Address site) {
        Set<Address> out = new TreeSet<>();
        for (Reference r : p.getReferenceManager().getReferencesFrom(site))
            if (r.getReferenceType().isComputed()) out.add(r.getToAddress());
        return out;
    }

    boolean has(Program p, Address a, String prefix, SourceType source) {
        for (Symbol s : p.getSymbolTable().getSymbols(a))
            if (s.getName().startsWith(prefix) && (source == null || s.getSource() == source)) return true;
        return false;
    }

    /** Stock decompiler options, as Decompiler Switch Analysis uses them. */
    JumpTable[] decompile(Program p, Function f, String fixture) {
        DecompInterface d = new DecompInterface();
        try {
            d.setOptions(new DecompileOptions());
            d.toggleSyntaxTree(true);
            d.openProgram(p);
            long t0 = System.nanoTime();
            DecompileResults r = d.decompileFunction(f, 60, monitor);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            check(fixture, r.decompileCompleted() && r.getHighFunction() != null,
                "stock-option decompile of " + f.getEntryPoint() + " completes (" + ms + " ms) " + r.getErrorMessage());
            return r.getHighFunction() == null ? new JumpTable[0] : r.getHighFunction().getJumpTables();
        } finally { d.dispose(); }
    }

    void fixture(File dir, String variant) throws Exception {
        Path file = dir.toPath().resolve(variant + ".ws");
        Files.write(file, rom(variant));
        GhidraProject project = GhidraProject.createProject(dir.getAbsolutePath(), "switch-order-" + variant, true);
        Program p;
        try {
            p = project.importProgram(file.toFile(), WonderSwanLoader.class, currentProgram.getLanguage(),
                currentProgram.getCompilerSpec());
            long t0 = System.nanoTime();
            int tx = p.startTransaction("analysis");
            try { analyzeAll(p); } finally { p.endTransaction(tx, true); }
            long seconds = (System.nanoTime() - t0) / 1_000_000_000L;
            check(variant, seconds < 120, "analysis finished in " + seconds + " s");
            Address site = at(p, variant.equals("guarded") ? SITE_GUARDED : SITE_PROVEN);
            Instruction ins = p.getListing().getInstructionAt(site);
            check(variant, ins != null && ins.toString().startsWith("JMP"), "dispatch site decoded: " + ins);
            if (ins == null) return;
            Function f = p.getFunctionManager().getFunctionContaining(site);
            check(variant, f != null && f.getEntryPoint().equals(at(p, 0x40)), "dispatcher function at F000:0040: " + f);
            Bookmark hazard = p.getBookmarkManager().getBookmark(site, BookmarkType.WARNING, "WSJumpTableHazard");
            int errors = p.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR);
            if (variant.equals("unprovable")) {
                check(variant, hazard != null, "rule C WARNING bookmark at the site: " + (hazard == null ? null : hazard.getComment()));
                check(variant, hazard == null || hazard.getComment().toLowerCase().contains("f000:0060"), "bookmark names the table");
                boolean kept = true;
                for (int off : new int[] {0x40, 0x42, 0x46, 0x48, 0x4a, 0x4c, 0x50})
                    kept &= p.getListing().getInstructionAt(at(p, off)) != null;
                check(variant, kept, "dispatcher code preserved (H2)");
                check(variant, !has(p, site, "switch", SourceType.USER_DEFINED), "no J1 lock: no table end invented");
                return;
            }
            check(variant, hazard == null, "no hazard tag on a table with a proven end");
            Set<Address> expected = new TreeSet<>();
            for (int h : ADJACENT) expected.add(at(p, h));
            check(variant, computedTargets(p, site).equals(expected),
                "exactly the 7 table targets referenced: " + computedTargets(p, site));
            boolean decoded = true;
            for (int h : ADJACENT) decoded &= p.getListing().getInstructionAt(at(p, h)) != null;
            check(variant, decoded, "all 7 handlers decoded");
            AddressSet code = new AddressSet(at(p, 0x00), at(p, 0x10));
            code.add(at(p, 0x40), at(p, variant.equals("guarded") ? 0x57 : 0x52));
            code.add(at(p, 0x6e), at(p, 0x9e));
            List<Address> stray = new ArrayList<>();
            for (Instruction i : p.getListing().getInstructions(true))
                if (!code.contains(i.getAddress()) && stray.size() < 8) stray.add(i.getAddress());
            check(variant, stray.isEmpty(), "no code decoded from handler bytes read as slots: " + stray);
            check(variant, errors == 0, "no ERROR bookmarks (" + errors + ")");
            boolean stock = has(p, site, "switchD", SourceType.ANALYSIS);
            if (variant.equals("proven"))
                check(variant, !stock, "stock switch recovery did not reach the site (no switchD label)");
            else
                check(variant, stock, "stock switch recovery still recovers the guarded table (switchD label)");
            if (f == null) return;
            JumpTable[] tables = decompile(p, f, variant);
            check(variant, tables.length == 1 && tables[0].getCases().length == 7,
                "decompiler sees one 7-case table: " + Arrays.stream(tables).map(t -> String.valueOf(t.getCases().length)).toList());
        } finally {
            project.close();
        }
    }

    @Override
    public void run() throws Exception {
        File dir = Files.createTempDirectory("ws-switch-order").toFile();
        String[] args = getScriptArgs();
        List<String> variants = args.length > 0 ? List.of(args) : List.of("proven", "unprovable", "guarded");
        for (String v : variants) {
            try { fixture(dir, v); }
            catch (Exception e) { check(v, false, "fixture raised " + e); }
        }
        println("WSSwitchOrderFixtures: checks=" + checks + " failures=" + failures);
        if (failures != 0) throw new AssertionError("WSSwitchOrderFixtures failures=" + failures);
        println("WSSwitchOrderFixtures: PASS checks=" + checks);
    }
}
