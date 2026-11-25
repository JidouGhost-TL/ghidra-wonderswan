// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.File;
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import jidoughost.wonderswan.WonderSwanLoader;

/**
 * Rules F3s (stack-spilled register-pair setter into F6 indexed RAM array with 1-based dispatch) and
 * CT3 (RAM-pointed non-power-of-2 strided far-pointer record tables) on synthetic cartridges, through
 * the real import and default auto-analysis.
 *
 * All test routines are reached only behind a non-taken boot branch so execution evidence observes none
 * of the targets; handlers sit between erased 0xFF bytes so nothing but F3s / CT3 names them.
 *
 * f3s_pos:      caller passes BX:AX = F000:0200 to a setter that spills AX/BX to [BP-4]/[BP-2] across a
 *               capacity guard, reloads them, and stores into [BX+0404h]/[BX+0406h]; dispatcher invokes
 *               CALLF [BX+0400h] (1-based BASE - 4): handler at F000:0200 decoded with F3s bookmark.
 * f3s_clobber:  same setter with INC BX between the two array stores: no pair, handler stays undecoded.
 * f3s_mismatch: same setter, but dispatcher invokes CALLF [BX+03F0h] (offset != 0, -4): stays undecoded.
 * ct3_pos:      init stores CS:0180h into SS:[0505h]/SS:[0507h]; dispatcher loads ES:[SI+5], DI:[SI+7]
 *               (caller sets SI=0500h), scales by MUL 0Ch (12-byte records) and calls ES:[DI] and ES:[DI+8];
 *               table at F000:0180 has 2 valid records (with a null 0000:0000 slot) followed by erased 0xFF:
 *               all three handlers (0200h, 0220h, 0240h) decoded as functions with CT3 bookmarks.
 * ct3_uninit:   same dispatcher and table, but init routine is a bare RET (RAM pointer uninitialized):
 *               no handlers decoded.
 *
 * Usage: headless post script on any program (it imports its own cartridges into a temporary project).
 */
public class WSF3sCt3Fixtures extends GhidraScript {
    int checks, failures;

    void check(String fixture, boolean ok, String message) {
        checks++;
        if (!ok) failures++;
        String line = (ok ? "ok   " : "FAIL ") + fixture + ": " + message;
        if (ok) println(line); else printerr(line);
    }

    static void put(byte[] rom, int off, String hex) {
        byte[] v = HexFormat.of().parseHex(hex);
        System.arraycopy(v, 0, rom, 0x10000 + off, v.length);
    }

    static final int CALLER = 0x40, DISPATCH = 0x80, CT3_DISP = 0xA0, SETTER = 0xC0, TABLE = 0x180;
    static final int HANDLER = 0x200, HANDLER2 = 0x220, HANDLER3 = 0x240;

    static byte[] rom(String variant) {
        byte[] rom = new byte[0x20000];
        Arrays.fill(rom, (byte) 0xff);
        // CLI; XOR AX,AX; MOV DS,AX; MOV SS,AX; MOV AL,[0100h]; CMP AL,5Ah; JNZ spin; CALL 0040h; CALL 0080h; spin: JMP spin
        put(rom, 0x00, "fa31c08ed88ed0a000013c5a7506e82f00e86c00ebfe");
        if (variant.startsWith("f3s_")) {
            // MOV AX,0200h; MOV BX,F000h; CALLF F000:00C0; RET
            put(rom, CALLER, "b80002bb00f09ac00000f0c3");
            // MOV BX,[0480h]; SHL BX,1; SHL BX,1; CALLF [BX+0400h] (or 03F0h for mismatch); RET
            put(rom, DISPATCH, variant.equals("f3s_mismatch")
                ? "8b1e8004d1e3d1e3ff9ff003c3"
                : "8b1e8004d1e3d1e3ff9f0004c3");
            // PUSH BP; MOV BP,SP; SUB SP,4; PUSH CX; MOV [BP-4],AX; MOV [BP-2],BX;
            // CMP WORD [0480h],10h; JNL fail; MOV BX,[0480h]; SHL BX,1; SHL BX,1;
            // MOV CX,[BP-4]; MOV AX,[BP-2]; MOV [BX+0404h],CX; [INC BX;] MOV [BX+0406h],AX;
            // INC WORD [0480h]; XOR AX,AX; JMP done; fail: MOV AX,FFFFh; done: POP CX; MOV SP,BP; POP BP; RETF
            put(rom, SETTER, variant.equals("f3s_clobber")
                ? "558bec83ec04518946fc895efe833e8004107d1f8b1e8004d1e3d1e38b4efc8b46fe898f04044389870604ff06800433c0eb03b8ffff598be55dcb"
                : "558bec83ec04518946fc895efe833e8004107d1e8b1e8004d1e3d1e38b4efc8b46fe898f040489870604ff06800433c0eb03b8ffff598be55dcb");
            put(rom, HANDLER, "b80100a30003cb");
        } else {
            // ct3_pos: MOV SS:[0505h],CS; MOV WORD SS:[0507h],0180h; RET  |  ct3_uninit: RET
            put(rom, CALLER, variant.equals("ct3_uninit") ? "c3" : "368c0e050536c70607058001c3");
            // MOV SI,0500h; CALL 00A0h; RET
            put(rom, DISPATCH, "be0005e81a00c3");
            // MOV ES,[SI+5]; MOV DI,[SI+7]; PUSH DI; MOV AL,0Ch; MUL BYTE [SI]; ADD DI,AX; CALLF ES:[DI]; POP DI;
            // PUSH DI; MOV AL,0Ch; MUL BYTE [SI]; ADD DI,AX; CALLF ES:[DI+8]; POP DI; RET
            put(rom, CT3_DISP, "8e44058b7c0757b00cf62403f826ff1d5f57b00cf62403f826ff5d085fc3");
            // 12-byte records at F000:0180:
            // [0]: +0=F000:0200, +4=0000:0000, +8=F000:0220
            // [1]: +0=0000:0000, +4=0000:0000, +8=F000:0240
            // [2]: erased 0xFF (stops scan)
            put(rom, TABLE,      "000200f000000000200200f0");
            put(rom, TABLE + 12, "0000000000000000400200f0");
            put(rom, HANDLER,  "b80100a30003cb");
            put(rom, HANDLER2, "b80200a30003cb");
            put(rom, HANDLER3, "b80300a30003cb");
        }
        int f = rom.length - 16;
        Arrays.fill(rom, f, rom.length, (byte) 0);
        rom[f] = (byte) 0xea; rom[f + 4] = (byte) 0xf0;
        rom[f + 7] = 0x01;
        int sum = 0;
        for (int i = 0; i < rom.length - 2; i++) sum += rom[i] & 0xff;
        rom[f + 14] = (byte) sum; rom[f + 15] = (byte) (sum >> 8);
        return rom;
    }

    Address at(Program p, int off) {
        return ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(0xf000, off);
    }

    String wsEvidence(Program p, Address a) {
        for (Bookmark b : p.getBookmarkManager().getBookmarks(a))
            if (b.getCategory().equals("WSEvidence")) return b.getComment();
        return null;
    }

    void fixture(File dir, String variant) throws Exception {
        Path file = dir.toPath().resolve(variant + ".ws");
        Files.write(file, rom(variant));
        GhidraProject project = GhidraProject.createProject(dir.getAbsolutePath(), "f3s-ct3-" + variant, true);
        try {
            Program p = project.importProgram(file.toFile(), WonderSwanLoader.class, currentProgram.getLanguage(),
                currentProgram.getCompilerSpec());
            int tx = p.startTransaction("analysis");
            try { analyzeAll(p); } finally { p.endTransaction(tx, true); }
            Listing l = p.getListing();
            if (variant.startsWith("f3s_")) {
                check(variant, l.getInstructionAt(at(p, SETTER)) != null && l.getInstructionAt(at(p, DISPATCH)) != null,
                    "setter and dispatcher decoded");
                Instruction h = l.getInstructionAt(at(p, HANDLER));
                if (!variant.equals("f3s_pos")) {
                    check(variant, h == null, "handler at F000:0200 not decoded: " + h);
                    return;
                }
                check(variant, h != null && h.toString().startsWith("MOV AX"), "handler at F000:0200 decoded: " + h);
                check(variant, p.getFunctionManager().getFunctionAt(at(p, HANDLER)) != null, "handler is a function");
                String why = wsEvidence(p, at(p, HANDLER));
                check(variant, why != null && why.startsWith("F3s setter"), "F3s evidence bookmark: " + why);
                check(variant, p.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR) == 0, "no ERROR bookmarks");
            } else {
                check(variant, l.getInstructionAt(at(p, CT3_DISP)) != null, "CT3 dispatcher decoded");
                int[] targets = { HANDLER, HANDLER2, HANDLER3 };
                if (!variant.equals("ct3_pos")) {
                    for (int off : targets)
                        check(variant, l.getInstructionAt(at(p, off)) == null, "handler at F000:" + Integer.toHexString(off) + " not decoded");
                    return;
                }
                for (int off : targets) {
                    Address a = at(p, off);
                    Instruction h = l.getInstructionAt(a);
                    check(variant, h != null && h.toString().startsWith("MOV AX"), "handler at " + a + " decoded: " + h);
                    check(variant, p.getFunctionManager().getFunctionAt(a) != null, "handler at " + a + " is a function");
                    String why = wsEvidence(p, a);
                    check(variant, why != null && why.startsWith("CT3 table"), "CT3 evidence bookmark at " + a + ": " + why);
                }
                check(variant, p.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR) == 0, "no ERROR bookmarks");
            }
        } finally {
            project.close();
        }
    }

    @Override
    public void run() throws Exception {
        File dir = Files.createTempDirectory("ws-f3s-ct3").toFile();
        String[] args = getScriptArgs();
        List<String> variants = args.length > 0 ? List.of(args)
            : List.of("f3s_pos", "f3s_clobber", "f3s_mismatch", "ct3_pos", "ct3_uninit");
        for (String v : variants) {
            try { fixture(dir, v); }
            catch (Exception e) { check(v, false, "fixture raised " + e); }
        }
        println("WSF3sCt3Fixtures: checks=" + checks + " failures=" + failures);
        if (failures != 0) throw new AssertionError("WSF3sCt3Fixtures failures=" + failures);
        println("WSF3sCt3Fixtures: PASS checks=" + checks);
    }
}
