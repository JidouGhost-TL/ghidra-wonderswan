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
 * Rule F6 (far code-pointer fields) on synthetic cartridges, through the real import and default auto-analysis.
 * The store routine (F000:0040) and the dispatcher (F000:0080) are reached only through CALLs behind a branch that
 * does not execute, so execution evidence observes neither the dispatch nor the handler at F000:0200; the handler
 * sits between erased bytes, so nothing but the stored pointer names it.
 *
 * retf:      MOV SI,[BX+2Eh]; MOV AX,F000h; MOV [BX+SI+30h],AX; MOV AX,0200h; MOV [BX+SI+32h],AX, dispatched by
 *            MOV AX,[BX+SI+30h]; PUSH AX; MOV AX,[BX+SI+32h]; PUSH AX; RETF (segment word first, as pushed):
 *            the handler is decoded and becomes a function with an F6 evidence bookmark.
 * callf:     offset to [BX+SI+20h], segment to [BX+SI+22h], dispatched by CALLF [BX+SI+20h]: same expectations.
 * clobber:   the retf store routine with INC SI between the two stores: no pair, the handler stays undecoded.
 * mismatch:  the retf stores, but the dispatcher reads [BX+DI+30h]/[BX+DI+32h]: another field, nothing decoded.
 * ramseg:    the retf pair with segment 1000h (RAM): rejected, nothing decoded at F000:0200.
 * u1call:    retf, with the handler calling a subroutine at F000:0240 (decoded through the handler's flow, no function
 *            yet), and unreferenced code after the store routine's RET (F000:0056: PUSH AX; PUSH CX; CALL 0240h;
 *            POP CX; POP AX; RET): rule U1 accepts it, because a call to an instruction kept code already calls is a
 *            call to a subroutine entry (U1a), whether or not its function exists yet.
 * u1data:    u1call, but four data bytes at F000:0056 (the code moves to F000:005A) that the handler reads as a far
 *            pointer (LES SI,CS:[0056h]; the reader is itself phase-2 code, so no analysis has typed them yet): they
 *            are data (U1c), so U1 leaves them undecoded and starts its candidate at F000:005A, after them.
 *
 * Usage: headless post script on any program (it imports its own cartridges into a temporary project).
 */
public class WSFieldPointerFixtures extends GhidraScript {
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

    static final int STORE = 0x40, DISPATCH = 0x80, HANDLER = 0x200;

    /** 128 KiB cartridge: code at F000:0000 (file 0x10000), everything else erased (FF). */
    static byte[] rom(String variant) {
        byte[] rom = new byte[0x20000];
        Arrays.fill(rom, (byte) 0xff);
        // CLI; XOR AX,AX; MOV DS,AX; MOV AL,[0100h]; CMP AL,5Ah; JNZ spin; CALL 0040h; CALL 0080h; spin: JMP spin
        put(rom, 0x00, "fa31c08ed8a000013c5a7506e83100e86e00ebfe");
        String seg = variant.equals("ramseg") ? "0010" : "00f0";
        if (variant.equals("callf")) {
            // MOV BX,0400h; MOV SI,[BX+2Eh]; MOV AX,0200h; MOV [BX+SI+20h],AX; MOV AX,F000h; MOV [BX+SI+22h],AX; RET
            put(rom, STORE, "bb00048bb72e00b80002898020" + "00" + "b8" + seg + "898022" + "00" + "c3");
            // MOV BX,0400h; MOV SI,[BX+2Eh]; CALLF [BX+SI+20h]; RET
            put(rom, DISPATCH, "bb00048bb72e00ff982000c3");
        } else {
            // MOV BX,0400h; MOV SI,[BX+2Eh]; MOV AX,seg; MOV [BX+SI+30h],AX; [INC SI;] MOV AX,0200h; MOV [BX+SI+32h],AX; RET
            put(rom, STORE, "bb00048bb72e00b8" + seg + "89803000" + (variant.equals("clobber") ? "46" : "")
                + "b8000289803200c3");
            // MOV BX,0400h; MOV SI,[BX+2Eh]; MOV AX,[BX+SI+30h]; PUSH AX; MOV AX,[BX+SI+32h]; PUSH AX; RETF
            // (mismatch: the same through BX+DI)
            put(rom, DISPATCH, variant.equals("mismatch") ? "bb00048bbf2e008b813000508b81320050cb"
                : "bb00048bb72e008b803000508b80320050cb");
        }
        if (variant.equals("u1call") || variant.equals("u1data")) {
            if (variant.equals("u1data")) put(rom, HANDLER, "2ec4365600b80100e83500cb");   // LES SI,CS:[0056h]; MOV AX,1; CALL 0240h; RETF
            else put(rom, HANDLER, "b80100e83a00cb");              // MOV AX,1; CALL 0240h; RETF
            put(rom, 0x240, "a30003c3");                           // MOV [0300h],AX; RET
            if (variant.equals("u1data")) put(rom, 0x56, "11223344" + "5051e8e1015958c3");   // data; then the same code at 005Ah
            else put(rom, 0x56, "5051e8e5015958c3");               // PUSH AX; PUSH CX; CALL 0240h; POP CX; POP AX; RET
        } else
            put(rom, HANDLER, "b80100a30003cb");                   // MOV AX,1; MOV [0300h],AX; RETF
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

    void fixture(File dir, String variant) throws Exception {
        Path file = dir.toPath().resolve(variant + ".ws");
        Files.write(file, rom(variant));
        GhidraProject project = GhidraProject.createProject(dir.getAbsolutePath(), "field-pointer-" + variant, true);
        try {
            Program p = project.importProgram(file.toFile(), WonderSwanLoader.class, currentProgram.getLanguage(),
                currentProgram.getCompilerSpec());
            int tx = p.startTransaction("analysis");
            try { analyzeAll(p); } finally { p.endTransaction(tx, true); }
            Listing l = p.getListing();
            Instruction last = l.getInstructionAt(at(p, variant.equals("callf") ? DISPATCH + 7 : DISPATCH + 17));
            check(variant, l.getInstructionAt(at(p, STORE)) != null && last != null
                && (variant.equals("callf") ? last.toString().startsWith("CALLF") : last.toString().equals("RETF")),
                "store routine and dispatcher decoded: " + last);
            Instruction h = l.getInstructionAt(at(p, HANDLER));
            boolean positive = variant.equals("retf") || variant.equals("callf") || variant.equals("u1call") || variant.equals("u1data");
            if (!positive) {
                check(variant, h == null, "handler at F000:0200 not decoded: " + h);
                return;
            }
            check(variant, h != null && h.toString().startsWith(variant.equals("u1data") ? "LES" : "MOV AX"), "handler at F000:0200 decoded: " + h);
            Function fn = p.getFunctionManager().getFunctionAt(at(p, HANDLER));
            check(variant, fn != null, "handler is a function: " + fn);
            String why = null;
            for (Bookmark b : p.getBookmarkManager().getBookmarks(at(p, HANDLER)))
                if (b.getCategory().equals("WSEvidence")) why = b.getComment();
            check(variant, why != null && why.startsWith("F6 field store"), "F6 evidence bookmark: " + why);
            check(variant, p.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR) == 0, "no ERROR bookmarks");
            if (variant.equals("u1call") || variant.equals("u1data")) {
                int start = variant.equals("u1data") ? 0x5a : 0x56;
                Instruction u = l.getInstructionAt(at(p, start));
                String u1 = null;
                for (Bookmark b : p.getBookmarkManager().getBookmarks(at(p, start)))
                    if (b.getCategory().equals("WSEvidence")) u1 = b.getComment();
                check(variant, u != null && u.toString().equals("PUSH AX") && l.getInstructionAt(at(p, start + 7)) != null,
                    "unreferenced code at " + at(p, start) + " decoded: " + u);
                check(variant, u1 != null && u1.startsWith("U1"), "U1 bookmark: " + u1);
            }
            if (variant.equals("u1data"))
                check(variant, l.getInstructionContaining(at(p, 0x56)) == null && l.getInstructionContaining(at(p, 0x59)) == null,
                    "far-pointer bytes F000:0056-0059 read as data stay undecoded: " + l.getInstructionContaining(at(p, 0x56)));
        } finally {
            project.close();
        }
    }

    @Override
    public void run() throws Exception {
        File dir = Files.createTempDirectory("ws-field-pointer").toFile();
        String[] args = getScriptArgs();
        List<String> variants = args.length > 0 ? List.of(args) : List.of("retf", "callf", "clobber", "mismatch", "ramseg", "u1call", "u1data");
        for (String v : variants) {
            try { fixture(dir, v); }
            catch (Exception e) { check(v, false, "fixture raised " + e); }
        }
        println("WSFieldPointerFixtures: checks=" + checks + " failures=" + failures);
        if (failures != 0) throw new AssertionError("WSFieldPointerFixtures failures=" + failures);
        println("WSFieldPointerFixtures: PASS checks=" + checks);
    }
}
