// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.*;

/** Indirect-target rules CT1a-d (call tables by addressing form) and IT1a-c (interrupt inline-table dispatch):
 *  synthetic programs run through the repair rules. Each fixture names the rule it exercises. */
public class WSCallTableFixtures extends GhidraScript {
    int checks, failures;
    final List<String> failed = new ArrayList<>();
    void check(boolean ok, String message) {
        checks++;
        if (!ok) { failures++; failed.add(message); printerr("FAIL: " + message); }
    }
    static void put(byte[] b, int off, String hex) { byte[] v = HexFormat.of().parseHex(hex); System.arraycopy(v, 0, b, off, v.length); }
    static Address at(Program p, int seg, int off) {
        return ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(seg, off);
    }
    static Address at(Program p, int off) { return at(p, 0x4000, off); }

    ProgramDB make(String name, byte[] main, byte[] other) throws Exception {
        ProgramDB p = new ProgramDB(name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        p.startTransaction(name);
        var file = p.getMemory().createFileBytes(name, 0, main.length, new ByteArrayInputStream(main), monitor);
        var b = p.getMemory().createInitializedBlock("fixture", at(p, 0), file, 0, main.length, false);
        b.setPermissions(true, false, true);
        p.getProgramContext().setValue(p.getRegister("csval"), at(p, 0), at(p, main.length - 1), BigInteger.valueOf(0x4000));
        p.getProgramContext().setValue(p.getRegister("hwundef"), at(p, 0), at(p, main.length - 1), BigInteger.ZERO);
        if (other != null) {
            var f2 = p.getMemory().createFileBytes(name + "-5000", 0, other.length, new ByteArrayInputStream(other), monitor);
            var b2 = p.getMemory().createInitializedBlock("fixture5000", at(p, 0x5000, 0), f2, 0, other.length, false);
            b2.setPermissions(true, false, true);
            p.getProgramContext().setValue(p.getRegister("hwundef"), at(p, 0x5000, 0), at(p, 0x5000, other.length - 1), BigInteger.ZERO);
        }
        return p;
    }
    static byte[] fill(int n) { byte[] b = new byte[n]; Arrays.fill(b, (byte) 0xff); return b; }

    void code(Program p, int off, boolean function) throws Exception {
        new DisassembleCommand(at(p, off), null, true).applyTo(p, monitor);
        if (function) new CreateFunctionCmd(at(p, off)).applyTo(p, monitor);
    }
    boolean insn(Program p, Address a) { return p.getListing().getInstructionAt(a) != null; }
    boolean ref(Program p, int from, Address to) {
        for (Reference r : p.getReferenceManager().getReferencesFrom(at(p, from)))
            if (r.getToAddress().equals(to) && r.getReferenceType().isComputed()) return true;
        return false;
    }
    /** Runs the repair rules; their emit lines go to a per-program report, echoed for the table/inline rules. */
    List<String> repair(Program p, WSEvidence ev) throws Exception {
        java.nio.file.Path report = java.nio.file.Files.createTempFile(p.getName(), ".jsonl");
        WSEvidenceAnalyzer.repairEvidence(p, ev, report.toString(), monitor);
        List<String> out = java.nio.file.Files.readAllLines(report);
        println("REPORT " + p.getName() + " lines=" + out.size());
        for (String l : out)
            if (l.contains("\"rule\":\"J1") || l.contains("\"rule\":\"CT1") || l.contains("\"rule\":\"J3"))
                println("EMIT " + p.getName() + " " + (l.length() > 400 ? l.substring(0, 400) : l));
        return out;
    }
    boolean bookmark(Program p, Address a, String prefix) {
        for (Bookmark b : p.getBookmarkManager().getBookmarks(a)) if (b.getCategory().startsWith(prefix)) return true;
        return false;
    }
    void done(ProgramDB p) { p.release(this); }

    /** CT1a: CALLF CS:[BX+0x100], index unbounded, table ends at a function entry (strong stop). */
    void farStrongStop() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "33db8a1e1000d1e3d1e32eff9f0001c3");      // site 4000:004a
        put(m, 0x100, "000200402002004040020040");               // three far slots, segment 4000
        put(m, 0x10c, "c3");                                     // function entry right after the table
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100cb");
        ProgramDB p = make("ct1a-far", m, null);
        try {
            code(p, 0x40, true); code(p, 0x10c, true);
            repair(p, new WSEvidence());
            for (int t : new int[] { 0x200, 0x220, 0x240 }) {
                check(insn(p, at(p, t)), "CT1a far slot target decoded " + Integer.toHexString(t));
                check(ref(p, 0x4a, at(p, t)), "CT1a computed call reference " + Integer.toHexString(t));
                check(p.getFunctionManager().getFunctionAt(at(p, t)) != null, "CT1a far target function " + Integer.toHexString(t));
            }
            check(p.getListing().getInstructionContaining(at(p, 0x100)) == null, "CT1a table bytes not code");
        } finally { done(p); }
    }

    /** CT1a: far slots in another linear segment decode with that segment as CS. */
    void farOtherSegment() throws Exception {
        byte[] m = fill(0x1000), o = fill(0x100);
        put(m, 0x40, "33db8a1e1000d1e3d1e32eff9f0001c3");
        put(m, 0x100, "1000005020000050");                       // 5000:0010, 5000:0020
        put(m, 0x108, "c3");
        put(o, 0x10, "e81d00cb"); put(o, 0x20, "b80200cb"); put(o, 0x30, "c3");   // 5000:0010 CALL 0x0030 (near, in 5000)
        ProgramDB p = make("ct1a-other", m, o);
        try {
            code(p, 0x40, true); code(p, 0x108, true);
            repair(p, new WSEvidence());
            Address t0 = at(p, 0x5000, 0x10), t1 = at(p, 0x5000, 0x20);
            check(insn(p, t0) && insn(p, t1), "CT1a other-segment targets decoded");
            var v = p.getProgramContext().getValue(p.getRegister("csval"), t0, false);
            check(v != null && v.intValue() == 0x5000, "CT1a target CS is the slot segment: " + v);
            check(insn(p, at(p, 0x5000, 0x30)), "CT1a near call inside the far target resolves in its own segment");
        } finally { done(p); }
    }

    /** CT1a: a mask bounds four slots; the third slot's RAM/SRAM segment ends the table (FAR_RAM). */
    void farRamStop() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e100083e303d1e3d1e32eff9f0001c3");   // site 4000:004b
        put(m, 0x100, "00020040200200400003001040020040");
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100cb");
        ProgramDB p = make("ct1a-ram", m, null);
        try {
            code(p, 0x40, true);
            repair(p, new WSEvidence());
            check(insn(p, at(p, 0x200)) && insn(p, at(p, 0x220)), "CT1a slots before the RAM segment decoded");
            check(!insn(p, at(p, 0x240)), "CT1a slot after the RAM-segment stop not decoded");
        } finally { done(p); }
    }

    /** CT1b: MOV SI,tbl; MOV AX,CS:[BX+SI]; CALL AX (base in the second register). */
    void twoRegisterNear() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e3be00012e8b00ffd0c3");       // CALL AX at 4000:004c
        put(m, 0x100, "000220024002");
        put(m, 0x106, "c3");
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make("ct1b-near", m, null);
        try {
            code(p, 0x40, true); code(p, 0x106, true);
            repair(p, new WSEvidence());
            for (int t : new int[] { 0x200, 0x220, 0x240 })
                check(insn(p, at(p, t)) && ref(p, 0x4c, at(p, t)), "CT1b two-register table target " + Integer.toHexString(t));
        } finally { done(p); }
    }

    /** CT1a+CT1b: CALLF CS:[BX+SI] with SI constant. */
    void twoRegisterFar() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "be00018b1e1000d1e3d1e32eff18c3");       // CALLF at 4000:004b
        put(m, 0x100, "000200402002004040020040");
        put(m, 0x10c, "c3");
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100cb");
        ProgramDB p = make("ct1b-far", m, null);
        try {
            code(p, 0x40, true); code(p, 0x10c, true);
            repair(p, new WSEvidence());
            for (int t : new int[] { 0x200, 0x220, 0x240 })
                check(insn(p, at(p, t)) && ref(p, 0x4b, at(p, t)), "CT1a+b far two-register target " + Integer.toHexString(t));
        } finally { done(p); }
    }

    /** CT1b control: neither register constant -> no table (both builds). */
    void twoRegisterNoConstant() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e10008b3612002e8b00ffd0c3");          // MOV SI,[0x12]: not a constant
        put(m, 0x100, "000220024002");
        put(m, 0x106, "c3");
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make("ct1b-none", m, null);
        try {
            code(p, 0x40, true); code(p, 0x106, true);
            repair(p, new WSEvidence());
            check(!insn(p, at(p, 0x200)), "CT1b control: no constant register, no table");
        } finally { done(p); }
    }

    /** CT1c: unbounded index, weak stop (defined data); observed slots 0 and 3 prove slots 0..3, slots 4-5 stay H2. */
    void observedSpan() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e32eff970001c3");               // CALL CS:[BX+0x100] at 4000:0046
        put(m, 0x100, "00022002400260028002a0020003");          // 6 targets, then a slot into defined data (0x300)
        for (int t : new int[] { 0x200, 0x220, 0x240, 0x260, 0x280, 0x2a0 }) put(m, t, "b80100c3");
        ProgramDB p = make("ct1c-span", m, null);
        try {
            code(p, 0x40, true);
            p.getListing().createData(at(p, 0x300), ByteDataType.dataType);
            WSEvidence ev = new WSEvidence();
            ev.edges.add(new WSEvidence.Edge(0x40046, 0x40200, 0x4000, "call", 1));
            ev.edges.add(new WSEvidence.Edge(0x40046, 0x40260, 0x4000, "call", 1));
            repair(p, ev);
            for (int t : new int[] { 0x200, 0x220, 0x240, 0x260 })
                check(insn(p, at(p, t)) && ref(p, 0x46, at(p, t)), "CT1c span slot target decoded " + Integer.toHexString(t));
            for (int t : new int[] { 0x280, 0x2a0 }) check(!insn(p, at(p, t)), "CT1c beyond span not decoded " + Integer.toHexString(t));
            check(bookmark(p, at(p, 0x108), "WSHypothesis:CT1c") && bookmark(p, at(p, 0x10a), "WSHypothesis:CT1c"), "CT1c H2 tags on slots 4 and 5");
        } finally { done(p); }
    }

    /** CT1c control: no observed target -> unresolved (both builds). */
    void observedSpanNone() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e32eff970001c3");
        put(m, 0x100, "00022002400260028002a0020003");
        for (int t : new int[] { 0x200, 0x220, 0x240, 0x260, 0x280, 0x2a0 }) put(m, t, "b80100c3");
        ProgramDB p = make("ct1c-none", m, null);
        try {
            code(p, 0x40, true);
            p.getListing().createData(at(p, 0x300), ByteDataType.dataType);
            repair(p, new WSEvidence());
            check(!insn(p, at(p, 0x200)), "CT1c control: no observed target, no table");
        } finally { done(p); }
    }

    /** CT1d: a 0xFFFF slot is skipped like an empty slot; the table runs on to its function-entry stop. */
    void segmentEndSlot() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e32eff970001c3");
        put(m, 0x100, "0002ffff4002");
        put(m, 0x106, "c3");
        for (int t : new int[] { 0x200, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make("ct1d-ffff", m, null);
        try {
            code(p, 0x40, true); code(p, 0x106, true);
            repair(p, new WSEvidence());
            check(insn(p, at(p, 0x200)) && insn(p, at(p, 0x240)), "CT1d targets around the FFFF slot decoded");
        } finally { done(p); }
    }

    /** CT1e: unused slots aim at the table's end (undecodable fill there); the table ends exactly at that address. */
    void placeholderEnd(boolean matching) throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e32eff970001c3");               // CALL CS:[BX+0x100] at 4000:0046, unbounded index
        put(m, 0x100, matching ? "000206014002" : "00020a014002");   // slot 1 -> 0x106 (the table end) or 0x10a (not the end)
        if (!matching) { put(m, 0x106, "c3"); }                 // control: a function entry ends the table at 0x106
        for (int t : new int[] { 0x200, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make(matching ? "ct1e-placeholder" : "ct1e-control", m, null);
        try {
            code(p, 0x40, true);
            if (!matching) code(p, 0x106, true);
            repair(p, new WSEvidence());
            if (matching) {
                check(insn(p, at(p, 0x200)) && insn(p, at(p, 0x240)), "CT1e targets around the placeholder decoded");
                check(!insn(p, at(p, 0x106)), "CT1e placeholder target not decoded");
            } else check(!insn(p, at(p, 0x240)), "CT1e control: placeholder not aimed at the table end, table not proven");
        } finally { done(p); }
    }

    /** CT1g: 8-byte records of two far pointers; site A reads field +0, site B (ADD BX,4) field +4. */
    void recordStride() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "32ff8a1e1000c1e3032eff9f0001c3");         // site A at 4000:0049
        put(m, 0x60, "32ff8a1e1000c1e30383c3042eff9f0001c3");   // site B at 4000:006c
        put(m, 0x100, "000200400003004020020040200300404002004040030040");
        put(m, 0x118, "c3"); put(m, 0x11c, "c3");
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100cb");
        for (int t : new int[] { 0x300, 0x320, 0x340 }) put(m, t, "b80200cb");
        ProgramDB p = make("ct1g-stride", m, null);
        try {
            code(p, 0x40, true); code(p, 0x60, true); code(p, 0x118, true); code(p, 0x11c, true);
            repair(p, new WSEvidence());
            boolean aOk = true, bOk = true, mixed = false;
            for (int t : new int[] { 0x200, 0x220, 0x240 }) { aOk &= ref(p, 0x49, at(p, t)); mixed |= ref(p, 0x6c, at(p, t)); }
            for (int t : new int[] { 0x300, 0x320, 0x340 }) { bOk &= ref(p, 0x6c, at(p, t)); mixed |= ref(p, 0x49, at(p, t)); }
            check(aOk && bOk, "CT1g each site recovers its own field");
            check(!mixed, "CT1g no site holds the other field's targets");
        } finally { done(p); }
    }

    @SuppressWarnings("unchecked")
    void evidence(Program p, WSEvidence ev) throws Exception {
        var f = WSEvidenceAnalyzer.class.getDeclaredField("EVIDENCE");
        f.setAccessible(true);
        ((Map<Program, WSEvidence>) f.get(null)).put(p, ev);
    }

    /** F2v: a far pair stored at a low DS offset under a defaulted DS is no interrupt vector; under DS proven 0000
     *  by the chain, into a vector the program uses (INT 0x40), it is. Runs the full repair analyzer (F1-F4). */
    void vectorProof(boolean proven) throws Exception {
        byte[] m = fill(0x1000);
        if (proven) put(m, 0x40, "33c08ed8c70600012003c70602010040c3");   // XOR AX,AX; MOV DS,AX; [0x100]=4000:0320
        else put(m, 0x40, "c70644010003c70646010040c3");                  // [0x144]=4000:0300 with DS from the context
        put(m, 0x80, "cd40c3");
        put(m, proven ? 0x320 : 0x300, "b80100cf");
        ProgramDB p = make(proven ? "f2v-proven" : "f2v-default-ds", m, null);
        try {
            p.getProgramContext().setValue(p.getRegister("DS"), at(p, 0), at(p, 0xfff), BigInteger.ZERO);
            code(p, 0x40, true); code(p, 0x80, true);
            evidence(p, new WSEvidence());
            new WSEvidenceRepairAnalyzer().added(p, p.getMemory(), monitor, new ghidra.app.util.importer.MessageLog());
            if (proven) check(insn(p, at(p, 0x320)), "F2v vector stored under DS proven 0000 (used vector 0x40) seeds its handler");
            else check(!insn(p, at(p, 0x300)), "F2v pair at DS:0144 under a defaulted DS is not an interrupt handler");
        } finally { done(p); }
    }

    /** F2v: a hardware vector (interrupt base 0x20 written to port 0xB0) stored under a context DS that the execution
     *  evidence observed as 0000 at both stores seeds its handler; without that observation it does not. */
    void vectorObservedDs(boolean observed) throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "b020e6b0c70680000003c70682000040c3");    // MOV AL,0x20; OUT 0xB0,AL; [0x80]=4000:0300 (IVT[20])
        put(m, 0x300, "b80100cf");
        ProgramDB p = make(observed ? "f2v-observed" : "f2v-unobserved", m, null);
        try {
            p.getProgramContext().setValue(p.getRegister("DS"), at(p, 0), at(p, 0xfff), BigInteger.ZERO);
            code(p, 0x40, true);
            WSEvidence ev = new WSEvidence();
            if (observed) for (int a : new int[] { 0x44, 0x4a }) ev.ds.put(0x40000L + a, new HashSet<>(Set.of(0)));
            evidence(p, ev);
            new WSEvidenceRepairAnalyzer().added(p, p.getMemory(), monitor, new ghidra.app.util.importer.MessageLog());
            if (observed) check(insn(p, at(p, 0x300)), "F2v hardware vector under an observed DS 0000 seeds its handler");
            else check(!insn(p, at(p, 0x300)), "F2v hardware vector under an unobserved, defaulted DS is not seeded");
        } finally { done(p); }
    }

    /** CT1f: an unbounded 70-slot table (all slots plausible) that ends at a function entry, or (control) at fill. */
    void longTable(boolean strongEnd) throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e32eff970001c3");               // CALL CS:[BX+0x100] at 4000:0046, unbounded index
        StringBuilder t = new StringBuilder();
        for (int k = 0; k < 70; k++) { int a = 0x300 + 4 * k; t.append(String.format("%02x%02x", a & 0xff, a >> 8)); put(m, a, "b80100c3".substring(0, 2) + "00c3"); }
        put(m, 0x100, t.toString());
        if (strongEnd) put(m, 0x100 + 140, "c3");
        ProgramDB p = make(strongEnd ? "ct1f-long" : "ct1f-control", m, null);
        try {
            code(p, 0x40, true);
            if (strongEnd) code(p, 0x100 + 140, true);
            repair(p, new WSEvidence());
            if (strongEnd) check(insn(p, at(p, 0x300)) && insn(p, at(p, 0x300 + 4 * 69)) && ref(p, 0x46, at(p, 0x300 + 4 * 69)),
                "CT1f 70-slot table ended by a function entry fully recovered");
            else check(!insn(p, at(p, 0x300 + 4 * 69)), "CT1f control: no strong end, table not proven");
        } finally { done(p); }
    }

    /** IT1 program: INT n site at 0x40, two inline words, handler at 0x200 with an F2 IVT[n] bookmark. */
    ProgramDB interrupt(String name, int vector, String handler, String words, boolean csBase, boolean dataRef) throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, String.format("cd%02x", vector)); put(m, 0x42, words);
        put(m, 0x10, "b80100c3"); put(m, 0x20, "b80200c3");
        put(m, 0x80, csBase ? "2e8b874600c3" : "90c3");          // CS:[BX+0x46] names the slot after the words
        put(m, 0x200, handler);
        ProgramDB p = make(name, m, null);
        code(p, 0x200, true); code(p, 0x80, true);
        new DisassembleCommand(at(p, 0x40), new AddressSet(at(p, 0x40), at(p, 0x41)), false).applyTo(p, monitor);
        p.getFunctionManager().createFunction(null, at(p, 0x40), new AddressSet(at(p, 0x40), at(p, 0x41)), SourceType.DEFAULT);
        p.getBookmarkManager().setBookmark(at(p, 0x200), BookmarkType.ANALYSIS, "WSCodePointer",
            String.format("F2 store IVT[%02x] from %s", vector, at(p, 0x20)));
        if (dataRef) p.getReferenceManager().addMemoryReference(at(p, 0x80), at(p, 0x46), RefType.READ, SourceType.ANALYSIS, 0);
        return p;
    }
    static final String GENERAL = "53558bec065732e403c0c47e0403f8268b058946045f075d5bcf";   // PUSH BX; PUSH BP; MOV BP,SP; ... LES DI,[BP+4]
    static final String ES_SHAPE = "5589e50653b400d1e0c45e0201c3268b078946025b075dcf";
    static final String WRITES_CS = "53558bec065732e403c0c47e0403f8268b058946065f075d5bcf";   // writes [BP+6] (stacked CS)

    void interruptGeneral() throws Exception {
        ProgramDB p = interrupt("it1a-int41", 0x41, GENERAL, "10002000", true, false);
        try {
            repair(p, new WSEvidence());
            check(WSInlineTables.modeled(p, at(p, 0x40)), "IT1a INT 0x41 general handler modeled");
            check(insn(p, at(p, 0x10)) && insn(p, at(p, 0x20)), "IT1a/b both proven cases decoded");
            check(p.getListing().getDefinedDataContaining(at(p, 0x42)) != null && p.getListing().getDefinedDataContaining(at(p, 0x44)) != null,
                "IT1 table words are data");
            check(p.getListing().getDefinedDataContaining(at(p, 0x46)) == null, "IT1b table ends before the CS operand base");
        } finally { done(p); }
    }
    void interruptDataRefEnd() throws Exception {
        ProgramDB p = interrupt("it1b-int40", 0x40, ES_SHAPE, "10002000", false, true);
        try {
            repair(p, new WSEvidence());
            check(WSInlineTables.modeled(p, at(p, 0x40)), "IT1b INT 0x40 table ended by a data reference");
            check(insn(p, at(p, 0x10)) && insn(p, at(p, 0x20)), "IT1b cases decoded");
        } finally { done(p); }
    }
    void interruptNoEnd() throws Exception {
        ProgramDB p = interrupt("it1b-none", 0x41, GENERAL, "10002000", false, false);
        try {
            repair(p, new WSEvidence());
            check(!WSInlineTables.modeled(p, at(p, 0x40)), "IT1b control: no proven end, not modeled");
            check(!insn(p, at(p, 0x10)) && !insn(p, at(p, 0x20)), "IT1b control: unproven cases not decoded");
            check(bookmark(p, at(p, 0x40), "WSHypothesis:IT1"), "IT1b H2 hypothesis tag on the site");
        } finally { done(p); }
    }
    void interruptWritesCs() throws Exception {
        ProgramDB p = interrupt("it1a-cs", 0x41, WRITES_CS, "10002000", true, false);
        try {
            repair(p, new WSEvidence());
            check(!WSInlineTables.modeled(p, at(p, 0x40)), "IT1a control: handler writing the stacked CS is not an inline dispatcher");
        } finally { done(p); }
    }
    /** IT1b: speculative fall-through decoded from the INT straddles the end of the proven words (0x44-0x46). */
    void interruptStraddle() throws Exception {
        ProgramDB p = interrupt("it1b-straddle", 0x41, GENERAL, "10008000", true, false);
        try {
            new DisassembleCommand(at(p, 0x42), null, true).applyTo(p, monitor);
            check(p.getListing().getInstructionContaining(at(p, 0x46)) != null, "IT1b straddle setup: fall-through decode covers 0x46");
            repair(p, new WSEvidence());
            check(WSInlineTables.modeled(p, at(p, 0x40)), "IT1b straddling speculative instruction superseded, site modeled");
            check(p.getListing().getInstructionContaining(at(p, 0x46)) == null, "IT1b bytes after the words left undefined");
            check(bookmark(p, at(p, 0x44), "WSHypothesis:IT1-superseded"), "IT1b superseded instruction recorded");
        } finally { done(p); }
    }
    /** IT1c: case 1 of the first dispatch holds a second inline dispatch, only reachable through it. */
    void interruptNested() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "cd41"); put(m, 0x42, "10006000");
        put(m, 0x60, "b001cd41"); put(m, 0x64, "20003000");
        put(m, 0x10, "b80100c3"); put(m, 0x20, "b80200c3"); put(m, 0x30, "b80300c3");
        put(m, 0x80, "2e8b8746002e8b876800c3");
        put(m, 0x200, GENERAL);
        ProgramDB p = make("it1c-nested", m, null);
        try {
            code(p, 0x200, true); code(p, 0x80, true);
            new DisassembleCommand(at(p, 0x40), new AddressSet(at(p, 0x40), at(p, 0x41)), false).applyTo(p, monitor);
            p.getFunctionManager().createFunction(null, at(p, 0x40), new AddressSet(at(p, 0x40), at(p, 0x41)), SourceType.DEFAULT);
            p.getBookmarkManager().setBookmark(at(p, 0x200), BookmarkType.ANALYSIS, "WSCodePointer", "F2 store IVT[41] from " + at(p, 0x20));
            repair(p, new WSEvidence());
            check(WSInlineTables.modeled(p, at(p, 0x40)), "IT1c outer dispatch modeled");
            check(WSInlineTables.modeled(p, at(p, 0x62)), "IT1c nested dispatch (reached only through case 1) modeled");
            check(insn(p, at(p, 0x30)), "IT1c nested case 1 decoded");
        } finally { done(p); }
    }

    /** J1-ES/DS + commuted J1i: MOV DI,0x100; ADD DI,AX; PUSH AX; MOV AX,0x4000; MOV ES,AX; POP AX; CALL ES:[DI]. */
    void esDirectCommuted() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "acb400d1e0bf000103f850b800408ec05826ff15c3");   // CALL word ptr ES:[DI] at 4000:0051
        put(m, 0x100, "060100022002");                                  // 3 slots ending at OWN_TARGET 0x106
        for (int t : new int[] { 0x106, 0x200, 0x220 }) put(m, t, "b80100c3");
        ProgramDB p = make("j1-es-commuted", m, null);
        try {
            code(p, 0x40, true);
            repair(p, new WSEvidence());
            for (int t : new int[] { 0x106, 0x200, 0x220 })
                check(insn(p, at(p, t)) && ref(p, 0x51, at(p, t)), "J1-ES commuted target " + Integer.toHexString(t));
            check(p.getListing().getInstructionContaining(at(p, 0x100)) == null, "J1-ES table bytes not code");
        } finally { done(p); }
    }

    /** J1-ES/DS linear-alias segment: ES=0x4100 reads table at 4100:0100 == 4000:1100; near targets stay in CS=4000. */
    void esLinearAlias() throws Exception {
        byte[] m = fill(0x2000);
        put(m, 0x40, "a01000b400d1e00500018bf8b800418ec0268b05ffd0c3"); // CALL AX at 4000:0054
        put(m, 0x1100, "000220024002");                                 // 4100:0100 == 4000:1100
        put(m, 0x1106, "c3");                                           // function entry right after table
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make("j1-es-alias", m, null);
        try {
            code(p, 0x40, true); code(p, 0x1106, true);
            repair(p, new WSEvidence());
            for (int t : new int[] { 0x200, 0x220, 0x240 })
                check(insn(p, at(p, t)) && ref(p, 0x54, at(p, t)), "J1-ES linear-alias target in CS " + Integer.toHexString(t));
        } finally { done(p); }
    }

    /** J1-ES/DS with DS=const_rom_seg: MOV AX,0x4000; MOV DS,AX; CALL word ptr DS:[BX+0x100]. */
    void dsConstRom() throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "8b1e1000d1e3b800408ed83eff970001c3");            // CALL word ptr DS:[BX+0x100] at 4000:004b
        put(m, 0x100, "060100022002");
        for (int t : new int[] { 0x106, 0x200, 0x220 }) put(m, t, "b80100c3");
        ProgramDB p = make("j1-ds-const", m, null);
        try {
            code(p, 0x40, true);
            repair(p, new WSEvidence());
            for (int t : new int[] { 0x106, 0x200, 0x220 })
                check(insn(p, at(p, t)) && ref(p, 0x4b, at(p, t)), "J1-DS const-ROM target " + Integer.toHexString(t));
        } finally { done(p); }
    }

    /** J1-ES/DS negative controls: WRAM segment (0x0000), clobbered ES, or non-constant ES -> not recovered. */
    void esControl(String variant) throws Exception {
        byte[] m = fill(0x1000);
        if (variant.equals("wram"))
            put(m, 0x40, "acb400d1e0bf000103f8b800008ec026ff15c3");     // ES = 0x0000 (WRAM)
        else if (variant.equals("clobbered"))
            put(m, 0x40, "acb400d1e0bf000103f8b800408ec08ec326ff15c3"); // ES = 0x4000 then MOV ES,BX
        else
            put(m, 0x40, "acb400d1e0bf000103f88ec326ff15c3");           // MOV ES,BX (non-constant)
        put(m, 0x100, "060100022002");
        for (int t : new int[] { 0x106, 0x200, 0x220 }) put(m, t, "b80100c3");
        ProgramDB p = make("j1-es-ctrl-" + variant, m, null);
        try {
            code(p, 0x40, true);
            repair(p, new WSEvidence());
            check(!insn(p, at(p, 0x200)), "J1-ES control (" + variant + "): must not recover table");
        } finally { done(p); }
    }

    /** J1j+ OWN_CALL_TARGET cycle-breaker: unbounded CS: table followed by helper at 0x106 called from slot 2
     *  (near CALL or CALLF). Control puts unreachable CALLF bytes after RET in slot 2 and must stay unresolved. */
    void ownCallTarget(String variant) throws Exception {
        byte[] m = fill(0x1000);
        put(m, 0x40, "add1e08bf82eff950001c3");                         // CALL word ptr CS:[DI+0x100] at 4000:0045
        put(m, 0x100, "000220024002");                                  // 3 slots
        put(m, 0x106, "558becc3");                                      // helper function right after table (not pre-decoded)
        put(m, 0x200, "b80100c3");
        put(m, 0x220, "b80200c3");
        if (variant.equals("near"))
            put(m, 0x240, "e8c3fec3");                                  // CALL 0x0106; RET
        else if (variant.equals("far"))
            put(m, 0x240, "9a06010040c3");                              // CALLF 4000:0106; RET
        else
            put(m, 0x240, "b80300c39a06010040");                        // MOV AX,3; RET; <unreachable data bytes 9a 06 01 00 40>
        ProgramDB p = make("j1jp-" + variant, m, null);
        try {
            code(p, 0x40, true);
            repair(p, new WSEvidence());
            if (variant.equals("control")) {
                check(!insn(p, at(p, 0x200)), "J1j+ control: unreachable data bytes must not trigger OWN_CALL_TARGET");
            } else {
                for (int t : new int[] { 0x200, 0x220, 0x240 })
                    check(insn(p, at(p, t)) && ref(p, 0x45, at(p, t)), "J1j+ (" + variant + ") slot target " + Integer.toHexString(t));
                check(insn(p, at(p, 0x106)), "J1j+ (" + variant + ") helper at table end decoded via slot call");
                check(!ref(p, 0x45, at(p, 0x8b55)), "J1j+ (" + variant + ") did not scan past table end");
            }
        } finally { done(p); }
    }

    /** CT1a-ES/DS: CALLF/JMPF via constant-ROM ES/DS segment, plus negative controls (WRAM / clobbered ES). */
    void farEsDs(String variant) throws Exception {
        byte[] m = fill(0x1000), o = fill(0x100);
        if (variant.equals("es-callf"))
            // MOV CX,0x4000; MOV ES,CX; MOV AL,[0x10]; CBW; MOV SI,AX; SHL SI,1; SHL SI,1; CALLF ES:[SI+0x100]; RET
            put(m, 0x40, "b900408ec1a01000988bf0d1e6d1e626ff9c0001c3");      // site at 4000:004f
        else if (variant.equals("ds-jmpf"))
            // MOV AX,0x4000; MOV DS,AX; MOV BL,[0x10]; XOR BH,BH; SHL BX,1; SHL BX,1; JMPF DS:[BX+0x100]
            put(m, 0x40, "b800408ed88a1e100032ffd1e3d1e33effaf0001");        // site at 4000:004f
        else if (variant.equals("ctrl-wram"))
            // MOV CX,0x0000; MOV ES,CX; SHL SI,1; SHL SI,1; CALLF ES:[SI+0x100]; RET
            put(m, 0x40, "b900008ec1d1e6d1e626ff9c0001c3");
        else
            // MOV CX,0x4000; MOV ES,CX; MOV ES,BX; SHL SI,1; SHL SI,1; CALLF ES:[SI+0x100]; RET
            put(m, 0x40, "b900408ec18ec3d1e6d1e626ff9c0001c3");
        put(m, 0x100, "1000005020000050");                                   // 5000:0010, 5000:0020
        put(m, 0x108, "c3");                                                 // strong stop (function entry)
        put(o, 0x10, "b80100cb"); put(o, 0x20, "b80200cb");
        ProgramDB p = make("ct1a-esds-" + variant, m, o);
        try {
            code(p, 0x40, true); code(p, 0x108, true);
            repair(p, new WSEvidence());
            Address t0 = at(p, 0x5000, 0x10), t1 = at(p, 0x5000, 0x20);
            if (variant.startsWith("ctrl-")) {
                check(!insn(p, t0), "CT1a-ES/DS control (" + variant + "): must not recover table");
            } else {
                check(insn(p, t0) && insn(p, t1), "CT1a-ES/DS (" + variant + ") targets decoded");
                check(ref(p, 0x4f, t0) && ref(p, 0x4f, t1), "CT1a-ES/DS (" + variant + ") computed refs");
            }
        } finally { done(p); }
    }

    /** J1-STACKSAVE: MOV AH,0; PUSH AX; CALL helper; POP AX; JC skip; SHL AX,1; MOV BX,AX; CALL CS:[BX+0x100]. */
    void stackSave(boolean balanced) throws Exception {
        byte[] m = fill(0x1000);
        if (balanced)
            // MOV AL,[0x10]; MOV AH,0; PUSH AX; CALL 0x0080; POP AX; JC +0x8; SHL AX,1; MOV BX,AX; CALL CS:[BX+0x100]; RET
            put(m, 0x40, "a01000b40050e83700587208d1e08bd82eff970001c3");    // site at 4000:0050
        else
            // Unbalanced: PUSH AX; PUSH BX; CALL 0x0080; POP AX; ...
            put(m, 0x40, "a01000b4005053e83600587208d1e08bd82eff970001c3");  // site at 4000:0051
        put(m, 0x80, "f8c3");                                                // CLC; RET
        put(m, 0x100, "000220024002");                                       // 3 near slots
        put(m, 0x106, "c3");                                                 // strong stop
        for (int t : new int[] { 0x200, 0x220, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make(balanced ? "j1-stacksave" : "j1-stacksave-ctrl", m, null);
        try {
            code(p, 0x40, true); code(p, 0x80, true); code(p, 0x106, true);
            List<String> lines = repair(p, new WSEvidence());
            if (balanced) {
                for (int t : new int[] { 0x200, 0x220, 0x240 })
                    check(insn(p, at(p, t)) && ref(p, 0x50, at(p, t)), "J1-STACKSAVE target " + Integer.toHexString(t));
            } else {
                boolean claimedStackSave = lines.stream().anyMatch(l -> l.contains("J1-STACKSAVE") || l.contains("byte index"));
                check(!claimedStackSave, "J1-STACKSAVE control: unbalanced stack must not claim J1-STACKSAVE or byte index");
            }
        } finally { done(p); }
    }

    /** J1-NULLGUARD: MOV AX,CS:[BX+0x100]; OR/TEST/CMP AX,0; JE skip; CALL AX (with 0000 empty slot). */
    void nullGuard(String variant) throws Exception {
        byte[] m = fill(0x1000);
        int siteOff;
        if (variant.equals("or")) {
            // MOV BL,[0x10]; XOR BH,BH; SHL BX,1; MOV AX,CS:[BX+0x100]; OR AX,AX; JE +2; CALL AX; RET
            put(m, 0x40, "8a1e100032ffd1e32e8b8700010bc07402ffd0c3");
            siteOff = 0x51;
        } else if (variant.equals("test")) {
            put(m, 0x40, "8a1e100032ffd1e32e8b87000185c07402ffd0c3");
            siteOff = 0x51;
        } else {
            // Negative control: OR AX,1 modifies AX before CALL AX -> must not recover
            put(m, 0x40, "8a1e100032ffd1e32e8b87000183c8017402ffd0c3");
            siteOff = 0x52;
        }
        put(m, 0x100, "000200004002");                                       // slot 1 is 0000 (empty)
        put(m, 0x106, "c3");                                                 // strong stop
        for (int t : new int[] { 0x200, 0x240 }) put(m, t, "b80100c3");
        ProgramDB p = make("j1-nullguard-" + variant, m, null);
        try {
            code(p, 0x40, true); code(p, 0x106, true);
            repair(p, new WSEvidence());
            if (variant.equals("ctrl-or-imm")) {
                check(!insn(p, at(p, 0x200)), "J1-NULLGUARD control: OR AX,1 must not recover table");
            } else {
                for (int t : new int[] { 0x200, 0x240 })
                    check(insn(p, at(p, t)) && ref(p, siteOff, at(p, t)), "J1-NULLGUARD (" + variant + ") target " + Integer.toHexString(t));
            }
        } finally { done(p); }
    }

    @Override public void run() throws Exception {
        String only = getScriptArgs().length > 0 ? getScriptArgs()[0] : "";
        Map<String, ThrowingRunnable> all = new LinkedHashMap<>();
        all.put("CT1a-far-strong-stop", this::farStrongStop);
        all.put("CT1a-far-other-segment", this::farOtherSegment);
        all.put("CT1a-far-ram-stop", this::farRamStop);
        all.put("CT1b-two-register-near", this::twoRegisterNear);
        all.put("CT1b-two-register-far", this::twoRegisterFar);
        all.put("CT1b-control-no-constant", this::twoRegisterNoConstant);
        all.put("CT1c-observed-span", this::observedSpan);
        all.put("CT1c-control-no-observed", this::observedSpanNone);
        all.put("CT1d-ffff-slot", this::segmentEndSlot);
        all.put("CT1e-placeholder-end", () -> placeholderEnd(true));
        all.put("CT1e-control-not-end", () -> placeholderEnd(false));
        all.put("CT1f-long-table", () -> longTable(true));
        all.put("CT1f-control-no-strong-end", () -> longTable(false));
        all.put("CT1g-record-stride", this::recordStride);
        all.put("J1-ES-direct-commuted", this::esDirectCommuted);
        all.put("J1-ES-linear-alias", this::esLinearAlias);
        all.put("J1-DS-const-rom", this::dsConstRom);
        all.put("J1-ES-control-wram", () -> esControl("wram"));
        all.put("J1-ES-control-clobbered", () -> esControl("clobbered"));
        all.put("J1-ES-control-nonconst", () -> esControl("nonconst"));
        all.put("J1jp-own-call-target-near", () -> ownCallTarget("near"));
        all.put("J1jp-own-call-target-far", () -> ownCallTarget("far"));
        all.put("J1jp-control-data-bytes", () -> ownCallTarget("control"));
        all.put("CT1a-ES-callf", () -> farEsDs("es-callf"));
        all.put("CT1a-DS-jmpf", () -> farEsDs("ds-jmpf"));
        all.put("CT1a-ES-control-wram", () -> farEsDs("ctrl-wram"));
        all.put("CT1a-ES-control-clobbered", () -> farEsDs("ctrl-clobbered"));
        all.put("J1-STACKSAVE-balanced", () -> stackSave(true));
        all.put("J1-STACKSAVE-control-unbalanced", () -> stackSave(false));
        all.put("J1-NULLGUARD-or", () -> nullGuard("or"));
        all.put("J1-NULLGUARD-test", () -> nullGuard("test"));
        all.put("J1-NULLGUARD-control-or-imm", () -> nullGuard("ctrl-or-imm"));
        all.put("F2v-default-ds-not-vector", () -> vectorProof(false));
        all.put("F2v-control-proven-vector", () -> vectorProof(true));
        all.put("F2v-observed-ds-hardware-vector", () -> vectorObservedDs(true));
        all.put("F2v-unobserved-ds-hardware-vector", () -> vectorObservedDs(false));
        all.put("IT1a-general-handler", this::interruptGeneral);
        all.put("IT1b-data-reference-end", this::interruptDataRefEnd);
        all.put("IT1b-control-no-end", this::interruptNoEnd);
        all.put("IT1a-control-writes-cs", this::interruptWritesCs);
        all.put("IT1c-nested", this::interruptNested);
        all.put("IT1b-straddling-fallthrough", this::interruptStraddle);
        for (var e : all.entrySet()) {
            if (!only.isEmpty() && !e.getKey().equals(only)) continue;
            int before = failures;
            try { e.getValue().run(); }
            catch (Throwable t) { failures++; failed.add(e.getKey() + " threw " + t); printerr(e.getKey() + " threw " + t); }
            println("RESULT " + e.getKey() + " " + (failures == before ? "PASS" : "FAIL"));
        }
        println("WSCallTableFixtures: checks=" + checks + " failures=" + failures);
    }
    interface ThrowingRunnable { void run() throws Exception; }
}
