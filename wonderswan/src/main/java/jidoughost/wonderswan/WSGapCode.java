// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rules G1 / U1: code that nothing references, found structurally after a terminator, classified with evidence.
 *
 * Candidate: the first undefined byte after an instruction without fall-through (RET, RETF, IRET, JMP, JMPF), or the
 * first non-fill undefined byte after a run of >= 16 identical 00 / FF bytes in a block that holds code (code placed
 * at an aligned address after padding; such a candidate can only become U1).
 * The candidate is decoded by a trial flow walk (fall-through and direct branch targets, csval = the CS of the
 * terminator before it) that must stay entirely in undefined bytes of the same block, except that it may branch to
 * (join) the start of an existing instruction. It is rejected when any instruction fails to decode, overlaps
 * existing code or data, is implausible for game code (string I/O, BOUND, INTO, LOCK, escape/undefined
 * encodings, INT 3, writes to CS), takes a computed branch, or when a direct call targets anything but an existing
 * function entry or undefined bytes of the same block (an internal subroutine: walked too, and made a function); and when the walk does not end (every path must end in RET/RETF/IRET or join existing code)
 * within 1500 instructions.
 *
 * G1 DEAD_CODE: the terminator is an unconditional near JMP inside a function and the walk joins that function's
 *    code: a branch the compiler / author skipped. Disassembled, no function, bookmarked.
 * U1 UNREFERENCED_FUNCTION: otherwise, when the walk has at least two anchors (a call to an existing function, an
 *    absolute memory operand / I/O port that existing code also uses, or -- worth two -- at least two pushes whose
 *    stack depth returns to zero at every return on every path) and at least 3 instructions. Disassembled
 *    and made a function (tag WS_UNREFERENCED). Candidates with fewer anchors are reported (WEAK) and left as bytes.
 * Both repeat until no new candidate is accepted (an accepted function exposes the bytes after its own end).
 */
final class WSGapCode {
    static final Set<String> IMPLAUSIBLE = Set.of("INSB", "INSW", "OUTSB", "OUTSW", "BOUND", "INTO", "LOCK", "ESC", "WAIT",
        "ARPL", "SALC", "XLAT", "LAHF", "SAHF", "AAA", "AAS", "DAA", "DAS", "AAM", "AAD", "CMC", "INT3", "IRET.REP");

    final Program p;
    final Listing listing;
    final Memory mem;
    final ProgramContext ctx;
    final Register csval;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    final PseudoDisassembler pd;
    final Set<Address> tried = new HashSet<>();
    int dead, deadInsns, unref, unrefInsns, weak, rejected, passes;
    final Map<String, Integer> rejects = new TreeMap<>();

    WSGapCode(Program p, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor;
        listing = p.getListing(); mem = p.getMemory(); ctx = p.getProgramContext();
        csval = ctx.getRegister("csval");
        pd = new PseudoDisassembler(p);
    }

    String summary() {
        return String.format("G1/U1 gap code: passes %d, dead-code runs %d (%d instructions), unreferenced functions %d (%d instructions), weak candidates %d, rejected %d %s",
            passes, dead, deadInsns, unref, unrefInsns, weak, rejected, rejects);
    }

    int apply() throws Exception {
        int total = 0;
        for (int pass = 0; pass < 32; pass++) {
            int n = pass();
            passes = pass + 1;
            total += n;
            if (n == 0) break;
        }
        return total;
    }

    record Walk(AddressSet body, int insns, Set<Address> joins, int anchors, String fail, List<Address> calls, Set<Address> internal) { }

    int pass() throws Exception {
        // candidates: the first undefined byte after a terminator, and the first non-fill undefined byte after a fill
        // run (>= 16 bytes of 00 / FF) in a block that holds code -- e.g. code placed at an aligned address
        List<Object[]> cands = new ArrayList<>();   // {start, terminator or null}
        Set<MemoryBlock> codeBlocks = new LinkedHashSet<>();
        for (Instruction i : listing.getInstructions(true)) {
            monitor.checkCancelled();
            codeBlocks.add(mem.getBlock(i.getAddress()));
            if (i.hasFallthrough()) continue;
            Address n = i.getMaxAddress().next();
            if (n == null || tried.contains(n)) continue;
            MemoryBlock b = mem.getBlock(n);
            if (b == null || !b.isInitialized() || !b.isExecute() || !b.equals(mem.getBlock(i.getAddress()))) continue;
            if (WonderSwanLoader.isDataOverlay(b)) continue;
            CodeUnit cu = listing.getCodeUnitAt(n);
            if (!(cu instanceof Data d) || d.isDefined()) continue;
            cands.add(new Object[] { n, i });
        }
        for (MemoryBlock b : codeBlocks) {
            if (b == null || !b.isInitialized() || b.getSize() > 0x10000) continue;
            if (WonderSwanLoader.isDataOverlay(b)) continue;
            byte[] bytes = new byte[(int) b.getSize()];
            mem.getBytes(b.getStart(), bytes);
            for (int k = 0; k < bytes.length; ) {
                if (bytes[k] != 0 && bytes[k] != (byte) 0xFF) { k++; continue; }
                int j = k;
                while (j < bytes.length && bytes[j] == bytes[k]) j++;
                if (j - k >= 16 && j < bytes.length) {
                    Address n = b.getStart().add(j);
                    CodeUnit cu = listing.getCodeUnitAt(n);
                    if (!tried.contains(n) && cu instanceof Data d && !d.isDefined() && listing.getCodeUnitContaining(n.subtract(1)) instanceof Data)
                        cands.add(new Object[] { n, null });
                }
                k = j;
            }
        }
        int accepted = 0;
        for (Object[] cand : cands) {
            monitor.checkCancelled();
            Address s = (Address) cand[0];
            Instruction term = (Instruction) cand[1];
            if (!tried.add(s) || listing.getCodeUnitAt(s) instanceof Instruction) continue;
            if (allFill(s)) continue;
            Instruction before = term != null ? term : listing.getInstructionBefore(s);
            int cs = before != null && mem.getBlock(before.getAddress()).equals(mem.getBlock(s)) ? csOf(before.getAddress())
                : mem.getBlock(s).getStart() instanceof SegmentedAddress bs ? bs.getSegment() : csOf(s);
            Walk w = walk(s, cs);
            if (term == null) {
                if (w.fail() != null) { rejected++; rejects.merge(w.fail().replaceAll("@.*", ""), 1, Integer::sum);
                    emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"after\":\"fill\",\"outcome\":\"REJECTED\",\"why\":\"%s\"}", s, w.fail())); continue; }
                if (w.anchors() < 2 || w.insns() < 3) { weak++;
                    emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"after\":\"fill\",\"instructions\":%d,\"anchors\":%d,\"outcome\":\"WEAK\"}", s, w.insns(), w.anchors())); continue; }
                if (acceptUnreferenced(s, cs, w, "fill")) accepted++;
                continue;
            }
            Function f = p.getFunctionManager().getFunctionContaining(term.getAddress());
            String mn = term.getMnemonicString().toUpperCase();
            boolean jmp = mn.equals("JMP") && term.getFlowType().isUnConditional() && !term.getFlowType().isComputed();
            if (w.fail() != null) {
                rejected++;
                rejects.merge(w.fail().replaceAll("@.*", ""), 1, Integer::sum);
                emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"after\":\"%s %s\",\"outcome\":\"REJECTED\",\"why\":\"%s\"}", s, term.getAddress(), mn, w.fail()));
                continue;
            }
            boolean joinsOwn = false;
            if (f != null) for (Address j : w.joins()) if (f.getBody().contains(j)) joinsOwn = true;
            if (jmp && f != null && joinsOwn) {
                commit(s, cs, w, false);
                dead++; deadInsns += w.insns(); accepted++;
                p.getBookmarkManager().setBookmark(s, BookmarkType.ANALYSIS, "WSEvidence",
                    "G1 DEAD_CODE: skipped by the JMP at " + term.getAddress() + ", rejoins " + f.getName() + "; " + w.insns() + " instructions, not reachable");
                emit.accept(String.format("{\"rule\":\"G1\",\"start\":\"%s\",\"after\":\"%s\",\"function\":\"%s\",\"instructions\":%d,\"outcome\":\"DEAD_CODE\"}", s, term.getAddress(), f.getEntryPoint(), w.insns()));
                continue;
            }
            if (w.anchors() < 2 || w.insns() < 3) {
                weak++;
                emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"after\":\"%s %s\",\"instructions\":%d,\"anchors\":%d,\"outcome\":\"WEAK\"}", s, term.getAddress(), mn, w.insns(), w.anchors()));
                continue;
            }
            if (acceptUnreferenced(s, cs, w, mn + " at " + term.getAddress())) accepted++;
        }
        return accepted;
    }

    boolean acceptUnreferenced(Address s, int cs, Walk w, String after) throws Exception {
        commit(s, cs, w, true);
        Function nf = p.getFunctionManager().getFunctionAt(s);
        if (nf == null) {
            rejected++;
            rejects.merge("NO_FUNCTION", 1, Integer::sum);
            emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"outcome\":\"NO_FUNCTION\"}", s));
            return false;
        }
        nf.addTag("WS_UNREFERENCED");
        unref++; unrefInsns += w.insns();
        p.getBookmarkManager().setBookmark(s, BookmarkType.ANALYSIS, "WSEvidence",
            "U1 UNREFERENCED_FUNCTION: after " + after + ", " + w.insns() + " instructions, " + w.anchors() + " anchors; no reference found");
        emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"after\":\"%s\",\"instructions\":%d,\"anchors\":%d,\"joins\":%d,\"outcome\":\"UNREFERENCED_FUNCTION\"}",
            s, after, w.insns(), w.anchors(), w.joins().size()));
        return true;
    }

    boolean allFill(Address s) {
        try {
            byte b0 = mem.getByte(s);
            if (b0 != (byte) 0xFF && b0 != 0) return false;
            Address e = s;
            for (int k = 0; k < 16; k++) {
                e = e.next();
                if (e == null || listing.getCodeUnitAt(e) instanceof Instruction) return true;
                if (mem.getByte(e) != b0) return false;
            }
            return true;
        } catch (Exception x) { return false; }
    }

    int csOf(Address a) {
        BigInteger v = csval == null ? null : ctx.getValue(csval, a, false);
        if (v != null && v.intValue() != 0) return v.intValue();
        return a instanceof SegmentedAddress sa ? sa.getSegment() : (int) (a.getOffset() >> 4) & 0xF000;
    }

    Walk walk(Address s, int cs) {
        AddressSet body = new AddressSet();
        Set<Address> joins = new HashSet<>();
        List<Address> calls = new ArrayList<>();
        Set<Address> internal = new LinkedHashSet<>();
        Map<Address, Integer> depthAt = new HashMap<>();   // stack depth (words) on entry to each instruction
        Deque<Object[]> work = new ArrayDeque<>();
        work.push(new Object[] { s, 0 });
        MemoryBlock blk = mem.getBlock(s);
        int insns = 0, anchors = 0, pushes = 0;
        boolean balanced = true;
        while (!work.isEmpty()) {
            Object[] item = work.pop();
            Address a = (Address) item[0];
            int depth = (Integer) item[1];
            if (body.contains(a)) { if (!Objects.equals(depthAt.get(a), depth)) balanced = false; continue; }
            if (listing.getInstructionAt(a) != null) { joins.add(a); continue; }
            if (!blk.contains(a)) return fail("LEAVES_BLOCK@" + a);
            CodeUnit cu = listing.getCodeUnitContaining(a);
            if (cu instanceof Instruction || (cu instanceof Data d && d.isDefined())) return fail("OVERLAP@" + a);
            if (++insns > 1500) return fail("TOO_LONG");
            PseudoInstruction pi;
            try {
                PseudoDisassemblerContext pc = new PseudoDisassemblerContext(ctx);
                pc.setFutureRegisterValue(a, new RegisterValue(csval, BigInteger.valueOf(cs)));
                pi = pd.disassemble(a, pc, false);
            } catch (Exception e) { return fail("UNDECODABLE@" + a); }
            if (pi == null) return fail("UNDECODABLE@" + a);
            Address end = pi.getMaxAddress();
            for (Address q = a.next(); q != null && q.compareTo(end) <= 0; q = q.next()) {
                CodeUnit c = listing.getCodeUnitContaining(q);
                if (c instanceof Instruction || (c instanceof Data d && d.isDefined()) || body.contains(q)) return fail("OVERLAP@" + q);
            }
            if (!blk.contains(end)) return fail("LEAVES_BLOCK@" + a);
            body.add(a, end);
            depthAt.put(a, depth);
            String mn = pi.getMnemonicString().toUpperCase();
            String t = pi.toString().toUpperCase().replace(" ", "");
            if (IMPLAUSIBLE.contains(mn) || mn.startsWith("?") || mn.contains("UNDEF") || t.equals("INT0X3")
                    || t.matches("(MOV|POP)CS.*")) return fail("IMPLAUSIBLE@" + a + ":" + mn);
            anchors += anchorsOf(pi, a);
            int nd = depth;
            if (mn.equals("PUSH") || mn.equals("PUSHF")) { nd++; pushes++; }
            else if (mn.equals("PUSHA")) { nd += 8; pushes++; }
            else if (mn.equals("POP") || mn.equals("POPF")) nd--;
            else if (mn.equals("POPA")) nd -= 8;
            else if (t.contains("SP") && !mn.startsWith("RET")) balanced = false;   // explicit SP arithmetic: not tracked
            if (nd < 0) balanced = false;
            var ft = pi.getFlowType();
            if (ft.isComputed()) return fail("COMPUTED@" + a);
            if (mn.startsWith("RET") || mn.equals("IRET")) { if (nd != 0) balanced = false; }
            if (ft.isCall()) {
                for (Address c : pi.getFlows()) {
                    if (p.getFunctionManager().getFunctionAt(c) != null) { calls.add(c); anchors++; continue; }
                    // a call into undefined bytes of the same block: an internal subroutine, walked as part of the candidate
                    CodeUnit cc = listing.getCodeUnitContaining(c);
                    if (blk.contains(c) && cc instanceof Data cd && !cd.isDefined()) { internal.add(c); work.push(new Object[] { c, 0 }); continue; }
                    return fail("CALL_NOT_ENTRY@" + a);
                }
            }
            else if (ft.isJump()) for (Address j : pi.getFlows()) work.push(new Object[] { j, nd });
            Address fall = pi.getFallThrough();
            if (fall != null && !ft.isTerminal() && !(ft.isJump() && ft.isUnConditional())) work.push(new Object[] { fall, nd });
        }
        // a save/restore discipline that balances on every path to a return is structural evidence of code
        if (balanced && pushes >= 2 && joins.isEmpty()) anchors += 2;
        return new Walk(body, insns, joins, anchors, null, calls, internal);
    }

    static Walk fail(String why) { return new Walk(null, 0, Set.of(), 0, why, List.of(), Set.of()); }

    static final java.util.regex.Pattern ABS = java.util.regex.Pattern.compile("(?:(CS|DS|ES|SS):)?\\[0X([0-9A-F]+)\\]");

    /** Absolute memory operands (RAM / SRAM variables) and I/O ports that existing (already disassembled) code also uses. */
    int anchorsOf(PseudoInstruction pi, Address at) {
        int n = 0;
        String t = pi.toString().toUpperCase().replace(" ", "");
        String mn = pi.getMnemonicString().toUpperCase();
        AddressSpace ios = p.getAddressFactory().getAddressSpace("io");
        if ((mn.equals("IN") || mn.equals("OUT")) && ios != null) {
            for (int k = 0; k < pi.getNumOperands(); k++) for (Object o : pi.getOpObjects(k)) {
                long port = o instanceof Scalar sc ? sc.getUnsignedValue() : o instanceof Address ad && ad.getAddressSpace().equals(ios) ? ad.getOffset() : -1;
                if (port >= 0 && p.getReferenceManager().getReferencesTo(ios.getAddress(port & 0xFF)).hasNext()) n++;
            }
        }
        java.util.regex.Matcher m = ABS.matcher(t);
        if (m.find() && (m.group(1) == null || m.group(1).equals("DS"))) {
            BigInteger ds = ctx.getRegister("DS") == null ? null : ctx.getValue(ctx.getRegister("DS"), at, false);
            int seg = ds == null ? 0 : ds.intValue();
            Address ad = ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(seg, Integer.parseInt(m.group(2), 16) & 0xFFFF);
            if (refsFromCode(ad)) n++;
        }
        return Math.min(n, 2);
    }

    boolean refsFromCode(Address ad) {
        MemoryBlock b = mem.getBlock(ad);
        if (b == null || b.isExecute() && b.isInitialized() && !b.getName().equals("RAM")) return false;   // RAM / SRAM variables only
        for (Reference r : p.getReferenceManager().getReferencesTo(ad))
            if (listing.getInstructionAt(r.getFromAddress()) != null) return true;
        return false;
    }

    void commit(Address s, int cs, Walk w, boolean function) throws Exception {
        // csval at every walked range start and internal subroutine entry, before anything is disassembled
        Set<Address> starts = new LinkedHashSet<>();
        starts.add(s);
        for (AddressRange r : w.body()) starts.add(r.getMinAddress());
        starts.addAll(w.internal());
        for (Address a : starts) if (listing.getInstructionContaining(a) == null) ctx.setValue(csval, a, a, BigInteger.valueOf(cs));
        new DisassembleCommand(s, null, true).applyTo(p, monitor);
        for (Address c : w.internal()) if (listing.getInstructionAt(c) == null) new DisassembleCommand(c, null, true).applyTo(p, monitor);
        // internal subroutines first, so the caller's body stops at them
        for (Address c : w.internal()) if (p.getFunctionManager().getFunctionAt(c) == null) {
            new CreateFunctionCmd(c).applyTo(p, monitor);
            Function cf = p.getFunctionManager().getFunctionAt(c);
            if (cf != null) { cf.addTag("WS_UNREFERENCED"); unref++;
                emit.accept(String.format("{\"rule\":\"U1\",\"start\":\"%s\",\"after\":\"called from candidate %s\",\"outcome\":\"UNREFERENCED_FUNCTION\"}", c, s)); }
        }
        if (function) new CreateFunctionCmd(s).applyTo(p, monitor);
    }
}
