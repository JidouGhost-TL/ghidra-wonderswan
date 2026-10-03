// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rule J1: rule-based recovery of CS-relative jump/call tables, with per-site evidence.
 *
 * Sites: JMP/CALL word ptr CS:[reg(+d)] and JMP/CALL reg (reg loaded by MOV reg,word ptr CS:[...]).
 * Backward slice (<= 16 instructions, fall-through) on the index register:
 *   base   MOV idx,imm | LEA idx,[imm] | ADD idx,imm   (+ displacement of the memory operand)
 *   index  AND reg,mask then SHL/ROL/SHR/ROR by constants (mask pushed through the ops) -> candidate offsets
 *          (an upper bound: stop rules still end the table), or CMP reg,N + JA/JAE (Borland form) -> N+1 entries.
 * J1a: a table needs a constant address part (base immediate or displacement), else UNRESOLVED.
 * J1b: an unbounded index (no mask / CMP) is accepted only when the table ends on EXECUTED_CODE or
 *   TABLE_BOUNDARY; other stops (data, cap) leave the site UNRESOLVED.
 * J1c: a byte-width index (MOV rL,x + XOR rH,rH / MOV rH,0, or CBW for AX) bounds the table at
 *   256 << (shift-1) entries (CBW: 128 forward entries); the table end must still be proven by a strong stop
 *   (EXECUTED_CODE / TABLE_BOUNDARY) or by reaching that bound.
 * J1e: FUNCTION_ENTRY (either byte of a slot is the entry of a function, e.g. one created from a table recovered in an
 *   earlier pass) is a strong stop like EXECUTED_CODE: a table cannot run into a function.
 * J1f: TABLE_BASE (a slot is the base of another CS table used anywhere in the program) is a strong stop.
 * J1g: computed references another analysis left on a recovered site that are not in the proven table are removed.
 * J1h: code decoded only from a superseded reference (unexecuted, unreferenced, not reached by fall-through,
 *   not a function entry) is cleared, bytes kept and bookmarked; proven targets are re-flowed.
 * Index scaling by ADD r,r counts as SHL r,1.
 * J1d: a 0000 slot is empty (not a target, not a stop) inside a table whose end is proven.
 * Stop rules: EXECUTED_CODE (entry slot executed), TABLE_BOUNDARY (next recovered table), OUT_OF_ROM,
 *   MID_INSTRUCTION (inside an executed instruction), DEFINED_DATA, SELF; cap 64.
 * Evidence check: observed targets must be a subset; missing ones are added and reported.
 */
final class WSJumpTables {
    static final Pattern MEM = Pattern.compile("word ptr CS:\\[(BX|SI|DI|BP)(?: ?([+-]) ?0x([0-9a-f]+))?\\]", Pattern.CASE_INSENSITIVE);

    static final class Rec {
        String shape = "?", idx, scaledBy = null, bound = "none", stop = "BOUND";
        boolean baseFound, byteBound;
        int slots, empty;                       // slots scanned (incl. empty 0000 slots), empty slots
        List<Integer> slotOf = new ArrayList<>(); // slot index of each target
        List<Integer> emptySlots = new ArrayList<>();
        int base, disp, table, cap = 64;
        TreeSet<Integer> maskOffsets;
        List<Address> targets = new ArrayList<>();
    }

    final Program p;
    final Listing listing;
    final Memory mem;
    final SegmentedAddressSpace space;
    final WSEvidence ev;
    final Map<Long, Set<Long>> observed = new HashMap<>();
    final Consumer<String> emit;
    int sites, recovered, unresolved, newCode, observedMissing, offcut, errors;

    WSJumpTables(Program p, WSEvidence ev, Consumer<String> emit) {
        this.p = p; this.ev = ev; this.emit = emit;
        listing = p.getListing();
        mem = p.getMemory();
        space = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
        for (WSEvidence.Edge e : ev.edges)
            if (e.from() >= 0 && (e.kind().equals("jump") || e.kind().equals("call")))
                observed.computeIfAbsent(e.from(), k -> new TreeSet<>()).add(e.to());
    }

    boolean executed(long lin) { return ev.executed(lin); }

    /** Applies J1 until no new sites appear: recovered targets are disassembled, and the new code can hold
     *  further table sites, which must get J1 too rather than only Ghidra's default
     *  switch recovery after this analyzer has finished. */
    void apply(TaskMonitor monitor) throws Exception {
        Set<Address> done = new HashSet<>();
        for (int pass = 0; pass < 16; pass++) {
            int before = done.size();
            applyPass(done, monitor);
            if (done.size() == before) break;
            passes = pass + 1;
        }
    }

    int passes, supersededRefs;

    void applyPass(Set<Address> done, TaskMonitor monitor) throws Exception {
        Map<Instruction, Rec> recs = new LinkedHashMap<>();
        collectTableBases(monitor);
        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (!ins.getFlowType().isComputed()) continue;
            String mn = ins.getMnemonicString().toUpperCase();
            if (!(mn.equals("JMP") || mn.equals("CALL"))) continue;
            if (!done.add(ins.getAddress())) continue;
            recs.put(ins, recover(ins));
        }
        sites += recs.size();
        for (Rec ra : recs.values()) for (Rec rb : recs.values()) {
            if (ra == null || rb == null || ra == rb || ra.targets.isEmpty() || rb.targets.isEmpty()) continue;
            if (rb.table > ra.table && rb.table < ra.table + 2 * ra.slots) {
                // keep only targets read from slots before the next table
                int lim = (rb.table - ra.table) / 2;
                ra.slots = lim;
                ra.targets = trimToSlots(ra, lim);
                ra.empty = (int) ra.emptySlots.stream().filter(k -> k < lim).count();
                ra.stop = "TABLE_BOUNDARY";
            }
        }
        for (Map.Entry<Instruction, Rec> e : recs.entrySet()) {
            monitor.checkCancelled();
            try { applySite(e.getKey(), e.getValue(), monitor); }
            catch (ghidra.util.exception.CancelledException c) { throw c; }
            catch (Exception x) {
                errors++;
                emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}", e.getKey().getAddress(), String.valueOf(x).replace('"', '\'')));
            }
        }
    }

    void applySite(Instruction ins, Rec r, TaskMonitor monitor) throws Exception {
        Set<Long> obs = observed.getOrDefault(ins.getAddress().getOffset(), Set.of());
        if (r == null || r.targets.isEmpty()) {
            unresolved++;
            emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"UNRESOLVED\",\"shape\":\"%s\",\"observed\":%d}",
                ins.getAddress(), ins, r == null ? "-" : r.shape, obs.size()));
            return;
        }
        Set<Long> got = new HashSet<>();
        for (Address t : r.targets) got.add(t.getOffset());
        List<String> missing = new ArrayList<>();
        int cs = csOf(ins.getAddress());
        for (long o : obs) if (!got.contains(o)) {
            missing.add(String.format("%05x", o));
            r.targets.add(seg(cs, (int) ((o - ((long) cs << 4)) & 0xFFFF)));
            observedMissing++;
        }
        boolean isCall = ins.getMnemonicString().equalsIgnoreCase("CALL");
        List<Address> kept = new ArrayList<>();
        for (Address t : r.targets) {
            if (listing.getInstructionAt(t) == null) {
                if (listing.getInstructionContaining(t) != null) {
                    // target inside an existing (unexecuted) decode: conflict, reported, not forced
                    offcut++;
                    emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"TARGET_OFFCUT\",\"inside\":\"%s\"}",
                        ins.getAddress(), t, listing.getInstructionContaining(t).getAddress()));
                    continue;
                }
                // a fresh disassembly start has no flowing context: give the target the site's decode
                // context (CS-relative table -> same CS), else near branches resolve with CS=0 (into RAM)
                copyContext(ins.getAddress(), t, cs);
                new DisassembleCommand(t, null, true).applyTo(p, monitor);
                newCode++;
            }
            kept.add(t);
            if (isCall && p.getFunctionManager().getFunctionAt(t) == null && listing.getInstructionAt(t) != null)
                new CreateFunctionCmd(t).applyTo(p, monitor);
        }
        for (Address t : kept) ins.addMnemonicReference(t, isCall ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
        r.targets = kept;
        // J1g: computed-flow references another analysis guessed for this site (Ghidra's switch recovery reads
        // past the table end, e.g. into the next table) are superseded by the proven table; user references stay.
        Set<Address> keep = new HashSet<>(kept);
        int superseded = 0;
        List<Address> gone = new ArrayList<>();
        for (Reference ref : p.getReferenceManager().getReferencesFrom(ins.getAddress())) {
            if (!ref.getReferenceType().isComputed() || keep.contains(ref.getToAddress())) continue;
            if (ref.getSource() == SourceType.USER_DEFINED || ref.getSource() == SourceType.IMPORTED) continue;
            p.getReferenceManager().delete(ref);
            gone.add(ref.getToAddress());
            superseded++;
        }
        supersededRefs += superseded;
        // J1h: code decoded only because of a superseded reference (unexecuted, no remaining reference, not
        // reached by fall-through) is cleared, so it no longer blocks the proven targets (junk decoded from a
        // guessed target can overlap real handlers, which rule A1 would then clear). Bytes are kept.
        AddressSet cleared = new AddressSet();
        for (Address t : gone) cleared.add(clearOrphan(t));
        if (!cleared.isEmpty()) {
            // re-flow every proven target so a run blocked by the cleared code continues now
            for (Address t : kept) new DisassembleCommand(t, null, true).applyTo(p, monitor);
            removeStaleConflicts(cleared);
            clearedOrphans += cleared.getNumAddresses();
        }
        Function f = p.getFunctionManager().getFunctionContaining(ins.getAddress());
        if (!isCall && f != null) {
            new JumpTable(ins.getAddress(), new ArrayList<>(r.targets), true, 0).writeOverride(f);
            CreateFunctionCmd.fixupFunctionBody(p, f, monitor);
        }
        recovered++;
        emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"RECOVERED\",\"shape\":\"%s\",\"index\":\"%s\",\"scaled_by\":\"%s\",\"table\":\"%04x\",\"bound\":\"%s\",\"stop\":\"%s\",\"entries\":%d,\"superseded_refs\":%d,\"slots\":%d,\"empty_slots\":%d,\"observed\":%d,\"observed_missing_added\":%s}",
            ins.getAddress(), ins, r.shape, r.idx, r.scaledBy, r.table, r.bound.replace("\"", "'"), r.stop, r.targets.size(), superseded, r.slots, r.empty, obs.size(),
            missing.isEmpty() ? "[]" : "[\"" + String.join("\",\"", missing) + "\"]"));
    }

    void copyContext(Address site, Address target, int cs) throws Exception {
        ProgramContext ctx = p.getProgramContext();
        ctx.setValue(ctx.getRegister("csval"), target, target, java.math.BigInteger.valueOf(cs));
        ghidra.program.model.lang.Register soc = ctx.getRegister("colorsoc");
        java.math.BigInteger v = soc == null ? null : ctx.getValue(soc, site, false);
        if (v != null) ctx.setValue(soc, target, target, v);
    }

    long clearedOrphans;

    /** J1h helper: clears the unexecuted run starting at t that only the superseded reference reached. */
    AddressSetView clearOrphan(Address t) throws Exception {
        AddressSet out = new AddressSet();
        Instruction i = listing.getInstructionAt(t);
        while (i != null) {
            if (executed(i.getAddress().getOffset())) break;
            if (p.getReferenceManager().getReferencesTo(i.getAddress()).hasNext()) break;
            if (i.getAddress().equals(t) && i.getFallFrom() != null) break;   // the start is reached by fall-through: real flow
            if (p.getFunctionManager().getFunctionAt(i.getAddress()) != null) break;
            Address ft = i.getFallThrough();
            out.add(i.getAddress(), i.getMaxAddress());
            i = ft == null ? null : listing.getInstructionAt(ft);
        }
        for (AddressRange r : out) {
            listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
            p.getBookmarkManager().setBookmark(r.getMinAddress(), BookmarkType.ANALYSIS, "WSEvidence",
                "J1h SUPERSEDED_TARGET_CLEARED: decoded only from a superseded computed reference; bytes kept");
            emit.accept(String.format("{\"rule\":\"J1h\",\"start\":\"%s\",\"end\":\"%s\",\"outcome\":\"CLEARED\"}", r.getMinAddress(), r.getMaxAddress()));
        }
        return out;
    }

    /** ERROR bookmarks of a conflict with code J1h cleared are stale: removed (the re-flow reports any real one again). */
    void removeStaleConflicts(AddressSetView cleared) {
        BookmarkManager bm = p.getBookmarkManager();
        List<Bookmark> stale = new ArrayList<>();
        Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.ERROR);
        while (it.hasNext()) {
            Bookmark b = it.next();
            Matcher m = CONFLICT.matcher(b.getComment());
            if (cleared.contains(b.getAddress())) { stale.add(b); continue; }
            if (m.find()) {
                Address c = p.getAddressFactory().getAddress(m.group(1));
                if (c != null && cleared.contains(c)) stale.add(b);
            }
        }
        for (Bookmark b : stale) bm.removeBookmark(b);
    }

    static final Pattern CONFLICT = Pattern.compile("conflicting instruction at (\\S+)");

    String summary() {
        return String.format("J1 jump/call table sites %d (passes %d): recovered %d, unresolved %d, new code %d, observed targets added %d, offcut targets %d, superseded refs %d, orphan bytes cleared %d, site errors %d",
            sites, passes, recovered, unresolved, newCode, observedMissing, offcut, supersededRefs, clearedOrphans, errors);
    }

    /** cs:off in the space of the site being recovered: a site in a bank overlay (rule B2) reads its table
     *  and targets in the same overlay when the address falls inside it. */
    Address seg(int cs, int off) {
        Address base = space.getAddress(cs, off);
        if (siteSpace != null && siteSpace.isOverlaySpace()) {
            Address o = siteSpace.getAddress(base.getOffset());
            if (mem.contains(o)) return o;
        }
        return base;
    }

    AddressSpace siteSpace;

    /** Code segment of an instruction: seg:off addresses carry it; bank-overlay addresses are linear, so the
     *  csval context (the CS the evidence observed there) gives it, else the window segment. */
    int csOf(Address a) {
        if (a instanceof SegmentedAddress sa) return sa.getSegment();
        ghidra.program.model.lang.Register csval = p.getProgramContext().getRegister("csval");
        java.math.BigInteger v = csval == null ? null : p.getProgramContext().getValue(csval, a, false);
        return v != null ? v.intValue() : (int) (a.getOffset() >> 4) & 0xF000;
    }

    Rec recover(Instruction site) {
        siteSpace = site.getAddress().getAddressSpace();
        Rec r = new Rec();
        int cs = csOf(site.getAddress());
        List<Instruction> back = predecessors(site, 16);
        Matcher mm = MEM.matcher(site.toString());
        if (mm.find()) { r.shape = "MEM"; r.idx = mm.group(1).toUpperCase(); r.disp = disp(mm); }
        else {
            if (site.getNumOperands() != 1 || site.getRegister(0) == null) return null;
            String reg = site.getRegister(0).getName().toUpperCase();
            Instruction load = null;
            for (Instruction q : back) {
                String t = q.toString().toUpperCase();
                if (t.startsWith("MOV " + reg + ",")) { load = q; break; }
                if (writes(t, reg)) break;
            }
            if (load == null) { r.shape = "REG_NOLOAD"; return r; }
            Matcher lm = MEM.matcher(load.toString());
            if (!lm.find()) { r.shape = "REG_NOT_CS_TABLE"; return r; }
            r.shape = "REG"; r.idx = lm.group(1).toUpperCase(); r.disp = disp(lm);
            back = predecessors(load, 16);
        }
        for (Instruction q : back) {
            String t = q.toString().toUpperCase().replace(" ", "");
            if (t.startsWith("MOV" + r.idx + ",0X")) { r.base += hex(t); r.baseFound = true; break; }
            if (t.startsWith("LEA" + r.idx + ",[0X")) { r.base += Integer.parseInt(t.substring(t.indexOf("0X") + 2, t.indexOf(']')), 16); r.baseFound = true; break; }
            if (t.startsWith("ADD" + r.idx + ",0X")) { r.base += hex(t); r.baseFound = true; continue; }
            if (t.startsWith("ADD" + r.idx + ",") && r.scaledBy == null) { r.scaledBy = t.substring(t.indexOf(',') + 1); continue; }
            if (t.startsWith("SHL" + r.idx) || t.startsWith("SHR" + r.idx) || t.startsWith("ROL" + r.idx) || t.startsWith("ROR" + r.idx)
                    || t.startsWith("AND" + r.idx) || t.startsWith("XOR" + r.idx.charAt(0) + "L")) {
                if (r.scaledBy == null) r.scaledBy = r.idx;
                continue;
            }
            if (writes(t, r.idx)) break;
        }
        String ix = r.scaledBy == null ? r.idx : r.scaledBy;
        r.maskOffsets = maskValues(back, ix, r);
        r.table = (r.base + r.disp) & 0xFFFF;
        tableStart = seg(cs, r.table);
        // J1a: the table address needs a constant (base immediate or displacement); a bare [BX] whose BX
        // comes from elsewhere is an unknown table, not one at CS:0000.
        if (!r.baseFound && r.disp == 0) { r.shape += "/NO_BASE"; return r; }
        if (r.maskOffsets != null) {
            // A mask bounds the index (upper bound); it does not prove every value occurs: stop rules apply
            // entry by entry in ascending offset order (e.g. mask 0x1e allows 16 entries where the table has 9).
            r.stop = "MASK_BOUND";
            for (int v : r.maskOffsets) {
                Address ea = seg(cs, (r.table + v) & 0xFFFF);
                String why = scanSlot(cs, ea, r);
                if (why == null) continue;
                r.stop = why;
                break;
            }
            return r;
        }
        for (Instruction q : back) {
            String t = q.toString().toUpperCase().replace(" ", "");
            String r8 = ix.length() == 2 ? ix.charAt(0) + "L" : ix;
            if (t.startsWith("CMP" + ix + ",0X") || t.startsWith("CMP" + r8 + ",0X")) { r.cap = Math.min(256, hex(t) + 1); r.bound = q.toString(); break; }
        }
        if (r.bound.equals("none")) byteBound(back, ix, r);
        boolean bounded = !r.bound.equals("none");
        for (int i = 0; i < r.cap; i++) {
            Address ea;
            try { ea = seg(cs, (r.table + 2 * i) & 0xFFFF); } catch (Exception e) { r.stop = "OUT_OF_ROM"; break; }
            String why = scanSlot(cs, ea, r);
            if (why == null) continue;
            r.stop = why;
            break;
        }
        boolean strong = r.stop.equals("EXECUTED_CODE") || r.stop.equals("TABLE_BOUNDARY") || r.stop.equals("FUNCTION_ENTRY")
            || r.stop.equals("TABLE_BASE");
        // J1b: without an index bound only a strong end (next slot executed / next recovered table) proves
        // the extent; running into data or the cap does not (observed targets stay via rule E3).
        if (!bounded && !strong) {
            r.shape += "/UNBOUNDED_WEAK_STOP:" + r.stop;
            r.targets.clear();
        }
        // J1c: a byte-width bound is proven only by a strong stop or by reaching the bound itself.
        if (r.byteBound && !strong && !r.stop.equals("BOUND")) {
            r.shape += "/BYTE_INDEX_WEAK_STOP:" + r.stop;
            r.targets.clear();
        }
        return r;
    }

    List<Address> trimToSlots(Rec r, int lim) {
        List<Address> keep = new ArrayList<>();
        for (int k = 0; k < r.slotOf.size(); k++) if (r.slotOf.get(k) < lim) keep.add(r.targets.get(k));
        return keep;
    }

    /** One table slot: null = keep scanning (target added, or empty 0000 slot, J1d); else the stop reason. */
    String scanSlot(int cs, Address ea, Rec r) {
        String why = slotStop(ea);
        if (why != null) return why;
        r.slots++;
        try {
            if ((mem.getShort(ea) & 0xFFFF) == 0) { r.empty++; r.emptySlots.add(r.slots - 1); return null; }
        } catch (Exception e) { return "OUT_OF_ROM"; }
        Address t = read(cs, ea);
        why = implausible(t, ea);
        if (why != null) { r.slots--; return why; }
        r.slotOf.add(r.slots - 1);
        r.targets.add(t);
        return null;
    }

    /** J1c: index register loaded from a byte (zero- or sign-extended) before scaling. */
    void byteBound(List<Instruction> back, String reg, Rec r) {
        if (reg.length() != 2 || reg.charAt(1) != 'X' && !reg.equals("SI") && !reg.equals("DI")) return;
        String lo = reg.charAt(0) + "L", hi = reg.charAt(0) + "H";
        int shift = 0;
        boolean hiClear = false, loByte = false, cbw = false;
        for (Instruction q : back) {
            String t = q.toString().toUpperCase().replace(" ", "");
            java.util.regex.Matcher m = Pattern.compile("SHL" + reg + ",(0X[0-9A-F]+|1)").matcher(t);
            if (m.matches()) { shift += m.group(1).equals("1") ? 1 : Integer.parseInt(m.group(1).substring(2), 16); continue; }
            if (t.startsWith("ADD" + reg + ",0X")) continue;
            if (t.equals("ADD" + reg + "," + reg)) { shift++; continue; }   // x2 scaling
            if (t.equals("XOR" + hi + "," + hi) || t.equals("MOV" + hi + ",0X0") || t.equals("SUB" + hi + "," + hi)) { hiClear = true; if (loByte) break; continue; }
            if (t.startsWith("MOV" + lo + ",")) { loByte = true; if (hiClear) break; continue; }
            if (t.equals("CBW") && reg.equals("AX")) { cbw = true; loByte = true; hiClear = true; break; }
            if (t.startsWith("MOVZX" + reg)) { loByte = true; hiClear = true; break; }
            if (writes(t, reg)) return;
        }
        if (!(hiClear && loByte)) return;
        int bytes = (cbw ? 128 : 256) << shift;           // CBW: only the 0..127 half lies at or after the base
        r.cap = Math.max(1, bytes / 2);
        r.byteBound = true;
        r.bound = (cbw ? "byte index (CBW, forward half)" : "byte index") + " << " + shift + " -> " + r.cap + " entries";
    }

    String slotStop(Address ea) {
        if (!mem.contains(ea) || !mem.getBlock(ea).isInitialized()) return "OUT_OF_ROM";
        if (executed(ea.getOffset()) || executed(ea.getOffset() + 1)) return "EXECUTED_CODE";
        if (p.getFunctionManager().getFunctionAt(ea) != null || p.getFunctionManager().getFunctionAt(ea.add(1)) != null) return "FUNCTION_ENTRY";
        if (!ea.equals(tableStart) && tableBases.contains(ea)) return "TABLE_BASE";
        return null;
    }

    /** J1f: every constant CS-relative table base in the program (jump or data table, resolved or not): a
     *  table that runs into another object's base ends there (e.g. a command table followed directly by a
     *  direct-mode table). */
    final Set<Address> tableBases = new HashSet<>();
    Address tableStart;
    static final Pattern CSMEM = Pattern.compile("CS:\\[(?:(BX|SI|DI|BP)(?: ?([+-]) ?0x([0-9a-f]+))?|0x([0-9a-f]+))\\]", Pattern.CASE_INSENSITIVE);

    void collectTableBases(TaskMonitor monitor) throws Exception {
        tableBases.clear();
        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            String txt = ins.toString();
            if (!txt.contains("CS:[")) continue;
            Matcher m = CSMEM.matcher(txt);
            if (!m.find()) continue;
            siteSpace = ins.getAddress().getAddressSpace();
            int cs = csOf(ins.getAddress());
            if (m.group(4) != null) { tableBases.add(seg(cs, Integer.parseInt(m.group(4), 16))); continue; }
            String reg = m.group(1).toUpperCase();
            int disp = m.group(3) == null ? 0 : Integer.parseInt(m.group(3), 16) * (m.group(2).equals("-") ? -1 : 1), base = 0;
            boolean found = false;
            for (Instruction q : predecessors(ins, 16)) {
                String t = q.toString().toUpperCase().replace(" ", "");
                if (t.startsWith("MOV" + reg + ",0X")) { base += hex(t); found = true; break; }
                if (t.startsWith("LEA" + reg + ",[0X")) { base += Integer.parseInt(t.substring(t.indexOf("0X") + 2, t.indexOf(']')), 16); found = true; break; }
                if (t.startsWith("ADD" + reg + ",0X")) { base += hex(t); continue; }
                if (t.matches("ADD" + reg + ",(AX|BX|CX|DX|SI|DI|BP)")) continue;   // index added to the base register
                if (writes(t, reg)) break;
            }
            if (found || disp != 0) tableBases.add(seg(cs, (base + disp) & 0xFFFF));
        }
    }

    /** Byte offsets the index can take: AND mask pushed through SHL/ROL/SHR/ROR/XOR-low-byte (an upper bound). */
    TreeSet<Integer> maskValues(List<Instruction> back, String reg, Rec r) {
        List<String> ops = new ArrayList<>();
        Integer mask = null;
        String r8 = reg.length() == 2 ? reg.charAt(0) + "L" : reg;
        for (Instruction q : back) {
            String t = q.toString().toUpperCase().replace(" ", "");
            if (t.startsWith("AND" + reg + ",0X") || t.startsWith("AND" + r8 + ",0X")) {
                mask = hex(t) & (t.startsWith("AND" + r8 + ",") && !r8.equals(reg) ? 0xFF : 0xFFFF);
                break;
            }
            if (t.matches("(SHL|ROL|SHR|ROR)" + reg + ",(0X[0-9A-F]+|1)")) { ops.add(0, t); continue; }
            if (t.equals("ADD" + reg + "," + reg)) { ops.add(0, "SHL" + reg + ",1"); continue; }   // x2 scaling
            if (t.startsWith("ADD" + reg + ",0X")) continue;   // table base, already in r.base
            if (t.startsWith("XOR" + r8 + "," + r8) && !r8.equals(reg)) { ops.add(0, "CLRLOW"); continue; }
            if (writes(t, reg)) return null;
        }
        if (mask == null) return null;
        List<Integer> bits = new ArrayList<>();
        for (int b = 0; b < 16; b++) if ((mask >> b & 1) != 0) bits.add(1 << b);
        if (bits.size() > 12) return null;
        TreeSet<Integer> out = new TreeSet<>();
        for (int s = 0; s < (1 << bits.size()); s++) {
            int v = 0;
            for (int k = 0; k < bits.size(); k++) if ((s >> k & 1) != 0) v |= bits.get(k);
            for (String op : ops) {
                if (op.equals("CLRLOW")) { v &= 0xFF00; continue; }
                int n = op.endsWith(",1") ? 1 : Integer.parseInt(op.substring(op.indexOf("0X") + 2), 16);
                if (op.startsWith("SHL")) v = (v << n) & 0xFFFF;
                else if (op.startsWith("SHR")) v = v >>> n;
                else if (op.startsWith("ROL")) v = ((v << n) | (v >>> (16 - n))) & 0xFFFF;
                else v = ((v >>> n) | (v << (16 - n))) & 0xFFFF;
            }
            out.add(v);
        }
        r.bound = "mask 0x" + Integer.toHexString(mask) + " through " + ops;
        return out.size() <= 256 ? out : null;
    }

    Address read(int cs, Address ea) {
        try { return seg(cs, mem.getShort(ea) & 0xFFFF); } catch (Exception e) { return null; }
    }

    String implausible(Address t, Address slot) {
        if (t == null) return "OUT_OF_ROM";
        MemoryBlock b = mem.getBlock(t);
        if (b == null || !b.isExecute() || !b.isInitialized()) return "OUT_OF_ROM";
        if (t.equals(slot)) return "SELF";
        Instruction at = listing.getInstructionContaining(t);
        if (at != null && !at.getAddress().equals(t) && executed(at.getAddress().getOffset())) return "MID_INSTRUCTION";
        Data d = listing.getDataContaining(t);
        if (d != null && d.isDefined()) return "DEFINED_DATA";
        return null;
    }

    static boolean writes(String t, String reg) {
        t = t.toUpperCase().replace(" ", "");
        String r8a = reg.length() == 2 ? reg.charAt(0) + "L" : "", r8b = reg.length() == 2 ? reg.charAt(0) + "H" : "";
        for (String r : new String[] { reg, r8a, r8b }) {
            if (r.isEmpty()) continue;
            if (t.matches("(MOV|ADD|SUB|AND|OR|XOR|SHL|SHR|ROL|ROR|SAR|INC|DEC|NEG|NOT|LEA|POP|XCHG|MUL|DIV)" + r + "(,.*)?")) return true;
        }
        return false;
    }

    static int disp(Matcher m) { return m.group(3) == null ? 0 : Integer.parseInt(m.group(3), 16) * (m.group(2).equals("-") ? -1 : 1); }

    static int hex(String t) { return Integer.parseInt(t.substring(t.indexOf("0X") + 2).replaceAll("[^0-9A-F].*$", ""), 16); }

    List<Instruction> predecessors(Instruction ins, int n) {
        List<Instruction> out = new ArrayList<>();
        Instruction q = ins;
        for (int i = 0; i < n; i++) {
            Address fa = q.getFallFrom();
            if (fa == null) break;
            q = listing.getInstructionAt(fa);
            if (q == null) break;
            out.add(q);
        }
        return out;
    }
}
