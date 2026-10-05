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
import ghidra.util.exception.InvalidInputException;
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
 * J1b: an unbounded index (no mask / CMP) is accepted only when the table ends on a strong stop (EXECUTED_CODE,
 *   TABLE_BOUNDARY, FUNCTION_ENTRY, TABLE_BASE, OWN_TARGET); other stops (data, cap) leave the site UNRESOLVED.
 * J1c: a byte-width index (MOV rL,x + XOR rH,rH / MOV rH,0, or CBW for AX) bounds the table at
 *   256 << (shift-1) entries (CBW: 128 forward entries); the table end must still be proven by a strong stop
 *   (EXECUTED_CODE / TABLE_BOUNDARY) or by reaching that bound.
 * J1e: FUNCTION_ENTRY (either byte of a slot is the entry of a function, e.g. one created from a table recovered in an
 *   earlier pass) is a strong stop like EXECUTED_CODE: a table cannot run into a function.
 * J1f: TABLE_BASE (a slot is the base of another CS table used anywhere in the program) is a strong stop.
 * J1g: computed references another analysis left on a recovered site that are not in the proven table are removed.
 * J1h: code decoded only from a superseded reference (unexecuted, no remaining reference, not reached by
 *   fall-through from kept code) is cleared, bytes kept and bookmarked; proven targets are re-flowed. A run that
 *   fails the guard is kept and reported (SKIPPED). Lying inside a function entered outside the run is not a veto:
 *   with no reference and no fall-through the bytes are unreachable from that function too, and clearing them
 *   frees a fall-through tail for the routine-start rule (the carve is reported with the former container).
 * J1i: a base held in a second register: ADD idx,reg2 where reg2's last write before the ADD (same fall-through
 *   chain) is MOV reg2,imm or LEA reg2,[imm] adds that constant to the table address and leaves idx as the index
 *   (e.g. LEA AX,[tbl]; SHL BX,1; ADD BX,AX; JMP/CALL CS:[BX]). The constant must reach the ADD on every path: no
 *   flow joins between the write and the ADD, and no CALL/INT in between (callee-clobbered); an implicit write of
 *   reg2 (LODSW, MUL, CBW ...) ends the search as non-constant. The index keeps every other rule (mask, CMP, byte
 *   bound, J1b strong stop). A site left without a base reports the J1i reason in its shape.
 *   A MOV idx,imm reached after the base was added and after idx itself was scaled/masked/cleared is the index's
 *   start value, not part of the table address (MOV BX,2 / XOR BL,BL / ADD BX,tbl is a table at tbl).
 * J1j: OWN_TARGET (either byte of a slot is a target read from an earlier slot of the same table) is a strong stop:
 *   a dispatch target is code, so the table ends where its own handler code starts (table directly followed by
 *   its first handler, the usual layout when the dispatcher has not executed in the evidence run).
 * J1k: a target that does not decode as an instruction (UNDECODABLE, e.g. erased 0xFF fill) stops the table like
 *   OUT_OF_ROM (a weak stop).
 * J1l: an unresolved site whose guessed
 *   (non-observed, non-user) computed references point at an offcut, an ERROR bookmark or undecodable bytes
 *   is quarantined: the guessed references are deleted (observed targets are evidence and stay), code decoded
 *   only from them is cleared with the J1h guard, and the site is re-attempted every pass (the junk often
 *   polluted the backward slice). A site still unresolved at the end keeps its guesses deleted (nothing
 *   re-decodes the cleared junk without a reference); the deleted addresses stay in the evidence for rule J1m.
 * J1m (post-analysis script WSJumpTableFinish, after the merges): at a quarantined site, re-delete any guessed
 *   reference a later analysis re-derived (by the QUARANTINED address list) and lock the switch to its observed
 *   targets (a stored jump-table override); with no observed target the site stays an opaque indirect branch.
 * J1n: a kept target shadowed by single-byte data (a data pointer read the slot first) is deshadowed (analysis
 *   references to the byte deleted with it; the slot's code reference is added anyway): a proven code target
 *   beats one data byte. User/imported and multi-byte data stay, keeping the target undecoded.
 * Index scaling by ADD r,r counts as SHL r,1.
 * J1d: a 0000 slot is empty (not a target, not a stop) inside a table whose end is proven.
 * Stop rules: EXECUTED_CODE (entry slot executed), TABLE_BOUNDARY (next recovered table), OWN_TARGET (J1j), OUT_OF_ROM,
 *   MID_INSTRUCTION (inside an executed instruction), DEFINED_DATA, UNDECODABLE (J1k), SELF; cap 64.
 * Evidence check: observed targets must be a subset; missing ones are added and reported.
 */
public final class WSJumpTables {
    static final Pattern MEM = Pattern.compile("word ptr CS:\\[(BX|SI|DI|BP)(?: ?([+-]) ?0x([0-9a-f]+))?\\]", Pattern.CASE_INSENSITIVE);

    static final class Rec {
        String shape = "?", idx, scaledBy = null, bound = "none", stop = "BOUND";
        boolean baseFound, byteBound;
        int slots, empty;                       // slots scanned (incl. empty 0000 slots), empty slots
        List<Integer> slotOf = new ArrayList<>(); // slot index of each target
        List<Integer> emptySlots = new ArrayList<>();
        int base, disp, table, cap = 64;
        TreeSet<Integer> maskOffsets;
        Set<Address> baseAdds = new HashSet<>();  // J1i: ADD idx,reg2 instructions that added a constant base
        String baseVia = "direct", j1iMiss;       // J1i provenance / why a candidate base register was not constant
        List<Address> targets = new ArrayList<>();
    }

    final Program p;
    final Listing listing;
    final Memory mem;
    final SegmentedAddressSpace space;
    final WSEvidence ev;
    final Map<Long, Set<Long>> observed = new HashMap<>();
    final Consumer<String> emit;
    int recovered, newCode, observedMissing, offcut, errors, computedBases;

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
    /** Sites already recovered or rejected (kept across calls: phase 2 re-runs J1 after other rules add code).
     *  Quarantined (J1l) sites stay out until they recover or {@link #finish} restores them. */
    final Set<Address> done = new HashSet<>();
    /** Sites with an UNRESOLVED line (distinct-site count for the summary; removed on recovery). */
    final Set<Address> reported = new HashSet<>();
    /** Quarantined site -> guessed references deleted there (J1l). */
    final Map<Address, List<QuarRef>> quarantined = new LinkedHashMap<>();

    record QuarRef(Address to, RefType type) { }

    void apply(TaskMonitor monitor) throws Exception {
        for (int pass = 0; pass < 16; pass++) {
            int before = done.size() + quarantined.size();
            applyPass(monitor);
            passes++;
            if (done.size() + quarantined.size() == before) break;
        }
    }

    /** End of phase 2: quarantined sites that never recovered keep their guessed references deleted
     *  (nothing re-decodes the cleared junk without a reference, so the conflict stays resolved; the deleted
     *  addresses stay in the QUARANTINED line for the post-analysis lock, rule J1m, which also re-deletes any
     *  reference a later analysis re-derived there). */
    void finish() {
        for (Map.Entry<Address, List<QuarRef>> e : quarantined.entrySet()) {
            done.add(e.getKey());
            droppedRefs += e.getValue().size();
            emit.accept(String.format("{\"rule\":\"J1l\",\"site\":\"%s\",\"outcome\":\"QUARANTINE_FINAL\",\"refs_dropped\":%d}",
                e.getKey(), e.getValue().size()));
        }
        quarantined.clear();
    }

    int passes, supersededRefs, quarantines, droppedRefs, deshadowed;
    /** Every kept table target (proven code): rule A1 stops its artefact walk-back at these. */
    final Set<Address> keptTargets = new HashSet<>();
    /** Distinct computed-jump/call sites ever collected (retries do not inflate the count). */
    final Set<Address> seen = new HashSet<>();

    void applyPass(TaskMonitor monitor) throws Exception {
        Map<Instruction, Rec> recs = new LinkedHashMap<>();
        collectTableBases(monitor);
        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (!ins.getFlowType().isComputed()) continue;
            String mn = ins.getMnemonicString().toUpperCase();
            if (!(mn.equals("JMP") || mn.equals("CALL"))) continue;
            if (done.contains(ins.getAddress())) continue;
            seen.add(ins.getAddress());
            recs.put(ins, recover(ins));
        }
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
            try {
                if (e.getValue() == null || e.getValue().targets.isEmpty()) handleUnresolved(e.getKey(), e.getValue());
                else {
                    applySite(e.getKey(), e.getValue(), monitor);
                    done.add(e.getKey().getAddress());
                    if (quarantined.remove(e.getKey().getAddress()) != null) reported.remove(e.getKey().getAddress());
                }
            }
            catch (ghidra.util.exception.CancelledException c) { throw c; }
            catch (Exception x) {
                errors++;
                done.add(e.getKey().getAddress());
                emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}", e.getKey().getAddress(), String.valueOf(x).replace('"', '\'')));
            }
        }
    }

    /** An unrecovered site: quarantine (J1l) when its guesses look conflicted, else reject. Quarantined
     *  sites stay out of `done' so every later pass re-attempts them with the junk gone. */
    void handleUnresolved(Instruction ins, Rec r) throws Exception {
        Address site = ins.getAddress();
        if (!quarantined.containsKey(site) && quarantineTrigger(ins)) {
            quarantine(ins);
            if (reported.add(site)) emitUnresolved(ins, r);
            return;
        }
        if (quarantined.containsKey(site)) return;   // still unresolved after quarantine: wait for more code
        done.add(site);
        if (reported.add(site)) emitUnresolved(ins, r);
    }

    void emitUnresolved(Instruction ins, Rec r) {
        Set<Long> obs = observed.getOrDefault(ins.getAddress().getOffset(), Set.of());
        emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"UNRESOLVED\",\"shape\":\"%s\",\"observed\":%d}",
            ins.getAddress(), ins, r == null ? "-" : r.shape, obs.size()));
    }

    /** J1l trigger: the site holds a deletable guessed reference whose target is offcut, bookmarked ERROR or
     *  undecodable. */
    boolean quarantineTrigger(Instruction ins) {
        boolean guessed = false;
        Set<Long> obs = observed.getOrDefault(ins.getAddress().getOffset(), Set.of());
        for (Reference ref : p.getReferenceManager().getReferencesFrom(ins.getAddress())) {
            if (!ref.getReferenceType().isComputed()) continue;
            if (ref.getSource() == SourceType.USER_DEFINED || ref.getSource() == SourceType.IMPORTED) continue;
            if (obs.contains(ref.getToAddress().getOffset())) continue;
            guessed = true;
            Address t = ref.getToAddress();
            if (listing.getInstructionAt(t) == null && listing.getInstructionContaining(t) != null) return true;
            for (Bookmark b : p.getBookmarkManager().getBookmarks(t))
                if (b.getType().equals(BookmarkType.ERROR)) return true;
            if (listing.getInstructionAt(t) == null) {
                try { if (new ghidra.app.util.PseudoDisassembler(p).disassemble(t) == null) return true; }
                catch (Exception e) { return true; }
            }
        }
        // Only the guessed targets themselves are evidence of junk (offcut, ERROR-bookmarked, undecodable: checked
        // above). An ERROR elsewhere in the enclosing function is not: quarantining on it deleted sound switch
        // targets that only Ghidra's switch recovery knew, leaving reachable code undisassembled.
        return false;
    }

    /** J1l: delete the guessed references (observed targets stay), clear their orphan decode, re-attempt later. */
    void quarantine(Instruction ins) throws Exception {
        Address site = ins.getAddress();
        Set<Long> obs = observed.getOrDefault(site.getOffset(), Set.of());
        List<QuarRef> gone = new ArrayList<>();
        List<Address> targets = new ArrayList<>();
        for (Reference ref : p.getReferenceManager().getReferencesFrom(site)) {
            if (!ref.getReferenceType().isComputed()) continue;
            if (ref.getSource() == SourceType.USER_DEFINED || ref.getSource() == SourceType.IMPORTED) continue;
            if (obs.contains(ref.getToAddress().getOffset())) continue;
            gone.add(new QuarRef(ref.getToAddress(), ref.getReferenceType()));
            targets.add(ref.getToAddress());
            p.getReferenceManager().delete(ref);
        }
        quarantined.put(site, gone);
        AddressSet cleared = new AddressSet();
        for (Address t : targets) cleared.add(clearOrphan(t));
        if (!cleared.isEmpty()) removeStaleConflicts(cleared);
        quarantines++;
        List<String> goneAddrs = new ArrayList<>();
        for (QuarRef q : gone) goneAddrs.add("\"" + q.to() + "\"");
        emit.accept(String.format("{\"rule\":\"J1l\",\"site\":\"%s\",\"outcome\":\"QUARANTINED\",\"refs_deleted\":%d,\"orphan_bytes_cleared\":%d,\"deleted\":[%s]}",
            site, gone.size(), cleared.getNumAddresses(), String.join(",", goneAddrs)));
    }

    void applySite(Instruction ins, Rec r, TaskMonitor monitor) throws Exception {
        Set<Long> obs = observed.getOrDefault(ins.getAddress().getOffset(), Set.of());
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
                // single-byte data shadowing a proven target (a data pointer read the slot first):
                // cleared (user data and multi-byte data stay, keeping today's behavior there)
                if (listing.getDataAt(t) != null) deshadow(ins.getAddress(), t);
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
        keptTargets.addAll(kept);
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
        if (!r.baseAdds.isEmpty()) computedBases++;
        emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"RECOVERED\",\"shape\":\"%s\",\"index\":\"%s\",\"scaled_by\":\"%s\",\"table\":\"%04x\",\"bound\":\"%s\",\"stop\":\"%s\",\"entries\":%d,\"superseded_refs\":%d,\"slots\":%d,\"empty_slots\":%d,\"observed\":%d,\"base_via\":\"%s\",\"observed_missing_added\":%s}",
            ins.getAddress(), ins, r.shape, r.idx, r.scaledBy, r.table, r.bound.replace("\"", "'"), r.stop, r.targets.size(), superseded, r.slots, r.empty, obs.size(),
            r.baseVia.replace("\"", "'"),
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

    /** J1h helper: clears the unexecuted run starting at t that only the superseded reference reached.
     *  Stops at any instruction reached from kept code (executed, still referenced, or reached by fall-through
     *  from outside the run): carving live flow is never orphan cleanup. Bytes inside a function entered outside
     *  the run are still cleared when nothing reaches them: with no reference and no fall-through they are
     *  unreachable from that function too, and the cleared tail is usually re-owned by the routine-start rule. */
    AddressSetView clearOrphan(Address t) throws Exception {
        AddressSet out = new AddressSet();
        String skipped = null;
        String container = null;
        Instruction i = listing.getInstructionAt(t);
        while (i != null) {
            if (executed(i.getAddress().getOffset())) { skipped = "EXECUTED"; break; }
            if (p.getReferenceManager().getReferencesTo(i.getAddress()).hasNext()) { skipped = "REFERENCED"; break; }
            Address ff = i.getFallFrom();
            if (ff != null && !out.contains(ff)) { skipped = "FALLTHROUGH@" + ff; break; }
            Function cf = p.getFunctionManager().getFunctionContaining(i.getAddress());
            if (cf != null && !out.contains(cf.getEntryPoint()) && !cf.getEntryPoint().equals(t) && container == null)
                container = cf.getEntryPoint().toString();
            Address ft = i.getFallThrough();
            out.add(i.getAddress(), i.getMaxAddress());
            i = ft == null ? null : listing.getInstructionAt(ft);
        }
        if (skipped != null && out.isEmpty())
            emit.accept(String.format("{\"rule\":\"J1h\",\"start\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}", t, skipped));
        for (AddressRange r : out) {
            listing.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
            p.getBookmarkManager().setBookmark(r.getMinAddress(), BookmarkType.ANALYSIS, "WSEvidence",
                "J1h SUPERSEDED_TARGET_CLEARED: decoded only from a superseded computed reference; bytes kept");
            emit.accept(String.format(container == null
                ? "{\"rule\":\"J1h\",\"start\":\"%s\",\"end\":\"%s\",\"outcome\":\"CLEARED\"}"
                : "{\"rule\":\"J1h\",\"start\":\"%s\",\"end\":\"%s\",\"outcome\":\"CLEARED\",\"from\":\"%s\"}",
                r.getMinAddress(), r.getMaxAddress(), container == null ? "" : container));
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
        return String.format("J1 jump/call table sites %d (passes %d): recovered %d (J1i register base %d), unresolved %d, quarantined %d (refs dropped %d), new code %d, observed targets added %d, offcut targets %d, deshadowed %d, superseded refs %d, orphan bytes cleared %d, site errors %d",
            seen.size(), passes, recovered, computedBases, reported.size(), quarantines, droppedRefs, newCode, observedMissing, offcut, deshadowed, supersededRefs, clearedOrphans, errors);
    }

    /** J1n: clear single-byte data shadowing a proven table target so it disassembles. The shadowing byte
     *  comes from a data pointer that read the table slot first; a proven code target beats one data byte.
     *  User/imported data and multi-byte data stay (returns false, keeping the target undecoded). Analysis
     *  references to the byte are deleted with it (the slot's code reference is added by the caller). */
    boolean deshadow(Address site, Address t) throws Exception {
        var d = listing.getDataAt(t);
        if (d == null || d.getLength() != 1) return false;
        List<Reference> refs = new ArrayList<>();
        p.getReferenceManager().getReferencesTo(t).forEachRemaining(refs::add);
        for (Reference r : refs)
            if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) return false;
        for (Reference r : refs) p.getReferenceManager().delete(r);
        listing.clearCodeUnits(t, t, false);
        deshadowed++;
        emit.accept(String.format("{\"rule\":\"J1n\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"DESHADOWED\",\"refs_deleted\":%d}", site, t, refs.size()));
        return true;
    }

    /** Rule J1m (post-analysis, after the merges): at a site quarantined by J1l that never recovered, re-delete
     *  any guessed reference a later analysis re-derived (by the QUARANTINED address list; observed and user
     *  references stay) and lock the switch to its observed targets with a stored jump-table override. With no
     *  observed target the site stays an opaque indirect branch. Sites recovered after quarantine are skipped
     *  (their references are proven). Idempotent. Returns a summary; evidence lines go to emit. */
    public static String lockSwitches(Program p, List<String> evidence, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        AddressFactory af = p.getAddressFactory();
        Set<Address> recovered = new HashSet<>();
        Map<Address, Set<Address>> quar = new LinkedHashMap<>();
        for (String l : evidence) {
            if (l.contains("\"rule\":\"J1\"") && l.contains("\"outcome\":\"RECOVERED\"")) {
                Address s = addrField(l, "\"site\":\"", af);
                if (s != null) recovered.add(s);
            } else if (l.contains("\"rule\":\"J1l\"") && l.contains("\"outcome\":\"QUARANTINED\"")) {
                Address s = addrField(l, "\"site\":\"", af);
                Set<Address> del = addrList(l, "\"deleted\":[", af);
                if (s != null && del != null) quar.put(s, del);
            }
        }
        ReferenceManager rm = p.getReferenceManager();
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        int cleaned = 0, locked = 0, opaque = 0, skipped = 0;
        for (Map.Entry<Address, Set<Address>> e : quar.entrySet()) {
            monitor.checkCancelled();
            Address site = e.getKey();
            if (recovered.contains(site)) continue;
            Instruction ins = listing.getInstructionAt(site);
            if (ins == null || !ins.getFlowType().isComputed()) {
                skipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_SITE\"}", site));
                continue;
            }
            int n = 0;
            for (Reference r : rm.getReferencesFrom(site)) {
                if (!r.getReferenceType().isComputed() || !e.getValue().contains(r.getToAddress())) continue;
                if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) continue;
                rm.delete(r);
                n++;
            }
            cleaned += n;
            List<Address> obs = new ArrayList<>();
            for (Reference r : rm.getReferencesFrom(site)) {
                if (!r.getReferenceType().isComputed()) continue;
                if (listing.getInstructionAt(r.getToAddress()) == null) continue;
                obs.add(r.getToAddress());
            }
            if (obs.isEmpty()) {
                opaque++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"OPAQUE\",\"refs_deleted\":%d}", site, n));
                continue;
            }
            Function f = fm.getFunctionContaining(site);
            if (f == null) {
                skipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_FUNCTION\"}", site));
                continue;
            }
            try {
                new JumpTable(site, new ArrayList<>(obs), true, 0).writeOverride(f);
                locked++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"LOCKED\",\"refs_deleted\":%d,\"cases\":%d}", site, n, obs.size()));
            } catch (InvalidInputException x) {
                skipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}", site, x.getMessage().replace("\"", "'")));
            }
        }
        return String.format("J1m jump-table lock: quarantined sites %d, re-derived refs deleted %d, switches locked %d, opaque %d, skipped %d",
            quar.size(), cleaned, locked, opaque, skipped);
    }

    static Address addrField(String line, String key, AddressFactory af) {
        int i = line.indexOf(key);
        if (i < 0) return null;
        int j = line.indexOf('"', i + key.length());
        if (j < 0) return null;
        try {
            return af.getAddress(line.substring(i + key.length(), j));
        } catch (Exception ex) {
            return null;
        }
    }

    static Set<Address> addrList(String line, String key, AddressFactory af) {
        int i = line.indexOf(key);
        if (i < 0) return null;
        int j = line.indexOf(']', i + key.length());
        if (j < 0) return null;
        Set<Address> out = new HashSet<>();
        for (String q : line.substring(i + key.length(), j).split(",")) {
            q = q.trim();
            if (q.length() < 3 || !q.startsWith("\"") || !q.endsWith("\"")) continue;
            try {
                Address a = af.getAddress(q.substring(1, q.length() - 1));
                if (a != null) out.add(a);
            } catch (Exception ex) { /* not an address: not a deletion we can use */ }
        }
        return out;
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
        for (int qi = 0; qi < back.size(); qi++) {
            Instruction q = back.get(qi);
            String t = q.toString().toUpperCase().replace(" ", "");
            Matcher am = ADDREG.matcher(t);
            if (am.matches() && am.group(1).equals(r.idx) && !am.group(2).equals(r.idx)) {
                // J1i: the added register may hold the table base rather than the index
                String[] why = new String[1];
                Integer c = constBefore(back, qi, am.group(2), why);
                if (c != null) {
                    r.base += c; r.baseFound = true; r.baseAdds.add(q.getAddress());
                    r.baseVia = "J1i " + why[0] + " + " + q;
                    continue;
                }
                if (r.j1iMiss == null) r.j1iMiss = am.group(2) + "_" + why[0];
            }
            if (t.startsWith("MOV" + r.idx + ",0X") && r.baseFound && r.idx.equals(r.scaledBy)) {
                // J1i: idx was operated on (scaled/masked/cleared) before the base was added, so this constant is
                // the index's start value, not part of the table address
                r.baseVia += "; index start " + q;
                break;
            }
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
        if (!r.baseAdds.isEmpty()) back = withoutBaseAdds(back, r);
        r.maskOffsets = maskValues(back, ix, r);
        r.table = (r.base + r.disp) & 0xFFFF;
        tableStart = seg(cs, r.table);
        // J1a: the table address needs a constant (base immediate or displacement); a bare [BX] whose BX
        // comes from elsewhere is an unknown table, not one at CS:0000.
        if (!r.baseFound && r.disp == 0) { r.shape += "/NO_BASE" + (r.j1iMiss == null ? "" : "/J1i_" + r.j1iMiss); return r; }
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
            || r.stop.equals("TABLE_BASE") || r.stop.equals("OWN_TARGET");
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
        String why = slotStop(ea, r);
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

    String slotStop(Address ea, Rec r) {
        if (!mem.contains(ea) || !mem.getBlock(ea).isInitialized()) return "OUT_OF_ROM";
        if (executed(ea.getOffset()) || executed(ea.getOffset() + 1)) return "EXECUTED_CODE";
        if (p.getFunctionManager().getFunctionAt(ea) != null || p.getFunctionManager().getFunctionAt(ea.add(1)) != null) return "FUNCTION_ENTRY";
        if (!ea.equals(tableStart) && tableBases.contains(ea)) return "TABLE_BASE";
        if (r.targets.contains(ea) || r.targets.contains(ea.add(1))) return "OWN_TARGET";   // J1j
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
            List<Instruction> back = predecessors(ins, 16);
            for (int qi = 0; qi < back.size(); qi++) {
                Instruction q = back.get(qi);
                String t = q.toString().toUpperCase().replace(" ", "");
                Matcher am = ADDREG.matcher(t);
                if (am.matches() && am.group(1).equals(reg) && !am.group(2).equals(reg)) {
                    Integer c = constBefore(back, qi, am.group(2), new String[1]);   // J1i register base
                    if (c != null) { base += c; found = true; }
                    continue;
                }
                if (t.startsWith("MOV" + reg + ",0X")) { base += hex(t); found = true; break; }
                if (t.startsWith("LEA" + reg + ",[0X")) { base += Integer.parseInt(t.substring(t.indexOf("0X") + 2, t.indexOf(']')), 16); found = true; break; }
                if (t.startsWith("ADD" + reg + ",0X")) { base += hex(t); continue; }
                if (t.matches("ADD" + reg + ",(AX|BX|CX|DX|SI|DI|BP)")) continue;   // index added to the base register
                if (writes(t, reg)) break;
            }
            if (found || disp != 0) tableBases.add(seg(cs, (base + disp) & 0xFFFF));
        }
    }

    static final Pattern ADDREG = Pattern.compile("ADD(AX|BX|CX|DX|SI|DI|BP),(AX|BX|CX|DX|SI|DI|BP)");
    static final Pattern CONSTDEF = Pattern.compile("(?:MOV(AX|BX|CX|DX|SI|DI|BP),0X([0-9A-F]+)|LEA(AX|BX|CX|DX|SI|DI|BP),\\[0X([0-9A-F]+)\\])");

    /** J1i: the constant reg holds when back.get(at) executes, or null with the reason in why[0] (on success
     *  why[0] is the defining instruction). Searches back.get(at+1 ..) for the last write of reg; the write
     *  must be MOV reg,imm / LEA reg,[imm], reached from there to back.get(at) by fall-through only. */
    Integer constBefore(List<Instruction> back, int at, String reg, String[] why) {
        ghidra.program.model.lang.Register r16 = p.getRegister(reg);
        for (int j = at + 1; j < back.size(); j++) {
            Instruction d = back.get(j);
            // every instruction after d up to and including the ADD must be reached only by fall-through
            Instruction after = back.get(j - 1);
            for (Reference ref : p.getReferenceManager().getReferencesTo(after.getAddress()))
                if (ref.getReferenceType().isFlow()) { why[0] = "JOIN@" + after.getAddress(); return null; }
            String t = d.toString().toUpperCase().replace(" ", "");
            String mn = d.getMnemonicString().toUpperCase();
            if (mn.startsWith("CALL") || mn.startsWith("INT")) { why[0] = "CALL_BETWEEN@" + d.getAddress(); return null; }
            if (!writesReg(d, t, reg, r16)) continue;
            Matcher m = CONSTDEF.matcher(t);
            if (m.matches() && reg.equals(m.group(1) != null ? m.group(1) : m.group(3))) {
                why[0] = d.toString();
                return Integer.parseInt(m.group(2) != null ? m.group(2) : m.group(4), 16) & 0xFFFF;
            }
            why[0] = "NOT_CONST@" + d.getAddress();
            return null;
        }
        why[0] = "NO_DEF";
        return null;
    }

    /** Explicit (operand) or implicit (p-code result, e.g. LODSW/MUL/CBW writing AX) write of reg or a part of it. */
    static boolean writesReg(Instruction d, String t, String reg, ghidra.program.model.lang.Register r16) {
        if (writes(t, reg)) return true;
        if (r16 == null) return false;
        for (Object o : d.getResultObjects())
            if (o instanceof ghidra.program.model.lang.Register w && (w.contains(r16) || r16.contains(w))) return true;
        return false;
    }

    /** The slice without J1i base additions: they add the constant base, not a change of the index. */
    static List<Instruction> withoutBaseAdds(List<Instruction> back, Rec r) {
        List<Instruction> out = new ArrayList<>();
        for (Instruction q : back) if (!r.baseAdds.contains(q.getAddress())) out.add(q);
        return out;
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
        if (WonderSwanLoader.isDataOverlay(b)) return "DATA_OVERLAY";
        if (t.equals(slot)) return "SELF";
        Instruction at = listing.getInstructionContaining(t);
        if (at != null && !at.getAddress().equals(t) && executed(at.getAddress().getOffset())) return "MID_INSTRUCTION";
        Data d = listing.getDataContaining(t);
        if (d != null && d.isDefined()) return "DEFINED_DATA";
        // J1k: a target must decode as an instruction (e.g. erased 0xFF fill does not)
        if (at == null) {
            try { if (new ghidra.app.util.PseudoDisassembler(p).disassemble(t) == null) return "UNDECODABLE"; }
            catch (Exception e) { return "UNDECODABLE"; }
        }
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
