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
 *   TABLE_BOUNDARY, FUNCTION_ENTRY, DIRECT_CALL_ENTRY, TABLE_BASE, OWN_TARGET); other stops (data, cap) leave the site UNRESOLVED.
 * J1c: a byte-width index (MOV rL,x + XOR rH,rH / MOV rH,0, or CBW for AX) bounds the table at
 *   256 << (shift-1) entries (CBW: 128 forward entries); the table end must still be proven by a strong stop
 *   (EXECUTED_CODE / TABLE_BOUNDARY) or by reaching that bound.
 * J1e: FUNCTION_ENTRY (either byte of a slot is the entry of a function, e.g. one created from a table recovered in an
 *   earlier pass) is a strong stop like EXECUTED_CODE: a table cannot run into a function.
 * J1f: TABLE_BASE (a slot is the base of another CS table used anywhere in the program) is a strong stop.
 * J1g: computed references another analysis left on a recovered site that are not in the proven table are removed.
 * J1h (H2): superseding or quarantining a computed reference never invalidates its decoded code.
 *   Preserve instructions and functions, and tag each retained hypothesis with its source and reason.
 *   Missing execution, incoming references or fall-through cannot prove code invalid. Conflicting
 *   interpretations remain unresolved; ERROR bookmarks remain while their conflicting code exists.
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
 *   from them is preserved and tagged by J1h, and the site is re-attempted every pass (the guesses may
 *   have polluted the backward slice). A site still unresolved at the end keeps its guesses deleted;
 *   the retained decode remains a hypothesis. Deleted reference addresses stay in the evidence for J1m.
 * J1m (post-analysis script WSJumpTableFinish, after the merges): at a quarantined site, re-delete any guessed
 *   reference a later analysis re-derived (by the QUARANTINED address list) and lock the switch to its observed
 *   targets (a stored jump-table override); with no observed target the site stays an opaque indirect branch.
 *   Unresolved sites with E3 observed targets get the same lock; recovered jump sites are re-locked (J1p: merges
 *   strip the recovery override, after which the decompiler's own unbounded table read follows garbage
 *   cross-space). Every lock is filtered to the site's address space (J1q).
 * J1n: a kept target shadowed by single-byte data (a data pointer read the slot first) is deshadowed (analysis
 *   references to the byte deleted with it; the slot's code reference is added anyway): a proven code target
 *   beats one data byte. User/imported and multi-byte data stay, keeping the target undecoded.
 * J1o: a slot targeting the last byte of a bank overlay is skipped like an empty slot, and unproven
 *   computed references there are deleted: no case entry can live on that byte (any instruction either
 *   overruns the block or falls out of its address space, which neither the listing nor the decompiler
 *   can follow). User/imported references stay.
 * J1p: recovered jump sites are re-locked post-merge (rule J1m): a merge recreates the function and strips
 *   the recovery override, after which the decompiler's own unbounded table read follows garbage cross-space.
 * J1q: every jump-table override is filtered to the site's address space: a foreign-bank override target sends
 *   the decompiler where nothing was decoded. References keep every bank (they are evidence and harmless).
 * J1y: a site's table slots and observed targets resolve in the site's own address space when applied, not in
 *   the space of whichever site was recovered last in the pass: a bank-overlay site's observed targets are overlay
 *   addresses, never the empty bank window.
 * J1r: a quarantined site whose own instruction was removed by an earlier analysis gets one
 *   restoration attempt before the final
 *   verdict: the cleared run is re-decoded from the fall-through of the nearest preceding kept instruction in the
 *   same function (trial decode, undefined bytes only, bounded; it must reach the site with the same computed
 *   JMP/CALL mnemonic and contain no other computed branch), committed, and the site re-attempted. A recovered
 *   site applies normally; a still-unresolved one keeps its restored decode and stays quarantined (opaque).
 *   Anything else (no kept fall-through anchor, no clean rejoin, wrong shape) stays unresolved.
 * J1s: an offcut or protected target keeps the entire site unresolved; no reduced target set is
 *   published. Later analysis can retry the complete table if independent evidence resolves the conflict.
 * J1z: the exception is a CALL table (no switch override, every slot its own call entry): a conflicted slot stays
 *   unresolved with its preserved interpretation and conflict bookmark, and the other proven slots are published.
 * J1t (post-analysis script WSJumpTableFinish, after the J1m lock): a function at a recovered JMP site's kept
 *   target whose body contains another kept target of the same site is an over-glued case block (stock analysis
 *   joined sibling cases into one body, which then decompiles with the parent switch's mis-recovered cases):
 *   when the body partitions exactly into one terminal span per contained target (every span ends in a jump or
 *   return, every body range starts at a target), RET-terminated spans are kept as functions and JMP-terminated
 *   spans are demoted to case-blocks of the switch parent (stock switch-namespace labels stripped, the site
 *   re-locked to its proven targets). Anything else stays as it is.
 * J1u (analyzer WSSwitchOrderAnalyzer, just before stock Decompiler Switch Analysis): a JMP site whose index is
 *   bounded only by its byte width (J1c) or an AND mask, with no CMP guard and no conditional branch or join after
 *   the index is loaded (or masked), gets J1 as soon as it is decoded. Stock switch recovery bounds such an index
 *   only by that width or mask, reads up to 128 or 256 slots of handler bytes as targets and can grow the native
 *   decompiler without limit. Stock analysis skips a computed jump that already has computed references,
 *   and a stored lock (when a function contains the site) keeps every later decompile on the proven table. Same
 *   recovery and stop rules; a site J1 cannot prove yet is left for the later passes.
 * J1uw (end of phase 2): a J1u site phase 2 cannot re-prove loses the references and lock J1u wrote (code kept, H2).
 * Rule C (end of phase 2): an unguarded byte-index JMP site still unresolved for lack of a proven end, or because its
 *   proven targets conflict with existing code or data (J1s), gets a
 *   WARNING bookmark (WSJumpTableHazard), a log entry and a report line. Its code is preserved and no table
 *   end is invented.
 * Index scaling by ADD r,r counts as SHL r,1.
 * J1d: a 0000 slot is empty (not a target, not a stop) inside a table whose end is proven.
 * Stop rules: EXECUTED_CODE (entry slot executed), TABLE_BOUNDARY (next recovered table), OWN_TARGET (J1j), OUT_OF_ROM,
 *   MID_INSTRUCTION (inside an executed instruction), DEFINED_DATA, UNDECODABLE (J1k), SELF; cap 64.
 * Evidence check: observed targets must be a subset; missing ones are added and reported.
 * CT1a: far call tables. CALLF CS:[reg(+d)] (or a two-register form, CT1b) reads 4-byte slots (offset word, segment
 *   word); the index slice, bounds and stop rules are those of J1 with 4-byte slots (a byte index bounds the table at
 *   256 << (shift-2) entries). A 0000:0000 slot is empty (J1d). A slot whose segment is RAM/SRAM (< 0x2000) or a bank
 *   window (0x2000-0x3FFF) other than the site's own segment ends the table (FAR_RAM / FAR_BANK_WINDOW): the bank of a
 *   window target is unknown. Each target is decoded with its own segment as CS. CALLF sites without a CS-relative
 *   operand (pointer from RAM, e.g. ES:[DI+4]) are not table sites. Unresolved CALLF sites are reported only (never
 *   quarantined: J1l applies to near sites as before).
 * CT1b: two-register CS operands [BX|BP + SI|DI (+d)] (direct site or the MOV reg load of a CALL/JMP reg site): when
 *   exactly one of the two registers holds a constant at the access (its last write is MOV reg,imm / LEA reg,[imm],
 *   reached by fall-through only, no CALL/INT in between, as J1i), that constant plus d is the table base and the
 *   other register is the index; every J1 index rule then applies to it.
 * CT1c: observed span. A table whose end is not proven (J1b unbounded index or J1c byte index with a weak stop) is
 *   still a contiguous array starting at its proven constant base: every slot from the base up to the slot of the
 *   farthest observed target of this site is a table slot. When every observed target of the site is found in a slot
 *   before the weak stop, slots 0..span are kept (decoded like any recovered table); slots after the span up to the
 *   weak stop are H2 hypotheses (tagged WSHypothesis:CT1c on the slot, not decoded). No observed target: unresolved
 *   as before.
 * CT1e: a slot whose target does not decode but points forward, on a slot boundary, inside the scanned table region
 *   is a placeholder (unused entries aimed at the table's end). The scan goes on; the placeholders are accepted only
 *   when the table then ends exactly at their common target by the J1j OWN_TARGET stop. They are not decoded (kept like
 *   empty slots, one CT1e line each). Otherwise the table is rescanned as plain J1 (the first placeholder is the weak
 *   UNDECODABLE stop again).
 * CT1g: a far table whose index scale (SHL/ADD idx,idx along the slice) exceeds the 4-byte slot reads records:
 *   slots are one record stride apart (e.g. 8-byte records of two far pointers, read by two sites with +0 and +4).
 * CT1f: an unbounded index (J1b) whose first 64 slots are all plausible scans on, up to 256 slots; the longer
 *   table is kept only when it ends on a strong stop (the J1b proof); otherwise the 64-slot result stands as before.
 * CT1d (J1o extended to the segment end): a near slot 0xFFFF (last byte of the code segment, where the IP wraps) and a
 *   far slot FFFF:FFFF (past 1 MiB) are skipped like empty slots: no routine entry can live there.
 */
public final class WSJumpTables {
    static final Pattern MEM = Pattern.compile("word ptr CS:\\[(BX|SI|DI|BP)(?: ?([+-]) ?0x([0-9a-f]+))?\\]", Pattern.CASE_INSENSITIVE);

    static final class Rec {
        String shape = "?", idx, scaledBy = null, bound = "none", stop = "BOUND";
        Address site, returnEnd, tableAddress;
        boolean baseFound, byteBound;
        int slots, empty, ffffRun;              // slots scanned (incl. empty 0000 slots), empty slots, consecutive CT1d 0xFFFF run
        List<Integer> slotOf = new ArrayList<>(); // slot index of each target
        List<Integer> emptySlots = new ArrayList<>();
        int base, disp, table, cap = 64;
        int width = 2;                          // CT1a: 4 for far (offset, segment) slots
        int stride = 2;                         // CT1g: bytes between slots (> width for records of several pointers)
        String ct1;                             // CT1a/b/c/e provenance (null: plain J1)
        boolean allowPlaceholders;              // CT1e
        List<Integer> placeholderSlots = new ArrayList<>();
        Set<Address> placeholderTargets = new HashSet<>();
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
    /** J1r: quarantined site -> its mnemonic while decoded (matched on restoration). */
    final Map<Address, String> quarMn = new LinkedHashMap<>();

    record QuarRef(Address to, RefType type) { }
    void apply(TaskMonitor monitor) throws Exception {
        for (int pass = 0; pass < 16; pass++) {
            int before = done.size() + quarantined.size();
            applyPass(monitor);
            passes++;
            if (done.size() + quarantined.size() == before) break;
        }
        dropOverlayEndRefs();
    }

    /** J1o: delete computed references to the last byte of a bank overlay (no case entry can live
     *  there: the reference builds a cross-space body range that neither the listing nor the
     *  decompiler can follow). User and imported references stay; recovered tables never hold such
     *  targets (the reader skips them), so anything deleted here is an unproven guess. Idempotent. */
    void dropOverlayEndRefs() {
        for (Instruction ins : listing.getInstructions(true)) {
            if (!ins.getFlowType().isComputed()) continue;
            for (Reference ref : p.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                if (!ref.getReferenceType().isComputed()) continue;
                if (ref.getSource() == SourceType.USER_DEFINED || ref.getSource() == SourceType.IMPORTED) continue;
                if (!isOverlayEnd(ref.getToAddress())) continue;
                p.getReferenceManager().delete(ref);
                emit.accept(String.format("{\"rule\":\"J1o\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"REF_DELETED\"}",
                    ins.getAddress(), ref.getToAddress()));
            }
        }
    }

    /** J1o: the last byte of a bank overlay block. */
    boolean isOverlayEnd(Address a) {
        ghidra.program.model.mem.MemoryBlock b = mem.getBlock(a);
        return b != null && b.isOverlay() && a.getOffset() == b.getEnd().getOffset();
    }

    /** End of phase 2: quarantined sites that never recovered keep their guessed references deleted
     *  (retained code remains a hypothesis and existing conflicts remain; the deleted
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

    int passes, supersededRefs, quarantines, droppedRefs, deshadowed, restoredDispatches, restoredRecovered;

    /**
     * J1r: one restoration attempt per quarantined site whose own instruction is gone. Runs after the
     * J1/F1-F4/G1-U1 rounds, before J1l-finish finalizes the still-quarantined sites: a restored site
     * that recovers applies normally (and leaves quarantine); one that does not keeps its restored
     * decode and stays quarantined. Anything failing a check below stays unresolved.
     */
    void restoreClearedSites(TaskMonitor monitor) throws Exception {
        ghidra.program.model.lang.Register csval = p.getProgramContext().getRegister("csval");
        for (Address site : new ArrayList<>(quarantined.keySet())) {
            monitor.checkCancelled();
            if (listing.getInstructionAt(site) != null) continue;   // site alive: nothing to restore
            try {
                restoreOneSite(site, csval, monitor);
            } catch (Exception x) {
                errors++;
                emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}",
                    site, String.valueOf(x).replace('"', '\'')));
            }
        }
    }

    /** J1r body for one quarantined site (a failure here must not skip the remaining sites). */
    void restoreOneSite(Address site, ghidra.program.model.lang.Register csval, TaskMonitor monitor) throws Exception {
        String wantMn = quarMn.getOrDefault(site, "");
        if (!wantMn.equals("JMP") && !wantMn.equals("CALL")) {
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NOT_JMP_CALL\"}", site));
            return;
        }
        CodeUnit scu = listing.getCodeUnitAt(site);
        if (!(scu instanceof Data sd) || sd.isDefined()) {
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"SITE_DEFINED\"}", site));
            return;
        }
        // anchor: walk back over undefined bytes of the same block to a kept instruction whose
        // fall-through starts the gap; the anchor must sit in a function (live fall-through code)
        MemoryBlock sblk = mem.getBlock(site);
        Address g = site;
        Instruction anchor = null;
        for (int k = 0; k < 2048; k++) {
            Address b = g.previous();
            if (b == null) break;
            MemoryBlock bb = mem.getBlock(b);
            if (bb == null || !bb.equals(sblk)) break;
            CodeUnit u = listing.getCodeUnitContaining(b);
            if (u instanceof Data d && !d.isDefined()) { g = b; continue; }
            if (u instanceof Instruction pi && pi.getMaxAddress().equals(b)
                    && pi.getFallThrough() != null && pi.getFallThrough().equals(g)
                    && p.getFunctionManager().getFunctionContaining(pi.getAddress()) != null)
                anchor = pi;
            break;
        }
        if (anchor == null) {
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_ANCHOR\"}", site));
            return;
        }
        // trial decode from the anchor fall-through: fall-through only (any call, direct jump,
        // terminal or second computed branch bails), undefined bytes only, bounded; it must reach
        // the site with the same computed mnemonic
        int cs = csOf(anchor.getAddress());
        List<Address> span = new ArrayList<>();
        Address a = g;
        String fail = null;
        ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(p);
        for (int k = 0; k < 64; k++) {
            if (listing.getInstructionAt(a) != null) { fail = "REJOIN@" + a; break; }
            CodeUnit cu = listing.getCodeUnitAt(a);
            if (!(cu instanceof Data d) || d.isDefined()) { fail = "DEFINED@" + a; break; }
            ghidra.app.util.PseudoInstruction pi;
            try {
                ghidra.app.util.PseudoDisassemblerContext pc =
                    new ghidra.app.util.PseudoDisassemblerContext(p.getProgramContext());
                if (csval != null) pc.setFutureRegisterValue(a,
                    new ghidra.program.model.lang.RegisterValue(csval, java.math.BigInteger.valueOf(cs)));
                pi = pd.disassemble(a, pc, false);
            } catch (Exception x) { pi = null; }
            if (pi == null) { fail = "UNDECODABLE@" + a; break; }
            for (Address q = a.next(); q != null && q.compareTo(pi.getMaxAddress()) <= 0; q = q.next()) {
                CodeUnit c2 = listing.getCodeUnitAt(q);
                if (!(c2 instanceof Data d2) || d2.isDefined()) { fail = "OVERLAP@" + q; break; }
            }
            if (fail != null) break;
            span.add(a);
            if (pi.getFlowType().isComputed()) {
                if (!a.equals(site) || !pi.getMnemonicString().equalsIgnoreCase(wantMn)) fail = "SHAPE@" + a;
                a = null;
                break;
            }
            if (pi.getFlowType().isCall() || pi.getFlowType().isJump()
                    || pi.getFallThrough() == null || pi.getFlowType().isTerminal()) {
                fail = "BRANCH@" + a;
                break;
            }
            a = pi.getFallThrough();
        }
        if (fail != null || a != null) {
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}",
                site, fail == null ? "TOO_LONG" : fail));
            return;
        }
        // commit (must reproduce the trial: same bytes, same csval) and re-attempt once
        copyContext(anchor.getAddress(), g, cs);
        new DisassembleCommand(g, null, true).applyTo(p, monitor);
        Instruction now = listing.getInstructionAt(site);
        if (now == null || !now.getFlowType().isComputed() || !now.getMnemonicString().equalsIgnoreCase(wantMn)) {
            for (Address t : span) preserveHypothesis(site, t, "RESTORATION_MISMATCH");
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"MISMATCH\"}", site));
            return;
        }
        restoredDispatches++;
        newCode += span.size();
        // pull the dispatch into the anchor's function first: applySite writes the override and
        // pulls the targets only when the site sits in a function (it starts in the gap)
        Function af = p.getFunctionManager().getFunctionContaining(anchor.getAddress());
        if (af != null) CreateFunctionCmd.fixupFunctionBody(p, af, monitor);
        Rec r = recover(now);
        trimToBases(r);
        if (r == null || r.targets.isEmpty()) {
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"DISPATCH_RESTORED\",\"instructions\":%d}",
                site, span.size()));
            return;
        }
        try {
            if (!applySite(now, r, monitor)) {
                if (reported.add(site)) emitUnresolved(now, r);
                return;
            }
            done.add(site);
            quarantined.remove(site);
            reported.remove(site);
            restoredRecovered++;
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"RECOVERED\",\"instructions\":%d}",
                site, span.size()));
        } catch (Exception x) {
            errors++;
            emit.accept(String.format("{\"rule\":\"J1r\",\"site\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}",
                site, String.valueOf(x).replace('"', '\'')));
        }
    }

    /** TABLE_BOUNDARY trim for a lone re-attempted site (the pass loop's cross-site trim needs all Recs). */
    void trimToBases(Rec r) throws Exception {
        if (r == null || r.targets.isEmpty()) return;
        collectTableBases(TaskMonitor.DUMMY);
        for (Address tb : tableBases) {
            if (tb.equals(tableStart)) continue;
            long off;
            try { off = tb.subtract(tableStart); } catch (Exception e) { continue; }
            if (off <= 0 || off >= (long) r.stride * r.slots || off % r.stride != 0) continue;
            int lim = (int) (off / r.stride);
            r.slots = lim;
            r.targets = trimToSlots(r, lim);
            r.empty = (int) r.emptySlots.stream().filter(k -> k < lim).count();
            r.stop = "TABLE_BOUNDARY";
        }
    }
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
            // CT1a: a far call through a CS-relative operand is a table site; other far calls are not
            if (!(mn.equals("JMP") || mn.equals("CALL") || mn.equals("CALLF") && csPrefixed(ins))) continue;
            if (done.contains(ins.getAddress())) continue;
            seen.add(ins.getAddress());
            recs.put(ins, recover(ins));
        }
        trimToNextTable(recs.values());
        for (Map.Entry<Instruction, Rec> e : recs.entrySet()) {
            monitor.checkCancelled();
            try {
                if (e.getValue() == null || e.getValue().targets.isEmpty()) handleUnresolved(e.getKey(), e.getValue());
                else {
                    if (!applySite(e.getKey(), e.getValue(), monitor)) {
                        conflicts.put(e.getKey().getAddress(), e.getValue());   // proven end, conflicting targets (J1s)
                        if (reported.add(e.getKey().getAddress())) emitUnresolved(e.getKey(), e.getValue());
                        continue;
                    }
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

    /** TABLE_BOUNDARY: a recovered table ends where the next recovered table of the same space starts. */
    void trimToNextTable(Collection<Rec> recs) {
        for (Rec ra : recs) for (Rec rb : recs) {
            if (ra == null || rb == null || ra == rb || ra.targets.isEmpty() || rb.targets.isEmpty()) continue;
            // CS-relative offsets from separate recoveries are not spatial addresses.
            // Retain overlay identity and resolve segment bases before comparing table extents.
            if (ra.tableAddress == null || rb.tableAddress == null ||
                    !ra.tableAddress.getAddressSpace().equals(rb.tableAddress.getAddressSpace())) continue;
            long distance = rb.tableAddress.subtract(ra.tableAddress);
            // CT1g: a table base inside one of ra's records (another field of the same records) is no boundary
            if (ra.stride > ra.width && distance % ra.stride >= ra.width) continue;
            if (distance > 0 && distance < (long) ra.stride * ra.slots) {
                // keep only targets read from slots before the next table
                int lim = (int) (distance / ra.stride);
                ra.slots = lim;
                ra.targets = trimToSlots(ra, lim);
                ra.empty = (int) ra.emptySlots.stream().filter(k -> k < lim).count();
                ra.stop = "TABLE_BOUNDARY";
            }
        }
    }

    /** Rule J1u: instructions with a CS-relative operand decoded so far (J1f bases, kept across calls). */
    final Set<Address> csOperands = new HashSet<>();
    int beforeSwitch, beforeSwitchSites;

    /** J1u scope: an index bounded only by its byte width (J1c) or by an AND mask on the index register, with no
     *  conditional branch and no join (conditional or unconditional jump into the slice) between the instruction that
     *  loads the index from memory and the site. Stock switch recovery can then bound the index only by that width or
     *  mask (128 or 256 slots for a byte), so it reads past the real table. A branch or join after the load may guard
     *  the value for the stock recovery (CMP AL,n; JA before MOV BL,AL, or before an AND mask), so such sites stay
     *  with it; a join at the load cannot constrain a value read from memory there. The index is followed back
     *  through register copies (MOV BX,AX; MOV BL,AL) to its load; without a load in the slice, any branch or join
     *  in the whole slice counts as a possible guard. An equality exclusion (see {@link #equalityExclusion}) is no guard. */
    boolean unguardedByteIndex(Instruction site, Rec r) {
        if (r == null || !r.byteBound && r.maskOffsets == null) return false;
        String reg = r.idx == null ? null : (r.scaledBy == null ? r.idx : r.scaledBy);
        if (reg == null || reg.length() != 2) return false;
        List<Instruction> slice = new ArrayList<>(predecessors(site, 16));
        slice.add(0, site);
        for (int qi = 0; qi < slice.size(); qi++) {
            Instruction q = slice.get(qi);
            String t = q.toString().toUpperCase().replace(" ", "");
            String w = reg.matches("[ABCD][LHX]") ? reg.charAt(0) + "X" : reg;
            String lo = reg.charAt(1) == 'X' ? reg.charAt(0) + "L" : reg;
            String hi = reg.charAt(1) == 'X' ? reg.charAt(0) + "H" : null;
            if (hi != null && (t.equals("XOR" + hi + "," + hi) || t.equals("SUB" + hi + "," + hi)
                    || t.equals("MOV" + hi + ",0X0") || t.equals("CBW") && reg.equals("AX")
                    || t.startsWith("AND" + reg + ",0X") && (hex(t) & 0xFF00) == 0)) {
                reg = lo;                                                        // high byte cleared/derived: index lives in low byte
            }
            if (t.startsWith("MOV" + w + ",")) {
                String src = t.substring(t.indexOf(',') + 1);
                if (src.contains("[")) return true;                              // index word loaded here
                if (reg.equals(w) && src.matches("[ABCD]X|SI|DI|BP")) { reg = src; continue; }
                if (!reg.equals(w) && src.matches("[ABCD]X")) { reg = src.charAt(0) + "" + reg.charAt(1); continue; }
            }
            if (t.startsWith("MOV" + lo + ",") || t.startsWith("MOVZX" + w + ",")) {
                String src = t.substring(t.indexOf(',') + 1);
                if (src.contains("[")) return true;                              // index byte loaded here
                if (src.matches("[ABCD][LH]")) { reg = src; continue; }
            }
            if (q != site && q.getFlowType().isConditional() && !equalityExclusion(q, qi + 1 < slice.size() ? slice.get(qi + 1) : null, reg))
                return false;
            for (Reference ref : p.getReferenceManager().getReferencesTo(q.getAddress()))
                if (ref.getReferenceType().isJump() || ref.getReferenceType().isConditional()) return false;
        }
        return true;
    }

    /** An equality test that bounds no range for switch recovery, so it is no guard: JZ/JE on the flags of
     *  CMP x,imm, whose taken edge leaves the fall-through slice, excludes one value (e.g. an end marker FFFFh) on the
     *  path to the site; any JZ/JNZ on CMP reg,imm whose register does not overlap the index (e.g. another register
     *  or the disjoint high byte AH when the index is AL). JNZ/JNE on the index leaves the index constant on the path
     *  to the site, so it stays a possible guard (phase-2 J1 handles such a site). */
    static boolean equalityExclusion(Instruction branch, Instruction flags, String index) {
        String m = branch.getMnemonicString().toUpperCase();
        boolean jz = m.equals("JZ") || m.equals("JE"), jnz = m.equals("JNZ") || m.equals("JNE");
        if (!(jz || jnz) || flags == null) return false;
        java.util.regex.Matcher c = Pattern.compile("CMP([A-Z]{2}),-?0X[0-9A-F]+").matcher(flags.toString().toUpperCase().replace(" ", ""));
        if (!c.matches()) return false;
        if (!registersOverlap(c.group(1), index)) return true;         // disjoint register: the index is unconstrained
        return jz;                                                     // taken edge (equal) leaves the slice
    }

    /** Whether two registers share any bits: AX overlaps AL and AH, but AL and AH are disjoint; SI/DI/BP only match themselves. */
    static boolean registersOverlap(String a, String b) {
        if (a == null || b == null) return true;
        if (a.equals(b)) return true;
        boolean ga = a.matches("[ABCD][LHX]"), gb = b.matches("[ABCD][LHX]");
        return ga && gb && a.charAt(0) == b.charAt(0) && (a.charAt(1) == 'X' || b.charAt(1) == 'X');
    }

    /**
     * Rule J1u: apply J1 to the unguarded byte-index and masked JMP sites among newly decoded instructions before
     * stock Decompiler Switch Analysis reaches them. The site gets J1's computed references (the stock
     * analyzer skips a computed jump that already has computed references) and, when a function contains
     * it, J1's jump-table lock. Same recovery and stop rules as {@link #applyPass}; a site J1 cannot
     * prove yet is left untouched for the later passes (with a report line). Guarded sites are left to
     * stock recovery as before.
     */
    int applyBeforeSwitchAnalysis(AddressSetView set, TaskMonitor monitor) throws Exception {
        List<Instruction> sites = new ArrayList<>();
        for (Instruction ins : listing.getInstructions(set, true)) {
            monitor.checkCancelled();
            if (ins.toString().contains("CS:[")) csOperands.add(ins.getAddress());
            if (!ins.getFlowType().isJump() || !ins.getFlowType().isComputed()) continue;
            if (!ins.getMnemonicString().equalsIgnoreCase("JMP") || done.contains(ins.getAddress())) continue;
            sites.add(ins);
        }
        if (sites.isEmpty()) return 0;
        // J1f over every CS-relative operand decoded so far (incrementally collected; removed code drops out)
        tableBases.clear();
        for (Iterator<Address> it = csOperands.iterator(); it.hasNext(); ) {
            monitor.checkCancelled();
            Instruction ins = listing.getInstructionAt(it.next());
            if (ins == null || !addTableBase(ins)) it.remove();
        }
        Map<Instruction, Rec> recs = new LinkedHashMap<>();
        for (Instruction ins : sites) {
            Rec r = recover(ins);
            if (r == null) continue;
            String skip = !r.byteBound && r.maskOffsets == null ? null : !unguardedByteIndex(ins, r) ? "GUARDED"
                : r.targets.isEmpty() ? "NOT_PROVEN" : null;
            if (skip != null || r.targets.isEmpty() || !unguardedByteIndex(ins, r)) {
                if (skip != null)
                    emit.accept(String.format("{\"rule\":\"J1u\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"LEFT_TO_LATER_PASSES\",\"why\":\"%s\",\"shape\":\"%s\",\"stop\":\"%s\",\"slots\":%d}",
                        ins.getAddress(), ins, skip, r.shape, r.stop, r.slots));
                continue;
            }
            beforeSwitchSites++;
            recs.put(ins, r);
        }
        trimToNextTable(recs.values());
        int applied = 0;
        for (Map.Entry<Instruction, Rec> e : recs.entrySet()) {
            monitor.checkCancelled();
            try {
                if (!applySite(e.getKey(), e.getValue(), monitor)) { conflicts.put(e.getKey().getAddress(), e.getValue()); continue; }
            }
            catch (ghidra.util.exception.CancelledException c) { throw c; }
            catch (Exception x) {
                // reported, and the site stays open for the later J1 passes
                errors++;
                emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}", e.getKey().getAddress(), String.valueOf(x).replace('"', '\'')));
                ghidra.util.Msg.error(this, "J1u failed at " + e.getKey().getAddress() + ": " + x, x);
                continue;
            }
            done.add(e.getKey().getAddress());
            beforeSwitchTargets.put(e.getKey().getAddress(), new ArrayList<>(e.getValue().targets));
            applied++;
        }
        beforeSwitch += applied;
        return applied;
    }

    /** Sites whose proven table had conflicting targets (applySite refused, J1s), with the recovery that proved it. */
    final Map<Address, Rec> conflicts = new HashMap<>();
    /** Sites whose table this instance recovered (J1 or J1u). */
    final Set<Address> recoveredSites = new HashSet<>();
    /** J1u: site -> targets it applied before stock switch analysis. */
    final Map<Address, List<Address>> beforeSwitchTargets = new LinkedHashMap<>();
    int withdrawn;

    /**
     * Rule J1uw (end of phase 2, this instance = the phase-2 J1): a site J1u applied before stock switch analysis that
     * phase 2 cannot re-prove from the final listing loses what J1u wrote: its analysis-sourced computed references to
     * the J1u targets (observed targets stay) and its jump-table lock. The code decoded from those targets is kept and
     * tagged (H2, reason J1U_WITHDRAWN); the site is left to the later rules like any unresolved site.
     */
    String withdrawUnproven(WSJumpTables early, java.util.function.Consumer<String> log) throws Exception {
        if (early == null) return "J1uw J1u sites withdrawn 0";
        for (Map.Entry<Address, List<Address>> e : early.beforeSwitchTargets.entrySet()) {
            Address site = e.getKey();
            if (recoveredSites.contains(site)) continue;
            Instruction ins = listing.getInstructionAt(site);
            Set<Long> obs = observed.getOrDefault(site.getOffset(), Set.of());
            Set<Address> j1u = new HashSet<>(e.getValue());
            List<Address> gone = new ArrayList<>();
            for (Reference ref : p.getReferenceManager().getReferencesFrom(site)) {
                if (!ref.getReferenceType().isComputed() || ref.getSource() != SourceType.ANALYSIS) continue;
                if (!j1u.contains(ref.getToAddress()) || obs.contains(ref.getToAddress().getOffset())) continue;
                p.getReferenceManager().delete(ref);
                gone.add(ref.getToAddress());
            }
            int locks = 0;
            for (Symbol sw : p.getSymbolTable().getSymbols(site)) {
                if (!sw.getName().equals("switch") || !sw.getParentNamespace().getName().startsWith("jmp_")) continue;
                List<Symbol> labels = new ArrayList<>();
                boolean protectedNamespace = false;
                for (Symbol q : p.getSymbolTable().getSymbols(sw.getParentNamespace())) {
                    if (q.getSymbolType() != SymbolType.LABEL) protectedNamespace = true;
                    labels.add(q);
                }
                if (protectedNamespace) continue;
                for (Symbol q : labels) q.delete();
                locks++;
                break;
            }
            for (Address t : gone) preserveHypothesis(site, t, "J1U_WITHDRAWN");
            withdrawn++;
            String line = String.format("{\"rule\":\"J1uw\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"J1U_WITHDRAWN\",\"refs_deleted\":%d,\"locks_removed\":%d,\"j1u_targets\":%d}",
                site, ins, gone.size(), locks, j1u.size());
            emit.accept(line);
            log.accept(site + ": J1uw: phase 2 could not re-prove the table J1u applied before switch analysis; "
                + gone.size() + " references and " + locks + " lock withdrawn, decoded code kept as hypotheses");
        }
        return "J1uw J1u sites withdrawn " + withdrawn;
    }

    /**
     * Rule C (hazard tag): a JMP site J1 left unresolved whose byte-width index has no CMP guard, no AND
     * mask and no proven table end. Stock switch recovery bounds such an index only by its width and
     * reads handler bytes as further slots. The code is preserved (H2) and no table end is invented: the
     * site gets a WARNING bookmark, a log entry and a report line.
     */
    String tagHazards(java.util.function.Consumer<String> log) { return tagHazards(log, null); }

    /** @param early the J1u instance of this program (its target conflicts count too), or null */
    String tagHazards(java.util.function.Consumer<String> log, WSJumpTables early) {
        int tagged = 0, conflictTags = 0, failed = 0;
        for (Address site : new TreeSet<>(reported)) {
            try {
                Instruction ins = listing.getInstructionAt(site);
                if (ins == null || !ins.getMnemonicString().equalsIgnoreCase("JMP")) continue;
                // a proven end whose targets conflicted with existing code or data (J1s) when J1 or J1u tried it; the
                // recovery from that attempt is the evidence (later analysis, e.g. stock table data, may hide it now)
                Rec proven = conflicts.containsKey(site) ? conflicts.get(site) : early == null ? null : early.conflicts.get(site);
                Rec r = proven != null ? proven : recover(ins);  // null: not a CS-relative table site (rule C does not apply)
                if (r == null || !r.byteBound || !unguardedByteIndex(ins, r)) continue;
                boolean conflict = proven != null || !r.shape.contains("BYTE_INDEX_WEAK_STOP") && !r.targets.isEmpty();
                boolean weak = !conflict && r.shape.contains("BYTE_INDEX_WEAK_STOP");
                if (!weak && !conflict) continue;
                String note = weak
                    ? String.format("Rule C: unguarded byte-index CS jump table at %s (%s) has no range guard and "
                        + "no proven end (scan stopped on %s after %d slots); J1 left it unresolved. Stock switch recovery "
                        + "reads all %d index slots here.", r.tableAddress, r.bound, r.stop, r.slots, r.cap)
                    : String.format("Rule C: unguarded byte-index CS jump table at %s (%s) ends on %s after %d slots, "
                        + "but its targets conflict with existing code or data, so J1 left it unresolved (J1s). Stock "
                        + "switch recovery reads all %d index slots here.", r.tableAddress, r.bound, r.stop, r.slots, r.cap);
                p.getBookmarkManager().setBookmark(site, BookmarkType.WARNING, "WSJumpTableHazard", note);
                emit.accept(String.format("{\"rule\":\"C\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"%s\",\"table\":\"%s\",\"stop\":\"%s\",\"slots\":%d,\"cap\":%d}",
                    site, ins, weak ? "HAZARD_TAGGED" : "HAZARD_TAGGED_CONFLICT", r.tableAddress, r.stop, r.slots, r.cap));
                log.accept(site + ": " + note);
                tagged++;
                if (conflict) conflictTags++;
            }
            catch (RuntimeException e) {
                // one site must not end rule C for the others; reported per site, never silently
                failed++;
                emit.accept(String.format("{\"rule\":\"C\",\"site\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}", site, String.valueOf(e).replace('"', '\'')));
                log.accept(site + ": rule C failed at this site: " + e);
                p.getBookmarkManager().setBookmark(site, BookmarkType.ERROR, "WSJumpTableHazard", "Rule C failed at this site: " + e);
            }
        }
        hazards = tagged;
        return "C unguarded byte-index hazards tagged " + tagged + " (target conflicts " + conflictTags + ", site errors " + failed + ")";
    }
    int hazards;

    /** An unrecovered site: quarantine (J1l) when its guesses look conflicted, else reject. Quarantined
     *  sites stay out of `done' so every later pass re-attempts them with the guessed references removed. */
    void handleUnresolved(Instruction ins, Rec r) throws Exception {
        Address site = ins.getAddress();
        if (ins.getMnemonicString().equalsIgnoreCase("CALLF")) {   // CT1a: report only, never quarantine
            done.add(site);
            if (reported.add(site)) emitUnresolved(ins, r);
            return;
        }
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

    /** J1l: withdraw guessed references (observed targets stay), preserve/tag their code, re-attempt later. */
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
        quarMn.put(site, ins.getMnemonicString().toUpperCase());
        AddressSet preserved = new AddressSet();
        for (Address t : targets) preserved.add(preserveHypothesis(site, t, "QUARANTINED_REFERENCE"));
        quarantines++;
        List<String> goneAddrs = new ArrayList<>();
        for (QuarRef q : gone) goneAddrs.add("\"" + q.to() + "\"");
        emit.accept(String.format("{\"rule\":\"J1l\",\"site\":\"%s\",\"outcome\":\"QUARANTINED\",\"refs_deleted\":%d,\"hypothesis_bytes_preserved\":%d,\"deleted\":[%s]}",
            site, gone.size(), preserved.getNumAddresses(), String.join(",", goneAddrs)));
    }

    boolean applySite(Instruction ins, Rec r, TaskMonitor monitor) throws Exception {
        // J1y: resolve this site's table and observed targets in its own space. recover() runs for every
        // site of a pass before any applySite(), so the field still names the last recovered site's space.
        siteSpace = ins.getAddress().getAddressSpace();
        Set<Long> obs = observed.getOrDefault(ins.getAddress().getOffset(), Set.of());
        Set<Long> got = new HashSet<>();
        for (Address t : r.targets) got.add(t.getOffset());
        List<String> missing = new ArrayList<>();
        int cs = csOf(ins.getAddress());
        for (long o : obs) if (!got.contains(o)) {
            missing.add(String.format("%05x", o));
            // CT1a: a far target's segment is not the site's; use the canonical linear-window segment
            r.targets.add(r.width == 4 ? space.getAddress((int) ((o >> 4) & 0xF000), (int) (o & 0xFFFF))
                : seg(cs, (int) ((o - ((long) cs << 4)) & 0xFFFF)));
        }
        // J1z: a CALL table publishes no switch override; each slot is its own call entry. A conflicted slot
        // stays unresolved (its preserved interpretation untouched) without withholding the other proven slots.
        boolean callTable = ins.getMnemonicString().equalsIgnoreCase("CALL") || ins.getMnemonicString().equalsIgnoreCase("CALLF");
        List<Address> unresolvedTargets = new ArrayList<>();
        for (Address t : r.targets) {
            Instruction conflict = listing.getInstructionContaining(t);
            Data data = listing.getDefinedDataContaining(t);
            if ((conflict != null && !conflict.getAddress().equals(t))
                    || (data != null && !canDeshadow(t))) {
                if (conflict != null) offcut++;
                reportTargetConflict(ins, t);
                if (!callTable) return false;
                unresolvedTargets.add(t);
            }
        }
        r.targets.removeAll(unresolvedTargets);
        if (r.targets.isEmpty()) return false;
        boolean pushedCall = r.returnEnd != null && r.stop.equals("PUSH_RETURN_ENTRY");
        boolean isCall = callTable || pushedCall;
        if (pushedCall) {
            ins.setFlowOverride(FlowOverride.CALL);
            p.getBookmarkManager().setBookmark(ins.getAddress(), BookmarkType.ANALYSIS, "WSDecompilerBoundary",
                "J1x pushed near return represented as computed call; continuation=" + r.returnEnd);
            if (listing.getInstructionContaining(r.returnEnd) == null && listing.getDefinedDataContaining(r.returnEnd) == null) {
                copyContext(ins.getAddress(), r.returnEnd, cs);
                new DisassembleCommand(r.returnEnd, null, true).applyTo(p, monitor);
            }
            ins.setFallThrough(r.returnEnd);
        }
        List<Address> kept = new ArrayList<>();
        for (Address t : r.targets) {
            if (listing.getInstructionAt(t) == null) {
                if (listing.getInstructionContaining(t) != null) {
                    offcut++;
                    reportTargetConflict(ins, t);
                    if (!callTable) return false;
                    unresolvedTargets.add(t);
                    continue;
                }
                // single-byte data shadowing a proven target (a data pointer read the slot first):
                // cleared (user data and multi-byte data stay, keeping today's behavior there)
                if (listing.getDataAt(t) != null) deshadow(ins.getAddress(), t);
                // a fresh disassembly start has no flowing context: give the target the site's decode
                // context (CS-relative table -> same CS), else near branches resolve with CS=0 (into RAM);
                // CT1a: a far slot's own segment is the target's CS
                copyContext(ins.getAddress(), t, targetCs(r, t, cs));
                new DisassembleCommand(t, null, true).applyTo(p, monitor);
                if (listing.getInstructionAt(t) == null) {
                    reportTargetConflict(ins, t);
                    if (!callTable) return false;
                    unresolvedTargets.add(t);
                    continue;
                }
                newCode++;
            }
            kept.add(t);
            if (isCall && p.getFunctionManager().getFunctionAt(t) == null && listing.getInstructionAt(t) != null)
                new CreateFunctionCmd(t).applyTo(p, monitor);
        }
        if (kept.isEmpty()) return false;
        if (!unresolvedTargets.isEmpty()) {
            List<String> open = new ArrayList<>();
            for (Address t : unresolvedTargets) open.add("\"" + t + "\"");
            emit.accept(String.format("{\"rule\":\"J1z\",\"site\":\"%s\",\"outcome\":\"PARTIAL_CALL_TABLE\",\"published\":%d,\"unresolved\":[%s]}",
                ins.getAddress(), kept.size(), String.join(",", open)));
        }
        for (Address t : kept) ins.addMnemonicReference(t, isCall ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
        r.targets = kept;
        keptTargets.addAll(kept);
        // J1g: computed-flow references another analysis guessed for this site (Ghidra's switch recovery reads
        // past the table end, e.g. into the next table) are superseded by the proven table; user references stay.
        Set<Address> keep = new HashSet<>(kept);
        keep.addAll(unresolvedTargets);   // J1z: a proven slot left unresolved is not a superseded guess
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
        // Reference withdrawal is metadata; it is not proof against the decoded hypothesis.
        for (Address t : gone) preserveHypothesis(ins.getAddress(), t, "SUPERSEDED_REFERENCE");
        Function f = p.getFunctionManager().getFunctionContaining(ins.getAddress());
        if (!isCall && f != null) {
            // J1q: a jump-table override must stay in the site's address space: a foreign-bank target
            // sends the decompiler looking for code where none was decoded ("could not find op").
            // References keep every bank (they are evidence and harmless); only the override is filtered.
            List<Address> own = ownSpace(ins.getAddress(), r.targets);
            if (!own.isEmpty()) {
                new JumpTable(ins.getAddress(), new ArrayList<>(own), true, 0).writeOverride(f);
                CreateFunctionCmd.fixupFunctionBody(p, f, monitor);
            }
        }
        if (pushedCall && f != null) {
            CreateFunctionCmd.fixupFunctionBody(p, f, monitor);
            listing.getInstructionAt(ins.getAddress()).setFallThrough(r.returnEnd);
            emit.accept(String.format("{\"rule\":\"J1x\",\"site\":\"%s\",\"continuation\":\"%s\",\"outcome\":\"PUSHED_NEAR_CALL\"}", ins.getAddress(), r.returnEnd));
        }
        int dataSlots = 0;
        if (r.maskOffsets == null) {
            if (r.slots > 0 && WSInlineTables.words(p, seg(cs, r.table), ((r.slots - 1) * r.stride + r.width) / 2, ins.getAddress(), emit)) dataSlots = r.slots;
        } else {
            int scanned = 0;
            for (int offset : r.maskOffsets) {
                if (scanned++ >= r.slots) break;
                if (WSInlineTables.words(p, seg(cs, (r.table + offset) & 0xffff), r.width / 2, ins.getAddress(), emit)) dataSlots++;
            }
        }
        if (dataSlots > 0)
            emit.accept(String.format("{\"rule\":\"J1w\",\"site\":\"%s\",\"outcome\":\"TABLE_WORDS\",\"slots\":%d}", ins.getAddress(), dataSlots));
        // CT1c: slots after the observed span are H2 hypotheses: tagged on the slot, never decoded
        List<Address[]> hyp = spanHypotheses.remove(ins.getAddress());
        if (hyp != null) {
            spanSites++;
            for (Address[] h : hyp) {
                spanHypothesisSlots++;
                p.getBookmarkManager().setBookmark(h[0], BookmarkType.ANALYSIS, "WSHypothesis:CT1c:" + ins.getAddress() + ":" + h[1],
                    "CT1c H2 HYPOTHESIS: slot after the observed span of site " + ins.getAddress() + " (table end unproven: "
                    + r.ct1 + "); candidate target " + h[1] + " not decoded");
                emit.accept(String.format("{\"rule\":\"CT1c\",\"site\":\"%s\",\"slot\":\"%s\",\"target\":\"%s\",\"outcome\":\"HYPOTHESIS_NOT_DECODED\"}",
                    ins.getAddress(), h[0], h[1]));
            }
        }
        if (r.width == 4) ct1Far++;
        if (r.ct1 != null && r.ct1.contains("CT1b")) ct1Two++;
        observedMissing += missing.size();
        recovered++;
        recoveredSites.add(ins.getAddress());
        if (!r.baseAdds.isEmpty()) computedBases++;
        emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"insn\":\"%s\",\"outcome\":\"RECOVERED\",\"shape\":\"%s\",\"index\":\"%s\",\"scaled_by\":\"%s\",\"table\":\"%04x\",\"bound\":\"%s\",\"stop\":\"%s\",\"entries\":%d,\"superseded_refs\":%d,\"slots\":%d,\"empty_slots\":%d,\"observed\":%d,\"base_via\":\"%s\",\"width\":%d,\"ct1\":\"%s\",\"observed_missing_added\":%s}",
            ins.getAddress(), ins, r.shape, r.idx, r.scaledBy, r.table, r.bound.replace("\"", "'"), r.stop, r.targets.size(), superseded, r.slots, r.empty, obs.size(),
            r.baseVia.replace("\"", "'"), r.width, r.ct1 == null ? "-" : r.ct1.replace("\"", "'"),
            missing.isEmpty() ? "[]" : "[\"" + String.join("\",\"", missing) + "\"]"));
        return true;
    }

    /** CT1a: the CS a target runs with: its slot's segment for a far table, else the site's CS. */
    static int targetCs(Rec r, Address t, int cs) {
        return r.width == 4 && t instanceof SegmentedAddress sa ? sa.getSegment() : cs;
    }

    void copyContext(Address site, Address target, int cs) throws Exception {
        ProgramContext ctx = p.getProgramContext();
        ctx.setValue(ctx.getRegister("csval"), target, target, java.math.BigInteger.valueOf(cs));
        ghidra.program.model.lang.Register soc = ctx.getRegister("colorsoc");
        java.math.BigInteger v = soc == null ? null : ctx.getValue(soc, site, false);
        if (v != null) ctx.setValue(soc, target, target, v);
    }

    void reportTargetConflict(Instruction source, Address target) throws Exception {
        Address site = source.getAddress();
        String reason = listing.getInstructionContaining(target) != null
            || listing.getDefinedDataContaining(target) != null ? "PRESERVED_INTERPRETATION" : "TARGET_NOT_DECODED";
        emit.accept(String.format("{\"rule\":\"J1\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"UNRESOLVED_CONFLICT\",\"why\":\"%s\"}", site, target, reason));
        preserveHypothesis(site, target, "TARGET_CONFLICT");
        p.getBookmarkManager().setBookmark(site, BookmarkType.ANALYSIS,
            "WSJumpConflict:" + target, "J1 UNRESOLVED: target=" + target + "; reason=" + reason);
    }

    final AddressSet preservedHypotheses = new AddressSet();

    /** H2: reference withdrawal does not justify deleting instructions or functions. The category
     *  identifies the source site, so repeat analysis updates only our own provenance bookmark. */
    AddressSetView preserveHypothesis(Address site, Address target, String reason) throws Exception {
        AddressSet retained = new AddressSet();
        Instruction i = listing.getInstructionContaining(target);
        if (i == null) {
            emit.accept(String.format("{\"rule\":\"J1h\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"NO_CODE\",\"why\":\"%s\"}",
                site, target, reason));
            return retained;
        }
        Instruction source = listing.getInstructionAt(site);
        String sourceBytes = source == null ? "unknown" : HexFormat.of().formatHex(source.getBytes());
        boolean offcut = !i.getAddress().equals(target);
        while (i != null && !retained.contains(i.getAddress())) {
            Address start = i.getAddress();
            Function f = p.getFunctionManager().getFunctionContaining(start);
            String bytes = HexFormat.of().formatHex(i.getBytes());
            String support = executed(start.getOffset()) ? "EXECUTED" : "UNCONFIRMED";
            String detail = "J1h H2 PRESERVED: source=" + site + "; source_bytes=" + sourceBytes + "; target=" + target
                + "; reason=" + reason + "; bytes=" + bytes + "; evidence=" + support
                + "; incoming=" + p.getReferenceManager().getReferenceCountTo(start)
                + "; fall_from=" + i.getFallFrom() + "; function=" + (f == null ? "none" : f.getEntryPoint())
                + "; absence of evidence does not invalidate code";
            p.getBookmarkManager().setBookmark(start, BookmarkType.ANALYSIS,
                "WSHypothesis:" + site + ":" + sourceBytes + ":" + target + ":" + reason + ":" + bytes, detail);
            retained.add(start, i.getMaxAddress());
            emit.accept(String.format("{\"rule\":\"J1h\",\"site\":\"%s\",\"target\":\"%s\",\"start\":\"%s\",\"end\":\"%s\",\"bytes\":\"%s\",\"outcome\":\"PRESERVED\",\"why\":\"%s\",\"evidence\":\"%s\"}",
                site, target, start, i.getMaxAddress(), bytes, reason, support));
            Address next = i.getFallThrough();
            i = offcut || next == null ? null : listing.getInstructionAt(next);
        }
        preservedHypotheses.add(retained);
        return retained;
    }

    String summary() {
        return String.format("J1 jump/call table sites %d (passes %d): recovered %d (J1i register base %d), unresolved %d, quarantined %d (refs dropped %d), new code %d, observed targets added %d, offcut targets %d, deshadowed %d, superseded refs %d, hypothesis bytes preserved %d, dispatches restored %d (recovered %d), site errors %d, CT1 far %d two-register %d observed-span %d (hypothesis slots %d)",
            seen.size(), passes, recovered, computedBases, reported.size(), quarantines, droppedRefs, newCode, observedMissing, offcut, deshadowed, supersededRefs, preservedHypotheses.getNumAddresses(), restoredDispatches, restoredRecovered, errors,
            ct1Far, ct1Two, spanSites, spanHypothesisSlots);
    }

    /** J1n: only a single byte without user/imported symbols or references may be superseded by a
     *  structurally proven table target. RAM bytes without an image remain unknown. */
    boolean canDeshadow(Address t) {
        MemoryBlock block = mem.getBlock(t);
        if (block != null && !block.isOverlay() && block.getName().equals("RAM")) return false;
        Data data = listing.getDataAt(t);
        if (data == null || data.getLength() != 1) return false;
        for (Symbol symbol : p.getSymbolTable().getSymbols(t))
            if (symbol.getSource() == SourceType.USER_DEFINED || symbol.getSource() == SourceType.IMPORTED) return false;
        for (Reference ref : p.getReferenceManager().getReferencesTo(t))
            if (ref.getSource() == SourceType.USER_DEFINED || ref.getSource() == SourceType.IMPORTED) return false;
        return true;
    }

    /** Positive table evidence may supersede unprotected single-byte data; never instructions. */
    boolean deshadow(Address site, Address t) throws Exception {
        if (!canDeshadow(t)) return false;
        List<Reference> refs = new ArrayList<>();
        p.getReferenceManager().getReferencesTo(t).forEachRemaining(refs::add);
        for (Reference r : refs)
            if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) return false;
        // Incoming references are evidence from their own source instructions. Clearing
        // target data, or failing to decode it, cannot invalidate an encoded transfer.
        listing.clearCodeUnits(t, t, false);
        deshadowed++;
        emit.accept(String.format("{\"rule\":\"J1n\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"DESHADOWED\",\"refs_deleted\":0,\"refs_preserved\":%d}", site, t, refs.size()));
        return true;
    }

    /** Rule J1m (post-analysis, after the merges): at a site quarantined by J1l that never recovered, re-delete
     *  any guessed reference a later analysis re-derived (by the QUARANTINED address list; observed and user
     *  references stay) and lock the switch to its observed targets with a stored jump-table override. With no
     *  observed target the site stays an opaque indirect branch. Unresolved sites with rule-E3 observed targets
     *  get the same lock (their phase-1 override may never have been written: E3 runs before any function
     *  contains the site): other analysis computed references are deleted, observed targets stay. Recovered
     *  jump sites are re-locked as well (rule J1p: a merge recreates the function and strips the recovery
     *  override, after which the decompiler's own unbounded table read follows garbage cross-space): the lock
     *  is the union of observed and recovered targets in the site's space with code, no reference is deleted.
     *  Every lock is filtered to the site's address space (rule J1q: a foreign-bank override target sends the
     *  decompiler where nothing was decoded). Idempotent. Returns a summary. */
    public static String lockSwitches(Program p, List<String> evidence, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        pruneStaleOverrides(p, emit, monitor);
        AddressFactory af = p.getAddressFactory();
        Set<Address> recovered = new HashSet<>();
        Set<Address> recoveredJump = new LinkedHashSet<>();
        Set<Address> unresolved = new LinkedHashSet<>();
        Map<Address, Set<Address>> quar = new LinkedHashMap<>();
        Map<Address, Set<Address>> e3obs = new LinkedHashMap<>();
        List<String> observedEvidence = new ArrayList<>(evidence);
        observedEvidence.addAll(WSObservedSwitches.evidence(p));
        for (String l : observedEvidence) {
            if (l.contains("\"rule\":\"J1\"") && l.contains("\"outcome\":\"RECOVERED\"")) {
                Address s = addrField(l, "\"site\":\"", af);
                if (s != null) {
                    recovered.add(s);
                    if (l.contains("\"insn\":\"JMP")) recoveredJump.add(s);
                }
            } else if (l.contains("\"rule\":\"J1\"") && l.contains("\"outcome\":\"UNRESOLVED\"")) {
                Address s = addrField(l, "\"site\":\"", af);
                if (s != null) unresolved.add(s);
            } else if (l.contains("\"rule\":\"J1l\"") && l.contains("\"outcome\":\"QUARANTINED\"")) {
                Address s = addrField(l, "\"site\":\"", af);
                Set<Address> del = addrList(l, "\"deleted\":[", af);
                if (s != null && del != null) quar.put(s, del);
            } else if (l.contains("\"rule\":\"E3\"") && l.contains("\"targets\":[")) {
                Address s = addrField(l, "\"site\":\"", af);
                Set<Address> obs = addrList(l, "\"targets\":[", af);
                if (s != null && obs != null) {
                    e3obs.computeIfAbsent(s, k -> new TreeSet<>()).addAll(obs);
                    WSObservedSwitches.remember(p, s, obs);
                }
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
            if (ins == null || !ins.getFlowType().isComputed() || !ins.getFlowType().isJump()) {
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
            obs = ownSpace(site, obs);
            if (obs.isEmpty()) {
                opaqueJump(p, ins, emit);
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
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"LOCKED\",\"refs_deleted\":%d,\"cases\":%d,\"src\":\"quarantined\"}", site, n, obs.size()));
            } catch (InvalidInputException x) {
                skipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}", site, x.getMessage().replace("\"", "'")));
            }
        }
        int elocked = 0, eopaque = 0, eskipped = 0;
        // J2: an observed site needs no preceding static UNRESOLVED report.
        for (Address site : e3obs.keySet()) {
            monitor.checkCancelled();
            if (recovered.contains(site) || quar.containsKey(site)) continue;
            Set<Address> obs = e3obs.get(site);
            if (obs == null || obs.isEmpty()) continue;
            Instruction ins = listing.getInstructionAt(site);
            if (ins == null || !ins.getFlowType().isComputed() || !ins.getFlowType().isJump()) {
                eskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_SITE\"}", site));
                continue;
            }
            boolean protectedFlow = Arrays.stream(rm.getReferencesFrom(site)).anyMatch(r -> r.getReferenceType().isComputed()
                && (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED));
            if (protectedFlow) { eskipped++; continue; }
            int n = 0;
            for (Reference r : rm.getReferencesFrom(site)) {
                if (!r.getReferenceType().isComputed() || obs.contains(r.getToAddress())) continue;
                if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) continue;
                rm.delete(r);
                n++;
            }
            cleaned += n;
            List<Address> withCode = new ArrayList<>();
            for (Address t : ownSpace(site, obs)) if (listing.getInstructionAt(t) != null) withCode.add(t);
            if (withCode.isEmpty()) {
                opaqueJump(p, ins, emit);
                eopaque++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"OPAQUE\",\"refs_deleted\":%d}", site, n));
                continue;
            }
            Function f = fm.getFunctionContaining(site);
            if (f == null) {
                eskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_FUNCTION\"}", site));
                continue;
            }
            try {
                for (Address target : withCode)
                    ins.addMnemonicReference(target, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
                new JumpTable(site, new ArrayList<>(withCode), true, 0).writeOverride(f);
                // Retain detached executed components for A2 to split after locking.
                // A destructive fixup here would discard their only body membership.
                if (f.getSymbol().getSource() != SourceType.USER_DEFINED
                        && f.getSignatureSource() != SourceType.USER_DEFINED
                        && f.getSignatureSource() != SourceType.IMPORTED) {
                    AddressSet reachable = new AddressSet(CreateFunctionCmd.getFunctionBody(p, f.getEntryPoint(), monitor));
                    for (Function other : fm.getFunctions(true))
                        if (!other.equals(f)) reachable.delete(other.getBody());
                    AddressSet expanded = new AddressSet(f.getBody());
                    expanded.add(reachable);
                    if (!expanded.equals(f.getBody())) f.setBody(expanded);
                }
                elocked++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"LOCKED\",\"refs_deleted\":%d,\"cases\":%d,\"src\":\"observed\"}", site, n, withCode.size()));
            } catch (InvalidInputException x) {
                eskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}", site, x.getMessage().replace("\"", "'")));
            }
        }
        // J1p: re-lock J1-recovered jump sites. Recovery wrote its override before the merges; a merge
        // that recreates the function strips it, and the decompiler's own unbounded table read then
        // follows garbage cross-space. The lock is the union of observed (E3) and recovered (reference)
        // targets in the site's space with code; references are proven here, so none are deleted.
        int rlocked = 0, rskipped = 0;
        // (quarantined-then-recovered sites are locked here too: the quarantine pass skips them
        // because their references are proven, but the merge may still have stripped the override.)
        for (Address site : recoveredJump) {
            monitor.checkCancelled();
            Instruction ins = listing.getInstructionAt(site);
            if (ins == null || !ins.getFlowType().isComputed() || !ins.getFlowType().isJump()) {
                rskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_SITE\"}", site));
                continue;
            }
            Set<Address> cand = new LinkedHashSet<>();
            Set<Address> e3 = e3obs.get(site);
            if (e3 != null) cand.addAll(e3);
            for (Reference r : rm.getReferencesFrom(site)) {
                if (r.getReferenceType().isComputed()) cand.add(r.getToAddress());
            }
            List<Address> cases = new ArrayList<>();
            for (Address t : ownSpace(site, cand)) if (listing.getInstructionAt(t) != null) cases.add(t);
            if (cases.isEmpty()) {
                rskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_CASES\"}", site));
                continue;
            }
            Function f = fm.getFunctionContaining(site);
            if (f == null) {
                rskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"NO_FUNCTION\"}", site));
                continue;
            }
            try {
                new JumpTable(site, new ArrayList<>(cases), true, 0).writeOverride(f);
                rlocked++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"LOCKED\",\"refs_deleted\":0,\"cases\":%d,\"src\":\"recovered\"}", site, cases.size()));
            } catch (InvalidInputException x) {
                rskipped++;
                emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}", site, x.getMessage().replace("\"", "'")));
            }
        }
        return String.format("J1m jump-table lock: quarantined sites %d, re-derived refs deleted %d, switches locked %d, opaque %d, skipped %d (unresolved+E3 locked %d, opaque %d, skipped %d, recovered locked %d, skipped %d)",
            quar.size(), cleaned, locked + elocked + rlocked, opaque + eopaque, skipped + eskipped + rskipped, elocked, eopaque, eskipped, rlocked, rskipped);
    }

    /** Function splits and opaque transfers can invalidate a previously stored switch.
     * Native recovery still reads disconnected namespaces outside the owner's body,
     * which can crash the decompiler. A split prefix may still reach a switch by
     * fallthrough, so keep its finite view. Remove invalid labels only in automatic
     * functions; listing references, instruction bytes and valid overrides stay intact. */
    public static String pruneStaleOverrides(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        SymbolTable symbols = p.getSymbolTable();
        List<Symbol> switches = new ArrayList<>();
        for (Symbol s : symbols.getAllSymbols(true))
            if (s.getName().equals("switch") && s.getParentNamespace().getName().startsWith("jmp_")) switches.add(s);
        int removed = 0;
        for (Symbol s : switches) {
            monitor.checkCancelled();
            Namespace ns = s.getParentNamespace();
            Namespace owner = ns.getParentNamespace().getParentNamespace();
            if (!(owner instanceof Function f) || f.getSymbol().getSource() == SourceType.USER_DEFINED
                || f.getSignatureSource() == SourceType.USER_DEFINED || f.getSignatureSource() == SourceType.IMPORTED) continue;
            Instruction ins = p.getListing().getInstructionAt(s.getAddress());
            String why = ins == null ? "NO_INSTRUCTION"
                : !ins.getFlowType().isJump() || !ins.getFlowType().isComputed() ? "NOT_COMPUTED_JUMP"
                : !f.getBody().contains(s.getAddress()) && !directlyReachable(p, f, s.getAddress()) ? "DISCONNECTED_SITE" : null;
            if (why == null) continue;
            List<Symbol> labels = new ArrayList<>();
            boolean protectedNamespace = false;
            for (Symbol q : symbols.getSymbols(ns)) {
                if (q.getSymbolType() != SymbolType.LABEL) protectedNamespace = true;
                labels.add(q);
            }
            if (protectedNamespace) continue;
            Address site = s.getAddress();
            for (Symbol q : labels) q.delete();
            removed++;
            emit.accept(String.format("{\"rule\":\"J1v\",\"site\":\"%s\",\"function\":\"%s\",\"outcome\":\"STALE_OVERRIDE_REMOVED\",\"why\":\"%s\"}", site, f.getEntryPoint(), why));
        }
        return "J1v stale switch overrides removed " + removed;
    }

    private static boolean directlyReachable(Program p, Function f, Address target) {
        ArrayDeque<Address> queue = new ArrayDeque<>();
        Set<Address> seen = new HashSet<>();
        queue.add(f.getEntryPoint());
        while (!queue.isEmpty()) {
            Address a = queue.removeFirst();
            if (a.equals(target)) return true;
            if (!seen.add(a)) continue;
            Instruction i = p.getListing().getInstructionAt(a);
            if (i == null) continue;
            Address ft = i.getFallThrough();
            if (ft != null) queue.add(ft);
            if (i.getFlowOverride() == FlowOverride.NONE && i.getFlowType().isJump()
                && !i.getFlowType().isComputed()) for (Address t : i.getFlows()) queue.add(t);
        }
        return false;
    }

    /** An empty table override cannot be serialized. Keep a rejected indirect jump
     * opaque in the native decompiler too, which otherwise recovers the same guesses
     * again independently of listing references and stored function bodies. */
    private static void opaqueJump(Program p, Instruction ins, Consumer<String> emit) {
        Function f = p.getFunctionManager().getFunctionContaining(ins.getAddress());
        if (!ins.getFlowType().isJump() || ins.getFlowOverride() != FlowOverride.NONE
            || f != null && (f.getSymbol().getSource() == SourceType.USER_DEFINED
                || f.getSignatureSource() == SourceType.USER_DEFINED
                || f.getSignatureSource() == SourceType.IMPORTED)) return;
        ins.setFlowOverride(FlowOverride.CALL_RETURN);
        p.getBookmarkManager().setBookmark(ins.getAddress(), BookmarkType.ANALYSIS, "WSDecompilerBoundary",
            "Rejected indirect jump retained as opaque tail transfer (J1m)");
        emit.accept(String.format("{\"rule\":\"J1m\",\"site\":\"%s\",\"outcome\":\"OPAQUE_TAIL_TRANSFER\"}", ins.getAddress()));
    }

    /** J1q: the targets that may go into a jump-table override at a site: only the site's own
     *  address space. Foreign-bank or cross-space targets make the decompiler follow flows into
     *  spaces where nothing was decoded ("could not find op", cross-space block errors). */
    static List<Address> ownSpace(Address site, Collection<Address> targets) {
        List<Address> own = new ArrayList<>();
        for (Address t : targets) if (t.getAddressSpace().equals(site.getAddressSpace())) own.add(t);
        return own;
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

    /**
     * J1t: demote over-glued case pseudo-functions. Stock switch analysis commits one function per
     * recovered case, but when its case recovery over-approximates (reads past the table end) the
     * committed "function" glues several true cases together. A case-block that jumps back to the
     * switch parent is not a function at all (decompiling it as one inlines the parent's switch
     * tail); only a RET-terminated span is function-shaped. So per span: RET/RETF-terminated spans
     * are kept as functions, JMP-terminated spans are demoted (no function; the switch parent
     * absorbs them through the locked switch flows). The site is re-locked to its current
     * computed-targets-to-code (J1m pattern; best-effort, audited): without the lock the decompiler
     * re-derives stock's over-approximation and every span truncates.
     */
    public static String demoteGluedCases(Program p, List<String> evidence, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        AddressFactory af = p.getAddressFactory();
        Set<Address> sites = new LinkedHashSet<>();
        for (String line : evidence) {
            if (!line.contains("\"rule\":\"J1\"") || !line.contains("\"outcome\":\"RECOVERED\"")) continue;
            int ii = line.indexOf("\"insn\":\"");
            if (ii < 0 || !line.startsWith("JMP", ii + 8)) continue;
            Address a = addrField(line, "\"site\":\"", af);
            if (a != null) sites.add(a);
        }
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        int split = 0, kept = 0, dropped = 0;
        for (Address s : sites) {
            monitor.checkCancelled();
            Instruction ins = listing.getInstructionAt(s);
            if (ins == null || !ins.getFlowType().isComputed() || !"JMP".equalsIgnoreCase(ins.getMnemonicString()))
                continue;
            List<Address> targets = new ArrayList<>();
            for (Reference r : p.getReferenceManager().getReferencesFrom(s)) {
                if (!r.getReferenceType().isComputed()) continue;
                if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) continue;
                if (!targets.contains(r.getToAddress())) targets.add(r.getToAddress());
            }
            for (Address t : targets) {
                Function f = fm.getFunctionAt(t);
                if (f == null) continue;
                List<Address> in = new ArrayList<>();
                for (Address u : targets) {
                    if (!u.equals(t) && f.getBody().contains(u)) in.add(u);
                }
                if (in.isEmpty()) continue;
                List<Address> pts = new ArrayList<>(in);
                pts.add(t);
                Collections.sort(pts);
                if (!pts.get(0).equals(t)) {
                    emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"BACKWARD\"}",
                        s, t));
                    continue;
                }
                Set<Address> ptset = new HashSet<>(pts);
                String why = null;
                for (AddressRange r : f.getBody()) {
                    if (!ptset.contains(r.getMinAddress())) { why = "EXTRA_RANGE@" + r.getMinAddress(); break; }
                }
                for (int i = 0; why == null && i < pts.size(); i++) {
                    Address lo = pts.get(i);
                    Address hi = (i + 1 < pts.size()) ? pts.get(i + 1) : null;
                    Instruction last = null;
                    InstructionIterator it = listing.getInstructions(f.getBody(), true);
                    while (it.hasNext()) {
                        Instruction c = it.next();
                        if (c.getAddress().compareTo(lo) < 0) continue;
                        if (hi != null && c.getAddress().compareTo(hi) >= 0) break;
                        last = c;
                    }
                    if (last == null || last.getFallThrough() != null) why = "NOT_TERMINAL@" + lo;
                }
                if (why != null) {
                    emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}",
                        s, t, why));
                    continue;
                }
                // Per-span verdict from the terminal instruction (the partition check proved every
                // span non-empty and terminal): RET/RETF-terminated spans are real functions and kept;
                // JMP-terminated spans are case-blocks of the switch parent and demoted (no function;
                // the parent absorbs them through the locked switch flows at decompile).
                List<Address> keep = new ArrayList<>(), drop = new ArrayList<>();
                for (int i = 0; i < pts.size(); i++) {
                    Address lo = pts.get(i);
                    Address hi = (i + 1 < pts.size()) ? pts.get(i + 1) : null;
                    Instruction last = null;
                    InstructionIterator it = listing.getInstructions(f.getBody(), true);
                    while (it.hasNext()) {
                        Instruction c = it.next();
                        if (c.getAddress().compareTo(lo) < 0) continue;
                        if (hi != null && c.getAddress().compareTo(hi) >= 0) break;
                        last = c;
                    }
                    String mn = last.getMnemonicString().toUpperCase();
                    if (mn.equals("RET") || mn.equals("RETF")) keep.add(lo);
                    else drop.add(lo);
                }
                // Re-lock set (J1m pattern): current computed targets to code. The partition check
                // already proved this target set guess-free (a guessed target mid-block breaks the
                // terminal-span condition). Best-effort: the demote stands even unlocked (the listing
                // code is unchanged, so the decompiler re-derives exactly what it derived before).
                Function sf = fm.getFunctionContaining(s);
                List<Address> lockCases = new ArrayList<>();
                for (Reference r : p.getReferenceManager().getReferencesFrom(s)) {
                    if (!r.getReferenceType().isComputed()) continue;
                    if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) continue;
                    if (listing.getInstructionAt(r.getToAddress()) == null) continue;
                    if (!lockCases.contains(r.getToAddress())) lockCases.add(r.getToAddress());
                }
                lockCases = ownSpace(s, lockCases);   // J1q: every lock stays in the site's space
                String oldName = f.getName();
                if (WSRamCode.isRam(p, t)) continue;
                AddressSetView oldBody = new AddressSet(f.getBody());
                if (!fm.removeFunction(t)) {
                    emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"REMOVE_FAILED\"}",
                        s, t));
                    continue;
                }
                // strip stale stock case labels throughout the glued ranges (the decompiler
                // renders leftover case labels as goto-labels inside whatever absorbs the spans)
                int stripped = 0;
                for (AddressRange r : oldBody) {
                    Address a = r.getMinAddress();
                    while (a != null && a.compareTo(r.getMaxAddress()) <= 0) {
                        stripped += stripCaseNames(p, a);
                        a = a.next();
                    }
                }
                Namespace global = p.getGlobalNamespace();
                List<Address> made = new ArrayList<>();
                try {
                    for (Address lo : keep) {
                        int i = pts.indexOf(lo);
                        Address end = (i + 1 < pts.size()) ? pts.get(i + 1).previous() : oldBody.getMaxAddress();
                        if (end == null || end.compareTo(lo) < 0) continue;
                        // exact sub-body (no fixup: the partition check proved each span terminal and
                        // every range starting at a target); explicit global namespace, because stock
                        // case labels under switch-override namespaces break entry-based creation
                        AddressSet sub = new AddressSet(oldBody.intersect(new AddressSet(lo, end)));
                        if (sub.isEmpty()) continue;
                        String name = "FUN_" + lo.toString().replaceAll("[^A-Za-z0-9_]", "_");
                        fm.createFunction(name, global, lo, sub, SourceType.ANALYSIS);
                        made.add(lo);
                    }
                } catch (Exception x) {
                    emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}",
                        s, t, String.valueOf(x).replace('"', '\'')));
                    continue;
                }
                if (made.size() != keep.size()) {
                    emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"PARTIAL\",\"kept\":%d,\"demoted\":%d}",
                        s, t, made.size(), drop.size()));
                    continue;
                }
                int locked = 0;
                if (sf != null && !lockCases.isEmpty()) {
                    try {
                        new JumpTable(s, new ArrayList<>(lockCases), true, 0).writeOverride(sf);
                        locked = lockCases.size();
                    } catch (Exception x) {
                        emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"LOCK_FAILED\",\"error\":\"%s\"}",
                            s, t, String.valueOf(x).replace('"', '\'')));
                    }
                }
                // all-demoted: absorb the blocks into the switch parent (keeps executed code
                // in-function; skipped when spans were kept as functions, which fixup would eat)
                if (made.isEmpty() && sf != null) {
                    try {
                        ghidra.app.cmd.function.CreateFunctionCmd.fixupFunctionBody(p, sf, monitor);
                    } catch (Exception x) {
                        emit.accept(String.format("{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"FIXUP_FAILED\",\"error\":\"%s\"}",
                            s, t, String.valueOf(x).replace('"', '\'')));
                    }
                }
                for (Address q : made) {
                    try {
                        p.getBookmarkManager().setBookmark(q, BookmarkType.ANALYSIS, "J1t",
                            "kept function-shaped span of demoted " + oldName + "@" + t + " (site " + s + ")");
                    } catch (Exception x) { }
                }
                split++;
                kept += made.size();
                dropped += drop.size();
                emit.accept(String.format(
                    "{\"rule\":\"J1t\",\"site\":\"%s\",\"entry\":\"%s\",\"outcome\":\"DEMOTED\",\"was\":\"%s\",\"demoted\":%d,\"kept\":%d,\"stripped\":%d,\"cases\":%d}",
                    s, t, oldName.replace('"', '\''), drop.size(), made.size(), stripped, locked));
            }
        }
        return String.format("demote %d over-glued case functions (%d spans demoted, %d kept)", split, dropped, kept);
    }

    /**
     * J1t: delete stock switch-case labels at one address. Besides caseD_ names, this removes labels
     * in stock switch-override namespaces (namespace path containing "switchD", any source): the
     * stock switch analysis commits its case_N labels there; a function symbol cannot live under
     * such a namespace, so entry-based creation fails while they stand, and leftover case labels
     * render as goto-labels inside whatever absorbs the spans. Human labels live in global/function
     * namespaces, never under switchD_, so the path condition keeps them safe. Returns the number
     * deleted (audited on the J1t line).
     */
    static int stripCaseNames(Program p, Address a) {
        int n = 0;
        for (Symbol y : p.getSymbolTable().getSymbols(a)) {
            boolean caseD = y.getName().contains("caseD")
                && y.getSource() != SourceType.USER_DEFINED && y.getSource() != SourceType.IMPORTED;
            boolean switchNs = false;
            for (ghidra.program.model.symbol.Namespace ns = y.getParentNamespace(); ns != null;
                    ns = ns.getParentNamespace()) {
                if (ns.getName() != null && ns.getName().contains("switchD")) { switchNs = true; break; }
            }
            if (!caseD && !switchNs) continue;
            try { if (y.delete()) n++; } catch (Exception x) { }
        }
        return n;
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

    /** Display addresses may use a canonical bank segment even when code runs with a
     * different CS. Use the instruction's stored CPU context for CS-relative tables. */
    int csOf(Address a) {
        ghidra.program.model.lang.Register csval = p.getProgramContext().getRegister("csval");
        java.math.BigInteger v = csval == null ? null : p.getProgramContext().getValue(csval, a, false);
        if (v != null) return v.intValue();
        return a instanceof SegmentedAddress sa ? sa.getSegment() : (int) (a.getOffset() >> 4) & 0xF000;
    }

    Rec recover(Instruction site) {
        siteSpace = site.getAddress().getAddressSpace();
        Rec r = new Rec();
        r.site = site.getAddress();
        spanHypotheses.remove(r.site);
        int cs = csOf(site.getAddress());
        List<Instruction> back = predecessors(site, 16);
        boolean far = site.getMnemonicString().equalsIgnoreCase("CALLF");
        if (far) { r.width = 4; r.stride = 4; }
        Matcher mm = (far ? FARMEM : MEM).matcher(site.toString());
        if (far && !csPrefixed(site)) { r.shape = "FAR_NOT_CS"; return r; }
        if (mm.find()) { r.shape = far ? "FAR_MEM" : "MEM"; r.idx = mm.group(1).toUpperCase(); r.disp = disp(mm); if (far) r.ct1 = "CT1a"; }
        else if (TWOREG.matcher(site.toString()).find() && (far || site.toString().contains("CS:["))) {
            r.shape = far ? "FAR_MEM2" : "MEM2";
            if (!twoRegister(site, back, r)) return r;
            if (far) r.ct1 = "CT1a+" + r.ct1;
        }
        else if (far) { r.shape = "FAR_SHAPE"; return r; }
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
            List<Instruction> loadBack = predecessors(load, 16);
            if (lm.find()) { r.shape = "REG"; r.idx = lm.group(1).toUpperCase(); r.disp = disp(lm); }
            else if (load.toString().contains("CS:[") && TWOREG.matcher(load.toString()).find()) {
                r.shape = "REG2";
                if (!twoRegister(load, loadBack, r)) return r;
            }
            else { r.shape = "REG_NOT_CS_TABLE"; return r; }
            back = loadBack;
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
        if (r.width == 4) {
            // CT1g: the index scale is the record stride; a scale above the slot width means records of several
            // far pointers, of which this site reads one field (its offset is already in the base)
            int sh = scaleShift(back, ix);
            if (sh <= 8 && (1 << sh) > r.width) {
                r.stride = 1 << sh;
                r.ct1 = (r.ct1 == null ? "" : r.ct1 + "+") + "CT1g stride " + r.stride;
            }
        }
        r.table = (r.base + r.disp) & 0xFFFF;
        tableStart = seg(cs, r.table);
        r.tableAddress = tableStart;
        r.returnEnd = pushedContinuation(site, cs);
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
        r.allowPlaceholders = true;
        scanTable(cs, r);
        if (!bounded && r.stop.equals("BOUND") && r.cap == 64) {
            // CT1f: all 64 slots of an unbounded index were plausible; scan on (up to 256) and keep the longer table
            // only if it then ends on a strong stop, as J1b requires; otherwise the 64-slot result stands (weak)
            resetScan(r); r.cap = 256; scanTable(cs, r);
            if (STRONG.contains(r.stop)) r.ct1 = (r.ct1 == null ? "" : r.ct1 + "+") + "CT1f extended scan ended by " + r.stop + " at slot " + r.slots;
            else { resetScan(r); r.cap = 64; scanTable(cs, r); }
        }
        if (!r.placeholderTargets.isEmpty()) {
            // CT1e: placeholders are valid only when the table ends exactly at their (common) target
            Address end = r.stop.equals("OWN_TARGET") ? seg(cs, (r.table + r.stride * r.slots) & 0xFFFF) : null;
            boolean ok = end != null;
            for (Address t : r.placeholderTargets) if (!t.equals(end)) ok = false;
            if (ok) {
                r.ct1 = (r.ct1 == null ? "" : r.ct1 + "+") + "CT1e " + r.placeholderSlots.size() + " placeholder slots -> table end " + end;
                for (int k : r.placeholderSlots)
                    emit.accept(String.format("{\"rule\":\"CT1e\",\"site\":\"%s\",\"slot\":%d,\"target\":\"%s\",\"outcome\":\"PLACEHOLDER_NOT_DECODED\"}", r.site, k, end));
            } else {
                // not proven: rescan as plain J1 (the first placeholder is the weak UNDECODABLE stop again)
                resetScan(r); r.allowPlaceholders = false;
                scanTable(cs, r);
            }
        }
        boolean strong = r.stop.equals("EXECUTED_CODE") || r.stop.equals("TABLE_BOUNDARY") || r.stop.equals("FUNCTION_ENTRY") || r.stop.equals("DIRECT_CALL_ENTRY")
            || r.stop.equals("TABLE_BASE") || r.stop.equals("OWN_TARGET") || r.stop.equals("PUSH_RETURN_ENTRY");
        // J1b: without an index bound only a strong end (next slot executed / next recovered table) proves
        // the extent; running into data or the cap does not (observed targets stay via rule E3).
        if (!bounded && !strong) {
            r.shape += "/UNBOUNDED_WEAK_STOP:" + r.stop;
            observedSpan(r);
        }
        // J1c: a byte-width bound is proven only by a strong stop or by reaching the bound itself.
        else if (r.byteBound && !strong && !r.stop.equals("BOUND")) {
            r.shape += "/BYTE_INDEX_WEAK_STOP:" + r.stop;
            observedSpan(r);
        }
        return r;
    }

    /** CT1c slots after the observed span, up to the weak stop: H2 hypotheses (recorded by applySite's caller). */
    final Map<Address, List<Address[]>> spanHypotheses = new HashMap<>();
    int spanSites, spanHypothesisSlots, ct1Far, ct1Two;

    /**
     * CT1c: keep the slots from the base through the farthest observed target's first slot (a contiguous array
     * proven used at both ends); clear the table when an observed target is not among the scanned slots or the
     * site has no observed target. Slots after the span are kept aside as hypotheses (never decoded).
     */
    void observedSpan(Rec r) {
        Set<Long> obs = observed.getOrDefault(r.site.getOffset(), Set.of());
        int span = -1;
        for (long o : obs) {
            int first = -1;
            for (int k = 0; k < r.targets.size(); k++)
                if (r.targets.get(k).getOffset() == o) { first = r.slotOf.get(k); break; }
            if (first < 0) { span = -1; break; }
            span = Math.max(span, first);
        }
        if (span < 0) {
            if (!obs.isEmpty()) r.shape += "/CT1c_OBSERVED_OUTSIDE";
            r.targets.clear();
            return;
        }
        List<Address> keep = new ArrayList<>();
        List<Address[]> rest = new ArrayList<>();
        List<Integer> keepSlots = new ArrayList<>();
        int cs = csOf(r.site);
        for (int k = 0; k < r.targets.size(); k++) {
            if (r.slotOf.get(k) <= span) { keep.add(r.targets.get(k)); keepSlots.add(r.slotOf.get(k)); }
            else rest.add(new Address[] { seg(cs, (r.table + r.stride * r.slotOf.get(k)) & 0xFFFF), r.targets.get(k) });
        }
        int lim = span + 1;
        r.ct1 = (r.ct1 == null ? "" : r.ct1 + "+") + "CT1c span " + lim + " of " + r.slots + " scanned slots ("
            + obs.size() + " observed targets; weak stop " + r.stop + ")";
        r.targets = keep;
        r.slotOf = keepSlots;
        r.slots = lim;
        r.emptySlots.removeIf(k -> k >= lim);
        r.empty = r.emptySlots.size();
        r.stop = "OBSERVED_SPAN";
        spanHypotheses.put(r.site, rest);
    }

    static final Set<String> STRONG = Set.of("EXECUTED_CODE", "TABLE_BOUNDARY", "FUNCTION_ENTRY", "DIRECT_CALL_ENTRY",
        "TABLE_BASE", "OWN_TARGET", "PUSH_RETURN_ENTRY");

    static void resetScan(Rec r) {
        r.slots = 0; r.empty = 0; r.ffffRun = 0; r.emptySlots.clear(); r.slotOf.clear(); r.targets.clear(); r.stop = "BOUND";
        r.placeholderSlots.clear(); r.placeholderTargets.clear();
    }

    /** The ascending slot scan of a recovered site (stops on the first stop reason). */
    void scanTable(int cs, Rec r) {
        for (int i = 0; i < r.cap; i++) {
            Address ea;
            try { ea = seg(cs, (r.table + r.stride * i) & 0xFFFF); } catch (Exception e) { r.stop = "OUT_OF_ROM"; break; }
            String why = scanSlot(cs, ea, r);
            if (why == null) continue;
            r.stop = why;
            break;
        }
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
        Address t;
        try {
            if (r.width == 4) {
                int off = mem.getShort(ea) & 0xFFFF, sg = mem.getShort(ea.add(2)) & 0xFFFF;
                if (off == 0 && sg == 0) { r.ffffRun = 0; r.empty++; r.emptySlots.add(r.slots - 1); return null; }
                if (off == 0xFFFF && sg == 0xFFFF) return segmentEndSlot(r, "FFFF:FFFF");   // CT1d
                r.ffffRun = 0;
                // CT1a: a RAM/SRAM segment, or another bank window (bank unknown), ends the table
                if (sg < 0x2000) { r.slots--; return "FAR_RAM"; }
                if (sg < 0x4000 && sg != cs) { r.slots--; return "FAR_BANK_WINDOW"; }
                t = sg == cs ? seg(cs, off) : space.getAddress(sg, off);
            }
            else {
                if ((mem.getShort(ea) & 0xFFFF) == 0) { r.ffffRun = 0; r.empty++; r.emptySlots.add(r.slots - 1); return null; }
                if ((mem.getShort(ea) & 0xFFFF) == 0xFFFF) return segmentEndSlot(r, "FFFF");   // CT1d
                r.ffffRun = 0;
                t = read(cs, ea);
            }
        } catch (Exception e) { if (r.width == 4) r.slots--; return "OUT_OF_ROM"; }
        // J1o: a slot targeting the last byte of a bank overlay is skipped like an empty slot (no
        // case entry can live there: any instruction either overruns the block or falls out of its
        // address space, which neither the listing nor the decompiler can follow); the scan continues.
        if (t != null && isOverlayEnd(t)) {
            r.empty++;
            r.emptySlots.add(r.slots - 1);
            emit.accept(String.format("{\"rule\":\"J1o\",\"site\":\"%s\",\"slot\":%d,\"target\":\"%s\",\"outcome\":\"SKIPPED\"}",
                r.site, r.slots - 1, t));
            return null;
        }
        why = implausible(t, ea);
        // CT1e: an undecodable target that points forward into the scanned table region, on a slot boundary, is a
        // placeholder candidate (unused entries aimed at the table's end); kept only if the table ends exactly there
        if ("UNDECODABLE".equals(why) && r.allowPlaceholders && t != null && t.getAddressSpace().equals(ea.getAddressSpace())
                && tableStart != null && t.getAddressSpace().equals(tableStart.getAddressSpace())) {
            long d = t.subtract(tableStart);
            if (t.compareTo(ea) > 0 && d % r.stride == 0 && d / r.stride < r.cap) {
                r.placeholderSlots.add(r.slots - 1);
                r.placeholderTargets.add(t);
                r.empty++;
                r.emptySlots.add(r.slots - 1);
                return null;
            }
        }
        if (why != null) { r.slots--; return why; }
        r.slotOf.add(r.slots - 1);
        r.targets.add(t);
        return null;
    }

    /** CT1d (J1o at the segment end): a near slot holding 0xFFFF targets the last byte of its code segment, where no
     *  routine can start (the IP wraps to 0000 after it, so any instruction longer than one byte cannot decode
     *  there); a far slot FFFF:FFFF lies past the 1 MiB space. Up to 3 consecutive such slots are skipped like empty
     *  slots; 4+ consecutive 0xFFFF slots are erased ROM fill and end the scan (weak stop ERASED_FILL). */
    String segmentEndSlot(Rec r, String value) {
        if (++r.ffffRun >= 4) {
            int prior = r.ffffRun - 1;
            r.slots -= r.ffffRun;
            r.empty -= prior;
            for (int j = 0; j < prior; j++) r.emptySlots.remove(r.emptySlots.size() - 1);
            r.ffffRun = 0;
            return "ERASED_FILL";
        }
        r.empty++;
        r.emptySlots.add(r.slots - 1);
        emit.accept(String.format("{\"rule\":\"CT1d\",\"site\":\"%s\",\"slot\":%d,\"value\":\"%s\",\"outcome\":\"SKIPPED\"}",
            r.site, r.slots - 1, value));
        return null;
    }

    /** CT1g: total left shift applied to the index along the slice (SHL idx,n / ADD idx,idx) back to its last other
     *  write; constant additions (the base) are skipped. */
    static int scaleShift(List<Instruction> back, String reg) {
        int shift = 0;
        for (Instruction q : back) {
            String t = q.toString().toUpperCase().replace(" ", "");
            Matcher m = Pattern.compile("SHL" + reg + ",(0X[0-9A-F]+|1)").matcher(t);
            if (m.matches()) { shift += m.group(1).equals("1") ? 1 : Integer.parseInt(m.group(1).substring(2), 16); continue; }
            if (t.equals("ADD" + reg + "," + reg)) { shift++; continue; }
            if (t.startsWith("ADD" + reg + ",0X")) continue;
            if (writes(t, reg)) break;
        }
        return shift;
    }

    /** J1c: index register loaded from a byte (zero- or sign-extended) before scaling. */
    void byteBound(List<Instruction> back, String reg, Rec r) {
        if (reg.length() != 2 || reg.charAt(1) != 'X' && !reg.equals("SI") && !reg.equals("DI")) return;
        String lo = reg.charAt(0) + "L", hi = reg.charAt(0) + "H";
        int shift = 0;
        boolean hiClear = false, loByte = false, cbw = false;
        for (Instruction q : back) {
            String t = q.toString().toUpperCase().replace(" ", "");
            // J1c through a register copy (MOV BX,AX): the bound is the source's, scaled the same way
            java.util.regex.Matcher copy = Pattern.compile("MOV" + reg + ",([ABCD]X)").matcher(t);
            if (copy.matches() && !hiClear && !loByte) {
                reg = copy.group(1); lo = reg.charAt(0) + "L"; hi = reg.charAt(0) + "H";
                r.bound = "via MOV " + r.idx + "," + reg;
                continue;
            }
            java.util.regex.Matcher m = Pattern.compile("SHL" + reg + ",(0X[0-9A-F]+|1)").matcher(t);
            if (m.matches()) { shift += m.group(1).equals("1") ? 1 : Integer.parseInt(m.group(1).substring(2), 16); continue; }
            if (t.startsWith("ADD" + reg + ",0X")) continue;
            if (t.equals("ADD" + reg + "," + reg)) { shift++; continue; }   // x2 scaling
            if (t.equals("XOR" + hi + "," + hi) || t.equals("MOV" + hi + ",0X0") || t.equals("SUB" + hi + "," + hi)) { hiClear = true; if (loByte) break; continue; }
            if (t.startsWith("MOV" + lo + ",")) { loByte = true; if (hiClear) break; continue; }
            if (t.equals("CBW") && reg.equals("AX")) { cbw = true; loByte = true; hiClear = true; break; }
            if (t.startsWith("MOVZX" + reg)) { loByte = true; hiClear = true; break; }
            if (writes(t, reg)) { if (r.bound.startsWith("via ")) r.bound = "none"; return; }
        }
        if (!(hiClear && loByte)) { if (r.bound.startsWith("via ")) r.bound = "none"; return; }
        int bytes = (cbw ? 128 : 256) << shift;           // CBW: only the 0..127 half lies at or after the base
        r.cap = Math.max(1, bytes / r.stride);
        r.byteBound = true;
        String via = r.bound.startsWith("via ") ? " (" + r.bound + ")" : "";
        r.bound = (cbw ? "byte index (CBW, forward half)" : "byte index") + " << " + shift + " -> " + r.cap + " entries" + via;
    }

    /** The immediate must still be the top stack word on every path to dispatch.
     * Stack changes, stores that could alias the stack, and incoming flow veto it. */
    Address pushedContinuation(Instruction site, int cs) {
        if (!site.getMnemonicString().equals("JMP")) return null;
        Instruction after = site;
        for (Instruction q : predecessors(site, 16)) {
            for (Reference ref : p.getReferenceManager().getReferencesTo(after.getAddress()))
                if (ref.getReferenceType().isFlow()) return null;
            String mnemonic = q.getMnemonicString();
            if (mnemonic.equals("PUSH")) {
                if (q.getScalar(0) == null) return null;
                Address continuation = seg(cs, (int)q.getScalar(0).getUnsignedValue() & 0xffff);
                if (!continuation.getAddressSpace().equals(tableStart.getAddressSpace())) return null;
                long distance = continuation.subtract(tableStart);
                return distance > 0 && distance <= 512 && (distance & 1) == 0 && returnStub(continuation)
                    ? continuation : null;
            }
            String t = q.toString().toUpperCase().replace(" ", "");
            if (q.getFlowType().isCall() || mnemonic.startsWith("INT")
                || writesReg(q, t, "SP", p.getRegister("SP"))
                || writesReg(q, t, "SS", p.getRegister("SS"))) return null;
            for (var op : q.getPcode())
                if (op.getOpcode() == ghidra.program.model.pcode.PcodeOp.STORE) return null;
            after = q;
        }
        return null;
    }

    /** A saved near return IP immediately following the words is a code boundary
     * when it restores saved registers and returns. It cannot be another slot. */
    boolean returnStub(Address entry) {
        try {
            Address a = entry;
            var decoder = new ghidra.app.util.PseudoDisassembler(p);
            int pops = 0;
            for (int n = 0; n < 9; n++) {
                var i = decoder.disassemble(a);
                if (i == null) return false;
                String mnemonic = i.getMnemonicString();
                if ((mnemonic.equals("RET") || mnemonic.equals("RETF")) && i.getNumOperands() == 0) return pops > 0;
                if (!mnemonic.equals("POP") || i.getRegister(0) == null || i.getRegister(0).getBitLength() != 16) return false;
                pops++; a = i.getMaxAddress().next();
            }
        } catch (Exception e) { return false; }
        return false;
    }

    String slotStop(Address ea, Rec r) {
        if (!mem.contains(ea) || !mem.getBlock(ea).isInitialized()) return "OUT_OF_ROM";
        if (ea.equals(r.returnEnd)) return "PUSH_RETURN_ENTRY";
        // every byte of the slot (2, or 4 for a CT1a far slot) is checked
        List<Address> bytes = new ArrayList<>();
        for (int k = 0; k < r.width; k++) {
            try { bytes.add(ea.add(k)); } catch (Exception e) { return "OUT_OF_ROM"; }
        }
        for (Address b : bytes) if (executed(b.getOffset())) return "EXECUTED_CODE";
        for (Address b : bytes) if (p.getFunctionManager().getFunctionAt(b) != null) return "FUNCTION_ENTRY";
        // A merge may remove a callee's function object without removing its code
        // or direct call. Its bytes still cannot be read as further table slots.
        for (Address b : bytes) if (directCallEntry(b)) return "DIRECT_CALL_ENTRY";
        if (!ea.equals(tableStart) && tableBases.contains(ea)) return "TABLE_BASE";
        for (Address b : bytes) if (r.targets.contains(b) || r.placeholderTargets.contains(b)) return "OWN_TARGET";   // J1j, CT1e
        return null;
    }

    boolean directCallEntry(Address a) {
        if (listing.getInstructionAt(a) == null) return false;
        for (Reference ref : p.getReferenceManager().getReferencesTo(a)) {
            if (!ref.getReferenceType().isCall() || ref.getReferenceType().isComputed()) continue;
            Instruction call = listing.getInstructionAt(ref.getFromAddress());
            if (call != null && call.getFlowType().isCall() && !call.getFlowType().isComputed()) return true;
        }
        return false;
    }

    /** J1f: every constant CS-relative table base in the program (jump or data table, resolved or not): a
     *  table that runs into another object's base ends there (e.g. a command table followed directly by a
     *  direct-mode table). */
    final Set<Address> tableBases = new HashSet<>();
    Address tableStart;
    static final Pattern CSMEM = Pattern.compile("CS:\\[(?:(BX|SI|DI|BP)(?: ?([+-]) ?0x([0-9a-f]+))?|0x([0-9a-f]+))\\]", Pattern.CASE_INSENSITIVE);

    void collectTableBases(TaskMonitor monitor) throws Exception {
        AddressSpace caller = siteSpace;
        try { collectTableBasesInner(monitor); } finally { siteSpace = caller; }
    }

    void collectTableBasesInner(TaskMonitor monitor) throws Exception {
        tableBases.clear();
        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            addTableBase(ins);
        }
    }

    /** J1f for one instruction: adds its constant CS-relative table base, if it has one; true when the
     *  instruction has a CS-relative memory operand at all. */
    boolean addTableBase(Instruction ins) {
        String txt = ins.toString();
        if (!txt.contains("CS:[")) return false;
        Matcher m = CSMEM.matcher(txt);
        if (!m.find()) return false;
        siteSpace = ins.getAddress().getAddressSpace();
        int cs = csOf(ins.getAddress());
        if (m.group(4) != null) { tableBases.add(seg(cs, Integer.parseInt(m.group(4), 16))); return true; }
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
        return true;
    }

    /** CT1a: a far call through memory renders without its segment prefix (CALLF [BX + 0x7e]); the prefix is read
     *  from the bytes ({@link #csPrefixed}). */
    static final Pattern FARMEM = Pattern.compile("^CALLF \\[(BX|SI|DI|BP)(?: ?([+-]) ?0x([0-9a-f]+))?\\]$", Pattern.CASE_INSENSITIVE);
    /** CT1b: base + index register operand, optional displacement. */
    static final Pattern TWOREG = Pattern.compile("\\[(BX|BP) \\+ (SI|DI)(?: ?([+-]) ?0x([0-9a-f]+))?\\]", Pattern.CASE_INSENSITIVE);

    /** The last segment-override prefix of the instruction is CS (0x2E). */
    static boolean csPrefixed(Instruction i) {
        int segment = -1;
        try {
            for (byte b : i.getBytes()) {
                int v = b & 0xFF;
                if (v == 0x26 || v == 0x2E || v == 0x36 || v == 0x3E) segment = v;
                else if (v != 0xF0 && v != 0xF2 && v != 0xF3) break;
            }
        } catch (Exception e) { return false; }
        return segment == 0x2E;
    }

    /**
     * CT1b: resolve a [B + I (+d)] operand of {@code access} (the site or its load): exactly one register must hold a
     * constant there. Sets base, index and provenance; false (with the shape amended) when neither or both are constant.
     */
    boolean twoRegister(Instruction access, List<Instruction> back, Rec r) {
        Matcher m = TWOREG.matcher(access.toString());
        if (!m.find()) { r.shape += "/CT1b_SHAPE"; return false; }
        String a = m.group(1).toUpperCase(), b = m.group(2).toUpperCase();
        int d = m.group(4) == null ? 0 : Integer.parseInt(m.group(4), 16) * (m.group(3).equals("-") ? -1 : 1);
        String[] wa = new String[1], wb = new String[1];
        Integer ca = constAt(access, back, a, wa), cb = constAt(access, back, b, wb);
        if (ca != null && cb != null) { r.shape += "/CT1b_BOTH_CONSTANT"; return false; }
        if (ca == null && cb == null) { r.shape += "/CT1b_NO_CONSTANT:" + a + "_" + wa[0] + ":" + b + "_" + wb[0]; return false; }
        r.idx = ca == null ? a : b;
        r.base = ca == null ? cb : ca;
        r.disp = d;
        r.baseFound = true;
        r.baseVia = "CT1b " + (ca == null ? b : a) + " from " + (ca == null ? wb[0] : wa[0]);
        r.ct1 = "CT1b " + (ca == null ? b : a) + "=" + String.format("%04x", r.base) + " index " + r.idx;
        return true;
    }

    /** CT1b: the constant {@code reg} holds at {@code access}: its last write before it (fall-through chain
     *  {@code back}) is MOV reg,imm / LEA reg,[imm], no flow joins the chain after that write (nor at the access),
     *  and no CALL/INT lies in between. Null otherwise, with the reason in why[0]. */
    Integer constAt(Instruction access, List<Instruction> back, String reg, String[] why) {
        ghidra.program.model.lang.Register r16 = p.getRegister(reg);
        Instruction after = access;
        for (Instruction d : back) {
            for (Reference ref : p.getReferenceManager().getReferencesTo(after.getAddress()))
                if (ref.getReferenceType().isFlow()) { why[0] = "JOIN@" + after.getAddress(); return null; }
            String t = d.toString().toUpperCase().replace(" ", "");
            String mn = d.getMnemonicString().toUpperCase();
            if (mn.startsWith("CALL") || mn.startsWith("INT")) { why[0] = "CALL_BETWEEN@" + d.getAddress(); return null; }
            if (writesReg(d, t, reg, r16)) {
                Matcher c = CONSTDEF.matcher(t);
                if (c.matches() && reg.equals(c.group(1) != null ? c.group(1) : c.group(3))) {
                    why[0] = d.toString();
                    return Integer.parseInt(c.group(2) != null ? c.group(2) : c.group(4), 16) & 0xFFFF;
                }
                why[0] = "NOT_CONST@" + d.getAddress();
                return null;
            }
            after = d;
        }
        why[0] = "NO_DEF";
        return null;
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
