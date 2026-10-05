// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rule V1: RAM flags written by interrupt handlers and polled in a spin-wait loop are volatile.
 *
 * Without that, a wait loop ({@code MOV AL,[M]; TEST AL,AL; JNZ loop}) decompiles as
 * {@code do {} while (true)}: the decompiler sees no store in the loop and folds the condition.
 * Volatile is a per-block attribute, so the flag bytes are split out of the RAM block into a tiny
 * volatile block of their own; labels and references (by address) are unaffected.
 *
 * Writers: stores to RAM found on the intra-procedural flow (fall-through and direct jumps, no
 * calls) from an interrupt-handler entry: an installed vector target (rule F2/F3 into the IVT) or
 * an observed interrupt-entry edge (rule E2). Polls: a backward conditional branch whose loop body
 * loads the flag and stores it nowhere. Both are required; either alone is an ordinary access.
 */
final class WSVolatile {
    static final int MAX_FLAGS = 128, WALK_BOUND = 5000;

    final Program p;
    final Listing listing;
    final Memory mem;
    final AddressSpace ramSpace;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    final Set<Address> handlers = new HashSet<>();
    /** Title DS default (rule D0): resolves absolute operands whose DS is dynamic (no reference). */
    final int titleDs;
    int volatileFlags, existingVolatile;

    WSVolatile(Program p, WSEvidence ev, Set<Address> ivtHandlers, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor;
        listing = p.getListing();
        mem = p.getMemory();
        ramSpace = p.getAddressFactory().getDefaultAddressSpace();
        int d = WSCompilerRules.dominantDs(ev);
        titleDs = d < 0 ? 0 : d;
        if (ivtHandlers != null) handlers.addAll(ivtHandlers);
        SegmentedAddressSpace space = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
        for (WSEvidence.Edge e : ev.edges) {
            if (!e.kind().equals("int") && !e.kind().equals("irq")) continue;
            try {
                Address a = space.getAddress(e.targetCs(), (int) ((e.to() - ((long) e.targetCs() << 4)) & 0xFFFF));
                if (mem.contains(a)) handlers.add(a);
            } catch (Exception x) { /* not an address: not a handler we can scan */ }
        }
    }

    String summary() {
        return String.format("V1 volatile poll flags: interrupt handlers %d, flags marked volatile %d (already volatile %d)",
            handlers.size(), volatileFlags, existingVolatile);
    }

    record Store(Address site, int size) { }

    void apply() throws Exception {
        // writer scan: RAM stores on the handler flows
        Map<Long, List<Store>> writes = new TreeMap<>();
        Map<Long, Integer> sizes = new TreeMap<>();
        for (Address h : handlers) {
            monitor.checkCancelled();
            for (Address a : handlerFlow(h)) {
                Instruction ins = listing.getInstructionAt(a);
                if (ins == null) continue;
                boolean resolved = false;
                for (Reference r : ins.getReferencesFrom()) {
                    if (!r.getReferenceType().isWrite()) continue;
                    Address to = r.getToAddress();
                    if (!isRam(to)) continue;
                    resolved = true;
                    long lin = to.getOffset();
                    int n = storeSize(ins);
                    writes.computeIfAbsent(lin, k -> new ArrayList<>()).add(new Store(a, n));
                    sizes.merge(lin, n, Math::max);
                }
                // no reference: DS is dynamic here (e.g. just POP-restored); resolve with the title DS
                if (!resolved) {
                    MemAccess ac = absoluteAccess(ins);
                    if (ac != null && ac.store() && isRamLinear(ac.linear())) {
                        int n = storeSize(ins);
                        writes.computeIfAbsent(ac.linear(), k -> new ArrayList<>()).add(new Store(a, n));
                        sizes.merge(ac.linear(), n, Math::max);
                    }
                }
            }
        }
        if (writes.isEmpty()) return;
        // poll scan: backward conditional branches loading a written flag without storing it
        Map<Long, Set<Address>> polls = new TreeMap<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                if (!ins.getFlowType().isJump() || !ins.getFlowType().isConditional()) continue;
                for (Address t : ins.getFlows()) {
                    if (t.compareTo(ins.getAddress()) >= 0) continue;
                    pollLoop(t, ins.getAddress(), writes.keySet(), sizes, polls, ins.getAddress());
                }
            }
        }
        for (Map.Entry<Long, Set<Address>> e : polls.entrySet()) {
            if (volatileFlags + existingVolatile >= MAX_FLAGS) break;
            markVolatile(e.getKey(), sizes.getOrDefault(e.getKey(), 2), writes.get(e.getKey()), e.getValue());
        }
    }

    boolean isRam(Address a) {
        // no execute/initialized test: the loader maps work RAM rwx, and the offset range already
        // excludes code (linear 0x40000+) and the SRAM window (0x10000+)
        if (a == null || !a.getAddressSpace().equals(ramSpace) || a.getOffset() >= 0x10000) return false;
        return mem.getBlock(a) != null;
    }

    /** Intra-procedural flow from a handler entry: fall-through and direct jumps, bounded. */
    Set<Address> handlerFlow(Address h) {
        Set<Address> out = new LinkedHashSet<>();
        Deque<Address> work = new ArrayDeque<>(List.of(h));
        while (!work.isEmpty() && out.size() < WALK_BOUND) {
            Address a = work.pop();
            if (!out.add(a)) continue;
            Instruction ins = listing.getInstructionAt(a);
            if (ins == null) continue;
            if (ins.getFallThrough() != null && !ins.getFlowType().isTerminal()
                    && !(ins.getFlowType().isJump() && ins.getFlowType().isUnConditional())) work.push(ins.getFallThrough());
            if (ins.getFlowType().isJump() && !ins.getFlowType().isComputed())
                for (Address t : ins.getFlows()) work.push(t);
        }
        return out;
    }

    record MemAccess(long linear, boolean store, boolean load) { }

    static final java.util.regex.Pattern ABS = java.util.regex.Pattern.compile("(?:(CS|DS|ES|SS):)?\\[0[xX]([0-9a-fA-F]+)\\]");

    /** An absolute DS (or segment-default) memory operand resolved with the title DS, or null. Only
     *  for operands Ghidra left without a reference (dynamic DS); resolved references always win. */
    MemAccess absoluteAccess(Instruction ins) {
        String t = ins.toString().toUpperCase().replace(" ", "");
        java.util.regex.Matcher m = ABS.matcher(t);
        if (!m.find()) return null;
        if (m.group(1) != null && !m.group(1).equals("DS")) return null;
        String mn = ins.getMnemonicString().toUpperCase();
        if (mn.equals("LEA")) return null;
        long lin = (((long) titleDs << 4) + Long.parseLong(m.group(2), 16)) & 0xFFFFF;
        boolean store, load;
        if (mn.equals("PUSH")) { store = false; load = true; }
        else if (mn.equals("POP")) { store = true; load = false; }
        else if (mn.equals("CMP") || mn.equals("TEST")) { store = false; load = true; }
        else if (mn.equals("MOV") || mn.equals("XCHG")) {
            int comma = t.indexOf(',');
            store = m.start() < comma || mn.equals("XCHG");
            load = m.start() > comma || mn.equals("XCHG");
        }
        else if (mn.equals("JMP") || mn.equals("CALL") || mn.equals("JMPF") || mn.equals("CALLF")) { store = false; load = true; }
        else { store = true; load = true; }   // read-modify-write
        return new MemAccess(lin, store, load);
    }

    boolean isRamLinear(long lin) {
        if (lin >= 0x10000) return false;
        try {
            Address a = ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(0, (int) lin);
            return isRam(a);
        } catch (Exception e) { return false; }
    }

    /** Store width: byte when an 8-bit register or BYTE PTR is involved, else a word. */
    static int storeSize(Instruction ins) {
        if (ins.toString().toUpperCase().contains("BYTE")) return 1;
        for (int k = 0; k < ins.getNumOperands(); k++)
            for (Object o : ins.getOpObjects(k))
                if (o instanceof ghidra.program.model.lang.Register r && r.getBitLength() == 8) return 1;
        return 2;
    }

    void pollLoop(Address from, Address to, Set<Long> written, Map<Long, Integer> sizes,
            Map<Long, Set<Address>> polls, Address branch) {
        Set<Long> reads = new HashSet<>(), stores = new HashSet<>();
        Address a = from;
        int n = 0;
        while (a != null && a.compareTo(to) <= 0 && n++ < WALK_BOUND) {
            Instruction ins = listing.getInstructionAt(a);
            if (ins != null) {
                boolean ramRef = false;
                for (Reference r : ins.getReferencesFrom()) {
                    Address t = r.getToAddress();
                    if (!isRam(t)) continue;
                    ramRef = true;
                    if (r.getReferenceType().isWrite()) { stores.add(t.getOffset()); stores.add(t.getOffset() + 1); }
                    else if (r.getReferenceType().isRead()) { reads.add(t.getOffset()); reads.add(t.getOffset() + 1); }
                }
                if (!ramRef) {
                    MemAccess ac = absoluteAccess(ins);
                    if (ac != null && isRamLinear(ac.linear())) {
                        if (ac.store()) { stores.add(ac.linear()); stores.add(ac.linear() + 1); }
                        if (ac.load()) { reads.add(ac.linear()); reads.add(ac.linear() + 1); }
                    }
                }
            }
            try { a = a.next(); } catch (Exception e) { break; }
        }
        for (long m : written) {
            boolean loaded = false, stored = false;
            for (int k = 0; k < sizes.getOrDefault(m, 2); k++) {
                if (reads.contains(m + k)) loaded = true;
                if (stores.contains(m + k)) stored = true;
            }
            if (loaded && !stored) polls.computeIfAbsent(m, k -> new TreeSet<>()).add(branch);
        }
    }

    void markVolatile(long lin, int size, List<Store> writers, Set<Address> pollSites) throws Exception {
        SegmentedAddressSpace space = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
        Address m = space.getAddress(0, (int) lin);
        if (!mem.contains(m)) return;
        MemoryBlock block = mem.getBlock(m);
        if (block.isVolatile()) {
            existingVolatile++;
            emit.accept(String.format("{\"rule\":\"V1\",\"flag\":\"%s\",\"outcome\":\"ALREADY_VOLATILE\"}", m));
            return;
        }
        // split the flag bytes [m, m+size) out; labels and references stay by address
        Address after = m.add(size);
        if (block.contains(after)) mem.split(block, after);
        block = mem.getBlock(m);
        if (!m.equals(block.getStart())) mem.split(block, m);
        MemoryBlock flag = mem.getBlock(m);
        flag.setVolatile(true);
        flag.setComment(String.format("V1 VOLATILE: RAM flag written by interrupt code, polled in a spin-wait loop (%d byte%s)",
            size, size == 1 ? "" : "s"));
        volatileFlags++;
        StringBuilder w = new StringBuilder();
        for (Store s : writers) w.append(w.length() > 0 ? "," : "").append('"').append(s.site()).append('"');
        StringBuilder q = new StringBuilder();
        for (Address b : pollSites) q.append(q.length() > 0 ? "," : "").append('"').append(b).append('"');
        emit.accept(String.format("{\"rule\":\"V1\",\"flag\":\"%s\",\"size\":%d,\"writers\":[%s],\"polls\":[%s],\"outcome\":\"VOLATILE\"}",
            m, size, w, q));
    }
}
