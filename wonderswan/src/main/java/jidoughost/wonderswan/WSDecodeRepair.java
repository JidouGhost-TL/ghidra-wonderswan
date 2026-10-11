// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** Executed alignment outranks speculative decode; bad boundaries fence function bodies. */
public final class WSDecodeRepair {
    private WSDecodeRepair() { }

    public static void align(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        var starts = WSRomEvidence.property(p, WSRomEvidence.STARTS);
        var code = WSRomEvidence.property(p, WSRomEvidence.CODE);
        var cs = p.getProgramContext().getRegister("csval");
        if (cs == null) return;
        // Independent instruction markers are the anchors. Code flags alone never anchor an operand.
        if (ev.romFlags.length > 0) for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isExecute() || WonderSwanLoader.isDataOverlay(b)) continue;
            for (int k = 0; k < b.getSize(); k++) {
                Address a = b.getStart().add(k);
                int flags = WSRomEvidence.flags(p, ev, a);
                if ((flags & 1) != 0 && (flags & 12) != 0 && !starts.hasProperty(a)) starts.add(a, 2);
            }
        }
        ArrayDeque<Address> queue = new ArrayDeque<>();
        var it = starts.getPropertyIterator();
        while (it.hasNext()) queue.add(it.next());
        Set<Address> visited = new HashSet<>();
        TreeMap<Address, PseudoInstruction> expected = new TreeMap<>();
        Map<Address,BigInteger> segments = new HashMap<>();
        PseudoDisassembler decoder = new PseudoDisassembler(p);
        while (!queue.isEmpty()) {
            monitor.checkCancelled();
            Address a = queue.removeFirst();
            if (!visited.add(a)) continue;
            MemoryBlock b = p.getMemory().getBlock(a);
            if (b == null || !b.isInitialized() || !b.isExecute() || WSRamCode.isRam(p, a)) continue;
            if (ev.romFlags.length == 0 && p.getListing().getInstructionAt(a) != null) continue;
            var ctx = new PseudoDisassemblerContext(p.getProgramContext());
            var value = p.getProgramContext().getValue(cs, a, false);
            if (!a.getAddressSpace().isOverlaySpace() && ev.cs.containsKey(a.getOffset())) value = BigInteger.valueOf(ev.cs.get(a.getOffset()));
            if (value == null || value.signum() == 0) value = BigInteger.valueOf((a.getOffset() >>> 4) & 0xf000);
            ctx.setFutureRegisterValue(a, new RegisterValue(cs, value));
            PseudoInstruction ins;
            try { ins = decoder.disassemble(a, ctx, false); }
            catch (Exception ex) { continue; }
            if (ins == null || ins.getMnemonicString().contains("UNDEF")) continue;
            boolean physical = WSRomEvidence.code(p, ev, a, ins.getLength());
            if (!physical && !starts.hasProperty(a)) continue;
            expected.put(a, ins);
            segments.put(a, value);
            if (physical) {
                code.add(a, ins.getLength());
                Address ft = ins.getFallThrough();
                if (ft != null && a.getAddressSpace().equals(ft.getAddressSpace())) queue.add(ft);
                for (Address flow : ins.getFlows()) if (a.getAddressSpace().equals(flow.getAddressSpace())) queue.add(flow);
            }
        }
        AddressSet seeds = new AddressSet();
        int cleared = 0, ambiguous = 0, refs = 0;
        for (var e : expected.entrySet()) {
            Address a = e.getKey(); PseudoInstruction want = e.getValue();
            Set<Instruction> conflicts = new LinkedHashSet<>();
            Instruction containing = p.getListing().getInstructionContaining(a);
            if (containing != null && !containing.getAddress().equals(a)) conflicts.add(containing);
            // A speculative start can also lie later, inside the executed instruction's
            // operands. Checking only the instruction containing the winning start misses it.
            for (Instruction i : p.getListing().getInstructions(new AddressSet(a, a.add(want.getLength() - 1)), true))
                if (!i.getAddress().equals(a)) conflicts.add(i);
            boolean protectedConflict = false;
            for (Instruction have : conflicts) {
                Address old = have.getAddress();
                Function f = p.getFunctionManager().getFunctionAt(old);
                if (expected.containsKey(old) || starts.hasProperty(old) || f != null
                    && (f.getSymbol().getSource() != SourceType.DEFAULT
                        || f.getSignatureSource() == SourceType.USER_DEFINED
                        || f.getSignatureSource() == SourceType.IMPORTED)) protectedConflict = true;
            }
            if (protectedConflict) {
                ambiguous++;
                emit.accept(String.format("{\"rule\":\"E1A\",\"winner\":\"%s\",\"outcome\":\"AMBIGUOUS_OR_PROTECTED_ALIGNMENT\"}", a));
                continue;
            }
            for (Instruction have : conflicts) {
                Address old = have.getAddress(), end = have.getMaxAddress();
                Function f = p.getFunctionManager().getFunctionAt(old);
                if (f != null) p.getFunctionManager().removeFunction(old);
                p.getListing().clearCodeUnits(old, end, false);
                p.getBookmarkManager().setBookmark(old, BookmarkType.ANALYSIS, "WSExecutedAlignment", "Speculative decode cleared; executed instruction begins at " + a);
                emit.accept(String.format("{\"rule\":\"E1A\",\"winner\":\"%s\",\"loser\":\"%s\",\"end\":\"%s\"}", a, old, end));
                cleared++;
            }
            // A guessed computed edge into an operand makes the decompiler decode an overlap even
            // when the listing has only the correct instruction. Remove that guess, retain direct
            // or user edges and independently executed alternate starts as ambiguous evidence.
            for (int k = 1; k < want.getLength(); k++) {
                Address interior = a.add(k);
                if (expected.containsKey(interior) || starts.hasProperty(interior)) continue;
                List<Reference> remove = new ArrayList<>();
                for (Reference r : p.getReferenceManager().getReferencesTo(interior)) {
                    if (r.getSource() == SourceType.ANALYSIS && r.getReferenceType().isComputed() && r.getReferenceType().isFlow()) remove.add(r);
                }
                for (Reference r : remove) {
                    emit.accept(String.format("{\"rule\":\"E1A\",\"site\":\"%s\",\"offcut\":\"%s\",\"winner\":\"%s\",\"outcome\":\"GUESSED_EDGE_REMOVED\"}", r.getFromAddress(), interior, a));
                    p.getReferenceManager().delete(r); refs++;
                }
            }
            if (p.getListing().getInstructionContaining(a) == null) {
                p.getProgramContext().setValue(cs, a, a, segments.get(a));
                seeds.add(a);
            }
        }
        if (!seeds.isEmpty()) new DisassembleCommand(seeds, null, true).applyTo(p, monitor);
        emit.accept(String.format("{\"rule\":\"E1A\",\"anchors\":%d,\"executed_alignments\":%d,\"cleared\":%d,\"guessed_edges_removed\":%d,\"both_executed\":%d}", visited.size(), expected.size(), cleared, refs, ambiguous));
    }

    private static boolean proven(Program p, Address a) {
        var starts = p.getUsrPropertyManager().getIntPropertyMap(WSRomEvidence.STARTS);
        var code = p.getUsrPropertyManager().getIntPropertyMap(WSRomEvidence.CODE);
        return starts != null && starts.hasProperty(a) || code != null && code.hasProperty(a);
    }

    /** Keep decoded graph components; never join through undecodable bytes. Large speculative
     * paths are bounded after 256 consecutive bytes without execution evidence. User bodies stay. */
    public static String boundaries(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        int truncated = 0, capped = 0, separated = 0;
        AddressSet detached = new AddressSet();
        List<Function> functions = new ArrayList<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) functions.add(f);
        for (Function f : functions) {
            monitor.checkCancelled();
            if (f.isExternal() || f.getSymbol().getSource() == SourceType.USER_DEFINED) continue;
            boolean hasProof = false;
            for (Instruction i : p.getListing().getInstructions(f.getBody(), true)) if (proven(p, i.getAddress())) { hasProof = true; break; }
            if (!hasProof) continue;
            AddressSet body = new AddressSet();
            ArrayDeque<Map.Entry<Address,Integer>> queue = new ArrayDeque<>();
            queue.add(Map.entry(f.getEntryPoint(), 0));
            Map<Address,Integer> seen = new HashMap<>();
            boolean cap = false;
            while (!queue.isEmpty()) {
                var item = queue.removeFirst(); Address a = item.getKey(); int unplayed = item.getValue();
                if (!f.getBody().contains(a)) continue;
                if (seen.getOrDefault(a, Integer.MAX_VALUE) <= unplayed) continue;
                seen.put(a, unplayed);
                Instruction i = p.getListing().getInstructionAt(a);
                if (i == null || i.getMnemonicString().contains("UNDEF")) continue;
                unplayed = proven(p, a) ? 0 : unplayed + i.getLength();
                if (f.getBody().getNumAddresses() >= 32768 && unplayed > 256) { cap = true; continue; }
                body.add(i.getMinAddress(), i.getMaxAddress());
                Address ft = i.getFallThrough();
                if (ft != null) queue.add(Map.entry(ft, unplayed));
                if (!i.getFlowType().isCall()) for (Address flow : i.getFlows()) queue.add(Map.entry(flow, unplayed));
            }
            if (body.isEmpty() || !body.contains(f.getEntryPoint()) || body.equals(f.getBody())) continue;
            long before = f.getBody().getNumAddresses();
            AddressSet removed = new AddressSet(f.getBody());
            removed.delete(body);
            detached.add(removed);
            f.setBody(body); truncated++; if (cap) capped++;
            p.getBookmarkManager().setBookmark(f.getEntryPoint(), BookmarkType.ANALYSIS, "WSFunctionBoundary", "Body fenced at missing/bad instructions" + (cap ? "; speculative growth capped" : ""));
            emit.accept(String.format("{\"rule\":\"A2\",\"entry\":\"%s\",\"before\":%d,\"after\":%d,\"growth_capped\":%b}", f.getEntryPoint(), before, body.getNumAddresses(), cap));
        }
        // A fence must not strand executed components on its far side. Preserve their listing
        // and give each reachable, function-less component its own body instead of gluing it
        // back across the bad boundary. Speculative-only components remain without functions.
        for (Instruction i : p.getListing().getInstructions(detached, true)) {
            Address a = i.getAddress();
            if (!proven(p, a) || p.getFunctionManager().getFunctionContaining(a) != null) continue;
            AddressSet component = component(p, a, detached, monitor);
            if (component.isEmpty()) continue;
            createFunction(p, a, component);
            separated++;
            emit.accept(String.format("{\"rule\":\"A2\",\"entry\":\"%s\",\"outcome\":\"EXECUTED_COMPONENT_SPLIT\",\"bytes\":%d}", a, component.getNumAddresses()));
        }
        return String.format("A2 bodies fenced %d, speculative growth capped %d, executed components split %d", truncated, capped, separated);
    }

    /** Reachable decoded instructions inside a proposed body, stopping at other functions. */
    private static AddressSet component(Program p, Address entry, AddressSetView allowed,
                                        TaskMonitor monitor) throws Exception {
        AddressSet body = new AddressSet();
        Set<Address> seen = new HashSet<>();
        ArrayDeque<Address> pending = new ArrayDeque<>();
        pending.add(entry);
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            Address a = pending.removeFirst();
            if (!allowed.contains(a) || !seen.add(a)) continue;
            Function owner = p.getFunctionManager().getFunctionContaining(a);
            Function initial = p.getFunctionManager().getFunctionContaining(entry);
            if (owner != null && !owner.equals(initial)) continue;
            Instruction i = p.getListing().getInstructionAt(a);
            if (i == null || i.getMnemonicString().contains("UNDEF")) continue;
            body.add(i.getMinAddress(), i.getMaxAddress());
            if (i.getFallThrough() != null) pending.add(i.getFallThrough());
            if (!i.getFlowType().isCall()) Collections.addAll(pending, i.getFlows());
        }
        return body;
    }

    /** A3: the decompiler navigates beyond stored bodies and its switch overrides belong to
     * functions, not instructions. Split independently executed exterior entries, make direct
     * jumps across the resulting functions explicit tail transfers, and lock unresolved weak
     * tables to executed instruction targets. No ROM bytes or user overrides are changed.
     * Run after merges and J1 locks, in the final no-analysis pass. */
    public static String decompilerBoundaries(Program p, List<String> evidence,
                                             Consumer<String> emit, TaskMonitor monitor) throws Exception {
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        Set<Address> weak = weakTables(p, evidence);
        Set<Address> locked = new HashSet<>(), opaque = new HashSet<>();
        // Overrides live in the function namespace. Keep the original owner's lock before
        // shrinking its body: its prefix can still fall through into the separated dispatch.
        // Ghidra refuses writeOverride after the switch is outside that owner's stored body.
        lockWeakTables(p, weak, "BEFORE_SPLIT", locked, opaque, emit, monitor);
        Set<Address> entries = new TreeSet<>();
        for (Instruction i : listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (!plainJump(i) || !proven(p, i.getAddress())) continue;
            Function from = fm.getFunctionContaining(i.getAddress());
            if (from == null || from.getSymbol().getSource() == SourceType.USER_DEFINED) continue;
            Address t = i.getFlows()[0];
            Function into = fm.getFunctionContaining(t);
            if (into != null && !into.equals(from) && !into.getEntryPoint().equals(t)
                && into.getSymbol().getSource() == SourceType.DEFAULT && proven(p, t)
                && listing.getInstructionAt(t) != null) entries.add(t);
        }
        int split = 0, tails = 0;
        for (Address entry : entries) {
            Function old = fm.getFunctionContaining(entry);
            if (old == null || old.getEntryPoint().equals(entry)) continue;
            AddressSet body = component(p, entry, old.getBody(), monitor);
            // An internal loop back to the original entry is not a separable exterior entry.
            if (body.isEmpty() || body.contains(old.getEntryPoint())) continue;
            AddressSet kept = new AddressSet(old.getBody());
            kept.delete(body);
            old.setBody(kept);
            createFunction(p, entry, body);
            split++;
            p.getBookmarkManager().setBookmark(entry, BookmarkType.ANALYSIS, "WSDecompilerBoundary",
                "Executed entry reached by another function; split from " + old.getEntryPoint());
            emit.accept(String.format("{\"rule\":\"A3\",\"entry\":\"%s\",\"parent\":\"%s\",\"outcome\":\"EXTERIOR_ENTRY_SPLIT\"}", entry, old.getEntryPoint()));
        }
        for (Instruction i : listing.getInstructions(true)) {
            if (!plainJump(i) || i.getFlowOverride() != FlowOverride.NONE) continue;
            Function from = fm.getFunctionContaining(i.getAddress());
            Function into = fm.getFunctionAt(i.getFlows()[0]);
            if (from == null || into == null || from.equals(into) || !proven(p, into.getEntryPoint())
                || from.getSymbol().getSource() == SourceType.USER_DEFINED) continue;
            Address target = into.getEntryPoint();
            i.setFlowOverride(FlowOverride.CALL_RETURN);
            tails++;
            p.getBookmarkManager().setBookmark(i.getAddress(), BookmarkType.ANALYSIS, "WSDecompilerBoundary",
                "Direct jump to separate executed function represented as tail transfer: " + target);
            emit.accept(String.format("{\"rule\":\"A3\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"TAIL_TRANSFER\"}", i.getAddress(), target));
        }
        // A split changes the owner of a structurally recovered switch too. Re-attach its
        // existing finite J1 cases, then give the new owners their weak-table execution locks.
        WSJumpTables.lockSwitches(p, evidence, emit, monitor);
        lockWeakTables(p, weak, "AFTER_SPLIT", locked, opaque, emit, monitor);
        WSJumpTables.pruneStaleOverrides(p, emit, monitor);
        // Ordinary analysis recognizes thunks after the final tail flows change.
        // Complete that same metadata now so re-import does not change it later.
        for (Function f : fm.getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isExternal() || f.isThunk() || f.getSymbol().getSource() == SourceType.USER_DEFINED
                    || f.getSignatureSource() == SourceType.USER_DEFINED
                    || f.getSignatureSource() == SourceType.IMPORTED) continue;
            boolean tail = false;
            for (Instruction i : listing.getInstructions(f.getBody(), true))
                if (i.getFlowOverride() == FlowOverride.CALL_RETURN) { tail = true; break; }
            if (!tail) continue;
            Address target = CreateThunkFunctionCmd.getThunkedAddr(p, f.getEntryPoint(), true);
            Function into = target == null || target == Address.NO_ADDRESS ? null : fm.getFunctionAt(target);
            if (into == null || into.equals(f) || into.isThunk() && into.getThunkedFunction(true).equals(f)) continue;
            f.setThunkedFunction(into);
            emit.accept(String.format("{\"rule\":\"A3\",\"entry\":\"%s\",\"target\":\"%s\",\"outcome\":\"THUNK_METADATA\"}",
                f.getEntryPoint(), into.getEntryPoint()));
        }
        return String.format("A3 exterior entries split %d, tail transfers %d, weak tables locked %d, opaque %d", split, tails, locked.size(), opaque.size());
    }

    private static Set<Address> weakTables(Program p, List<String> evidence) {
        Set<Address> weak = new TreeSet<>();
        for (String line : evidence) {
            if (!line.contains("\"rule\":\"J1\"") || !line.contains("\"outcome\":\"UNRESOLVED\"")
                || !line.contains("UNBOUNDED_WEAK_STOP:")) continue;
            String marker = "\"site\":\"";
            int at = line.indexOf(marker);
            if (at < 0) continue;
            int start = at + marker.length(), end = line.indexOf('"', start);
            if (end < 0) continue;
            Address a = p.getAddressFactory().getAddress(line.substring(start, end));
            if (a != null) weak.add(a);
        }
        return weak;
    }

    private static boolean hasProof(Program p, Function f) {
        if (proven(p, f.getEntryPoint())) return true;
        for (Instruction i : p.getListing().getInstructions(f.getBody(), true))
            if (proven(p, i.getAddress())) return true;
        return false;
    }

    private static void lockWeakTables(Program p, Set<Address> weak, String phase,
                                       Set<Address> locked, Set<Address> opaque,
                                       Consumer<String> emit, TaskMonitor monitor) throws Exception {
        Listing listing = p.getListing();
        for (Address site : weak) {
            monitor.checkCancelled();
            Instruction i = listing.getInstructionAt(site);
            Function f = p.getFunctionManager().getFunctionContaining(site);
            if (i == null || !i.getFlowType().isJump() || !i.getFlowType().isComputed()
                || f == null || !hasProof(p, f) || f.getSymbol().getSource() == SourceType.USER_DEFINED) continue;
            ArrayList<Address> cases = new ArrayList<>();
            for (Address t : i.getFlows()) {
                if (site.getAddressSpace().equals(t.getAddressSpace()) && proven(p, t)
                    && listing.getInstructionAt(t) != null && !cases.contains(t)) cases.add(t);
            }
            if (cases.isEmpty()) {
                // An empty JumpTable is not a valid override. Represent the unknown JMP as
                // an opaque tail transfer: its computed destination and original bytes remain,
                // while speculative table reads cannot pull arbitrary code into this function.
                if (i.getFlowOverride() != FlowOverride.NONE) continue;
                i.setFlowOverride(FlowOverride.CALL_RETURN);
                opaque.add(site);
                p.getBookmarkManager().setBookmark(site, BookmarkType.ANALYSIS, "WSDecompilerBoundary",
                    "Unbounded weak table without supported cases; computed destination retained as opaque tail transfer");
                emit.accept(String.format("{\"rule\":\"A3\",\"site\":\"%s\",\"function\":\"%s\",\"outcome\":\"OPAQUE_WEAK_TABLE\"}", site, f.getEntryPoint()));
                continue;
            }
            new JumpTable(site, cases, true, 0).writeOverride(f);
            locked.add(site);
            p.getBookmarkManager().setBookmark(site, BookmarkType.ANALYSIS, "WSDecompilerBoundary",
                "Unbounded weak table: finite executed-target view; unplayed cases remain unknown");
            emit.accept(String.format("{\"rule\":\"A3\",\"site\":\"%s\",\"function\":\"%s\",\"outcome\":\"EXECUTED_TABLE_LOCK\",\"phase\":\"%s\",\"cases\":%d}", site, f.getEntryPoint(), phase, cases.size()));
        }
    }

    private static boolean plainJump(Instruction i) {
        return i.getFlowType().isJump() && !i.getFlowType().isComputed()
            && i.getFlows().length == 1;
    }

    private static Function createFunction(Program p, Address entry, AddressSetView body) throws Exception {
        Symbol primary = p.getSymbolTable().getPrimarySymbol(entry);
        if (primary == null || primary.isDynamic() || primary.getParentNamespace().isGlobal())
            return p.getFunctionManager().createFunction(null, entry, body, SourceType.DEFAULT);
        // Default creation promotes the primary label, including a case label in a function's
        // jump-override namespace. Functions cannot have that parent. Keep the override label
        // intact and create the automatic function explicitly in the global namespace instead.
        Function f = p.getFunctionManager().createFunction("ws_executed_" + entry.toString().replace(':', '_'),
            p.getGlobalNamespace(), entry, body, SourceType.ANALYSIS);
        f.setName(SymbolUtilities.getDefaultFunctionName(entry), SourceType.DEFAULT);
        return f;
    }
}
