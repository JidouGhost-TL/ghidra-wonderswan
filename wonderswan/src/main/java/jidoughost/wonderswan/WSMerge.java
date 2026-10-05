// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rules M1 / T1: merge functions that one routine was split into, with per-item evidence.
 *
 * Runs as a post-script (MergeRoutines), not inside the evidence analyzers: Ghidra's own
 * late analysis re-splits analyzer-phase merges (it recreates functions at the merged-away
 * entries), while post-script merges survive to the saved project. Every phase that reads
 * function structure runs the merge script first, so all readers see the merged state.
 *
 * M1 (outlined blocks): a function T reached only by plain jumps from inside one other function C
 * (judged on the referring instructions: real calls and computed branches veto), whose body holds
 * no other entry, and whose every exit (jump targets and fall-through; calls return) lands inside
 * T or C is a block of C outlined by the splitter (the usual shape is a compare-chain switch: the
 * chain jumps to case fragments, each its own function because an unconditional jump stopped the
 * body). T is removed (its name kept as a label when it is not a default name); the referring
 * jumps' tail-call flow overrides are cleared and their call-typed references retyped (else neither
 * the body fixup nor the decompiler follows them), then C's body is fixed up over T. Anything the
 * fixup does not pull is restored as a function. Computed jumps inside T, recursion, and interrupt
 * entries veto the merge.
 *
 * T1 (fall-through): a function A with no return instruction whose last instruction is a CALL to a
 * returning function and whose fall-through is exactly the entry of another function B returns
 * through B: one routine split in two. B is removed (name kept as a label), A's body fixed up over
 * it. B must not be a thunk or an interrupt entry.
 */
public final class WSMerge {
    final Program p;
    final Listing listing;
    final FunctionManager fm;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    final Set<Address> interruptEntries = new HashSet<>();
    int m1, t1, retyped, cleared, unpulled;

    public WSMerge(Program p, Set<Address> interruptEntries, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor;
        listing = p.getListing();
        fm = p.getFunctionManager();
        if (interruptEntries != null) this.interruptEntries.addAll(interruptEntries);
    }

    public String summary() {
        return String.format("M1/T1 merges: outlined blocks merged %d, fall-through merges %d, jump overrides cleared %d, local call-refs retyped to jumps %d, unpulled restored %d",
            m1, t1, cleared, retyped, unpulled);
    }

    public void apply() throws Exception {
        for (int round = 0; round < 32; round++) {
            monitor.checkCancelled();
            int n = mergeOutlined() + mergeFallThrough();
            if (n == 0) break;
        }
    }

    // ---- M1 ------------------------------------------------------------------------------------

    int mergeOutlined() throws Exception {
        Map<Function, List<Function>> merges = new LinkedHashMap<>();
        for (Function t : fm.getFunctions(true)) {
            monitor.checkCancelled();
            if (t.isExternal() || t.isThunk()) continue;
            Function c = soleFlowReferrer(t);
            if (c == null || !exitsInside(t, c)) continue;
            merges.computeIfAbsent(c, k -> new ArrayList<>()).add(t);
        }
        int n = 0;
        for (Map.Entry<Function, List<Function>> e : merges.entrySet()) {
            Set<Address> demoted = new HashSet<>();
            for (Function t : e.getValue()) {
                if (fm.getFunctionAt(t.getEntryPoint()) == null) continue;   // already merged this round
                demote(t);
                demoted.add(t.getEntryPoint());
                emit.accept(String.format("{\"rule\":\"M1\",\"into\":\"%s\",\"merged\":\"%s\",\"outcome\":\"MERGED\"}",
                    e.getKey().getEntryPoint(), t.getEntryPoint()));
                m1++;
                n++;
            }
            // the container may itself have been merged away this round: the next round re-derives
            Function c = fm.getFunctionAt(e.getKey().getEntryPoint());
            if (c != null && !demoted.isEmpty()) {
                // retype first (clearing the override drops the call-typed reference as a side
                // effect, and a surviving call reference would recreate the function later);
                // clear second (a jump overridden to a call is not followed by the fixup)
                retypeLocalCalls(c, demoted);
                clearJumpOverrides(c, demoted);
                CreateFunctionCmd.fixupFunctionBody(p, c, monitor);
                verifyPulled(c.getEntryPoint(), demoted, "M1");
            }
        }
        return n;
    }

    /** The single function reaching t by plain (non-computed) jumps only, or null. Real calls veto
     *  (a called subroutine is not an outlined block, even when called once); computed branches veto
     *  (dispatch targets belong to the jump-table rules); recursion vetoes too. Data references are
     *  ignored: they survive on the kept label. The test is on the referring mnemonic, not the flow
     *  or reference type (a jump to a function entry can be overridden to a call in both). */
    Function soleFlowReferrer(Function t) {
        Function found = null;
        for (Reference r : p.getReferenceManager().getReferencesTo(t.getEntryPoint())) {
            if (!r.getReferenceType().isFlow()) continue;
            Instruction from = listing.getInstructionAt(r.getFromAddress());
            if (from == null || !isJump(from) || from.getFlowType().isComputed()) return null;
            Function cf = fm.getFunctionContaining(r.getFromAddress());
            if (cf == null || cf.equals(t)) return null;
            if (found == null) found = cf;
            else if (!found.equals(cf)) return null;
        }
        if (found == null || found.isThunk()) return null;
        if (found.getEntryPoint().equals(t.getEntryPoint())) return null;
        if (t.getBody().contains(found.getEntryPoint()) || found.getBody().contains(t.getEntryPoint())) return null;
        if (interruptEntries.contains(t.getEntryPoint())) return null;
        for (Function u : fm.getFunctions(t.getBody(), true))
            if (!u.getEntryPoint().equals(t.getEntryPoint())) return null;   // an entry nested in t
        return found;
    }

    /** A jump-family mnemonic (JMP/Jcc/JCXZ/LOOP): no call, interrupt or return starts this way. */
    static boolean isJump(Instruction ins) {
        String mn = ins.getMnemonicString().toUpperCase();
        return mn.startsWith("J") || mn.startsWith("LOOP");
    }

    /**
     * A jump to a merged-away entry keeps its tail-call flow override (CALL_TERMINATOR), which the
     * body fixup does not follow: clear it back to a plain jump. Only jumps to demoted entries.
     */
    void clearJumpOverrides(Function c, Set<Address> demoted) {
        for (Instruction ins : listing.getInstructions(c.getBody(), true)) {
            if (!isJump(ins) || ins.getFlowOverride() == FlowOverride.NONE) continue;
            for (Address f : ins.getFlows())
                if (demoted.contains(f)) {
                    ins.setFlowOverride(FlowOverride.NONE);
                    cleared++;
                    break;
                }
        }
    }

    /**
     * After a merge, a jump inside the container that still carries a call-typed reference to a
     * merged-away entry (a tail-call override from when the target was a function) would decompile
     * as a call to a label: retype it to the plain jump it now is, before the fixup. Computed and
     * user/imported references are left alone.
     */
    void retypeLocalCalls(Function c, Set<Address> demoted) {
        for (Instruction ins : listing.getInstructions(c.getBody(), true)) {
            if (!isJump(ins)) continue;
            for (Reference r : p.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                if (!r.getReferenceType().isCall() || r.getReferenceType().isComputed()) continue;
                if (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED) continue;
                if (!demoted.contains(r.getToAddress())) continue;
                RefType to = r.getReferenceType().isConditional() ? RefType.CONDITIONAL_JUMP : RefType.UNCONDITIONAL_JUMP;
                p.getReferenceManager().delete(r);
                p.getReferenceManager().addMemoryReference(ins.getAddress(), r.getToAddress(), to, r.getSource(), Reference.MNEMONIC);
                retyped++;
            }
        }
    }

    /**
     * The fixup must have pulled every demoted entry into the container; anything left outside is
     * restored as a function (an orphaned body is worse than a split routine).
     */
    void verifyPulled(Address container, Set<Address> demoted, String rule) throws Exception {
        Function c = fm.getFunctionAt(container);
        if (c == null) return;
        for (Address d : demoted) {
            if (c.getBody().contains(d)) continue;
            unpulled++;
            emit.accept(String.format("{\"rule\":\"%s\",\"into\":\"%s\",\"merged\":\"%s\",\"outcome\":\"UNPULLED_RESTORED\"}",
                rule, container, d));
            CreateFunctionCmd cmd = new CreateFunctionCmd(d);
            cmd.applyTo(p, monitor);
        }
    }

    /** Every exit of t (jump targets, any fall-through) lands in t or c; no computed branches. */
    boolean exitsInside(Function t, Function c) {
        AddressSetView inside = t.getBody().union(c.getBody());
        for (Instruction ins : listing.getInstructions(t.getBody(), true)) {
            if (ins.getFlowType().isComputed()) return false;
            if (ins.getFlowType().isJump())
                for (Address f : ins.getFlows()) if (!inside.contains(f)) return false;
            if (ins.getFallThrough() != null && !inside.contains(ins.getFallThrough())) return false;
        }
        return true;
    }

    // ---- T1 ------------------------------------------------------------------------------------

    int mergeFallThrough() throws Exception {
        List<Function[]> merges = new ArrayList<>();
        for (Function a : fm.getFunctions(true)) {
            monitor.checkCancelled();
            if (a.isExternal() || a.isThunk()) continue;
            Instruction last = null;
            boolean returns = false;
            for (Instruction ins : listing.getInstructions(a.getBody(), true)) {
                last = ins;
                String mn = ins.getMnemonicString().toUpperCase();
                if (mn.startsWith("RET") || mn.equals("IRET")) { returns = true; break; }
            }
            if (returns || last == null || !last.getFlowType().isCall()) continue;
            Address ft = last.getFallThrough();
            if (ft == null) continue;
            Function b = fm.getFunctionAt(ft);
            if (b == null || b.isThunk() || b.isExternal() || b.equals(a)) continue;
            if (a.getBody().contains(b.getEntryPoint()) || b.getBody().contains(a.getEntryPoint())) continue;
            if (interruptEntries.contains(b.getEntryPoint())) continue;
            boolean nested = false;
            for (Function u : fm.getFunctions(b.getBody(), true))
                if (!u.getEntryPoint().equals(b.getEntryPoint())) { nested = true; break; }
            if (nested) continue;   // swallowing an entry (thunks included) breaks the fixup
            if (!callReturns(last)) continue;
            merges.add(new Function[] { a, b });
        }
        int n = 0;
        for (Function[] m : merges) {
            if (fm.getFunctionAt(m[0].getEntryPoint()) == null || fm.getFunctionAt(m[1].getEntryPoint()) == null) continue;
            demote(m[1]);
            Set<Address> demoted = new HashSet<>(List.of(m[1].getEntryPoint()));
            retypeLocalCalls(m[0], demoted);
            clearJumpOverrides(m[0], demoted);
            CreateFunctionCmd.fixupFunctionBody(p, m[0], monitor);
            verifyPulled(m[0].getEntryPoint(), demoted, "T1");
            emit.accept(String.format("{\"rule\":\"T1\",\"into\":\"%s\",\"merged\":\"%s\",\"outcome\":\"MERGED\"}",
                m[0].getEntryPoint(), m[1].getEntryPoint()));
            t1++;
            n++;
        }
        return n;
    }

    /** False only when the call target is known and never returns (then A cannot fall through). */
    boolean callReturns(Instruction call) {
        for (Address f : call.getFlows()) {
            Function t = fm.getFunctionAt(f);
            if (t == null) t = fm.getFunctionContaining(f);
            if (t != null && t.hasNoReturn()) return false;
        }
        return true;
    }

    /** Remove a function but keep a non-default name as a label (data references stay resolved). */
    void demote(Function t) throws Exception {
        Address e = t.getEntryPoint();
        String name = t.getName();
        fm.removeFunction(e);
        try {
            if (!name.startsWith("FUN_") && !name.startsWith("LAB_") && !name.startsWith("DAT_")
                    && !name.startsWith("SUB_") && p.getSymbolTable().getPrimarySymbol(e) == null)
                p.getSymbolTable().createLabel(e, name, SourceType.ANALYSIS).setPrimary();
        } catch (Exception x) { /* a label failed: the merge stands without it */ }
    }
}
