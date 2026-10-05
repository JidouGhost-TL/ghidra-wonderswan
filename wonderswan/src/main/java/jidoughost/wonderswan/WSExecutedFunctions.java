// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Rule E5: executed code outside every function gets a function.
 *
 * <p>Execution evidence (WSMachine, or an imported reference-emulator trace whose coverage lists executed addresses
 * without the transfers that reached them) can leave proven code decoded but outside any function: nothing observed a
 * call into it and no existing function flows to it (the body fixup would have taken it). Such code is grouped into
 * connected pieces by flow (fall-through and branches between executed, function-less instructions); every piece
 * entry, an instruction that something calls or that no other instruction of the piece flows to, becomes a function.
 * Executed code is proven, so this never creates a function in data. Only the default address space is considered:
 * bank-window overlays need per-bank evidence.
 */
public class WSExecutedFunctions {
    private final Program p;
    private final WSEvidence ev;
    private final Consumer<String> emit;
    private final TaskMonitor monitor;
    int pieces, created, failed, outside;

    public WSExecutedFunctions(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.ev = ev; this.emit = emit; this.monitor = monitor;
    }

    public void apply() throws Exception {
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        Set<Address> out = new TreeSet<>();
        for (Instruction i : listing.getInstructions(p.getMemory().getLoadedAndInitializedAddressSet(), true)) {
            monitor.checkCancelled();
            Address a = i.getAddress();
            if (a.getAddressSpace().isOverlaySpace()) continue;
            if (!ev.executed(a.getOffset())) continue;
            if (fm.getFunctionContaining(a) == null) out.add(a);
        }
        outside = out.size();
        // entries: called from anywhere, or not reached by flow from another function-less executed instruction
        Set<Address> hasPred = new HashSet<>();
        for (Address a : out) {
            Instruction i = listing.getInstructionAt(a);
            for (Address t : i.getFlows()) if (out.contains(t)) hasPred.add(t);
            Address ft = i.getFallThrough();
            if (ft != null && out.contains(ft)) hasPred.add(ft);
        }
        List<Address> called = new ArrayList<>(), heads = new ArrayList<>();
        for (Address a : out) {
            boolean isCalled = false;
            for (Reference r : p.getReferenceManager().getReferencesTo(a)) if (r.getReferenceType().isCall()) { isCalled = true; break; }
            if (isCalled) called.add(a);
            else if (!hasPred.contains(a)) heads.add(a);
        }
        List<Address> entries = new ArrayList<>(called);
        entries.addAll(heads);
        for (Address a : entries) {
            monitor.checkCancelled();
            if (fm.getFunctionContaining(a) != null) continue;   // absorbed by a function created earlier in this loop
            pieces++;
            boolean ok = new CreateFunctionCmd(a).applyTo(p, monitor) && fm.getFunctionAt(a) != null;
            if (ok) created++; else failed++;
            emit.accept(String.format("{\"rule\":\"E5\",\"entry\":\"%s\",\"why\":\"%s\",\"outcome\":\"%s\"}",
                a, called.contains(a) ? "CALLED" : "HEAD", ok ? "FUNCTION" : "FAILED"));
        }
    }

    public String summary() {
        return String.format("E5 executed code outside functions: %d instructions, %d entries, %d functions created, %d failed",
            outside, pieces, created, failed);
    }
}
