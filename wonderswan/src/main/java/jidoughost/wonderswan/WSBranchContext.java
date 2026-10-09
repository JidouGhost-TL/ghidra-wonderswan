// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rule D2: a near branch resolving to another segment is always misdecoded (a 16-bit near branch
 * cannot change CS): the instruction was disassembled with the wrong decode context, typically by
 * following a context-less computed reference. Unexecuted branches are re-disassembled with the
 * context of their own segment (clear the single instruction, set csval, re-decode it alone); the
 * re-decode must reproduce the mnemonic and length or the original decode is restored. Executed
 * branches are ground truth and stay. Runs after the jump tables (their targets are the usual
 * victims) and before the body fixup, so bodies form with the corrected flows.
 */
public final class WSBranchContext {
    final Program p;
    final Listing listing;
    final WSEvidence ev;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    int fixed, skippedExec, failed;

    public WSBranchContext(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p;
        this.ev = ev;
        this.emit = emit;
        this.monitor = monitor;
        listing = p.getListing();
    }

    public void apply() throws Exception {
        ProgramContext ctx = p.getProgramContext();
        ghidra.program.model.lang.Register csval = ctx.getRegister("csval");
        if (csval == null) return;
        for (Instruction x : listing.getInstructions(true)) {
            monitor.checkCancelled();
            var ft = x.getFlowType();
            if (!(ft.isJump() || ft.isCall() || ft.isConditional()) || ft.isComputed() || ft.isIndirect()) continue;
            String mn = x.getMnemonicString().toUpperCase();
            if (mn.equals("JMPF") || mn.equals("CALLF") || mn.equals("RETF") || mn.equals("IRET")) continue;
            Address s = x.getAddress();
            if (WSRamCode.isRam(p, s)) continue;
            if (!(s instanceof SegmentedAddress ss)) continue;
            for (Reference r : x.getReferencesFrom()) {
                if (!r.getReferenceType().isJump() && !r.getReferenceType().isCall()) continue;
                if (!(r.getToAddress() instanceof SegmentedAddress tt) || tt.getSegment() == ss.getSegment()) continue;
                if (ev.executed(s.getOffset())) {
                    skippedExec++;
                    emit.accept(String.format("{\"rule\":\"D2\",\"branch\":\"%s\",\"to\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"EXECUTED\"}", s, r.getToAddress()));
                    continue;
                }
                fixBranch(ctx, csval, x, ss.getSegment(), r.getToAddress());
                break;
            }
        }
    }

    void fixBranch(ProgramContext ctx, ghidra.program.model.lang.Register csval, Instruction x, int seg, Address was) throws Exception {
        Address s = x.getAddress();
        String mn = x.getMnemonicString();
        int len = x.getLength();
        java.math.BigInteger old = null;
        try {
            old = ctx.getValue(csval, s, false);
        } catch (Exception e) { /* no value to restore */ }
        // clear first: setting context over a decoded instruction conflicts with it
        listing.clearCodeUnits(s, s, false);
        ctx.setValue(csval, s, s, java.math.BigInteger.valueOf(seg));
        try {
            new DisassembleCommand(s, new AddressSet(s, s), true).applyTo(p, monitor);
        } finally {
            if (listing.getInstructionAt(s) == null) {
                if (old != null) try {
                    ctx.setValue(csval, s, s, old);
                } catch (Exception e) { /* restore what we can */ }
                new DisassembleCommand(s, new AddressSet(s, s), true).applyTo(p, monitor);
            }
        }
        Instruction n = listing.getInstructionAt(s);
        if (n != null && n.getMnemonicString().equalsIgnoreCase(mn) && n.getLength() == len) {
            Address to = null;
            for (Reference r : n.getReferencesFrom())
                if (r.getReferenceType().isJump() || r.getReferenceType().isCall()) to = r.getToAddress();
            fixed++;
            emit.accept(String.format("{\"rule\":\"D2\",\"branch\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"outcome\":\"FIXED\"}", s, was, to));
            return;
        }
        // re-decode differs: restore the original decode rather than leave a changed one
        listing.clearCodeUnits(s, s, false);
        if (old != null) try {
            ctx.setValue(csval, s, s, old);
        } catch (Exception e) { /* restore what we can */ }
        new DisassembleCommand(s, new AddressSet(s, s), true).applyTo(p, monitor);
        failed++;
        emit.accept(String.format("{\"rule\":\"D2\",\"branch\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"REDECODE_MISMATCH\"}", s));
    }

    public String summary() {
        return String.format("D2 cross-segment branches: fixed %d, executed kept %d, re-decode mismatches %d", fixed, skippedExec, failed);
    }
}
