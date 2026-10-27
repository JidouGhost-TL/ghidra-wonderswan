// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.function.Consumer;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rule D2: preserve near branches across address-display segment boundaries.
 * A rendered segment is a canonical address representation, not architectural CS.
 * Near flow can cross such a boundary without changing CS, or wrap IP within a
 * known CS. Neither case justifies replacing the instruction's decode context.
 * Without independent context evidence, retain the decode as a hypothesis.
 */
public final class WSBranchContext {
    final Program p;
    final Listing listing;
    final WSEvidence ev;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    int keptContext, skippedExec, unresolved;

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
                String why;
                if (ev.executed(s.getOffset())) {
                    skippedExec++;
                    why = "EXECUTED";
                } else if (ctx.getValue(csval, s, false) != null) {
                    keptContext++;
                    why = "CONTEXT_PRESERVED";
                } else {
                    unresolved++;
                    why = "UNKNOWN_CS";
                    if (p.getBookmarkManager().getBookmark(s, BookmarkType.ANALYSIS, "branch-context") == null)
                        p.getBookmarkManager().setBookmark(s, BookmarkType.ANALYSIS, "branch-context",
                            "Unknown architectural CS; existing near-branch decode retained as a hypothesis");
                }
                emit.accept(String.format("{\"rule\":\"D2\",\"branch\":\"%s\",\"to\":\"%s\",\"outcome\":\"SKIPPED\",\"why\":\"%s\"}", s, r.getToAddress(), why));
                break;
            }
        }
    }

    public String summary() {
        return String.format("D2 display-boundary branches: context kept %d, executed kept %d, unknown CS kept %d",
            keptContext, skippedExec, unresolved);
    }
}
