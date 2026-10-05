// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;

/**
 * Rule E0b: pending computed-branch edges resolve in the same interrupt context.
 *
 * A computed JMP/CALL's target is the first instruction executed after it <em>in the same
 * interrupt context</em>. When a hardware interrupt (or a software INT / trap) preempts the
 * branch, the handler entry — and every following handler instruction — executes in a deeper
 * context, so none of them is the branch target; the pending edge is carried across the handler
 * (including nested interrupts) and recorded at the post-IRET instruction, where execution
 * actually resumes. A computed branch inside a handler resolves normally among handler
 * instructions, which share its context.
 *
 * This supersedes rule E0's one-instruction skip (which skipped the handler entry but recorded
 * the handler's second instruction — still interrupt flow — as the branch target).
 *
 * Pure Java (no Ghidra): unit-tested by {@code WSComputedEdgesTest}.
 */
public final class WSComputedEdges {
    /** A computed branch awaiting its target. */
    private static final class Pending {
        final long from;
        final String kind;
        final int depth;
        boolean carried;
        Pending(long from, String kind, int depth) {
            this.from = from;
            this.kind = kind;
            this.depth = depth;
        }
    }

    /** Recorded-edge sink (WSMachine merges into its edge counts). */
    public interface Sink {
        void edge(long from, long to, int targetCs, String kind);
    }

    private final Deque<Pending> pending = new ArrayDeque<>();
    /** Current interrupt-nesting depth (0 = ordinary code). */
    private int depth;
    private int maxDepth;
    /** Pending edges that survived at least one interrupt entry. */
    private long carried;
    /** Carried edges later resolved at a same-context (post-IRET) instruction. */
    private long resumed;

    /** A computed JMP/CALL just executed at {@code from}: its target is still to come. */
    public void noteComputedBranch(long from, String kind) {
        pending.addLast(new Pending(from, kind, depth));
    }

    /** An interrupt entry (hardware IRQ, trap, INT, divide error) is about to execute. */
    public void noteInterruptEntry() {
        depth++;
        if (depth > maxDepth) maxDepth = depth;
    }

    /** An IRET just executed: the interrupted context resumes (clamped at ordinary code). */
    public void noteIret() {
        if (depth > 0) depth--;
    }

    /**
     * The instruction at {@code lin} (executing with CS {@code cs}) is about to run: record
     * every pending edge from this same context with it as the target; edges from shallower
     * contexts stay pending across this interrupt flow.
     */
    public void resolveAt(long lin, int cs, Sink sink) {
        for (Pending p : pending)
            if (!p.carried && p.depth < depth) {
                p.carried = true;
                carried++;
            }
        Iterator<Pending> it = pending.iterator();
        while (it.hasNext()) {
            Pending p = it.next();
            if (p.depth != depth) continue;
            sink.edge(p.from, lin, cs, p.kind);
            if (p.carried) resumed++;
            it.remove();
        }
    }

    /** True while a computed branch still awaits its target (diagnostics only). */
    public boolean hasPending() {
        return !pending.isEmpty();
    }

    public int depth() {
        return depth;
    }

    public int maxDepth() {
        return maxDepth;
    }

    public long carried() {
        return carried;
    }

    public long resumed() {
        return resumed;
    }

    /** Forget all state (snapshot restore starts a fresh run). */
    public void reset() {
        pending.clear();
        depth = 0;
        maxDepth = 0;
        carried = 0;
        resumed = 0;
    }
}
