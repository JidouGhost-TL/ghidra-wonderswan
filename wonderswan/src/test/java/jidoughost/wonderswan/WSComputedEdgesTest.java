// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/** Rule E0b: computed branches resolve in their own interrupt context (see {@link WSComputedEdges}). */
public final class WSComputedEdgesTest {
    private WSComputedEdgesTest() { }

    static final class Seen implements WSComputedEdges.Sink {
        final List<String> edges = new ArrayList<>();
        @Override public void edge(long from, long to, int targetCs, String kind) {
            edges.add(String.format("%x,%x,%x,%s", from, to, targetCs, kind));
        }
    }

    public static void run() {
        plainJump();
        preemptedJumpSkipsHandlerFlow();
        nestedInterrupts();
        branchInsideHandler();
        softwareInterrupt();
        iretAtZero();
        reset();
        System.out.println("WSComputedEdgesTest: PASS");
    }

    /** No interrupt: the next instruction is the target. */
    static void plainJump() {
        WSComputedEdges e = new WSComputedEdges();
        Seen s = new Seen();
        e.noteComputedBranch(0x5000, "jump");
        e.resolveAt(0x5100, 0x5000, s);
        Check.eq(1, s.edges.size(), "plain jump records one edge");
        Check.eq("5000,5100,5000,jump", s.edges.get(0), "plain jump target");
        Check.eq(0, e.carried(), "plain jump carried");
        Check.eq(0, e.resumed(), "plain jump resumed");
        Check.isFalse(e.hasPending(), "plain jump nothing pending");
    }

    /** The false-target shape: an IRQ preempts the branch. Neither the handler entry nor the
     *  handler's second instruction (the old E0 outcome) is recorded; the edge resolves at the
     *  post-IRET instruction. */
    static void preemptedJumpSkipsHandlerFlow() {
        WSComputedEdges e = new WSComputedEdges();
        Seen s = new Seen();
        e.noteComputedBranch(0x5000, "jump");
        e.noteInterruptEntry();          // a timer IRQ fires on the boundary right after the JMP
        e.resolveAt(0x8000, 0x8000, s);  // handler entry (1-byte prologue instruction)
        Check.eq(0, s.edges.size(), "entry is not the target");
        e.resolveAt(0x8001, 0x8000, s);  // handler's 2nd instruction: still handler flow
        Check.eq(0, s.edges.size(), "entry+1 is not the target either");
        Check.eq(1, e.carried(), "preempted edge carried");
        Check.isTrue(e.hasPending(), "preempted edge still pending in handler");
        e.resolveAt(0x8002, 0x8000, s);  // handler body: still nothing
        Check.eq(0, s.edges.size(), "handler body is not the target");
        e.noteIret();
        e.resolveAt(0x5100, 0x5000, s);  // resumed true target
        Check.eq(1, s.edges.size(), "post-IRET instruction is the target");
        Check.eq("5000,5100,5000,jump", s.edges.get(0), "resumed edge");
        Check.eq(1, e.resumed(), "carried edge resumed");
        Check.eq(1, e.maxDepth(), "max depth one");
    }

    /** Nested interrupts: the outer edge survives both levels and resolves after both IRETs. */
    static void nestedInterrupts() {
        WSComputedEdges e = new WSComputedEdges();
        Seen s = new Seen();
        e.noteComputedBranch(0x100, "call");
        e.noteInterruptEntry();
        e.resolveAt(0x200, 0xf000, s);
        e.noteInterruptEntry();          // nested IRQ inside the outer handler
        e.resolveAt(0x300, 0xf000, s);   // inner entry
        e.resolveAt(0x301, 0xf000, s);   // inner 2nd instruction
        Check.eq(0, s.edges.size(), "nothing recorded inside nested handlers");
        e.noteIret();                    // inner handler returns
        e.resolveAt(0x201, 0xf000, s);   // outer handler resumes: still not the target
        Check.eq(0, s.edges.size(), "outer handler flow is not the target");
        e.noteIret();
        e.resolveAt(0x104, 0x1000, s);
        Check.eq(1, s.edges.size(), "outer edge resolves after both IRETs");
        Check.eq("100,104,1000,call", s.edges.get(0), "outer edge kind kept");
        Check.eq(1, e.carried(), "nested carried once");
        Check.eq(1, e.resumed(), "nested resumed");
        Check.eq(2, e.maxDepth(), "max depth two");
    }

    /** A computed branch inside a handler resolves among handler instructions while the outer
     *  edge waits; both are recorded. */
    static void branchInsideHandler() {
        WSComputedEdges e = new WSComputedEdges();
        Seen s = new Seen();
        e.noteComputedBranch(0x100, "jump");
        e.noteInterruptEntry();
        e.resolveAt(0x200, 0xf000, s);
        e.noteComputedBranch(0x200, "jump");  // handler's own computed jump
        e.resolveAt(0x210, 0xf000, s);        // its handler-flow target
        Check.eq(1, s.edges.size(), "inner edge resolves in handler");
        Check.eq("200,210,f000,jump", s.edges.get(0), "inner edge");
        e.noteIret();
        e.resolveAt(0x104, 0x1000, s);
        Check.eq(2, s.edges.size(), "outer edge resolves after IRET");
        Check.eq("100,104,1000,jump", s.edges.get(1), "outer edge");
        Check.eq(1, e.carried(), "outer carried");
        Check.eq(1, e.resumed(), "outer resumed");
    }

    /** A software INT is itself a same-context target; the INT handler flow is not. */
    static void softwareInterrupt() {
        WSComputedEdges e = new WSComputedEdges();
        Seen s = new Seen();
        e.noteComputedBranch(0x100, "jump");
        e.resolveAt(0x104, 0x1000, s);   // the INT instruction is the branch target
        Check.eq("100,104,1000,jump", s.edges.get(0), "INT instruction is the target");
        e.noteInterruptEntry();          // the INT handler
        e.resolveAt(0x300, 0xf000, s);
        e.resolveAt(0x301, 0xf000, s);
        Check.eq(1, s.edges.size(), "INT handler flow records nothing");
        e.noteIret();
        e.resolveAt(0x106, 0x1000, s);   // resumed after the INT: nothing pending
        Check.eq(1, s.edges.size(), "no phantom edge after INT handler");
        Check.eq(0, e.carried(), "nothing carried across a software INT");
    }

    /** An IRET with no open interrupt (unbalanced code) does not go negative. */
    static void iretAtZero() {
        WSComputedEdges e = new WSComputedEdges();
        e.noteIret();
        Check.eq(0, e.depth(), "depth stays zero");
        Seen s = new Seen();
        e.noteComputedBranch(0x100, "jump");
        e.resolveAt(0x104, 0x1000, s);
        Check.eq(1, s.edges.size(), "branches still resolve");
    }

    static void reset() {
        WSComputedEdges e = new WSComputedEdges();
        e.noteComputedBranch(0x100, "jump");
        e.noteInterruptEntry();
        e.resolveAt(0x200, 0xf000, new Seen());
        e.reset();
        Check.eq(0, e.depth(), "reset depth");
        Check.eq(0, e.maxDepth(), "reset max depth");
        Check.eq(0, e.carried(), "reset carried");
        Check.eq(0, e.resumed(), "reset resumed");
        Check.isFalse(e.hasPending(), "reset pending");
    }

    public static void main(String[] args) {
        run();
    }
}
