// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.function.IntConsumer;

/** Two independent consoles, a full-duplex cable and one deterministic master clock. */
public final class WSLink {
    public record ByteEvent(String direction, long clock, long frame, int value, int baud, String result) { }

    @FunctionalInterface
    public interface ByteObserver { void transferred(ByteEvent event); }

    private record Pending(int source, int value, int baud, long end, long token, long order) { }

    public final WSMachine a, b;
    private final PriorityQueue<Pending> pending = new PriorityQueue<>(
        Comparator.comparingLong(Pending::end).thenComparingLong(Pending::order));
    private long order, clock;
    private final ByteObserver observer;

    /** Attach before either console runs. ROMs, console models and save hardware may differ. */
    public WSLink(WSMachine a, WSMachine b, ByteObserver observer) {
        if (a == b || a.instructions != 0 || b.instructions != 0 || a.cycles != 0 || b.cycles != 0
                || a.serial() != null || b.serial() != null)
            throw new IllegalArgumentException("link needs two fresh, unattached machines");
        this.a = a;
        this.b = b;
        this.observer = observer;
        a.attachSerial((value, baud, start, end, token) -> pending.add(new Pending(0, value, baud, end, token, order++)));
        b.attachSerial((value, baud, start, end, token) -> pending.add(new Pending(1, value, baud, end, token, order++)));
        a.serialClock = b.serialClock = this::synchronise;
    }

    public long clock() { return clock; }

    /** Advance both CPUs to this clock, interleaving instructions; the wire also ticks during DMA. */
    public void runUntil(long targetClock) {
        if (targetClock < clock) throw new IllegalArgumentException("link clock moved backwards");
        while (a.cycles < targetClock || b.cycles < targetClock) {
            synchronise();
            WSMachine next = a.cycles <= b.cycles ? a : b;
            next.stepLinkInstruction();
        }
        synchronise();
    }

    private void synchronise() {
        clock = Math.min(a.cycles, b.cycles);
        while (!pending.isEmpty() && pending.peek().end <= clock) {
            Pending p = pending.remove();
            WSMachine sender = p.source == 0 ? a : b, receiver = p.source == 0 ? b : a;
            String result = sender.serial().validTransmission(p.token)
                ? receiver.serial().receive(p.value, p.baud).name() : "CANCELLED";
            if (observer != null) observer.transferred(new ByteEvent(p.source == 0 ? "A>B" : "B>A",
                p.end, p.end / WSMachine.CYCLES_PER_FRAME, p.value, p.baud, result));
        }
        a.pollSerial();
        b.pollSerial();
    }

    /** Input callback runs before each shared frame interval (159 * 256 clocks). */
    public void run(int frames, IntConsumer onFrame) {
        if (frames < 0) throw new IllegalArgumentException("negative frame count");
        long start = clock;
        for (int f = 0; f < frames; f++) {
            if (onFrame != null) onFrame.accept(f);
            runUntil(start + (f + 1L) * WSMachine.CYCLES_PER_FRAME);
        }
    }
}
