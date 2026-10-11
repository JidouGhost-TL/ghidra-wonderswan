// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.function.IntConsumer;

/**
 * Two independent consoles, a full-duplex cable and one deterministic master clock.
 *
 * <p>Console B is switched on {@link #powerOnOffset()} master clocks after console A. Two people never press
 * their power switches at the same instant, so two real consoles never run with the same display phase. With
 * identical cartridges and no offset, both programs would execute the same instruction on the same clock, and
 * every frame-driven transmission would start at the same time on both ends. Software that breaks symmetric
 * collisions by waiting for the partner's next frame would then wait forever, which never happens on hardware.
 * The default is a fixed, non-zero offset so that runs stay reproducible; pass 0 for the old lockstep start.
 */
public final class WSLink {
    public record ByteEvent(String direction, long clock, long frame, int value, int baud, String result) { }

    @FunctionalInterface
    public interface ByteObserver { void transferred(ByteEvent event); }

    /**
     * Default power-on delay of console B: 10,000 master clocks (about 3.3 ms, a quarter of a frame). It is
     * longer than a 38,400 baud byte (800 clocks) and a 9,600 baud byte (3,200 clocks) and shorter than a frame
     * (40,704 clocks), so a byte sent at one console's frame start arrives before the other console's next frame
     * start in both directions.
     */
    public static final long DEFAULT_POWER_ON_OFFSET = 10_000;

    private record Pending(int source, int value, int baud, long end, long token, long order) { }

    public final WSMachine a, b;
    private final PriorityQueue<Pending> pending = new PriorityQueue<>(
        Comparator.comparingLong(Pending::end).thenComparingLong(Pending::order));
    private long order, clock;
    private final long offsetB;
    private final ByteObserver observer;

    /** Attach before either console runs, with the default power-on offset. */
    public WSLink(WSMachine a, WSMachine b, ByteObserver observer) {
        this(a, b, observer, DEFAULT_POWER_ON_OFFSET);
    }

    /**
     * Attach before either console runs. ROMs, console models and save hardware may differ. Console B starts
     * {@code powerOnOffset} shared clocks after A (0 = both switched on together); until then it is off and
     * bytes sent to it are dropped as {@code DISABLED}.
     */
    public WSLink(WSMachine a, WSMachine b, ByteObserver observer, long powerOnOffset) {
        if (a == b || a.instructions != 0 || b.instructions != 0 || a.cycles != 0 || b.cycles != 0
                || a.serial() != null || b.serial() != null)
            throw new IllegalArgumentException("link needs two fresh, unattached machines");
        if (powerOnOffset < 0) throw new IllegalArgumentException("negative power-on offset");
        this.a = a;
        this.b = b;
        this.offsetB = powerOnOffset;
        this.observer = observer;
        a.attachSerial((value, baud, start, end, token) -> pending.add(new Pending(0, value, baud, end, token, order++)));
        b.attachSerial((value, baud, start, end, token) ->
            pending.add(new Pending(1, value, baud, end + offsetB, token, order++)));
        a.serialClock = b.serialClock = this::synchronise;
    }

    public long clock() { return clock; }

    /** Shared clocks between A's and B's power-on. */
    public long powerOnOffset() { return offsetB; }

    /** A console's own clock on the shared time line. */
    private long time(WSMachine m) { return m == b ? m.cycles + offsetB : m.cycles; }

    /** Advance both CPUs to this clock, interleaving instructions; the wire also ticks during DMA. */
    public void runUntil(long targetClock) {
        if (targetClock < clock) throw new IllegalArgumentException("link clock moved backwards");
        while (time(a) < targetClock || time(b) < targetClock) {
            synchronise();
            WSMachine next = time(a) <= time(b) ? a : b;
            next.stepLinkInstruction();
        }
        synchronise();
    }

    private void synchronise() {
        clock = Math.min(time(a), time(b));
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
