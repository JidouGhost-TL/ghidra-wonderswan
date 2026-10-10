// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.ArrayDeque;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.IntConsumer;

/**
 * A console's serial port (the EXT connector's UART) exposed as a raw byte stream, so any program that speaks raw
 * serial bytes can be the cable partner: another console in a separate process or machine, a relay, a bridge to a USB
 * serial adapter on a real console, or an adapter model. The stream carries raw 8N1 data bytes and no speed, so both
 * ends must select the same speed.
 *
 * <p>Transmit: a byte leaves at the end of its byte time, as on the cable ({@link WSSerial.Peer}). Receive: bytes
 * from the stream are delivered no sooner than one byte time apart. {@link Pacing#PULL} also holds a byte while the
 * previous one is unread (no overrun from host-side bursts); {@link Pacing#WIRE} delivers at line rate, so an unread
 * byte causes overrun. Bytes arriving while the port is disabled are dropped, as on hardware.
 *
 * <p>Unlike {@link WSLink}, runs are not deterministic: arrival depends on the other end's wall-clock timing.
 */
public final class WSSerialEndpoint implements AutoCloseable {
    public enum Pacing { PULL, WIRE }

    private record Pending(int value, long end, long token) { }

    private final WSMachine machine;
    private final OutputStream out;
    private final WSLink.ByteObserver observer;
    private final ArrayDeque<Pending> sending = new ArrayDeque<>();
    private final Receiver receiver;
    private final Thread reader;
    private volatile boolean ended;
    private volatile IOException readFailure;

    /** Attach before the console runs. The reader thread drains {@code in} until it ends or {@link #close()}. */
    public WSSerialEndpoint(WSMachine machine, InputStream in, OutputStream out, Pacing pacing, WSLink.ByteObserver observer) {
        if (machine.instructions != 0 || machine.cycles != 0 || machine.serial() != null)
            throw new IllegalArgumentException("serial endpoint needs a fresh, unattached machine");
        this.machine = machine;
        this.out = out;
        this.observer = observer;
        receiver = new Receiver(pacing);
        machine.attachSerial((value, baud, start, end, token) -> sending.add(new Pending(value, end, token)));
        machine.serialClock = this::synchronise;
        reader = new Thread(() -> {
            try {
                for (int b; (b = in.read()) >= 0;) receiver.arrived.add(b);
            } catch (IOException e) {
                readFailure = e;
            } finally { ended = true; }
        }, "WSSerialEndpoint reader");
        reader.setDaemon(true);
        reader.start();
    }

    /** True once the other end closed the stream (bytes already received are still delivered). */
    public boolean ended() { return ended && receiver.arrived.isEmpty(); }

    /** Run the console to this master clock. */
    public void runUntil(long targetClock) {
        while (machine.cycles < targetClock) {
            synchronise();
            machine.stepLinkInstruction();
        }
        synchronise();
    }

    /**
     * Run whole frames (159 * 256 clocks). Input callback runs before each frame. With {@code realTime}, each frame
     * waits until its wall-clock time (about 75.5 frames per second), for partners that run in real time.
     */
    public void run(int frames, boolean realTime, IntConsumer onFrame) {
        if (frames < 0) throw new IllegalArgumentException("negative frame count");
        long start = machine.cycles, wallStart = System.nanoTime();
        double frameNanos = 1e9 * WSMachine.CYCLES_PER_FRAME / WSSerial.MASTER_HZ;
        for (int f = 0; f < frames; f++) {
            if (onFrame != null) onFrame.accept(f);
            runUntil(start + (f + 1L) * WSMachine.CYCLES_PER_FRAME);
            if (realTime) {
                long wait = wallStart + (long) ((f + 1) * frameNanos) - System.nanoTime();
                if (wait > 0) {
                    try { Thread.sleep(wait / 1_000_000, (int) (wait % 1_000_000)); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("serial endpoint run interrupted", e); }
                }
            }
        }
    }

    private void synchronise() {
        long now = machine.cycles;
        WSSerial serial = machine.serial();
        while (!sending.isEmpty() && sending.peek().end <= now) {
            Pending p = sending.remove();
            boolean valid = serial.validTransmission(p.token);
            if (valid) {
                try {
                    out.write(p.value);
                    out.flush();
                } catch (IOException e) { throw new UncheckedIOException("serial peer write failed", e); }
            }
            report("TX", p.end, p.value, serial.baud(), valid ? "SENT" : "CANCELLED");
        }
        receiver.deliver(serial, now, this::report);
        machine.pollSerial();
    }

    @FunctionalInterface
    interface Reporter { void report(String direction, long clock, int value, int baud, String result); }

    /** Receive side, separate from the machine so tests can drive a bare {@link WSSerial}. */
    static final class Receiver {
        final ConcurrentLinkedQueue<Integer> arrived = new ConcurrentLinkedQueue<>();
        private final Pacing pacing;
        private long nextReceive;

        Receiver(Pacing pacing) { this.pacing = pacing; }

        /** Hand arrived bytes to the UART at master clock {@code now}. */
        void deliver(WSSerial serial, long now, Reporter reporter) {
            if (nextReceive > now + serial.byteClocks()) nextReceive = now;    // clock restarted
            while (now >= nextReceive) {
                Integer value = arrived.peek();
                if (value == null) return;
                if (pacing == Pacing.PULL && serial.enabled() && (serial.readStatus() & 1) != 0) return;
                arrived.remove();
                WSSerial.Reception result = serial.receive(value, serial.baud());
                reporter.report("RX", now, value, serial.baud(), result.name());
                if (result != WSSerial.Reception.DISABLED) nextReceive = now + serial.byteClocks();
            }
        }
    }

    private void report(String direction, long clock, int value, int baud, String result) {
        if (observer != null)
            observer.transferred(new WSLink.ByteEvent(direction, clock, clock / WSMachine.CYCLES_PER_FRAME, value, baud, result));
    }

    /** The read failure, if the stream failed rather than ended. */
    public IOException readFailure() { return readFailure; }

    @Override public void close() throws IOException {
        out.close();
        reader.interrupt();
    }
}
