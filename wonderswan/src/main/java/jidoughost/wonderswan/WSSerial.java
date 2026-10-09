// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * One-byte UART buffers, clocked in 3.072 MHz master clocks.
 * Hardware contract: https://ws.nesdev.org/wiki/UART (8N1, B1/B3) and
 * https://ws.nesdev.org/wiki/Interrupts (level sources 0 and 3).
 * The transport schedules a completed byte; it does not emulate the individual wire bits.
 */
public final class WSSerial {
    public static final int MASTER_HZ = 3_072_000;

    /**
     * A cable or device attached to the transmitter. Called at the start of a byte, with
     * absolute master-clock timestamps. Deliver only at {@code endClock}, and only if
     * {@link #validTransmission(long)} still holds. Device replies use {@link #receive}.
     */
    @FunctionalInterface
    public interface Peer {
        void transmit(int value, int baud, long startClock, long endClock, long token);
    }

    public enum Reception { RECEIVED, DISABLED, SPEED_MISMATCH, OVERRUN }

    private final Peer peer;
    private int control, received;
    private boolean full, overrun, transmitting;
    private long clock, txEnd, token;

    public WSSerial(Peer peer) {
        this.peer = java.util.Objects.requireNonNull(peer);
    }

    public boolean enabled() { return (control & 0x80) != 0; }
    public int baud() { return (control & 0x40) != 0 ? 38_400 : 9_600; }
    public int byteClocks() { return MASTER_HZ / baud() * 10; }
    public long clock() { return clock; }

    /** Monotonic clock; the transmit buffer becomes empty exactly at the stop-bit boundary. */
    public void advanceTo(long nextClock) {
        if (nextClock < clock) throw new IllegalArgumentException("serial clock moved backwards");
        clock = nextClock;
        if (transmitting && clock >= txEnd) transmitting = false;
    }

    public int readStatus() {
        return control | (enabled() ? (full ? 1 : 0) | (overrun ? 2 : 0) | (transmitting ? 0 : 4) : 0);
    }

    /** Only enable and speed are stored; bit 5 clears the sticky overrun flag. */
    public void writeControl(int value) {
        if ((value & 0x20) != 0) overrun = false;
        int next = value & 0xC0;
        if ((next & 0x80) == 0) {
            full = overrun = transmitting = false;
            received = 0;
            token++;                         // cancel any byte still on the wire
        }
        control = next;
    }

    /** Disabled or busy writes are ignored; software must wait for B3 bit 2. */
    public boolean writeData(int value) {
        if (!enabled() || transmitting) return false;
        transmitting = true;
        txEnd = clock + byteClocks();
        peer.transmit(value & 0xFF, baud(), clock, txEnd, token);
        return true;
    }

    public boolean validTransmission(long transmissionToken) { return enabled() && token == transmissionToken; }

    /** The unread byte survives an overrun; the incoming byte is discarded. */
    public Reception receive(int value, int senderBaud) {
        if (!enabled()) return Reception.DISABLED;
        if (baud() != senderBaud) return Reception.SPEED_MISMATCH;
        if (full) { overrun = true; return Reception.OVERRUN; }
        received = value & 0xFF;
        full = true;
        return Reception.RECEIVED;
    }

    /** Reading B1 consumes the receive buffer, but does not clear overrun or the IRQ latch. */
    public int readData() {
        full = false;
        return received;
    }

    /** Active level sources, before the machine's B2 mask and B4 latch. */
    public int interruptLevels() {
        if (!enabled()) return 0;
        return (transmitting ? 0 : 1) | (full ? 8 : 0);
    }
}
