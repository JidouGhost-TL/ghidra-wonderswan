// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * Unit tests for {@link WSRtc}: the 2003 command protocol on $CA/$CB (status bits, payload
 * lengths, first-byte pre-load, invalid commands, no-chip reads) and the S-3511A register model
 * (BCD validation, clock init, frame advance with rollover).
 */
public final class WSRtcTest {
    private WSRtcTest() { }

    public static void run() {
        defaultClock();
        readStatusBits();
        writeThenReadDateTime();
        writeTimeOnly();
        resetCommands();
        invalidCommand();
        nonsenseCommands();
        alarmWrite();
        noChip();
        validation();
        advanceRollover();
        System.out.println("WSRtcTest: PASS");
    }

    /** Read out a full command payload the way the test ROM does (poll ready, read, check busy). */
    private static int[] fetch(WSRtc r, int cmd) {
        r.writeCommand(cmd);
        int[] out = new int[9];
        int n = 0;
        for (int i = 0; i < 9; i++) {
            int st = r.readStatus();
            Check.isTrue((st & 0x80) != 0, "ready set while fetching " + Integer.toHexString(cmd));
            out[n++] = r.readData();
            if ((r.readStatus() & 0x10) == 0) break;
        }
        int[] got = new int[n];
        System.arraycopy(out, 0, got, 0, n);
        return got;
    }

    private static void defaultClock() {
        // Fixed default: 2000-01-01 00:00:00 UTC, a Saturday (day-of-week 6, Sunday = 0).
        WSRtc r = new WSRtc();
        int[] dt = fetch(r, 0x15);
        Check.eq(7, dt.length, "date+time length");
        Check.eq(0x00, dt[0], "year");
        Check.eq(0x01, dt[1], "month");
        Check.eq(0x01, dt[2], "day");
        Check.eq(0x06, dt[3], "day of week");
        Check.eq(0x00, dt[4], "hour");
        Check.eq(0x00, dt[5], "minute");
        Check.eq(0x00, dt[6], "second");
    }

    private static void readStatusBits() {
        WSRtc r = new WSRtc();
        int[] st = fetch(r, 0x13);
        Check.eq(1, st.length, "status length");
        Check.eq(0x02, st[0] & 0x7F, "status low bits preserved");
        // Power-on state has the power-failure bit set; reading the status clears it.
        Check.eq(0x00, r.statusByte() & 0x80, "power-failure cleared by status read");
        int[] hms = fetch(r, 0x17);
        Check.eq(3, hms.length, "time length");
    }

    private static void writeThenReadDateTime() {
        WSRtc r = new WSRtc();
        // 24-hour mode first (power-on is 12-hour): status bit 6.
        r.writeData(0x42);
        r.writeCommand(0x12);
        Check.eq(0, r.readStatus() & 0x10, "single-byte write completes at once");
        int[] payload = { 0x03, 0x12, 0x25, 0x04, 0x23, 0x59, 0x58 };
        r.writeData(payload[0]);   // first byte pre-loaded before the command
        r.writeCommand(0x14);
        for (int i = 1; i < payload.length; i++) r.writeData(payload[i]);
        Check.eq(0, r.readStatus() & 0x10, "busy clears with the last byte");
        Check.isTrue((r.readStatus() & 0x80) != 0, "ready set at the end");
        int[] dt = fetch(r, 0x15);
        for (int i = 0; i < payload.length; i++) {
            // In 24-hour mode the AM/PM bit follows the value (set for hour >= $12).
            int want = i == 4 ? 0xA3 : payload[i];
            Check.eq(want, dt[i], "date+time byte " + i);
        }
    }

    private static void writeTimeOnly() {
        WSRtc r = new WSRtc();
        r.writeData(0x42);
        r.writeCommand(0x12);
        r.writeData(0x11);
        r.writeCommand(0x16);
        r.writeData(0x22);
        r.writeData(0x33);
        int[] hms = fetch(r, 0x17);
        Check.eq(0x11, hms[0], "hour");
        Check.eq(0x22, hms[1], "minute");
        Check.eq(0x33, hms[2], "second");
        int[] dt = fetch(r, 0x15);
        Check.eq(0x00, dt[0], "date untouched by time write");
    }

    private static void resetCommands() {
        for (int cmd : new int[] { 0x10, 0x11 }) {
            WSRtc r = new WSRtc();
            r.writeData(0x42);
            r.writeCommand(0x12);
            r.writeCommand(cmd);
            int st = r.readStatus();
            Check.eq(0, st & 0x10, "reset completes at once");
            Check.isTrue((st & 0x80) != 0, "ready set after reset");
            Check.eq(0, r.statusByte(), "reset clears status");
            int[] dt = fetch(r, 0x15);
            Check.eq(0x01, dt[1], "reset month");
            Check.eq(0x01, dt[2], "reset day");
            Check.eq(0x00, dt[4], "reset hour");
        }
    }

    private static void invalidCommand() {
        WSRtc r = new WSRtc();
        r.writeCommand(0x05);   // bit 4 clear in the command: stuck clear, never ready
        Check.eq(0, r.readStatus() & 0x90, "invalid $05: neither ready nor busy");
        r.writeCommand(0x1D);   // bit 4 set: stuck set
        Check.eq(0x10, r.readStatus() & 0x90, "invalid $1D: busy stuck as written");
        r.writeCommand(0x15);   // a valid command recovers
        Check.isTrue((r.readStatus() & 0x80) != 0, "valid command after invalid works");
    }

    private static void nonsenseCommands() {
        WSRtc r = new WSRtc();
        int[] n = fetch(r, 0x1B);
        Check.eq(2, n.length, "nonsense read length");
        Check.eq(0xFF, n[0], "nonsense byte 0");
        Check.eq(0xFF, n[1], "nonsense byte 1");
        r.writeData(0xAA);
        r.writeCommand(0x1A);
        r.writeData(0xBB);   // ignored by the chip
        Check.eq(0, r.readStatus() & 0x10, "nonsense write completes");
        int[] a = fetch(r, 0x19);
        Check.eq(0xFF, a[0] & 0xFF, "alarm nonsense byte 0");
        Check.eq(0xFFFF, (r.alarm()[0] << 8) | r.alarm()[1], "$19 writes $FFFF to the alarm");
    }

    private static void alarmWrite() {
        WSRtc r = new WSRtc();
        r.writeData(0x12);
        r.writeCommand(0x18);
        r.writeData(0x34);
        Check.eq(0x12, r.alarm()[0], "alarm byte 0");
        Check.eq(0x34, r.alarm()[1], "alarm byte 1");
    }

    private static void noChip() {
        WSRtc r = new WSRtc();
        r.chipPresent = false;
        int[] dt = fetch(r, 0x15);
        for (int b : dt) Check.eq(0xFF, b, "no-chip payload reads $FF");
        Check.eq(0x82, r.statusByte(), "no-chip writes change nothing");
    }

    private static void validation() {
        WSRtc r = new WSRtc();
        r.writeData(0x42);   // 24-hour mode
        r.writeCommand(0x12);
        int[] bad = { 0x1A, 0x13, 0x32, 0x07, 0x24, 0x60, 0x59 };
        r.writeData(bad[0]);
        r.writeCommand(0x14);
        for (int i = 1; i < bad.length; i++) r.writeData(bad[i]);
        int[] dt = r.dateTime();
        Check.eq(0x00, dt[0], "bad year -> 00");
        Check.eq(0x01, dt[1], "bad month -> 01");
        Check.eq(0x01, dt[2], "bad day -> 01");
        Check.eq(0x00, dt[3], "bad weekday -> 00");
        Check.eq(0x00, dt[4], "bad hour -> 00");
        Check.eq(0x00, dt[5], "bad minute -> 00");
        Check.eq(0x59, dt[6], "good second kept");
    }

    private static void advanceRollover() {
        // Leap-day rollover: 2000-02-28 23:59:58 + 75*3 frames = 2000-02-29 00:00:01.
        WSRtc r = new WSRtc(new WSRtc.FixedClock(951782398000L));
        int[] dt = r.dateTime();
        Check.eq(0x28, dt[2], "leap eve day");
        r.advanceFrames(75 * 3);
        dt = r.dateTime();
        Check.eq(0x29, dt[2], "leap day");
        Check.eq(0x00, dt[4], "midnight hour");
        Check.eq(0x01, dt[6], "one second past");
        // Month lengths: 2001-02-28 23:59:59 + 1 s = 2001-03-01 00:00:00 (not a leap year).
        WSRtc r2 = new WSRtc(new WSRtc.FixedClock(983404799000L));
        r2.advanceFrames(75);
        dt = r2.dateTime();
        Check.eq(0x03, dt[1], "march");
        Check.eq(0x01, dt[2], "first");
        // Determinism: same frames, same time.
        WSRtc a = new WSRtc(), b = new WSRtc();
        a.advanceFrames(7500);
        b.advanceFrames(7500);
        int[] da = a.dateTime(), db = b.dateTime();
        for (int i = 0; i < 7; i++) Check.eq(da[i], db[i], "deterministic byte " + i);
    }

    public static void main(String[] args) {
        run();
    }
}
