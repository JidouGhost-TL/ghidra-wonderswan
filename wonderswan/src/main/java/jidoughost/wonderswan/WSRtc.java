// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * The 2003 mapper's real-time clock interface (ports $CA command/status, $CB data) with an
 * S-3511A register model behind it (WSdev Bandai_2003, Real-Time_Clock; nesdev forum t21513).
 *
 * <p>Interface: writing a valid command ($10-$1B) to $CA starts a transaction. Status reads from
 * $CA return {@code R00B CCCC} (R = ready bit 7, B = busy bit 4, C = command). Busy is set while
 * payload bytes are still to transfer and clears with the last one; ready is set whenever $CB is
 * ready for access, including at the end of a command (also zero-byte ones). A new $CA write
 * aborts any ongoing transaction. Invalid commands ($00-$0F, $1C-$1F) stop the transaction with
 * bit 4 stuck as written and ready clear. For write commands the first payload byte must already
 * be in $CB when the command is written.
 *
 * <p>Payloads: $10/$11 reset (none), $12/$13 status (1 byte), $14/$15 date+time (7 bytes
 * YMDW HMS), $16/$17 time (3 bytes HMS), $18/$19 alarm (2 bytes), $1A/$1B nonsense (2 bytes).
 * $19 reads back $FFFF while writing $FFFF to the alarm register; $1A's bytes are ignored;
 * $1B reads $FFFF. Without an S-3511A chip ({@link #chipPresent} false) all payload reads are
 * $FF (the 2003's pull-up) and writes change nothing, while the status bits behave the same.
 *
 * <p>Time: the date/time registers initialise from a {@link Clock} (fixed by default, so runs are
 * reproducible) and advance one second per {@link #FRAMES_PER_SECOND} frames via
 * {@link #advanceFrames}. Reset commands restore the documented reset values; otherwise the
 * registers only change through the write commands. The alarm output pin (cartridge IRQ) is not
 * modelled.
 */
public final class WSRtc {

    /** Nominal display frames per emulated second (WS VBlank rate, rounded). */
    public static final int FRAMES_PER_SECOND = 75;
    /** Default clock: 2000-01-01 00:00:00 UTC (a Saturday), fixed for reproducible runs. */
    public static final long DEFAULT_EPOCH_MILLIS = 946684800000L;

    /** Source of the date/time the registers initialise from. */
    public interface Clock {
        long epochMilli();
    }

    /** Fixed clock (the default). */
    public record FixedClock(long epochMilli) implements Clock { }

    /** Host wall clock (opt-in for interactive runs; not reproducible). */
    public enum SystemClock implements Clock {
        INSTANCE;
        @Override public long epochMilli() { return System.currentTimeMillis(); }
    }

    /** False models a 2003 board without the S-3511A fitted: payload reads are $FF. */
    public boolean chipPresent = true;

    // S-3511A registers (raw bytes as the chip stores them).
    private int year, month, day, week, hour, minute, second, status, alarm0, alarm1;
    /** A second value was written that the chip stores but rolls over (WSdev Real-Time_Clock). */
    private boolean secondRollover;
    // 2003 interface state.
    private int command = -1, readIndex, writeIndex, writeTotal;
    private final int[] writeBuf = new int[7];
    private int cbLatch;
    private boolean busy, ready;
    private long frameRemainder;
    /** Every command and payload exchange, newest last (capped). */
    public final List<String> log = new ArrayList<>();
    public long operations;

    public WSRtc() {
        this(new FixedClock(DEFAULT_EPOCH_MILLIS));
    }

    public WSRtc(Clock clock) {
        powerOn();
        setFromEpoch(clock.epochMilli());
        note("power-on");
    }

    /** Documented power-on state (WSdev Real-Time_Clock). */
    private void powerOn() {
        year = 0x00; month = 0x01; day = 0x01; week = 0x00;
        hour = 0x00; minute = 0x00; second = 0x00;
        status = 0x82; alarm0 = 0x80; alarm1 = 0x00;
        secondRollover = false;
    }

    /** Documented reset-command state ($10/$11): all-zero except month/day = 01. */
    private void reset() {
        year = 0x00; month = 0x01; day = 0x01; week = 0x00;
        hour = 0x00; minute = 0x00; second = 0x00;
        status = 0x00; alarm0 = 0x00; alarm1 = 0x00;
        secondRollover = false;
    }

    /** Payload lengths to (+) and from (-) the RTC per command,indexed by command & 0x1F. */
    private static final int[] DIR = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   // $00-$0F invalid
        0, 0, 1, -1, 7, -7, 3, -3, 2, -2, 2, -2, 0, 0, 0, 0, // $10-$1B, $1C-$1F invalid
    };

    private void note(String s) { if (log.size() < 4096) log.add(s); }

    // ------------------------------------------------------------------ interface
    /** $CA write: start (or abort to) a command transaction. */
    public void writeCommand(int value) {
        value &= 0xFF;
        ready = false;
        int cmd = value & 0x1F;
        if (cmd < 0x10 || cmd > 0x1B) {
            command = -1;
            busy = (value & 0x10) != 0;   // stuck as written
            note(String.format("invalid command %02x", value));
            return;
        }
        command = cmd;
        operations++;
        int dir = DIR[cmd];
        if (dir == 0) {   // $10/$11 reset
            if (chipPresent) reset();
            busy = false;
            ready = true;
            note(String.format("command %02x reset", cmd));
            return;
        }
        if (dir > 0) {    // write command: first byte already latched in $CB
            writeBuf[0] = cbLatch;
            writeIndex = 1;
            writeTotal = dir;
            if (writeIndex >= writeTotal) {
                applyWrite();
                busy = false;
            } else {
                busy = true;
            }
            ready = true;
            note(String.format("command %02x write %d bytes, first=%02x", cmd, dir, cbLatch));
            return;
        }
        readIndex = 0;    // read command
        busy = true;
        ready = true;
        if (cmd == 0x13) clearPowerFail();   // reading the status clears the power-failure bit
        if (cmd == 0x19 && chipPresent) { alarm0 = 0xFF; alarm1 = 0xFF; }   // the S-3511A thinks it is written to
        note(String.format("command %02x read %d bytes", cmd, -dir));
    }

    /** $CA read: status {@code R00B CCCC}. */
    public int readStatus() {
        int c = command < 0 ? 0 : command & 0x0F;
        return (ready ? 0x80 : 0) | (busy ? 0x10 : 0) | c;
    }

    /** $CB write: payload byte (or the pre-loaded first byte while idle). */
    public void writeData(int value) {
        value &= 0xFF;
        cbLatch = value;
        if (!busy || command < 0 || DIR[command] <= 0) {
            if (!busy) ready = false;   // idle access clears ready
            return;
        }
        writeBuf[writeIndex++] = value;
        if (writeIndex >= writeTotal) {
            applyWrite();
            busy = false;
        }
        ready = true;
    }

    /** $CB read: next payload byte. */
    public int readData() {
        int out = cbLatch;
        if (busy && command >= 0 && DIR[command] < 0) {
            out = readPayload();
            readIndex++;
            if (readIndex >= -DIR[command]) busy = false;
            ready = true;
        } else if (!busy) {
            ready = false;   // idle access clears ready
        }
        cbLatch = out & 0xFF;
        return cbLatch;
    }

    private int readPayload() {
        if (!chipPresent) return 0xFF;
        return switch (command) {
            case 0x13 -> status;
            case 0x15 -> switch (readIndex) {
                case 0 -> year; case 1 -> month; case 2 -> day; case 3 -> week;
                case 4 -> hour; case 5 -> minute; default -> second;
            };
            case 0x17 -> switch (readIndex) { case 0 -> hour; case 1 -> minute; default -> second; };
            case 0x19 -> 0xFF;   // S-3511A disagrees: alarm reads back $FFFF
            case 0x1B -> 0xFF;
            default -> 0xFF;
        };
    }

    private void applyWrite() {
        switch (command) {
            case 0x12 -> { if (chipPresent) status = writeBuf[0] & 0xFF; note(String.format("status <- %02x", writeBuf[0])); }
            case 0x14 -> {
                if (chipPresent) {
                    year = checkYear(writeBuf[0]); month = checkMonth(writeBuf[1]); day = checkDay(writeBuf[2]);
                    week = checkWeek(writeBuf[3]);
                    hour = checkHour(writeBuf[4]); minute = checkMinute(writeBuf[5]); second = checkSecond(writeBuf[6]);
                    fixDayOverflow();
                }
                note("datetime written");
            }
            case 0x16 -> {
                if (chipPresent) {
                    hour = checkHour(writeBuf[0]); minute = checkMinute(writeBuf[1]); second = checkSecond(writeBuf[2]);
                }
                note("time written");
            }
            case 0x18 -> {
                if (chipPresent) { alarm0 = writeBuf[0] & 0xFF; alarm1 = writeBuf[1] & 0xFF; }
                note(String.format("alarm <- %02x%02x", writeBuf[0], writeBuf[1]));
            }
            case 0x1A -> note("nonsense written (ignored)");
            default -> { }
        }
    }

    /** $13 also clears the power-failure bit (WSdev Real-Time_Clock), like the reset commands. */
    private void clearPowerFail() { status &= 0x7F; }

    // ------------------------------------------------------------------ validation (WSdev Real-Time_Clock)
    private static boolean bcd(int v) { return (v & 0x0F) <= 9 && (v & 0xF0) <= 0x90; }

    private static int checkYear(int v) { return bcd(v & 0xFF) ? v & 0xFF : 0x00; }

    private static int checkMonth(int v) {
        v &= 0xFF;
        return bcd(v) && v >= 0x01 && v <= 0x12 ? v : 0x01;
    }

    private static int checkDay(int v) {
        v &= 0xFF;
        return bcd(v) && v >= 0x01 && v <= 0x31 ? v : 0x01;
    }

    private static int checkWeek(int v) {
        v &= 0xFF;
        return bcd(v) && v <= 0x06 ? v : 0x00;
    }

    private int checkHour(int v) {
        v &= 0xFF;
        boolean h24 = (status & 0x40) != 0;
        if (!bcd(v & (h24 ? 0x3F : 0x1F))) return 0x00;
        if (h24) {
            if ((v & 0x3F) > 0x23) return 0x00;
            return (v & 0x3F) | ((v & 0x3F) >= 0x12 ? 0x80 : 0);   // AM/PM follows the value
        }
        if ((v & 0x1F) > 0x11) return 0x00;
        return v & 0x9F;
    }

    private static int checkMinute(int v) {
        v &= 0xFF;
        return bcd(v) && v <= 0x59 ? v : 0x00;
    }

    private int checkSecond(int v) {
        v &= 0xFF;
        if (bcd(v) && v <= 0x59) { secondRollover = false; return v; }
        secondRollover = true;   // stored, but rolls over after one second
        return v;
    }

    /** A valid-looking day past the month's end increments the month and resets the day to 01. */
    private void fixDayOverflow() {
        int max = daysInMonth(year, month);
        if (fromBcd(day) > max) {
            month = toBcd(fromBcd(month) % 12 + 1);
            if (month == 0x01) year = toBcd((fromBcd(year) + 1) % 100);
            day = 0x01;
        }
    }

    // ------------------------------------------------------------------ time
    /** Advance the emulated clock by `frames` display frames. */
    public void advanceFrames(long frames) {
        if (!chipPresent || frames <= 0) return;
        frameRemainder += frames;
        while (frameRemainder >= FRAMES_PER_SECOND) {
            frameRemainder -= FRAMES_PER_SECOND;
            tickSecond();
        }
    }

    private void tickSecond() {
        if (secondRollover) {
            secondRollover = false;
            second = 0x00;
            tickMinute();
            return;
        }
        int s = fromBcd(second) + 1;
        if (s < 60) { second = toBcd(s); return; }
        second = 0x00;
        tickMinute();
    }

    private void tickMinute() {
        int m = fromBcd(minute) + 1;
        if (m < 60) { minute = toBcd(m); return; }
        minute = 0x00;
        boolean h24 = (status & 0x40) != 0;
        if (h24) {
            int h = fromBcd(hour & 0x3F) + 1;
            if (h < 24) { hour = toBcd(h) | (h >= 12 ? 0x80 : 0); return; }
            hour = 0x00;
        } else {
            int h = fromBcd(hour & 0x1F);
            boolean pm = (hour & 0x80) != 0;
            h++;
            if (h < 12) { hour = toBcd(h) | (pm ? 0x80 : 0); return; }
            hour = (pm ? 0x00 : 0x80);   // 11 AM -> 00 PM, 11 PM -> 00 AM (+day)
            if (pm) { tickDay(); return; }
            return;
        }
        tickDay();
    }

    private void tickDay() {
        week = (week + 1) % 7;
        int d = fromBcd(day) + 1, max = daysInMonth(year, month);
        if (d <= max) { day = toBcd(d); return; }
        day = 0x01;
        int m = fromBcd(month) + 1;
        if (m <= 12) { month = toBcd(m); return; }
        month = 0x01;
        year = toBcd((fromBcd(year) + 1) % 100);
    }

    private static int daysInMonth(int yearBcd, int monthBcd) {
        return switch (fromBcd(monthBcd)) {
            case 2 -> fromBcd(yearBcd) % 4 == 0 ? 29 : 28;   // chip years are 2000-2099
            case 4, 6, 9, 11 -> 30;
            default -> 31;
        };
    }

    private static int fromBcd(int v) { return (v >> 4) * 10 + (v & 0x0F); }
    private static int toBcd(int v) { return ((v / 10) << 4) | (v % 10); }

    /** Set the date/time registers from epoch milliseconds (UTC). */
    public void setFromEpoch(long epochMilli) {
        ZonedDateTime t = Instant.ofEpochMilli(epochMilli).atZone(ZoneOffset.UTC);
        year = toBcd(t.getYear() % 100);
        month = toBcd(t.getMonthValue());
        day = toBcd(t.getDayOfMonth());
        week = t.getDayOfWeek().getValue() % 7;   // Sunday = 0 (FreyaBIOS convention)
        boolean h24 = (status & 0x40) != 0;
        int h = t.getHour();
        hour = h24 ? toBcd(h) | (h >= 12 ? 0x80 : 0)
            : ((h % 12 == 0 ? 0x00 : toBcd(h % 12)) | (h >= 12 ? 0x80 : 0));
        minute = toBcd(t.getMinute());
        second = toBcd(t.getSecond());
        secondRollover = false;
    }

    // ------------------------------------------------------------------ inspection / state
    /** Current date/time registers as raw bytes (Y M D W H M S). */
    public int[] dateTime() { return new int[] { year, month, day, week, hour, minute, second }; }

    public int statusByte() { return status; }
    public int[] alarm() { return new int[] { alarm0, alarm1 }; }

    /** Replace the contents and control state (a battery-backed image, see saveState). */
    public void saveState(java.io.DataOutputStream o) throws java.io.IOException {
        o.writeInt(year); o.writeInt(month); o.writeInt(day); o.writeInt(week);
        o.writeInt(hour); o.writeInt(minute); o.writeInt(second);
        o.writeInt(status); o.writeInt(alarm0); o.writeInt(alarm1);
        o.writeBoolean(secondRollover);
        o.writeInt(command); o.writeInt(readIndex); o.writeInt(writeIndex); o.writeInt(writeTotal);
        o.writeInt(cbLatch); o.writeBoolean(busy); o.writeBoolean(ready);
        o.writeLong(frameRemainder);
        o.writeBoolean(chipPresent);
    }

    public void restoreState(java.io.DataInputStream o) throws java.io.IOException {
        year = o.readInt(); month = o.readInt(); day = o.readInt(); week = o.readInt();
        hour = o.readInt(); minute = o.readInt(); second = o.readInt();
        status = o.readInt(); alarm0 = o.readInt(); alarm1 = o.readInt();
        secondRollover = o.readBoolean();
        command = o.readInt(); readIndex = o.readInt(); writeIndex = o.readInt(); writeTotal = o.readInt();
        cbLatch = o.readInt(); busy = o.readBoolean(); ready = o.readBoolean();
        frameRemainder = o.readLong();
        chipPresent = o.readBoolean();
    }
}
