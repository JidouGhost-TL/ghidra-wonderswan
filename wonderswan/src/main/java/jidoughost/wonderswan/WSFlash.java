// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/**
 * Parallel NOR flash behind the 2003 mapper's self-flash window (port $CE maps the chip into the
 * SRAM window at 0x10000), as on WonderWitch-style flash cartridges (Fujitsu 29DL400TC class,
 * byte mode). The machine routes the window's banked accesses here through {@link #read} and
 * {@link #write} with chip offsets; command addresses are recognised by their window offset
 * ($AAA/$555) in any bank, since the shipped flashing routine issues them in the selected bank
 * (higher address bits are don't-care for command recognition).
 *
 * <p>Commands (all values byte-wide):
 * <ul>
 * <li>Reset/read: $F0 anywhere (also leaves auto-select and fast mode).
 * <li>Auto-select: $AA/$AAA, $55/$555, $90/$AAA; then window offsets 0/1/2 read the manufacturer
 *   ID, device ID and sector-protection byte, other offsets read the array.
 * <li>Byte program: $AA/$AAA, $55/$555, $A0/$AAA, then data to the target (bits only clear, 1-&gt;0).
 * <li>Chip erase: $AA/$AAA, $55/$555, $80/$AAA, $AA/$AAA, $55/$555, $10/$AAA.
 * <li>Sector erase: same, ending with $30 to any address in the sector (64 KiB uniform sectors;
 *   the real top-boot part has smaller parameter sectors at the top — unverified here).
 * <li>Fast mode (WonderWitch flashing routine, WSMan): $AA/$AAA, $55/$555, $20/$AAA enters it;
 *   then $A0 anywhere arms one byte program, repeatable; $90 then $F0 leaves it.
 * </ul>
 *
 * <p>Any write that is not the next byte of a command sequence aborts back to read mode (except
 * in auto-select, where only reset leaves). Operations complete instantly: this emulator has no
 * cycle timing, so status polling always sees completion (stable toggle bit, data polling shows
 * the programmed data). Every command and every aborted sequence is logged.
 */
public final class WSFlash {

    /** Unlock/command window offsets (any bank). */
    public static final int ADDR_AAA = 0xAAA, ADDR_555 = 0x555;
    /** Uniform sector size for sector erase (approximation, see class note). */
    public static final int SECTOR_BYTES = 0x10000;

    /** Auto-select IDs (typical values for the part class; informational). */
    public int manufacturerId = 0x04, deviceId = 0xB9;

    /** Flash contents (the ROM image for a flash cartridge; mutated by program/erase). */
    public final byte[] contents;
    /** Every command and aborted sequence, newest last (capped). */
    public final List<String> log = new ArrayList<>();
    public long operations, refused;

    private enum State { READ, UNLOCK1, UNLOCK2, AUTOSELECT, ERASE1, ERASE2, ERASE3, PROGRAM, FAST, FAST_EXIT }
    private State state = State.READ;
    /** True when the armed program returns to fast mode (repeatable) instead of read mode. */
    private boolean programFromFast;

    public WSFlash(int sizeBytes) {
        this.contents = new byte[sizeBytes];
        java.util.Arrays.fill(contents, (byte) 0xFF);
    }

    public WSFlash(byte[] image) {
        this.contents = image;
    }

    private void note(String s) { if (log.size() < 4096) log.add(s); }

    /** Read a chip offset (masked to the size). */
    public int read(int offset) {
        offset &= contents.length - 1;
        if (state == State.AUTOSELECT) {
            int w = offset & 0xFFFF;
            if (w == 0) return manufacturerId;
            if (w == 1) return deviceId;
            if (w == 2) return 0x00;   // sector unprotected
        }
        return contents[offset] & 0xFF;
    }

    /** Write a chip offset: command byte or program data. */
    public void write(int offset, int value) {
        offset &= contents.length - 1;
        value &= 0xFF;
        int w = offset & 0xFFFF;
        switch (state) {
            case READ -> {
                if (w == ADDR_AAA && value == 0xAA) state = State.UNLOCK1;
                else if (value == 0xF0) { }   // reset is a no-op in read mode
                else { refused++; note(String.format("ignored write %02x to %06x outside a command", value, offset)); }
            }
            case UNLOCK1 -> {
                if (w == ADDR_555 && value == 0x55) state = State.UNLOCK2;
                else abort(offset, value);
            }
            case UNLOCK2 -> {
                if (w != ADDR_AAA) abort(offset, value);
                else switch (value) {
                    case 0x90 -> { state = State.AUTOSELECT; operations++; note("auto-select"); }
                    case 0xA0 -> { state = State.PROGRAM; programFromFast = false; note("program armed"); }
                    case 0x80 -> { state = State.ERASE1; note("erase armed"); }
                    case 0x20 -> { state = State.FAST; operations++; note("fast mode"); }
                    default -> abort(offset, value);
                };
            }
            case AUTOSELECT -> {
                if (value == 0xF0) { state = State.READ; note("auto-select exit"); }
                else { refused++; note(String.format("ignored write %02x in auto-select (only reset leaves)", value)); }
            }
            case ERASE1 -> {
                if (w == ADDR_AAA && value == 0xAA) state = State.ERASE2;
                else abort(offset, value);
            }
            case ERASE2 -> {
                if (w == ADDR_555 && value == 0x55) state = State.ERASE3;
                else abort(offset, value);
            }
            case ERASE3 -> {
                if (w == ADDR_AAA && value == 0x10) {
                    java.util.Arrays.fill(contents, (byte) 0xFF);
                    state = State.READ; operations++; note("chip erase");
                } else if (value == 0x30) {
                    int base = offset & ~(SECTOR_BYTES - 1);
                    java.util.Arrays.fill(contents, base, Math.min(contents.length, base + SECTOR_BYTES), (byte) 0xFF);
                    state = State.READ; operations++; note(String.format("sector erase %06x", base));
                } else abort(offset, value);
            }
            case PROGRAM -> {
                contents[offset] &= (byte) value;   // NOR programming only clears bits
                state = programFromFast ? State.FAST : State.READ; operations++;
                note(String.format("program %06x <- %02x", offset, value));
            }
            case FAST -> {
                if (value == 0xA0) { state = State.PROGRAM; programFromFast = true; note("fast program armed"); }
                else if (value == 0x90) state = State.FAST_EXIT;
                else if (value == 0xF0) { state = State.READ; note("fast mode exit (reset)"); }
                else abort(offset, value);
            }
            case FAST_EXIT -> {
                if (value == 0xF0) { state = State.READ; operations++; note("fast mode exit"); }
                else { state = State.FAST; refused++; note("fast mode exit broken (expected F0 after 90)"); }
            }
        }
    }

    private void abort(int offset, int value) {
        state = State.READ;
        refused++;
        note(String.format("sequence aborted by %02x to %06x", value, offset));
    }

    /** Replace the contents (an image of exactly this chip's size). */
    public void load(byte[] image) {
        if (image.length != contents.length)
            throw new IllegalArgumentException("flash image is " + image.length + " bytes, this chip has " + contents.length);
        System.arraycopy(image, 0, contents, 0, contents.length);
        state = State.READ;
    }

    /** Write the full device state (contents plus command state). */
    public void saveState(java.io.DataOutputStream o) throws java.io.IOException {
        o.writeInt(contents.length);
        o.write(contents);
        o.writeUTF(state.name());
        o.writeBoolean(programFromFast);
    }

    /** Restore state written by {@link #saveState}; the chip size must match. */
    public void restoreState(java.io.DataInputStream o) throws java.io.IOException {
        int n = o.readInt();
        if (n != contents.length) throw new IllegalArgumentException("flash state has " + n + " bytes, this chip has " + contents.length);
        o.readFully(contents);
        state = State.valueOf(o.readUTF());
        programFromFast = o.readBoolean();
    }
}
