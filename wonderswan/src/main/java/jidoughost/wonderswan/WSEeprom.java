// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/**
 * One M93LCx6-compatible serial EEPROM behind the WonderSwan's port interface (WSdev EEPROM): the
 * internal one (ports BA-BE) or the cartridge one (C4-C8). Word organisation only.
 *
 * Ports (offsets from the base): +0/+1 data (write = write buffer; read = read buffer, a separate
 * register that changes only when a READ completes), +2/+3 command word (read back as written),
 * +4 control (write) / status (read).
 *
 * Command word for an EEPROM with N word-address bits: bit N+2 = start bit, bits N+1..N = opcode
 * (01 WRITE, 10 READ, 11 ERASE; 00 = extended, sub-opcode in the top two address bits: 00 WDS,
 * 01 WRAL, 10 ERAL, 11 WEN), bits N-1..0 = word address. Any other bit set: unknown command.
 * N = 6 (1 Kbit), 9 (8 Kbit), 10 (16 Kbit). The colour SoC's 16 Kbit internal EEPROM takes 1 Kbit
 * commands while colour mode is off (WSdev: "emulates a 93C46 in ASWAN compatibility mode").
 *
 * Control write: bit 4 READ, 5 WRITE (WRITE, WRAL), 6 short (ERASE, WDS, ERAL, WEN), 7 internal:
 * set write protection (sticky; words >= 0x30 can no longer be written), cartridge: abort. More than
 * one of these bits, or abort, is an invalid operation: nothing happens. A control request whose
 * class does not match the command's opcode is ignored too; both cases are counted in {@link #log}.
 *
 * Status read: bit 0 done (read completed), bit 1 ready (idle), bit 7 internal write protection.
 * Done: the internal EEPROM clears it when a READ starts and sets it when the read completes; the
 * cartridge (2001 mapper) erratum: a READ does not clear it, WRITE and short operations do (a short request
 * clears it even when the command word holds another opcode).
 * Operations take {@link #BUSY_INSTRUCTIONS} instructions (timing is instruction-count based).
 *
 * WSdev's prose swaps the WRAL/ERAL descriptions; this follows the M93LCx6 datasheet and WSdev's own
 * opcode table (SOURCE-CONFLICT: WRAL writes the data word to every address, ERAL erases all).
 * Write enable at power-on: the cartridge EEPROM starts write-disabled (ws-test-suite
 * "Locked on start"); the internal EEPROM is left write-enabled by the boot ROM, which is skipped.
 */
public final class WSEeprom {
    public static final int BUSY_INSTRUCTIONS = 8;

    public final boolean internal;
    public final byte[] data;
    private final int bigAddressBits;
    private int command, writeBuffer, readBuffer, pendingRead = -1;
    private boolean writeEnabled, protectedHigh, done = true;
    private long busyUntil = -1;
    private Runnable pendingWrite;
    /** Every operation and every refused or invalid request, newest last (capped). */
    public final List<String> log = new ArrayList<>();
    public long operations, refused;

    public WSEeprom(boolean internal, int sizeBytes) {
        this.internal = internal;
        this.data = new byte[sizeBytes];
        // Initial contents: a cartridge EEPROM is delivered erased (all ones, M93LCx6 datasheet). No source
        // documents a console's internal EEPROM contents; it starts zero-filled, which matches the reference
        // emulator for the area games read (load a dump of a real console for its owner data).
        if (!internal) java.util.Arrays.fill(data, (byte) 0xFF);
        this.bigAddressBits = Integer.numberOfTrailingZeros(sizeBytes / 2);
        this.writeEnabled = internal;
    }

    /** Word-address bits in effect: the full size, or 1 Kbit form for the internal EEPROM in mono mode. */
    private int addressBits(boolean colorMode) {
        return internal && !colorMode && bigAddressBits > 6 ? 6 : bigAddressBits;
    }

    private void tick(long now) {
        if (busyUntil < 0 || now < busyUntil) return;
        busyUntil = -1;
        if (pendingRead >= 0) { readBuffer = pendingRead; pendingRead = -1; done = true; }
        if (pendingWrite != null) { pendingWrite.run(); pendingWrite = null; }
    }

    public int read(int offset, long now) {
        tick(now);
        switch (offset) {
            case 0: return readBuffer & 0xFF;
            case 1: return readBuffer >> 8 & 0xFF;
            case 2: return command & 0xFF;
            case 3: return command >> 8 & 0xFF;
            case 4: return (done ? 1 : 0) | (busyUntil < 0 ? 2 : 0) | (internal && protectedHigh ? 0x80 : 0);
            default: return 0;
        }
    }

    public void write(int offset, int value, long now, boolean colorMode, long pc) {
        tick(now);
        switch (offset) {
            case 0: writeBuffer = writeBuffer & 0xFF00 | value; return;
            case 1: writeBuffer = writeBuffer & 0x00FF | value << 8; return;
            case 2: command = command & 0xFF00 | value; return;
            case 3: command = command & 0x00FF | value << 8; return;
            case 4: control(value, now, colorMode, pc); return;
            default:
        }
    }

    private void note(String s) { if (log.size() < 4096) log.add(s); }

    private void control(int v, long now, boolean colorMode, long pc) {
        boolean rd = (v & 0x10) != 0, wr = (v & 0x20) != 0, sh = (v & 0x40) != 0, top = (v & 0x80) != 0;
        int bits = (rd ? 1 : 0) + (wr ? 1 : 0) + (sh ? 1 : 0) + (top ? 1 : 0);
        if (bits == 0) return;
        if (bits > 1 || top && !internal) { refused++; note(String.format("%05x invalid control %02x", pc, v)); return; }
        if (top) { protectedHigh = true; note(String.format("%05x protect", pc)); return; }
        if (busyUntil >= 0) { refused++; note(String.format("%05x busy, control %02x ignored", pc, v)); return; }

        int n = addressBits(colorMode), mask = (1 << n) - 1;
        int hi = command >> n, op = hi & 3, addr = command & mask;
        String name = hi >> 2 != 1 ? "UNKNOWN" : switch (op) {
            case 1 -> "WRITE"; case 2 -> "READ"; case 3 -> "ERASE";
            default -> switch (addr >> (n - 2) & 3) { case 0 -> "WDS"; case 1 -> "WRAL"; case 2 -> "ERAL"; default -> "WEN"; };
        };
        if (sh) done = false;   // a short request clears done whatever the command (2001-mapper erratum test)
        boolean match = rd ? name.equals("READ") : wr ? name.equals("WRITE") || name.equals("WRAL")
            : name.equals("ERASE") || name.equals("ERAL") || name.equals("WDS") || name.equals("WEN");
        if (!match) { refused++; note(String.format("%05x control %02x does not match command %04x (%s)", pc, v, command, name)); return; }
        operations++;
        note(String.format("%05x %s %03x%s", pc, name, addr, wr ? String.format(" <- %04x", writeBuffer) : ""));

        if (rd) {
            if (internal) done = false;
            int a = addr % (data.length / 2);
            pendingRead = (data[2 * a] & 0xFF) | (data[2 * a + 1] & 0xFF) << 8;
            busyUntil = now + BUSY_INSTRUCTIONS;
            return;
        }
        done = false;
        final int w = writeBuffer;
        switch (name) {
            case "WRITE" -> { pendingWrite = () -> store(addr, w); busyUntil = now + BUSY_INSTRUCTIONS; }
            case "ERASE" -> { pendingWrite = () -> store(addr, 0xFFFF); busyUntil = now + BUSY_INSTRUCTIONS; }
            case "WRAL" -> { pendingWrite = () -> { for (int i = 0; i < data.length / 2; i++) store(i, w); }; busyUntil = now + BUSY_INSTRUCTIONS; }
            case "ERAL" -> { pendingWrite = () -> { for (int i = 0; i < data.length / 2; i++) store(i, 0xFFFF); }; busyUntil = now + BUSY_INSTRUCTIONS; }
            case "WDS" -> writeEnabled = false;
            case "WEN" -> writeEnabled = true;
            default -> { }
        }
    }

    private void store(int wordAddr, int value) {
        int a = wordAddr % (data.length / 2);
        if (!writeEnabled) { refused++; note(String.format("write %03x refused: write-disabled", a)); return; }
        if (internal && protectedHigh && a >= 0x30) { refused++; note(String.format("write %03x refused: protected", a)); return; }
        data[2 * a] = (byte) value;
        data[2 * a + 1] = (byte) (value >> 8);
    }

    /** Replace the contents (an image of exactly this EEPROM's size). */
    public void load(byte[] image) {
        if (image.length != data.length)
            throw new IllegalArgumentException("EEPROM image is " + image.length + " bytes, this EEPROM has " + data.length);
        System.arraycopy(image, 0, data, 0, data.length);
    }
}
