// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/**
 * The KARNAK mapper's ADPCM decoder and timer (Pocket Challenge V2 cartridges; ports $D6/$D8/$D9).
 *
 * <p>$D6 bit 7 enables the ADPCM engine and the timer; writing it (either direction) resets the
 * engine: accumulator $100 (output $80), step index 0, top nybble first. Rewriting the same value
 * does not touch the engine. The low 7 bits are the timer reload: {@code (value + 1) * 2}
 * cartridge clocks at 384 kHz.
 *
 * <p>ADPCM bytes go to $D8 (top nybble first; every other write uses the other nybble) and decoded
 * PCM bytes come from $D9; only writes change the engine, reads do not, and writes while disabled
 * are ignored. The algorithm is the NEC uPD775x one: a step table indexed by (step index, nybble
 * magnitude), sign from nybble bit 3, an index shift per magnitude (index clamped to 0-15), and a
 * 10-bit accumulator; the output is the accumulator's middle 8 bits except $200-$2FF which read
 * $FF and $300-$3FF which read $00 (the accumulator itself is not saturated). The tables below are
 * the hardware-verified values from the KARNAK mapper test's software model.
 *
 * <p>Timer: counts cartridge clocks (8 CPU clocks each; this emulator counts 8 instructions per
 * cartridge clock, an approximation) and raises the cartridge interrupt on expiry, reloading while
 * enabled. The interrupt wiring and reload behaviour are inferred, not hardware-verified: no test
 * covers them.
 */
public final class WSKarnak {

    /** Step sizes [step index 0-15][magnitude 0-7] (hardware-verified test values). */
    public static final int[][] STEP = {
        { 0, 0, 1, 2, 3, 5, 7, 10 }, { 0, 1, 2, 3, 4, 6, 8, 13 },
        { 0, 1, 2, 4, 5, 7, 10, 15 }, { 0, 1, 3, 4, 6, 9, 13, 19 },
        { 0, 2, 3, 5, 8, 11, 15, 23 }, { 0, 2, 4, 7, 10, 14, 19, 29 },
        { 0, 3, 5, 8, 12, 16, 22, 33 }, { 1, 4, 7, 10, 15, 20, 29, 43 },
        { 1, 4, 8, 13, 18, 25, 35, 53 }, { 1, 6, 10, 16, 22, 31, 43, 64 },
        { 2, 7, 12, 19, 27, 37, 51, 76 }, { 2, 9, 16, 24, 34, 46, 64, 96 },
        { 3, 11, 19, 29, 41, 57, 79, 117 }, { 4, 13, 24, 36, 50, 69, 96, 143 },
        { 4, 16, 29, 44, 62, 85, 118, 175 }, { 6, 20, 36, 54, 76, 104, 144, 214 },
    };
    /** Step-index shift per magnitude (hardware-verified test values). */
    public static final int[] INDEX_SHIFT = { -1, -1, 0, 0, 1, 2, 2, 3 };

    /** Instructions counted per cartridge clock (CPU 3.072 MHz / 384 kHz; approximation). */
    public static final int INSN_PER_CART_CLOCK = 8;

    /** Cartridge interrupt level the timer raises on expiry (WSMan HWINT_CART; unverified). */
    public static final int TIMER_IRQ_LEVEL = 2;

    private int acc = 0x100, index, control;
    private boolean topFirst = true;
    private int timerRemaining, timerPhase;
    /** Every control write, newest last (capped). */
    public final List<String> log = new ArrayList<>();

    private void note(String s) { if (log.size() < 4096) log.add(s); }

    /** $D6 write: enable bit (resets the engine on change) + timer reload. */
    public void writeControl(int value) {
        value &= 0xFF;
        if (((value ^ control) & 0x80) != 0) {
            acc = 0x100;
            index = 0;
            topFirst = true;
        }
        control = value;
        reloadTimer();
        note(String.format("control %02x (%s)", value, enabled() ? "enabled" : "disabled"));
    }

    public boolean enabled() { return (control & 0x80) != 0; }

    private void reloadTimer() {
        timerRemaining = ((control & 0x7F) + 1) * 2;
        timerPhase = 0;
    }

    /**
     * Count down `instructions` instructions; returns true when the timer expired (the machine
     * raises the cartridge interrupt). The timer reloads while enabled.
     */
    public boolean tick(long instructions) {
        if (!enabled()) return false;
        boolean expired = false;
        for (long i = 0; i < instructions; i++) {
            if (++timerPhase < INSN_PER_CART_CLOCK) continue;
            timerPhase = 0;
            if (--timerRemaining > 0) continue;
            reloadTimer();
            expired = true;
        }
        return expired;
    }

    /** $D8 write: one ADPCM byte (top nybble first, alternating). Ignored while disabled. */
    public void writeAdpcm(int value) {
        if (!enabled()) return;
        int nybble = topFirst ? (value >> 4) & 0x0F : value & 0x0F;
        topFirst = !topFirst;
        int diff = STEP[index][nybble & 7];
        if ((nybble & 8) != 0) diff = -diff;
        index = Math.min(15, Math.max(0, index + INDEX_SHIFT[nybble & 7]));
        acc = (acc + diff) & 0x3FF;
    }

    /** $D9 read: decoded PCM byte (valid whether or not the engine is enabled). */
    public int readAdpcm() {
        if (acc >= 0x300) return 0x00;
        if (acc >= 0x200) return 0xFF;
        return (acc >> 1) & 0xFF;
    }

    // ------------------------------------------------------------------ inspection / state
    public int accumulator() { return acc; }
    public int stepIndex() { return index; }

    public void saveState(java.io.DataOutputStream o) throws java.io.IOException {
        o.writeInt(acc); o.writeInt(index); o.writeInt(control);
        o.writeBoolean(topFirst);
        o.writeInt(timerRemaining); o.writeInt(timerPhase);
    }

    public void restoreState(java.io.DataInputStream o) throws java.io.IOException {
        acc = o.readInt(); index = o.readInt(); control = o.readInt();
        topFirst = o.readBoolean();
        timerRemaining = o.readInt(); timerPhase = o.readInt();
    }
}
