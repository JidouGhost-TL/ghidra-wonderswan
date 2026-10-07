// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * Sound channel 4 noise generator: the 15-bit LFSR behind REG_SND_NOISE (port $8E) and REG_SND_RANDOM
 * (ports $92/$93, read only).
 *
 * <p>Algorithm (WSdev Sound, "Sound Channel 4 Noise Control"; WSMan "Noise"): the new bit is the inverted XOR of
 * bit 7 with the tap bit selected by $8E bits 0-2 (taps 14, 10, 13, 4, 8, 6, 9, 11 for modes 0-7); the register
 * shifts one bit to the left and the new bit enters as bit 0. Writing $8E with bit 3 set clears the register
 * (WSMan: "Resetting noise sets the LFSR counter to 00000h"); bit 3 always reads 0, and only bits 0-4 are
 * implemented (WSMan mask {@code 000*****}).
 *
 * <p>Clock (WSdev Sound, "Sound Channel Frequency"): channel 4's sample period counter steps every
 * {@code 2048 - divisor} cycles of the 3.072 MHz clock (divisor in $86/$87, 11 bits) while channel 4 is enabled
 * ($90 bit 3); each step advances the LFSR when $8E bit 4 (LFSR enable) is set. Channel 4's noise mode ($90 bit 7)
 * only selects the output: WSMan states the register updates in wave mode too, and WSdev requires only the
 * channel 4 enable and LFSR enable bits.
 *
 * <p>Counter (not documented; measured): the counter counts down the cycles left in the current period. A
 * divisor write does not restart it (the new period applies from the next reload), and while channel 4 is
 * disabled it holds its value. Evidence: a cycle-exact reference trace where a program enables channel 4 about
 * 10 million cycles after resetting the LFSR reads the documented sequence at exactly the position this model
 * gives, and a restart on the divisor write or on enable would put it several steps off.
 */
public final class WSNoise {
    /** Tap bit per $8E tap mode 0-7 (WSdev / WSMan tap table). */
    static final int[] TAPS = { 14, 10, 13, 4, 8, 6, 9, 11 };

    /** Shift register (15 bits). */
    int lfsr;
    /** Cycles left in channel 4's current sample period (0: the next enabled cycle steps). */
    int counter;

    /** One LFSR step in tap mode {@code mode} (0-7). */
    static int step(int lfsr, int mode) {
        int bit = ~((lfsr >> 7) ^ (lfsr >> TAPS[mode & 7])) & 1;
        return ((lfsr << 1) | bit) & 0x7FFF;
    }

    /** A write of {@code b} to $8E: a set reset bit clears the register. Returns the value the port keeps. */
    int control(int b) {
        if ((b & 0x08) != 0) lfsr = 0;
        return b & 0x17;
    }

    /** Sample period of channel 4 in cycles for the divisor in $86/$87. */
    static int period(int freqLo, int freqHi) {
        return 2048 - ((freqLo | freqHi << 8) & 0x7FF);
    }

    /** Advance one clock cycle with the given port values ($90, $8E, $86, $87). */
    void tick(int ctrl, int noise, int freqLo, int freqHi) {
        if ((ctrl & 0x08) == 0) return;
        if (--counter > 0) return;
        counter = period(freqLo, freqHi);
        if ((noise & 0x10) != 0) lfsr = step(lfsr, noise & 7);
    }

    /** The register after {@code n} more cycles with the given port values, without changing the state. */
    int peek(int n, int ctrl, int noise, int freqLo, int freqHi) {
        if ((ctrl & 0x08) == 0 || (noise & 0x10) == 0) return lfsr;
        int per = period(freqLo, freqHi), c = counter, v = lfsr;
        for (int i = 0; i < n; i++)
            if (--c <= 0) { c = per; v = step(v, noise & 7); }
        return v;
    }
}
