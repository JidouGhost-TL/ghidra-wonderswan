// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for {@link WSNoise}, derived from the documented algorithm (WSdev Sound: tap table with sequence
 * lengths, new bit = inverted XOR of bit 7 and the tap bit, shift left; WSMan Noise: reset to 0, register mask).
 */
public final class WSNoiseTest {
    private WSNoiseTest() { }

    /** Sequence length per tap mode, from the WSdev tap table. */
    private static final int[] LENGTHS = { 32767, 1953, 254, 217, 73, 63, 42, 28 };

    public static void run() {
        sequenceLengths();
        firstStepsFromReset();
        stepFormula();
        resetAndMask();
        clockedByChannelFourPeriod();
        counterKeepsRunningPeriod();
        enableBits();
        peekMatchesTick();
        System.out.println("WSNoiseTest: PASS");
    }

    /** From the reset value every tap mode enters a cycle of the documented length. */
    private static void sequenceLengths() {
        for (int mode = 0; mode < 8; mode++) {
            Map<Integer, Integer> seen = new HashMap<>();
            int v = 0, i = 0;
            while (!seen.containsKey(v)) { seen.put(v, i++); v = WSNoise.step(v, mode); }
            Check.eq(LENGTHS[mode], i - seen.get(v), "sequence length of tap mode " + mode);
        }
    }

    /** From 0, bit 7 and every tap are 0, so ones shift in until a one reaches bit 7. */
    private static void firstStepsFromReset() {
        int v = 0;
        for (int i = 1; i <= 8; i++) {
            v = WSNoise.step(v, 0);
            Check.eq((1 << i) - 1, v, "step " + i + " from reset");
        }
        Check.eq(0x1FE, WSNoise.step(0xFF, 0), "bit 7 set, tap 14 clear: new bit 0");
    }

    /** New bit = NOT(bit 7 XOR tap); the register shifts left and keeps 15 bits. */
    private static void stepFormula() {
        for (int mode = 0; mode < 8; mode++) {
            int tap = 1 << WSNoise.TAPS[mode];
            Check.eq(1, WSNoise.step(0, mode) & 1, "mode " + mode + ": bit 7 0, tap 0 -> 1");
            Check.eq(0, WSNoise.step(0x80, mode) & 1, "mode " + mode + ": bit 7 1, tap 0 -> 0");
            Check.eq(0, WSNoise.step(tap, mode) & 1, "mode " + mode + ": bit 7 0, tap 1 -> 0");
            Check.eq(1, WSNoise.step(0x80 | tap, mode) & 1, "mode " + mode + ": bit 7 1, tap 1 -> 1");
            Check.eq(((0x80 | tap) << 1 | 1) & 0x7FFF, WSNoise.step(0x80 | tap, mode), "mode " + mode + ": shift left");
        }
        Check.eq(0x0001, WSNoise.step(0x4000, 1), "bit 14 shifts out");
    }

    /** $8E: bit 3 resets the register and reads 0; bits 5-7 are not implemented. */
    private static void resetAndMask() {
        WSNoise n = new WSNoise();
        n.lfsr = 0x1234;
        Check.eq(0x17, n.control(0xFF), "port keeps enable and tap mode only");
        Check.eq(0, n.lfsr, "reset clears the register");
        n.lfsr = 0x1234;
        Check.eq(0x15, n.control(0x15), "write without reset");
        Check.eq(0x1234, n.lfsr, "no reset bit: register kept");
    }

    /** One step every 2048 - divisor cycles while channel 4 and the LFSR are enabled. */
    private static void clockedByChannelFourPeriod() {
        Check.eq(2048, WSNoise.period(0, 0), "divisor 0");
        Check.eq(1, WSNoise.period(0xFF, 0x07), "divisor 7FF");
        Check.eq(1, WSNoise.period(0xFF, 0xFF), "divisor is 11 bits");
        WSNoise n = new WSNoise();
        int lo = 0xF0, hi = 0x07;                     // divisor 7F0: period 16
        n.tick(0x08, 0x10, lo, hi);
        Check.eq(1, n.lfsr, "expired counter: first enabled cycle steps");
        for (int i = 0; i < 15; i++) n.tick(0x08, 0x10, lo, hi);
        Check.eq(1, n.lfsr, "no step before a full period");
        n.tick(0x08, 0x10, lo, hi);
        Check.eq(3, n.lfsr, "step at the end of the period");
        for (int i = 0; i < 16 * 6; i++) n.tick(0x08, 0x10, lo, hi);
        Check.eq(0xFF, n.lfsr, "eight steps over seven more periods");
    }

    /** A divisor change applies from the next reload; a disabled channel holds the count (measured). */
    private static void counterKeepsRunningPeriod() {
        WSNoise n = new WSNoise();
        n.tick(0x08, 0x10, 0xF0, 0x07);               // step, reload 16
        for (int i = 0; i < 6; i++) n.tick(0x08, 0x10, 0xF0, 0x07);
        Check.eq(10, n.counter, "10 cycles left");
        for (int i = 0; i < 9; i++) n.tick(0x08, 0x10, 0xFE, 0x07);   // divisor 7FE: period 2 from the next reload
        Check.eq(1, n.lfsr, "new divisor does not cut the running period");
        n.tick(0x08, 0x10, 0xFE, 0x07);
        Check.eq(3, n.lfsr, "running period ends");
        Check.eq(2, n.counter, "reload with the new period");
        for (int i = 0; i < 50; i++) n.tick(0x00, 0x10, 0xFE, 0x07);
        Check.eq(2, n.counter, "disabled channel holds the count");
        Check.eq(3, n.lfsr, "disabled channel: no step");
    }

    /** The register advances only with both channel 4 ($90 bit 3) and LFSR ($8E bit 4) enabled; noise mode
     *  ($90 bit 7) is not required. */
    private static void enableBits() {
        WSNoise n = new WSNoise();
        for (int i = 0; i < 64; i++) n.tick(0x80, 0x10, 0xFF, 0x07);
        Check.eq(0, n.lfsr, "channel 4 off: no step");
        for (int i = 0; i < 64; i++) n.tick(0x08, 0x00, 0xFF, 0x07);
        Check.eq(0, n.lfsr, "LFSR disabled: no step");
        Check.eq(1, n.counter, "LFSR disabled: the period counter still runs");
        n.tick(0x08, 0x10, 0xFF, 0x07);
        Check.eq(1, n.lfsr, "wave mode with both enables: steps");
        n.tick(0x88, 0x10, 0xFF, 0x07);
        Check.eq(3, n.lfsr, "noise mode: steps");
    }

    /** peek(n) predicts n ticks without changing the state. */
    private static void peekMatchesTick() {
        WSNoise n = new WSNoise();
        n.lfsr = 0x2A5; n.counter = 3;
        int want;
        WSNoise m = new WSNoise();
        m.lfsr = 0x2A5; m.counter = 3;
        for (int i = 0; i < 37; i++) m.tick(0x08, 0x13, 0xFA, 0x07);
        want = m.lfsr;
        Check.eq(want, n.peek(37, 0x08, 0x13, 0xFA, 0x07), "peek equals ticking");
        Check.eq(0x2A5, n.lfsr, "peek leaves the register");
        Check.eq(3, n.counter, "peek leaves the counter");
    }
}
