// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * Unit tests for {@link WSKarnak}: reset state, nybble order, the uPD775x step/index tables
 * (hand-computed sequences), saturation mapping, enable gating and the timer countdown.
 */
public final class WSKarnakTest {
    private WSKarnakTest() { }

    public static void run() {
        tables();
        resetState();
        topFirst();
        handSequence();
        saturation();
        disabledIgnoresWrites();
        sameValueNoReset();
        timer();
        System.out.println("WSKarnakTest: PASS");
    }

    private static void tables() {
        Check.eq(16, WSKarnak.STEP.length, "16 step rows");
        Check.eq(8, WSKarnak.STEP[0].length, "8 magnitudes");
        Check.eq(10, WSKarnak.STEP[0][7], "step[0][7]");
        Check.eq(214, WSKarnak.STEP[15][7], "step[15][7]");
        Check.eq(1, WSKarnak.STEP[7][0], "step[7][0]");
        int[] sh = WSKarnak.INDEX_SHIFT;
        Check.eq(8, sh.length, "8 index shifts");
        Check.eq(-1, sh[0], "shift[0]");
        Check.eq(3, sh[7], "shift[7]");
    }

    private static void resetState() {
        WSKarnak k = new WSKarnak();
        k.writeControl(0x80);   // enable: resets the engine
        Check.eq(0x100, k.accumulator(), "reset accumulator");
        Check.eq(0, k.stepIndex(), "reset index");
        Check.eq(0x80, k.readAdpcm(), "reset output");
    }

    private static void topFirst() {
        WSKarnak a = new WSKarnak(), b = new WSKarnak();
        a.writeControl(0x80);
        b.writeControl(0x80);
        a.writeAdpcm(0x70);   // top nybble 7 first
        b.writeAdpcm(0x07);   // top nybble 0 first
        Check.eq(3, a.stepIndex(), "top nybble 7 shifts index by 3");
        Check.eq(0, b.stepIndex(), "top nybble 0 shifts index by -1, clamped");
        Check.isTrue(a.accumulator() != b.accumulator(), "nybble order matters");
    }

    private static void handSequence() {
        // Hand-computed from the tables: acc=0x100, idx=0.
        WSKarnak k = new WSKarnak();
        k.writeControl(0x80);
        k.writeAdpcm(0x70);   // top: mag 7, + -> diff +STEP[0][7]=+10, idx 0+3=3
        Check.eq(0x10A, k.accumulator(), "acc after +10");
        Check.eq(3, k.stepIndex(), "idx after +3");
        Check.eq(0x85, k.readAdpcm(), "output (0x10A >> 1)");
        k.writeAdpcm(0x70);   // low: mag 0, + -> diff +STEP[3][0]=+0, idx 3-1=2
        Check.eq(0x10A, k.accumulator(), "acc unchanged by +0");
        Check.eq(2, k.stepIndex(), "idx after -1");
        k.writeAdpcm(0xF0);   // top: mag 7, - -> diff -STEP[2][7]=-15, idx 2+3=5
        Check.eq(0x10A - 15, k.accumulator(), "acc after -15");
        Check.eq(5, k.stepIndex(), "idx 5");
        k.writeAdpcm(0xF0);   // low: mag 0, + -> diff +STEP[5][0]=+0, idx 5-1=4
        Check.eq(0x10A - 15, k.accumulator(), "acc unchanged by +0");
        Check.eq(4, k.stepIndex(), "idx 4");
        k.writeAdpcm(0xFF);   // top: mag 7, - -> diff -STEP[4][7]=-23, idx 4+3=7
        Check.eq(0x10A - 15 - 23, k.accumulator(), "acc after -23");
        Check.eq(7, k.stepIndex(), "idx 7");
    }

    private static void saturation() {
        WSKarnak k = new WSKarnak();
        k.writeControl(0x80);
        // Drive the accumulator up with maximum positive steps.
        for (int i = 0; i < 60; i++) k.writeAdpcm(0x77);
        Check.isTrue(k.accumulator() >= 0x200, "accumulator reached saturation");
        if (k.accumulator() >= 0x300) Check.eq(0x00, k.readAdpcm(), ">= $300 reads $00");
        else Check.eq(0xFF, k.readAdpcm(), "$200-$2FF reads $FF");
        Check.isTrue((k.accumulator() & ~0x3FF) == 0, "accumulator stays 10-bit");
        // Drive it back down with maximum negative steps; output follows the middle 8 bits.
        for (int i = 0; i < 120; i++) k.writeAdpcm(0xFF);
        int acc = k.accumulator();
        int expected = acc >= 0x300 ? 0x00 : acc >= 0x200 ? 0xFF : (acc >> 1) & 0xFF;
        Check.eq(expected, k.readAdpcm(), "output mapping after negative drive");
    }

    private static void disabledIgnoresWrites() {
        WSKarnak k = new WSKarnak();   // control 0 = disabled
        k.writeAdpcm(0x77);
        k.writeAdpcm(0x77);
        Check.eq(0x100, k.accumulator(), "disabled writes ignored");
        Check.eq(0x80, k.readAdpcm(), "disabled reads still valid");
        k.writeControl(0x80);
        k.writeAdpcm(0x77);
        Check.isTrue(k.accumulator() != 0x100, "enabled writes apply");
        k.writeControl(0x00);   // disable resets the engine
        Check.eq(0x100, k.accumulator(), "disable resets accumulator");
        Check.eq(0, k.stepIndex(), "disable resets index");
    }

    private static void sameValueNoReset() {
        WSKarnak k = new WSKarnak();
        k.writeControl(0x80);
        k.writeAdpcm(0x77);
        int acc = k.accumulator();
        k.writeControl(0x80);   // same value: engine untouched
        Check.eq(acc, k.accumulator(), "rewriting control keeps state");
    }

    private static void timer() {
        WSKarnak k = new WSKarnak();
        k.writeControl(0x80);   // reload 0 -> (0+1)*2 = 2 cart clocks = 16 instructions
        Check.isFalse(k.tick(15), "no expiry before the period");
        Check.isTrue(k.tick(1), "expiry at the period");
        Check.isFalse(k.tick(1), "reloaded after expiry");
        Check.isTrue(k.tick(15), "periodic expiry");
        k.writeControl(0x00);
        Check.isFalse(k.tick(100000), "disabled timer never fires");
        WSKarnak k2 = new WSKarnak();
        k2.writeControl(0xFF);   // reload 127 -> 256 cart clocks
        Check.isFalse(k2.tick(256 * 8 - 1), "long period");
        Check.isTrue(k2.tick(1), "long period expiry");
    }

    public static void main(String[] args) {
        run();
    }
}
