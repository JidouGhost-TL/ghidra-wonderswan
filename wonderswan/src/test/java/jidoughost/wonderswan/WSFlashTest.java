// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * Unit tests for {@link WSFlash}: JEDEC program / erase / ID sequences and the WonderWitch fast
 * mode, driven exactly as the documented flashing routine drives them (unlock at window offsets
 * $AAA/$555 in the selected bank, poll-style reads).
 */
public final class WSFlashTest {
    private WSFlashTest() { }

    private static final int AAA = 0xAAA, AA5 = 0x555;

    /** Unlock sequence in the given 64 KiB bank (window offsets, any bank). */
    private static void unlock(WSFlash f, int bank) {
        int base = bank << 16;
        f.write(base + AAA, 0xAA);
        f.write(base + AA5, 0x55);
    }

    public static void run() {
        program();
        programClearsBitsOnly();
        programAnyBank();
        autoSelect();
        chipErase();
        sectorErase();
        sequenceAbort();
        fastMode();
        System.out.println("WSFlashTest: PASS");
    }

    private static void program() {
        WSFlash f = new WSFlash(0x80000);
        unlock(f, 3);
        f.write(3 << 16 | AAA, 0xA0);
        f.write(0x31234, 0x5A);
        Check.eq(0x5A, f.read(0x31234), "programmed byte reads back");
        Check.eq(0xFF, f.read(0x31235), "neighbour untouched");
        Check.eq(1L, f.operations, "one operation counted");
    }

    private static void programClearsBitsOnly() {
        WSFlash f = new WSFlash(0x80000);
        f.contents[0x100] = 0x5A;
        unlock(f, 0);
        f.write(AAA, 0xA0);
        f.write(0x100, 0xFF);   // cannot set bits without an erase
        Check.eq(0x5A, f.read(0x100), "program cannot set bits");
        unlock(f, 0);
        f.write(AAA, 0xA0);
        f.write(0x100, 0x0F);
        Check.eq(0x0A, f.read(0x100), "program clears bits (AND)");
    }

    private static void programAnyBank() {
        // The shipped routine issues unlock cycles in the selected bank, not bank 0.
        WSFlash f = new WSFlash(0x80000);
        unlock(f, 8 - 8);   // bank 0 form, sanity
        f.write(AAA, 0x00); // wrong third byte: abort back to read mode
        unlock(f, 5);
        f.write(5 << 16 | AAA, 0xA0);
        f.write(0x5ABCD, 0x33);
        Check.eq(0x33, f.read(0x5ABCD), "program in bank 5");
    }

    private static void autoSelect() {
        WSFlash f = new WSFlash(0x80000);
        f.contents[0] = 0x12;
        unlock(f, 0);
        f.write(AAA, 0x90);
        Check.eq(0x04, f.read(0), "manufacturer ID");
        Check.eq(0xB9, f.read(1), "device ID");
        Check.eq(0x00, f.read(2), "sector unprotected");
        f.write(0x1234, 0xF0);   // reset from anywhere
        Check.eq(0x12, f.read(0), "array visible after reset");
    }

    private static void chipErase() {
        WSFlash f = new WSFlash(0x80000);
        java.util.Arrays.fill(f.contents, (byte) 0x00);
        unlock(f, 0);
        f.write(AAA, 0x80);
        unlock(f, 0);
        f.write(AAA, 0x10);
        Check.eq(0xFF, f.read(0), "chip erase byte 0");
        Check.eq(0xFF, f.read(0x7FFFF), "chip erase last byte");
    }

    private static void sectorErase() {
        WSFlash f = new WSFlash(0x80000);
        java.util.Arrays.fill(f.contents, (byte) 0x00);
        unlock(f, 0);
        f.write(AAA, 0x80);
        unlock(f, 0);
        f.write(0x2BEEF, 0x30);   // any address in the sector
        Check.eq(0xFF, f.read(0x20000), "erased sector start");
        Check.eq(0xFF, f.read(0x2FFFF), "erased sector end");
        Check.eq(0x00, f.read(0x1FFFF), "previous sector kept");
        Check.eq(0x00, f.read(0x30000), "next sector kept");
    }

    private static void sequenceAbort() {
        WSFlash f = new WSFlash(0x80000);
        f.write(AAA, 0xAA);
        f.write(0x1234, 0x55);   // wrong address: abort
        f.write(0x100, 0x00);    // plain write outside a command: ignored
        Check.eq(0xFF, f.read(0x100), "aborted sequence writes nothing");
        Check.isTrue(f.refused > 0, "aborts counted");
    }

    private static void fastMode() {
        // The WonderWitch routine: enter fast mode, program bytes with A0, poll bit 6, exit 90/F0.
        WSFlash f = new WSFlash(0x80000);
        unlock(f, 2);
        f.write(2 << 16 | AAA, 0x20);
        int base = 2 << 16;
        for (int i = 0; i < 4; i++) {
            f.write(base, 0xA0);
            f.write(base + i, 0xA0 + i);
            // Poll-style reads: bit 6 equal on successive reads = done (instant here).
            int r1 = f.read(base + i), r2 = f.read(base + i);
            Check.eq(r1 & 0x40, r2 & 0x40, "toggle bit stable (done)");
            Check.eq(0xA0 + i, r1, "fast-programmed byte " + i);
        }
        f.write(base, 0x90);
        f.write(base, 0xF0);
        f.write(base + 9, 0x00);   // plain write after exit: ignored
        Check.eq(0xFF, f.read(base + 9), "writes ignored after fast-mode exit");
    }

    public static void main(String[] args) {
        run();
    }
}
