// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/** Minimal assertion helper for the plain-Java unit tests (no framework; failures throw). */
final class Check {
    private Check() { }

    static int count;

    static void eq(int expected, int actual, String what) {
        count++;
        if (expected != actual)
            throw new AssertionError(what + ": expected " + expected + " (0x" + Integer.toHexString(expected)
                + ") but got " + actual + " (0x" + Integer.toHexString(actual) + ")");
    }

    static void eq(long expected, long actual, String what) {
        count++;
        if (expected != actual)
            throw new AssertionError(what + ": expected " + expected + " but got " + actual);
    }

    static void eq(String expected, String actual, String what) {
        count++;
        if (!expected.equals(actual))
            throw new AssertionError(what + ": expected <" + expected + "> but got <" + actual + ">");
    }

    static void isTrue(boolean cond, String what) {
        count++;
        if (!cond) throw new AssertionError(what + ": expected true");
    }

    static void isFalse(boolean cond, String what) {
        count++;
        if (cond) throw new AssertionError(what + ": expected false");
    }
}
