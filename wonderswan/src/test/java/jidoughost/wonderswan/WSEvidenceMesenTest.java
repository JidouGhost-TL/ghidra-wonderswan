// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import static org.junit.Assert.*;

import java.util.Map;
import java.util.Set;

import org.junit.Test;

/** Synthetic-data unit tests for Mesen evidence mapping (no ROM, no Ghidra program). */
public class WSEvidenceMesenTest {

    static WSMesenTrace.CovData cov(long lin, Set<Integer> c0) {
        WSMesenTrace.CovData d = new WSMesenTrace.CovData();
        d.byLinear.put(lin, new WSMesenTrace.Cov(lin, 5, Set.of(0), Set.of(0), c0, Set.of(), Set.of()));
        return d;
    }

    static WSEvidence evidenced(WSMesenTrace.CovData cov, long romLen) {
        return WSEvidence.fromMesen(null, cov, null, "test", romLen, null, -1);
    }

    // An 8 MiB cartridge: C0 = 0x0F shows the same bytes the loader maps (C0 = 0xFF masked
    // to the size), so its rows are kept; C0 = 0x0E shows another bank and is skipped.
    @Test
    public void c0AliasKept() {
        WSEvidence e = evidenced(cov(0x81000L, Set.of(0x0F)), 0x800000L);
        assertTrue(e.cs.containsKey(0x81000L));
        assertEquals(0, e.mesenStats.c0Skipped());
    }

    @Test
    public void c0OtherBankSkipped() {
        WSEvidence e = evidenced(cov(0x81000L, Set.of(0x0E)), 0x800000L);
        assertFalse(e.cs.containsKey(0x81000L));
        assertEquals(1, e.mesenStats.c0Skipped());
    }

    @Test
    public void c0MixedBanksKeptOnce() {
        WSEvidence e = evidenced(cov(0x81000L, Set.of(0x0E, 0x0F)), 0x800000L);
        assertTrue(e.cs.containsKey(0x81000L));
        assertEquals(0, e.mesenStats.c0Skipped());
        assertEquals(1, e.mesenStats.multiC0());
    }

    // Logs without bank columns assume the loader mapping.
    @Test
    public void c0AbsentKept() {
        WSEvidence e = evidenced(cov(0x81000L, Set.of()), 0x800000L);
        assertTrue(e.cs.containsKey(0x81000L));
        assertEquals(0, e.mesenStats.c0Skipped());
    }

    // A 1 MiB cartridge: the size mask erases C0 entirely, so every C0 matches the loader.
    @Test
    public void c0IrrelevantOnSmallRom() {
        WSEvidence e = evidenced(cov(0x81000L, Set.of(0x00)), 0x100000L);
        assertTrue(e.cs.containsKey(0x81000L));
        assertEquals(0, e.mesenStats.c0Skipped());
    }

    // Window, SRAM and RAM rows are unaffected by the C0 rule.
    @Test
    public void nonLinearUnaffected() {
        WSMesenTrace.CovData d = new WSMesenTrace.CovData();
        d.byLinear.put(0x21000L, new WSMesenTrace.Cov(0x21000L, 5, Set.of(0), Set.of(0), Set.of(), Set.of(0xE0), Set.of()));
        d.byLinear.put(0x00100L, new WSMesenTrace.Cov(0x00100L, 5, Set.of(0), Set.of(0), Set.of(), Set.of(), Set.of()));
        WSEvidence e = evidenced(d, 0x800000L);
        assertTrue(e.windowBanks.containsKey(0x21000L));
        assertTrue(e.cs.containsKey(0x00100L));
        assertEquals(0, e.mesenStats.c0Skipped());
    }
}
