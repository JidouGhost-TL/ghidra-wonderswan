// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import static org.junit.Assert.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Test;

/** Synthetic-data unit tests for the title segment-default rules D0 (DS and SS). */
public class WSCompilerRulesTest {

    static WSEvidence evidenced(int zeroDs, int ds1000, int zeroSs, int ss1000) {
        WSEvidence e = new WSEvidence();
        long lin = 0x40000;
        for (int i = 0; i < zeroDs; i++) e.ds.put(lin++, Set.of(0));
        for (int i = 0; i < ds1000; i++) e.ds.put(lin++, Set.of(0x1000));
        lin = 0x40000;
        for (int i = 0; i < zeroSs; i++) e.ss.put(lin++, Set.of(0));
        for (int i = 0; i < ss1000; i++) e.ss.put(lin++, Set.of(0x1000));
        return e;
    }

    // DS=0 dominates: the loader default stays.
    @Test
    public void dominantDsKeepsZero() {
        assertEquals(-1, WSCompilerRules.dominantDs(evidenced(90, 10, 0, 0)));
    }

    // Another DS covers >= 50 % of single-DS addresses: it becomes the default.
    @Test
    public void dominantDsSetsNonZero() {
        assertEquals(0x1000, WSCompilerRules.dominantDs(evidenced(40, 60, 0, 0)));
    }

    // Multi-valued addresses are not single-DS evidence and are ignored.
    @Test
    public void dominantDsIgnoresMultiValued() {
        WSEvidence e = evidenced(40, 30, 0, 0);
        for (long lin = 0x80000; lin < 0x80020; lin++) {
            Set<Integer> both = new TreeSet<>();
            both.add(0);
            both.add(0x1000);
            e.ds.put(lin, both);
        }
        assertEquals(-1, WSCompilerRules.dominantDs(e));
    }

    // SS=0 dominates: the loader default stays.
    @Test
    public void dominantSsKeepsZero() {
        assertEquals(-1, WSCompilerRules.dominantSs(evidenced(0, 0, 90, 10)));
    }

    // Titles whose stack lives outside segment 0 (e.g. cartridge SRAM): the
    // dominant SS becomes the default, the same treatment DS gets in D0.
    @Test
    public void dominantSsSetsSramStack() {
        assertEquals(0x1000, WSCompilerRules.dominantSs(evidenced(0, 0, 5, 95)));
    }

    @Test
    public void dominantSsIgnoresMultiValued() {
        WSEvidence e = evidenced(0, 0, 40, 30);
        for (long lin = 0x80000; lin < 0x80020; lin++) {
            Set<Integer> both = new TreeSet<>();
            both.add(0);
            both.add(0x1000);
            e.ss.put(lin, both);
        }
        assertEquals(-1, WSCompilerRules.dominantSs(e));
    }

    @Test
    public void shares() {
        WSEvidence e = evidenced(40, 60, 5, 95);
        assertEquals(0.6, WSCompilerRules.share(e, 0x1000), 1e-9);
        assertEquals(0.95, WSCompilerRules.shareSs(e, 0x1000), 1e-9);
        assertEquals(0.05, WSCompilerRules.shareSs(e, 0), 1e-9);
    }

    // Reference-trace evidence carries per-address SS from the trace window (coverage logs
    // have no SS column, so only traced addresses contribute).
    @Test
    public void traceEvidenceCarriesSs() {
        WSMesenTrace.TraceData t = new WSMesenTrace.TraceData();
        t.firstCs.put(0x0123L, 0);
        t.ds.put(0x0123L, Set.of(0));
        t.ss.put(0x0123L, Set.of(0x1000));
        WSEvidence e = WSEvidence.fromMesen(t, null, null, "test", 0x100000L, null, -1);
        assertEquals(Set.of(0x1000), e.ss.get(0x0123L));
        assertEquals(Set.of(0), e.ds.get(0x0123L));
    }

    // coverage.json files written before SS sampling have no "ss" key: loading
    // them leaves the SS map empty instead of failing.
    @Test
    public void loadBackCompatWithoutSs() throws Exception {
        Path dir = Files.createTempDirectory("wsev");
        Files.writeString(dir.resolve("coverage.json"),
            "[{\"linear\":262144,\"rom_off\":-1,\"cs\":8192,\"ds\":[0],\"es\":[0]}]");
        WSEvidence e = WSEvidence.load(dir);
        assertEquals(Set.of(0), e.ds.get(262144L));
        assertTrue(e.ss.isEmpty());
    }

    @Test
    public void loadReadsSs() throws Exception {
        Path dir = Files.createTempDirectory("wsev");
        Files.writeString(dir.resolve("coverage.json"),
            "[{\"linear\":262144,\"rom_off\":-1,\"cs\":8192,\"ds\":[0],\"es\":[0],\"ss\":[4096]}]");
        WSEvidence e = WSEvidence.load(dir);
        assertEquals(Set.of(0x1000), e.ss.get(262144L));
    }
}
