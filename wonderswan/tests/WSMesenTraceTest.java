// SPDX-License-Identifier: MIT OR Apache-2.0
// Unit tests for WSMesenTrace (Mesen 2 trace/coverage/CDL parsers) and WSEvidence.fromMesen/merge.
// Plain-java main, no framework: run wonderswan/tests/run.sh [sampledir] (a sampledir holding real
// trace.tsv/coverage.tsv/*.cdl additionally runs the cross-file invariants).
import java.nio.file.*;
import java.util.*;
import jidoughost.wonderswan.WSEvidence;
import jidoughost.wonderswan.WSHardware;
import jidoughost.wonderswan.WSMesenTrace;

public class WSMesenTraceTest {
    static int passed;
    static void check(boolean cond, String name) {
        if (!cond) throw new AssertionError("FAILED: " + name);
        passed++;
    }

    public static void main(String[] a) throws Exception {
        Path fx = Paths.get(a[0]);
        traceV2(fx.resolve("trace-v2.tsv"));
        traceV1(fx.resolve("trace-v1.tsv"));
        coverageV2(fx.resolve("coverage-v2.tsv"));
        coverageV1(fx.resolve("coverage-v1.tsv"));
        cdl();
        cdlLinears();
        fromMesen(fx);
        merge();
        resolve();
        if (a.length > 1) realFiles(Paths.get(a[1]));
        System.out.println("WSMesenTraceTest: " + passed + " checks passed");
    }

    static void traceV2(Path f) throws Exception {
        WSMesenTrace.TraceData d = WSMesenTrace.parseTrace(f);
        check(d.steps.size() == 6, "v2 6 steps");
        check(d.steps.get(0).linear() == 0xffff0, "v2 linear cs*16+ip");
        check(d.steps.get(2).linear() == 0xb0003, "v2 linear b000:0003");
        check(d.steps.get(3).c2() == 0xf2 && d.steps.get(3).c0() == 0xff, "v2 bank cols");
        check(d.firstCs.get(0xb0000L) == 0xb000, "v2 firstCs");
        check(d.firstCs.get(0x20010L) == 0x2000, "v2 firstCs window");
        check(d.ds.get(0xb0003L).equals(Set.of(0x1000)), "v2 ds set");
        check(d.ss.get(0xb0003L).equals(Set.of(0x1000)), "v2 ss set");
        check(d.ss.get(0xb0000L).equals(Set.of(0)), "v2 ss zero");
        check(d.c0.get(0xb0000L).equals(Set.of(0xff)), "v2 c0 aggregate");
        check(d.windowBanks.get(0x20010L).equals(Set.of(0xf2)), "v2 window banks from trace");
        check(d.transfers.size() == 5, "v2 5 consecutive transfers");
        check(d.transfers.get(List.of(0xb0003L, 0xb000L, 0x20010L, 0x2000L))[0] == 1, "v2 transfer key+count");
        check(d.skipped == 0, "v2 no skipped lines");
    }

    static void traceV1(Path f) throws Exception {
        WSMesenTrace.TraceData d = WSMesenTrace.parseTrace(f);
        check(d.steps.size() == 3, "v1 3 steps");
        check(d.steps.get(0).c0() == -1 && d.steps.get(0).c3() == -1, "v1 banks unknown");
        check(d.c0.isEmpty() && d.windowBanks.isEmpty(), "v1 no bank aggregates");
        check(d.firstCs.get(0xb0003L) == 0xb000, "v1 firstCs");
        check(d.ss.get(0xb0003L).equals(Set.of(0)), "v1 ss set");
        check(d.transfers.size() == 2, "v1 2 transfers");
    }

    static void coverageV2(Path f) throws Exception {
        WSMesenTrace.CovData d = WSMesenTrace.parseCoverage(f);
        check(d.byLinear.size() == 7, "cov v2 7 addrs");
        check(d.byLinear.get(0xb0000L).count() == 10, "cov count");
        check(d.byLinear.get(0xb0000L).ds().equals(Set.of(0)), "cov ds");
        check(d.byLinear.get(0xb0000L).c0().equals(Set.of(0xff)), "cov c0 single");
        check(d.byLinear.get(0xb0003L).c0().equals(Set.of(0x0e, 0xff)), "cov c0 multi");
        check(d.byLinear.get(0x20010L).c2().equals(Set.of(0xf2, 0xff)), "cov c2 multi");
        check(d.byLinear.get(0x20020L).c2().isEmpty(), "cov empty banks col");
        check(d.skipped == 0, "cov v2 no skipped");
    }

    static void coverageV1(Path f) throws Exception {
        WSMesenTrace.CovData d = WSMesenTrace.parseCoverage(f);
        check(d.byLinear.size() == 7, "cov v1 7 addrs");
        check(d.byLinear.get(0xb0000L).c0().isEmpty(), "cov v1 no banks");
    }

    static void cdl() throws Exception {
        long romLen = 0x100000;
        byte[] flags = new byte[(int) romLen];
        flags[0x41234] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_JUMP_TARGET);
        flags[0x12345] = WSMesenTrace.CDL_CODE;
        flags[0x45678] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_SUB_ENTRY);
        flags[0x50000] = WSMesenTrace.CDL_DATA;
        Path dir = Files.createTempDirectory("wscdl");
        Path f = dir.resolve("trace.cdl");
        byte[] hdr = { 'C', 'D', 'L', 'v', '2', 0x78, 0x56, 0x34, 0x12 };
        Files.write(f, concat(hdr, flags));
        WSMesenTrace.CdlData c = WSMesenTrace.parseCdl(f, romLen);
        check(!c.headerless && c.storedCrc == 0x12345678L, "cdl header crc");
        check(c.codeBytes() == 3 && c.dataBytes() == 1, "cdl code/data counts");
        check(c.jumpTargets() == 1 && c.subEntries() == 1, "cdl jt/se counts");
        check((c.flags[0x41234] & 0xFF) == 0x05, "cdl flag byte");
        Path raw = dir.resolve("raw.bin");
        Files.write(raw, flags);
        WSMesenTrace.CdlData r = WSMesenTrace.parseCdl(raw, romLen);
        check(r.headerless && r.storedCrc == -1 && r.codeBytes() == 3, "cdl headerless accepted");
        Path shortF = dir.resolve("short.bin");
        Files.write(shortF, new byte[100]);
        boolean threw = false;
        try { WSMesenTrace.parseCdl(shortF, romLen); } catch (java.io.IOException e) { threw = true; }
        check(threw, "cdl short file refused");
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    static void cdlLinears() {
        // 1 MiB ROM: linear bytes map to themselves, low bytes are window-only.
        check(WSMesenTrace.cdlLinears(0x41234, 0x100000).equals(List.of(0x41234L)), "cdl 1M unique");
        check(WSMesenTrace.cdlLinears(0x12345, 0x100000).isEmpty(), "cdl 1M window-only");
        check(WSMesenTrace.cdlLinears(0xFFFFF, 0x100000).equals(List.of(0xFFFFFL)), "cdl 1M top");
        // 512 KiB ROM: mirrors.
        check(WSMesenTrace.cdlLinears(0x52345, 0x80000).equals(List.of(0x52345L, 0xD2345L)), "cdl 512K mirror");
        check(WSMesenTrace.cdlLinears(0x12345, 0x80000).equals(List.of(0x92345L)), "cdl 512K single");
        // inverse of linearToRom under C0=FF, sampled.
        long[] lens = { 0x10000, 0x80000, 0x100000, 0x400000, 0x1000000 };
        for (long len : lens) {
            for (long lin = 0x40000; lin < 0x100000; lin += 0x1ee7) {
                long off = WSHardware.linearToRom(lin, WSHardware.RESET_C0, len);
                check(WSMesenTrace.cdlLinears(off, len).contains(lin),
                    String.format("cdl inverse len=%x lin=%x", len, lin));
            }
        }
    }

    static void fromMesen(Path fx) throws Exception {
        WSMesenTrace.TraceData trace = WSMesenTrace.parseTrace(fx.resolve("trace-v2.tsv"));
        WSMesenTrace.CovData cov = WSMesenTrace.parseCoverage(fx.resolve("coverage-v2.tsv"));
        Map<Long, Integer> wsm = Map.of(0x20020L, 0x2000, 0xb0006L, 0xb000);
        // 2 MiB: C0 = 0x0E shows other bytes than the loader's C0 = 0xFF (bit 20 differs), so its
        // rows are skipped; on a 1 MiB cartridge the size mask makes every C0 alias (kept, below).
        WSEvidence e = WSEvidence.fromMesen(trace, cov, null, "test", 0x200000, wsm, -1);
        check(e.cs.get(0xb0000L) == 0xb000, "mesen cs from trace");
        check(e.cs.get(0x500L) == 0x0000, "mesen cs guessed for RAM");
        check(!e.cs.containsKey(0xb0006L), "mesen c0 other image skipped");
        check(WSEvidence.fromMesen(trace, cov, null, "test", 0x100000, wsm, -1).cs.containsKey(0xb0006L),
            "mesen c0 aliased by size mask kept");
        check(!e.cs.containsKey(0x20020L), "mesen window without banks skipped");
        check(!e.cs.containsKey(0x15000L), "mesen sram skipped");
        check(e.cs.containsKey(0xb0003L), "mesen multi-c0 with FF kept");
        check(e.windowBanks.get(0x20010L).equals(Set.of(0xf2, 0xff)), "mesen window banks union");
        check(e.ds.get(0xb0003L).equals(Set.of(0x1000)), "mesen ds union");
        check(e.ds.containsKey(0x15000L), "mesen ds covers unseeded sram");
        check(e.ss.get(0xb0003L).equals(Set.of(0x1000)), "mesen ss from trace");
        check(e.transfers.size() == 5, "mesen transfers carried");
        WSEvidence.MesenStats m = e.mesenStats;
        check(m.csFromTrace() == 6, "mesen csFromTrace");
        check(m.csFromWsm() == 1, "mesen csFromWsm");
        check(m.csGuessed() == 2, "mesen csGuessed");
        check(m.c0Skipped() == 1 && m.multiC0() == 1, "mesen c0 stats");
        check(m.windowBanked() == 2 && m.windowNoBank() == 1, "mesen window stats");
        check(m.sramAddrs() == 1 && m.ramAddrs() == 1, "mesen sram/ram stats");
        // v1 logs (no banks): C0 assumed, windows unseedable.
        WSMesenTrace.TraceData t1 = WSMesenTrace.parseTrace(fx.resolve("trace-v1.tsv"));
        WSMesenTrace.CovData c1 = WSMesenTrace.parseCoverage(fx.resolve("coverage-v1.tsv"));
        WSEvidence e1 = WSEvidence.fromMesen(t1, c1, null, "test", 0x100000, Map.of(), -1);
        check(e1.cs.containsKey(0xb0006L), "mesen v1 c0 assumed");
        check(!e1.cs.containsKey(0x20010L) && e1.mesenStats.windowNoBank() == 2, "mesen v1 windows unseeded");
        // CDL: only jump targets and sub-entries seed (plain code bytes are mostly operands);
        // mirror and window-only report, sub-entry becomes a call edge.
        long romLen = 0x100000;
        byte[] flags = new byte[(int) romLen];
        flags[0x41234] = WSMesenTrace.CDL_CODE;
        flags[0x41236] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_JUMP_TARGET);
        flags[0x12345] = WSMesenTrace.CDL_CODE;
        flags[0x45678] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_SUB_ENTRY);
        Path dir = Files.createTempDirectory("wscdl2");
        Path f = dir.resolve("t.cdl");
        Files.write(f, flags);
        WSMesenTrace.CdlData cdl = WSMesenTrace.parseCdl(f, romLen);
        WSEvidence e2 = WSEvidence.fromMesen(null, null, cdl, "cdl", romLen, Map.of(), -1);
        check(e2.cs.get(0x41236L) == 0x4000, "mesen cdl jump target seeds with guess");
        check(!e2.cs.containsKey(0x41234L) && e2.mesenStats.cdlNotSeeded() == 1, "mesen cdl plain code not seeded");
        check(!e2.cs.containsKey(0x12345L) && e2.mesenStats.cdlWindowOnly() == 1, "mesen cdl window-only reported");
        check(e2.cdlEntries.size() == 1 && e2.cdlEntries.get(0).to() == 0x45678
            && e2.cdlEntries.get(0).kind().equals("call"), "mesen cdl sub-entry edge");
        check(e2.mesenStats.cdlSeededNew() == 2, "mesen cdl seeded-new");
        // With a trace/coverage alongside, CDL seeds need corroboration under the loader mapping.
        // 2 MiB (C0 = 0x0E is another image there): CDL offsets are the loader's (C0 = 0xFF) images.
        long romLenC = 0x200000;
        byte[] flagsC = new byte[(int) romLenC];
        flagsC[0x1b0000] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_SUB_ENTRY); // covered, C0=FF
        flagsC[0x1b0006] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_SUB_ENTRY); // C0-skipped
        flagsC[0x170000] = (byte) (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_JUMP_TARGET); // unobserved
        Path fc = dir.resolve("c.cdl");
        Files.write(fc, flagsC);
        WSMesenTrace.CdlData cdlC = WSMesenTrace.parseCdl(fc, romLenC);
        WSEvidence e4 = WSEvidence.fromMesen(trace, cov, cdlC, "cdl", romLenC, Map.of(), -1);
        check(e4.cdlEntries.size() == 1 && e4.cdlEntries.get(0).to() == 0xb0000, "mesen cdl corroborated entry kept");
        check(e4.mesenStats.cdlNotSeeded() == 2, "mesen cdl uncorroborated/c0 declined");
        byte[] flagsM = new byte[0x80000];
        flagsM[0x52345] = WSMesenTrace.CDL_CODE;
        Path fm = dir.resolve("m.cdl");
        Files.write(fm, flagsM);
        WSEvidence e3 = WSEvidence.fromMesen(null, null, WSMesenTrace.parseCdl(fm, 0x80000), "cdl", 0x80000, Map.of(), -1);
        check(e3.cs.isEmpty() && e3.mesenStats.cdlAmbiguousMirror() == 1, "mesen cdl mirror reported");
    }

    static void merge() {
        WSEvidence p = new WSEvidence(), s = new WSEvidence();
        p.cs.put(0xb0000L, 0xb000);
        p.ds.put(0xb0000L, new TreeSet<>(Set.of(0x1000)));
        p.ss.put(0xb0000L, new TreeSet<>(Set.of(0x1000)));
        p.windowBanks.put(0x20010L, new TreeSet<>(Set.of(0xf2)));
        p.edges.add(new WSEvidence.Edge(1, 2, 0xb000, "jump", 3));
        p.transfers.add(new WSEvidence.Transfer(1, 0xb000, 2, 0xb000, 1));
        s.cs.put(0xb0000L, 0xa000);
        s.cs.put(0xc0000L, 0xc000);
        s.ds.put(0xb0000L, new TreeSet<>(Set.of(0)));
        s.ss.put(0xb0000L, new TreeSet<>(Set.of(0)));
        s.windowBanks.put(0x20010L, new TreeSet<>(Set.of(0xff)));
        s.edges.add(new WSEvidence.Edge(1, 2, 0xb000, "jump", 4));
        s.edges.add(new WSEvidence.Edge(5, 6, 0xc000, "call", 1));
        p.provenance = "P";
        s.provenance = "S";
        WSEvidence e = WSEvidence.merge(p, s);
        check(e.cs.get(0xb0000L) == 0xb000, "merge primary wins cs");
        check(e.cs.get(0xc0000L) == 0xc000, "merge keeps secondary-only");
        check(e.ds.get(0xb0000L).equals(Set.of(0, 0x1000)), "merge ds union");
        check(e.ss.get(0xb0000L).equals(Set.of(0, 0x1000)), "merge ss union");
        check(e.windowBanks.get(0x20010L).equals(Set.of(0xf2, 0xff)), "merge banks union");
        check(e.edges.size() == 2, "merge edges deduped");
        check(e.edges.stream().filter(x -> x.from() == 1).findFirst().get().count() == 7, "merge counts summed");
        check(e.transfers.size() == 1, "merge transfers concat");
    }

    static void resolve() throws Exception {
        Path dir = Files.createTempDirectory("wsresolve");
        Files.writeString(dir.resolve("trace.tsv"), "n\tcs\tip\n");
        Files.writeString(dir.resolve("coverage.tsv"), "b0000\t1\t0000\t0000\n");
        Files.write(dir.resolve("t.cdl"), new byte[16]);
        WSMesenTrace.Resolved r = WSMesenTrace.resolve(dir);
        check(r.trace() != null && r.coverage() != null && r.cdl() != null, "resolve dir trio");
        WSMesenTrace.Resolved rc = WSMesenTrace.resolve(dir.resolve("t.cdl"));
        check(rc.cdl() != null && rc.trace() == null, "resolve cdl file");
        WSMesenTrace.Resolved rt = WSMesenTrace.resolve(dir.resolve("trace.tsv"));
        check(rt.trace() != null && rt.coverage() != null, "resolve tsv via dir");
        boolean threw = false;
        try { WSMesenTrace.resolve(Files.createTempDirectory("wsempty")); } catch (java.io.IOException e) { threw = true; }
        check(threw, "resolve empty dir throws");
    }

    static void realFiles(Path dir) throws Exception {
        WSMesenTrace.Resolved r = WSMesenTrace.resolve(dir);
        check(r.trace() != null && r.coverage() != null, "real pair present");
        WSMesenTrace.TraceData t = WSMesenTrace.parseTrace(r.trace());
        WSMesenTrace.CovData c = WSMesenTrace.parseCoverage(r.coverage());
        check(t.steps.size() > 100, "real trace steps " + t.steps.size());
        check(c.byLinear.size() > 100, "real coverage addrs " + c.byLinear.size());
        long orphans = t.firstCs.keySet().stream().filter(l -> !c.byLinear.containsKey(l)).count();
        check(orphans == 0, "real traced linears all covered (orphans " + orphans + ")");
        check(t.skipped == 0 && c.skipped == 0, "real no skipped lines");
        System.out.println(String.format("real %s: steps=%d unique_traced=%d coverage=%d transfers=%d",
            dir, t.steps.size(), t.firstCs.size(), c.byLinear.size(), t.transfers.size()));
    }
}
