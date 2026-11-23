// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Execution evidence for one program: which linear addresses executed (with the CS, DS and SS values
 * seen there) and the control-flow edges static analysis cannot see (computed jumps/calls, software
 * and hardware interrupt entries). Produced by a {@link WSMachine} run or loaded from a WSEmulate
 * output directory (coverage.json + edges.tsv).
 */
public final class WSEvidence {
    /** One observed transfer. from = -1 for an injected hardware interrupt. */
    public record Edge(long from, long to, int targetCs, String kind, int count) { }

    /**
     * One consecutive-step transfer from a Mesen trace (from/to linears with their observed CS
     * values, occurrences). Raw material: the seeder resolves each against the disassembled source
     * (fall-through flows are dropped, computed branches become edges, straight-line
     * discontinuities become interrupt entries) before the edge rules run.
     */
    public record Transfer(long from, int fromCs, long to, int toCs, int count) { }

    /** What a Mesen import observed, for the evidence report. Null when no Mesen input was used. */
    public record MesenStats(String source, Set<Long> linears, long traceSteps, long coverageAddrs,
            long csFromTrace, long csFromWsm, long csGuessed, long c0Skipped, long multiC0,
            long windowNoBank, long windowBanked, long sramAddrs, long ramAddrs, long transfers,
            long cdlCode, long cdlData, long cdlJumpTargets, long cdlSubEntries, long cdlSeededNew,
            long cdlAmbiguousMirror, long cdlWindowOnly, long cdlNotSeeded, long cdlCrcStored,
            boolean cdlHeaderless, boolean cdlCrcMatch) { }

    /** Executed linear address -> CS at first execution. */
    public final Map<Long, Integer> cs = new TreeMap<>();
    /** Physical ROM byte flags; code bytes are not implicitly instruction starts or CPU placements. */
    public byte[] romFlags = new byte[0];
    /** Executed linear address -> DS values seen (first 64 visits). */
    public final Map<Long, Set<Integer>> ds = new HashMap<>();
    /** Executed linear address -> SS values seen (first 64 visits; rule D0 gives SS the same treatment as DS). */
    public final Map<Long, Set<Integer>> ss = new HashMap<>();
    /** Exact ROM file offset for DS/SS samples whose instruction image is established. */
    final Map<Long, Long> segmentSampleImages = new HashMap<>();
    public final List<Edge> edges = new ArrayList<>();
    /** Executed ROM0/ROM1 window address (linear 20000-3FFFF) -> ROM bank values it executed under (rule B1). */
    public final Map<Long, Set<Integer>> windowBanks = new TreeMap<>();
    /** Raw Mesen trace transfers, resolved into {@link #edges} by the seeder (empty otherwise). */
    public final List<Transfer> transfers = new ArrayList<>();
    /** CDL sub-entry call edges (from = -1), joined into {@link #edges} by the seeder. */
    public final List<Edge> cdlEntries = new ArrayList<>();
    /** Mesen contribution statistics, or null when no Mesen input was used. */
    public MesenStats mesenStats;
    /** Free-text provenance (how the evidence was produced). */
    public String provenance = "";
    /** B3 site|linear keys already resolved (terminal outcomes never change; the repair pass skips them). */
    public final java.util.Set<String> b3resolved = new java.util.HashSet<>();
    /** Rule E0b: computed-branch edges carried across interrupt handler flow, and those later
     *  resolved at a same-context (post-IRET) instruction. Only known for in-process WSMachine
     *  runs ({@link #e0bKnown}); loaded or Mesen evidence leaves them unset. */
    public long e0bCarried, e0bResumed;
    public int e0bMaxDepth;
    public boolean e0bKnown;

    public static WSEvidence of(WSMachine m) {
        return of(m, Set.of());
    }

    /**
     * Evidence from a run, leaving out the addresses in {@code drop} (and every edge from or to them). A run that
     * ended in an error passes {@link WSMachine#untrustedTail()}: what executed before the failure is still
     * evidence, only the tail that led into it is not.
     */
    public static WSEvidence of(WSMachine m, Set<Long> drop) {
        WSEvidence e = new WSEvidence();
        for (Map.Entry<Long, Integer> x : m.csAt.entrySet()) if (!drop.contains(x.getKey())) e.cs.put(x.getKey(), x.getValue());
        for (Map.Entry<Long, Set<Integer>> x : m.executed.entrySet()) {
            if (drop.contains(x.getKey())) continue;
            Set<Integer> d = new TreeSet<>();
            for (int packed : x.getValue()) d.add(packed >>> 16);
            e.ds.put(x.getKey(), d);
        }
        for (Map.Entry<Long, Set<Integer>> x : m.executedSs.entrySet()) {
            if (drop.contains(x.getKey())) continue;
            e.ss.put(x.getKey(), new TreeSet<>(x.getValue()));
        }
        for (Map.Entry<String, Integer> x : m.edges.entrySet()) {
            String[] f = x.getKey().split(",");
            long from = Long.parseLong(f[0], 16), to = Long.parseLong(f[1], 16);
            if (drop.contains(from) || drop.contains(to)) continue;
            e.edges.add(parse(f, x.getValue()));
        }
        for (Map.Entry<Long, Set<Integer>> x : m.windowBanks.entrySet())
            if (!drop.contains(x.getKey())) e.windowBanks.put(x.getKey(), new TreeSet<>(x.getValue()));
        for (long lin : e.ds.keySet()) {
            if (lin < 0x20000 || lin >= 0x100000 || m.unmatchedRomRegisterSamples.get((int) lin)) continue;
            if (lin >= 0x40000) {
                e.recordSegmentImage(lin, WSHardware.linearToRom(lin, WSHardware.RESET_C0, m.rom.length),
                    m.cartridge.fileSize);
            } else {
                e.recordWindowSegmentImage(lin, e.windowBanks.get(lin), m.cartridge.fileSize);
            }
        }
        e.provenance = String.format("WSMachine in-process: %d instructions%s", m.instructions,
            drop.isEmpty() ? "" : String.format(" (run ended in an error; %d tail addresses dropped)", drop.size()));
        e.e0bCarried = m.computedEdges.carried();
        e.e0bResumed = m.computedEdges.resumed();
        e.e0bMaxDepth = m.computedEdges.maxDepth();
        e.e0bKnown = true;
        return e;
    }

    /** Load WSEmulate outputs: coverage.json (linear, cs, ds) and edges.tsv. */
    public static WSEvidence load(Path dir) throws IOException {
        WSEvidence e = new WSEvidence();
        Matcher m = Pattern.compile("\"linear\":(\\d+),\"rom_off\":-?\\d+,\"cs\":(-?\\d+),\"ds\":\\[([\\d, ]*)\\]")
            .matcher(Files.readString(dir.resolve("coverage.json")));
        while (m.find()) {
            long lin = Long.parseLong(m.group(1));
            int c = Integer.parseInt(m.group(2));
            if (c >= 0) e.cs.put(lin, c);
            Set<Integer> d = new TreeSet<>();
            for (String v : m.group(3).split(",\\s*")) if (!v.isBlank()) d.add(Integer.parseInt(v.trim()));
            e.ds.put(lin, d);
        }
        Matcher b = Pattern.compile("\"linear\":(\\d+)[^}]*\"banks\":\\[([\\d, ]*)\\]").matcher(Files.readString(dir.resolve("coverage.json")));
        while (b.find()) {
            Set<Integer> s = new TreeSet<>();
            for (String v : b.group(2).split(",\\s*")) if (!v.isBlank()) s.add(Integer.parseInt(v.trim()));
            e.windowBanks.put(Long.parseLong(b.group(1)), s);
        }
        // Files written before SS sampling have no "ss" key: the SS map then stays empty (SS default 0).
        Matcher s = Pattern.compile("\"linear\":(\\d+)[^}]*\"ss\":\\[([\\d, ]*)\\]").matcher(Files.readString(dir.resolve("coverage.json")));
        while (s.find()) {
            Set<Integer> v = new TreeSet<>();
            for (String w : s.group(2).split(",\\s*")) if (!w.isBlank()) v.add(Integer.parseInt(w.trim()));
            if (!v.isEmpty()) e.ss.put(Long.parseLong(s.group(1)), v);
        }
        Path ed = dir.resolve("edges.tsv");
        if (Files.exists(ed)) {
            for (String line : Files.readAllLines(ed)) {
                if (line.isBlank() || line.startsWith("from")) continue;
                String[] f = line.split("\t");
                e.edges.add(parse(f, Integer.parseInt(f[4])));
            }
        }
        e.provenance = "WSEmulate output " + dir;
        return e;
    }

    private static Edge parse(String[] f, int count) {
        long from = Long.parseLong(f[0], 16);
        if (f[3].equals("irq")) from = -1;
        return new Edge(from, Long.parseLong(f[1], 16), Integer.parseInt(f[2], 16), f[3], count);
    }

    /**
     * Build evidence from Mesen 2 inputs (any of {@code trace}, {@code coverage}, {@code cdl} may be
     * null, but at least one must be present). {@code romLen} is the program's ROM size (power of
     * two); {@code wsmCs} is an optional WSMachine coverage CS fallback (linear -> CS), used where
     * the trace has no CS for an address; remaining addresses get the bank-aligned guess
     * {@code (linear & 0xF0000) >> 4}. {@code romCrc} is the program ROM's CRC32 (-1 to skip the
     * CDL header check); a mismatch is reported in the stats, not fatal.
     *
     * <p>Mapping rules: linear-window code is seeded when an observed C0 shows the same bytes the
     * loader maps (effective-ROM offset under C0 = 0xFF; several C0 values alias to one image under the
     * size mask), or the log predates bank columns (that mapping is assumed); otherwise the address is
     * skipped (no image for what it executed). Bank-window code only with observed banks (rule B1);
     * SRAM has no program bytes and is reported, not seeded.
     * CDL code bytes seed only their unambiguous linear image, and only when they are known
     * instruction starts (jump targets and sub-entries; plain code bytes are mostly instruction
     * operands, which must never seed). With a trace or coverage alongside, CDL seeds additionally
     * require the address to have executed there under the loader mapping (this also excludes
     * phantom images of bytes that ran with another C0). CDL sub-entries become call-edge targets
     * (rule E2). Mirrored, window-only and declined bytes are reported, not seeded.
     */
    public static WSEvidence fromMesen(WSMesenTrace.TraceData trace, WSMesenTrace.CovData coverage,
            WSMesenTrace.CdlData cdl, String source, long romLen, Map<Long, Integer> wsmCs, long romCrc) {
        WSEvidence e = new WSEvidence();
        Set<Long> linears = new TreeSet<>();
        if (coverage != null) linears.addAll(coverage.byLinear.keySet());
        if (trace != null) linears.addAll(trace.firstCs.keySet());
        Set<Long> c0skip = new HashSet<>();
        long effectiveSize = WSHardware.effectiveSize(romLen);
        boolean romMatches = cdl == null || cdl.headerless || romCrc < 0 || cdl.storedCrc == romCrc;
        long csFromTrace = 0, csFromWsm = 0, csGuessed = 0, c0Skipped = 0, multiC0 = 0,
            windowNoBank = 0, windowBanked = 0, sramAddrs = 0, ramAddrs = 0;
        for (long lin : linears) {
            // Title defaults use all samples. A zero override needs a separately qualified image.
            WSMesenTrace.Cov row = coverage == null ? null : coverage.byLinear.get(lin);
            boolean traceSamples = trace != null && (trace.ds.containsKey(lin) || trace.ss.containsKey(lin));
            boolean tracePlacementKnown = trace == null || !trace.unplacedSegmentSamples.contains(lin);
            boolean coverageSamples = row != null && !row.ds().isEmpty();
            Set<Integer> ds = new TreeSet<>();
            if (coverageSamples) ds.addAll(row.ds());
            if (trace != null && trace.ds.containsKey(lin)) ds.addAll(trace.ds.get(lin));
            if (!ds.isEmpty()) e.ds.put(lin, ds);
            // SS evidence comes from the trace window only (coverage logs have no SS column).
            if (trace != null && trace.ss.containsKey(lin)) e.ss.put(lin, new TreeSet<>(trace.ss.get(lin)));
            int cs;
            if (trace != null && trace.firstCs.containsKey(lin)) { cs = trace.firstCs.get(lin); csFromTrace++; }
            else if (wsmCs != null && wsmCs.containsKey(lin)) { cs = wsmCs.get(lin); csFromWsm++; }
            else { cs = (int) ((lin & 0xF0000) >> 4); csGuessed++; }
            long off = lin - ((long) cs << 4);
            if (off < 0 || off > 0xFFFF) { cs = (int) ((lin & 0xF0000) >> 4); }
            if (lin >= 0x40000) {
                Set<Integer> coverageC0 = row == null ? Set.of() : row.c0();
                Set<Integer> traceC0 = trace == null ? Set.of() : trace.c0.getOrDefault(lin, Set.of());
                Set<Integer> c0 = new TreeSet<>(coverageC0);
                c0.addAll(traceC0);
                // Keep an address its observed C0 maps to the same bytes the loader shows (effective-ROM
                // offset under RESET_C0): several C0 values alias to one image once the size mask applies.
                // Only a C0 showing genuinely other bytes is skipped (no image for what it executed).
                long loaderOff = WSHardware.linearToRom(lin, WSHardware.RESET_C0, effectiveSize);
                boolean imaged = c0.isEmpty();
                for (int v : c0) if (WSHardware.linearToRom(lin, v, effectiveSize) == loaderOff) { imaged = true; break; }
                if (!imaged) { c0Skipped++; c0skip.add(lin); continue; }
                if (c0.size() > 1) multiC0++;
                e.cs.put(lin, cs);
                if (romMatches && tracePlacementKnown && (!traceSamples || !traceC0.isEmpty()) && (!coverageSamples || !coverageC0.isEmpty())
                    && !c0.isEmpty() && c0.stream().allMatch(v -> WSHardware.linearToRom(lin, v, effectiveSize) == loaderOff))
                    e.recordSegmentImage(lin, loaderOff, romLen);
            } else if (lin >= 0x20000) {
                Set<Integer> coverageBanks = row == null ? Set.of() : lin < 0x30000 ? row.c2() : row.c3();
                Set<Integer> traceBanks = trace == null ? Set.of() : trace.windowBanks.getOrDefault(lin, Set.of());
                Set<Integer> banks = new TreeSet<>(coverageBanks);
                banks.addAll(traceBanks);
                if (banks.isEmpty()) { windowNoBank++; continue; }
                e.cs.put(lin, cs);
                e.windowBanks.put(lin, banks);
                if (romMatches && tracePlacementKnown && (!traceSamples || !traceBanks.isEmpty())
                    && (!coverageSamples || !coverageBanks.isEmpty()))
                    e.recordWindowSegmentImage(lin, banks, romLen);
                windowBanked++;
            } else if (lin >= 0x10000) {
                sramAddrs++;
            } else {
                e.cs.put(lin, cs);
                ramAddrs++;
            }
        }
        if (trace != null) {
            for (Map.Entry<List<Long>, int[]> t : trace.transfers.entrySet()) {
                List<Long> k = t.getKey();
                e.transfers.add(new Transfer(k.get(0), k.get(1).intValue(), k.get(2), k.get(3).intValue(), t.getValue()[0]));
            }
        }
        long cdlCode = 0, cdlData = 0, cdlJumpTargets = 0, cdlSubEntries = 0, cdlSeededNew = 0,
            cdlAmbiguousMirror = 0, cdlWindowOnly = 0, cdlNotSeeded = 0;
        if (cdl != null) {
            e.romFlags = cdl.flags.clone();
            cdlCode = cdl.codeBytes();
            cdlData = cdl.dataBytes();
            cdlJumpTargets = cdl.jumpTargets();
            cdlSubEntries = cdl.subEntries();
            boolean corroborated = trace != null || coverage != null;
            for (int romOff = 0; romOff < cdl.flags.length; romOff++) {
                int f = cdl.flags[romOff] & 0xFF;
                if ((f & (WSMesenTrace.CDL_CODE | WSMesenTrace.CDL_SUB_ENTRY)) == 0) continue;
                List<Long> lins = WSMesenTrace.cdlLinears(romOff, romLen);
                if (lins.size() != 1) {
                    if (lins.isEmpty()) cdlWindowOnly++;
                    else cdlAmbiguousMirror++;
                    continue;
                }
                long lin = lins.get(0);
                boolean start = (f & (WSMesenTrace.CDL_JUMP_TARGET | WSMesenTrace.CDL_SUB_ENTRY)) != 0;
                boolean ok = start && (!corroborated || linears.contains(lin) && !c0skip.contains(lin));
                if (!ok) { cdlNotSeeded++; continue; }
                if (!e.cs.containsKey(lin)) {
                    int cs;
                    if (trace != null && trace.firstCs.containsKey(lin)) { cs = trace.firstCs.get(lin); csFromTrace++; }
                    else if (wsmCs != null && wsmCs.containsKey(lin)) { cs = wsmCs.get(lin); csFromWsm++; }
                    else { cs = (int) ((lin & 0xF0000) >> 4); csGuessed++; }
                    e.cs.put(lin, cs);
                    linears.add(lin);
                    cdlSeededNew++;
                }
                if ((f & WSMesenTrace.CDL_SUB_ENTRY) != 0)
                    e.cdlEntries.add(new Edge(-1, lin, e.cs.get(lin), "call", 1));
            }
        }
        e.mesenStats = new MesenStats(source, linears, trace == null ? 0 : trace.steps.size(),
            coverage == null ? 0 : coverage.byLinear.size(), csFromTrace, csFromWsm, csGuessed,
            c0Skipped, multiC0, windowNoBank, windowBanked, sramAddrs, ramAddrs, e.transfers.size(),
            cdlCode, cdlData, cdlJumpTargets, cdlSubEntries, cdlSeededNew, cdlAmbiguousMirror,
            cdlWindowOnly, cdlNotSeeded, cdl == null ? -1 : cdl.storedCrc, cdl != null && cdl.headerless,
            cdl == null || cdl.headerless || romCrc < 0 || cdl.storedCrc == romCrc);
        e.provenance = "Mesen " + source;
        return e;
    }

    /**
     * Merge two evidences; {@code primary} wins CS conflicts (same linear observed with different
     * segment values), DS/SS sets and window banks unite, edges with the same
     * (from, to, targetCs, kind) sum their counts, transfers concatenate.
     */
    public static WSEvidence merge(WSEvidence primary, WSEvidence secondary) {
        WSEvidence e = new WSEvidence();
        e.romFlags = java.util.Arrays.copyOf(primary.romFlags, Math.max(primary.romFlags.length, secondary.romFlags.length));
        for (int k = 0; k < secondary.romFlags.length; k++) e.romFlags[k] |= secondary.romFlags[k];
        e.cs.putAll(secondary.cs);
        e.cs.putAll(primary.cs);
        for (Map.Entry<Long, Set<Integer>> x : secondary.ds.entrySet())
            e.ds.computeIfAbsent(x.getKey(), k -> new TreeSet<>()).addAll(x.getValue());
        for (Map.Entry<Long, Set<Integer>> x : primary.ds.entrySet())
            e.ds.computeIfAbsent(x.getKey(), k -> new TreeSet<>()).addAll(x.getValue());
        for (Map.Entry<Long, Set<Integer>> x : secondary.ss.entrySet())
            e.ss.computeIfAbsent(x.getKey(), k -> new TreeSet<>()).addAll(x.getValue());
        for (Map.Entry<Long, Set<Integer>> x : primary.ss.entrySet())
            e.ss.computeIfAbsent(x.getKey(), k -> new TreeSet<>()).addAll(x.getValue());
        e.mergeSegmentImages(primary, secondary);
        e.mergeSegmentImages(secondary, primary);
        Map<String, Edge> edges = new LinkedHashMap<>();
        for (Edge x : secondary.edges) edges.put(edgeKey(x), x);
        for (Edge x : primary.edges)
            edges.merge(edgeKey(x), x, (a, b) -> new Edge(a.from(), a.to(), a.targetCs(), a.kind(), a.count() + b.count()));
        e.edges.addAll(edges.values());
        for (Map.Entry<Long, Set<Integer>> x : secondary.windowBanks.entrySet())
            e.windowBanks.computeIfAbsent(x.getKey(), k -> new TreeSet<>()).addAll(x.getValue());
        for (Map.Entry<Long, Set<Integer>> x : primary.windowBanks.entrySet())
            e.windowBanks.computeIfAbsent(x.getKey(), k -> new TreeSet<>()).addAll(x.getValue());
        e.transfers.addAll(secondary.transfers);
        e.transfers.addAll(primary.transfers);
        e.cdlEntries.addAll(secondary.cdlEntries);
        e.cdlEntries.addAll(primary.cdlEntries);
        e.mesenStats = primary.mesenStats != null ? primary.mesenStats : secondary.mesenStats;
        e.provenance = primary.provenance + " + " + secondary.provenance;
        return e;
    }

    private void recordSegmentImage(long linear, long effectiveOffset, long fileSize) {
        long fileOffset = WSHardware.fileOffset(effectiveOffset, fileSize);
        if (fileOffset >= 0 && fileOffset < fileSize) segmentSampleImages.put(linear, fileOffset);
    }

    private void recordWindowSegmentImage(long linear, Set<Integer> banks, long fileSize) {
        if (banks == null || banks.size() != 1) return;
        long effectiveOffset = WSHardware.bankToRom(banks.iterator().next(), WSHardware.effectiveSize(fileSize));
        recordSegmentImage(linear, effectiveOffset + (linear & 0xFFFF), fileSize);
    }

    private void mergeSegmentImages(WSEvidence source, WSEvidence other) {
        source.segmentSampleImages.forEach((linear, offset) -> {
            if (offset.equals(other.segmentSampleImages.get(linear))
                || !other.ds.containsKey(linear) && !other.ss.containsKey(linear))
                segmentSampleImages.put(linear, offset);
        });
    }

    private static String edgeKey(Edge x) {
        return x.from() + "," + x.to() + "," + x.targetCs() + "," + x.kind();
    }

    public boolean executed(long linear) { return cs.containsKey(linear); }
}
