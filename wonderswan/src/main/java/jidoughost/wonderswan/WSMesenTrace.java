// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Parsers for Mesen 2 WonderSwan execution evidence: the trace log pair ({@code trace.tsv} +
 * {@code coverage.tsv}) written by this repository's Mesen trace script, and Mesen's native
 * Code/Data Logger file ({@code .cdl}).
 *
 * <p>Supported Mesen version: Mesen 2 at commit {@code b9fa69ddc6d0a331fb103fdb5eef6904305703c2}
 * (see {@code tools/mesen2/Dockerfile}). The trace-script formats are defined by
 * {@code tools/mesen2/trace.lua}; the CDL layout is Mesen's {@code CDLv2} format
 * ({@code Core/Debugger/CodeDataLogger.cpp} {@code SaveCdlFile}).
 *
 * <h2>trace.tsv</h2>
 * One line per executed instruction for the first N steps of the run (after that only
 * {@code coverage.tsv} is updated). Columns, tab-separated:
 * <pre>
 * n  cs  ip  ax bx cx dx si di bp sp ds es ss flags  [c0 c1 c2 c3]
 * </pre>
 * {@code n} is a 1-based decimal sequence number; {@code cs}..{@code flags} are 4 hex digits;
 * the optional trailing bank columns (recorded by current trace scripts, absent from older
 * logs) are the 2-hex-digit C0..C3 bank registers at execution time. The linear CPU address is
 * {@code (cs * 16 + ip) & 0xFFFFF}. REP string instructions are recorded once (first iteration).
 *
 * <h2>coverage.tsv</h2>
 * One line per executed linear address over the whole run, no header:
 * <pre>
 * linear  count  ds-list  es-list  [banks]
 * </pre>
 * {@code linear} is hex (5 digits), {@code count} decimal, the DS/ES lists are comma-separated
 * 4-hex-digit sets sampled over the first 64 visits of the address (as is the optional
 * {@code banks} column: {@code C0:ff}, {@code C2:f2,ff}, ...; the bank register relevant to the
 * address's window, absent from older logs). Bank-window addresses additionally record their
 * bank on every visit, so their bank sets are exact.
 *
 * <h2>trace.cdl / *.cdl (CDLv2)</h2>
 * {@code "CDLv2"} + a 4-byte little-endian CRC32 of the ROM + one flag byte per ROM byte
 * (index = ROM file offset): {@code Code = 0x01}, {@code Data = 0x02},
 * {@code JumpTarget = 0x04}, {@code SubEntryPoint = 0x08}. A headerless file of raw flag bytes
 * (as written by older Mesen versions) is accepted with a warning, like Mesen itself does.
 *
 * <p>All parsers are lenient: malformed lines are skipped and counted, never fatal. Pure Java,
 * no Ghidra dependencies, so the parsers and their tests run with a plain {@code javac/java}.
 */
public final class WSMesenTrace {
    private WSMesenTrace() { }

    /** Mesen 2 commit the formats were verified against. */
    public static final String MESEN_VERSION = "b9fa69ddc6d0a331fb103fdb5eef6904305703c2";

    /** CDL flag bits (Mesen {@code CdlFlags}). */
    public static final int CDL_CODE = 0x01, CDL_DATA = 0x02, CDL_JUMP_TARGET = 0x04, CDL_SUB_ENTRY = 0x08;
    static final byte[] CDL_MAGIC = { 'C', 'D', 'L', 'v', '2' };
    static final int CDL_HEADER = 9;

    /** One traced instruction step. Bank registers are -1 when the log predates them. */
    public record Step(long linear, int cs, int ip, int ds, int es, int c0, int c1, int c2, int c3) { }

    /** Full-run coverage of one linear address. Bank sets are empty when the log predates them. */
    public record Cov(long linear, long count, Set<Integer> ds, Set<Integer> es,
            Set<Integer> c0, Set<Integer> c2, Set<Integer> c3) { }

    /** Parsed trace log: ordered steps plus per-linear aggregates. */
    public static final class TraceData {
        /** Steps in execution order. */
        public final List<Step> steps = new ArrayList<>();
        /** Linear -> CS at its first traced step. */
        public final Map<Long, Integer> firstCs = new HashMap<>();
        /** Linear -> DS values seen in the trace window. */
        public final Map<Long, Set<Integer>> ds = new HashMap<>();
        /** Linear -> SS values seen in the trace window. */
        public final Map<Long, Set<Integer>> ss = new HashMap<>();
        /** Linear -> C0 values seen in the trace window (linear-window addresses). */
        public final Map<Long, Set<Integer>> c0 = new HashMap<>();
        /** Linear -> C2/C3 values seen in the trace window (ROM0/ROM1-window addresses). */
        public final Map<Long, Set<Integer>> windowBanks = new HashMap<>();
        /** Consecutive-step transfers (fromLin, fromCs, toLin, toCs) -> occurrences. */
        public final Map<List<Long>, int[]> transfers = new LinkedHashMap<>();
        public long skipped;
    }

    /** Parsed coverage log. */
    public static final class CovData {
        /** Linear -> entry. */
        public final Map<Long, Cov> byLinear = new TreeMap<>();
        public long skipped;
    }

    /** Parsed CDL file. Stored CRC is -1 for a headerless file. */
    public static final class CdlData {
        public final byte[] flags;
        public final long storedCrc;
        public final boolean headerless;
        CdlData(byte[] flags, long storedCrc, boolean headerless) {
            this.flags = flags; this.storedCrc = storedCrc; this.headerless = headerless;
        }
        public int codeBytes() { return count(CDL_CODE); }
        public int dataBytes() { return count(CDL_DATA); }
        public int jumpTargets() { return count(CDL_JUMP_TARGET); }
        public int subEntries() { return count(CDL_SUB_ENTRY); }
        private int count(int bit) {
            int n = 0;
            for (byte b : flags) if ((b & bit) != 0) n++;
            return n;
        }
    }

    /** Evidence files resolved from a user-supplied path (any may be null). */
    public record Resolved(Path trace, Path coverage, Path cdl) { }

    /**
     * Resolve a trace/coverage/CDL input path: a directory contributes its {@code trace.tsv},
     * {@code coverage.tsv} and (when exactly one is present) {@code *.cdl}; a {@code .tsv} file
     * resolves through its directory; a {@code .cdl} file stands alone.
     */
    public static Resolved resolve(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            Path trace = Files.exists(path.resolve("trace.tsv")) ? path.resolve("trace.tsv") : null;
            Path cov = Files.exists(path.resolve("coverage.tsv")) ? path.resolve("coverage.tsv") : null;
            List<Path> cdls = new ArrayList<>();
            try (var s = Files.list(path)) {
                s.filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".cdl"))
                    .sorted().forEach(cdls::add);
            }
            Path cdl = cdls.size() == 1 ? cdls.get(0) : null;
            if (trace == null && cov == null && cdl == null)
                throw new IOException(path + ": no trace.tsv, coverage.tsv or *.cdl found");
            return new Resolved(trace, cov, cdl);
        }
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".cdl")) {
            if (!Files.exists(path)) throw new IOException(path + ": file not found");
            return new Resolved(null, null, path);
        }
        Path dir = path.toAbsolutePath().getParent();
        if (dir == null) throw new IOException(path + ": cannot resolve parent directory");
        return resolve(dir);
    }

    /** Parse a {@code trace.tsv} file (see the class comment). */
    public static TraceData parseTrace(Path file) throws IOException {
        TraceData d = new TraceData();
        Step prev = null;
        for (String line : Files.readAllLines(file)) {
            String[] t = line.split("\t", -1);
            if (t.length < 3 || t[0].equals("n") || t[0].isBlank()) continue;
            try {
                int cs = Integer.parseInt(t[1].trim(), 16), ip = Integer.parseInt(t[2].trim(), 16);
                long lin = (((long) cs << 4) + ip) & 0xFFFFF;
                int ds = t.length > 12 ? Integer.parseInt(t[11].trim(), 16) : 0;
                int es = t.length > 13 ? Integer.parseInt(t[12].trim(), 16) : 0;
                int ss = t.length > 14 ? Integer.parseInt(t[13].trim(), 16) : 0;
                int c0 = t.length > 15 ? Integer.parseInt(t[15].trim(), 16) : -1;
                int c1 = t.length > 16 ? Integer.parseInt(t[16].trim(), 16) : -1;
                int c2 = t.length > 17 ? Integer.parseInt(t[17].trim(), 16) : -1;
                int c3 = t.length > 18 ? Integer.parseInt(t[18].trim(), 16) : -1;
                Step s = new Step(lin, cs, ip, ds, es, c0, c1, c2, c3);
                d.steps.add(s);
                d.firstCs.putIfAbsent(lin, cs);
                if (t.length > 12) d.ds.computeIfAbsent(lin, k -> new TreeSet<>()).add(ds);
                if (t.length > 14) d.ss.computeIfAbsent(lin, k -> new TreeSet<>()).add(ss);
                if (c0 >= 0 && lin >= 0x40000) d.c0.computeIfAbsent(lin, k -> new TreeSet<>()).add(c0);
                if (lin >= 0x20000 && lin < 0x30000 && c2 >= 0)
                    d.windowBanks.computeIfAbsent(lin, k -> new TreeSet<>()).add(c2);
                if (lin >= 0x30000 && lin < 0x40000 && c3 >= 0)
                    d.windowBanks.computeIfAbsent(lin, k -> new TreeSet<>()).add(c3);
                if (prev != null && prev.linear() != lin) {
                    List<Long> key = List.of(prev.linear(), (long) prev.cs(), lin, (long) cs);
                    int[] n = d.transfers.computeIfAbsent(key, k -> new int[1]);
                    n[0]++;
                }
                prev = s;
            } catch (NumberFormatException e) {
                d.skipped++;
            }
        }
        return d;
    }

    /** Parse a {@code coverage.tsv} file (see the class comment). */
    public static CovData parseCoverage(Path file) throws IOException {
        CovData d = new CovData();
        for (String line : Files.readAllLines(file)) {
            if (line.isBlank()) continue;
            String[] t = line.split("\t", -1);
            try {
                long lin = Long.parseLong(t[0].trim(), 16);
                long count = t.length > 1 && !t[1].isBlank() ? Long.parseLong(t[1].trim()) : 0;
                Set<Integer> ds = hexSet(t.length > 2 ? t[2] : "");
                Set<Integer> es = hexSet(t.length > 3 ? t[3] : "");
                Set<Integer> c0 = new TreeSet<>(), c2 = new TreeSet<>(), c3 = new TreeSet<>();
                if (t.length > 4 && !t[4].isBlank()) {
                    for (String part : t[4].split(";")) {
                        String[] kv = part.split(":", 2);
                        if (kv.length != 2) continue;
                        Set<Integer> vals = hexSet(kv[1]);
                        switch (kv[0].trim().toUpperCase(Locale.ROOT)) {
                            case "C0" -> c0.addAll(vals);
                            case "C2" -> c2.addAll(vals);
                            case "C3" -> c3.addAll(vals);
                            default -> { }
                        }
                    }
                }
                d.byLinear.put(lin, new Cov(lin, count, ds, es, c0, c2, c3));
            } catch (NumberFormatException e) {
                d.skipped++;
            }
        }
        return d;
    }

    private static Set<Integer> hexSet(String csv) {
        Set<Integer> out = new TreeSet<>();
        for (String v : csv.split(",")) {
            v = v.trim();
            if (!v.isEmpty()) out.add(Integer.parseInt(v, 16));
        }
        return out;
    }

    /**
     * Parse a Mesen CDL file (CDLv2 with CRC header, or headerless raw flags). The flag array is
     * indexed by ROM file offset; {@code romLen} (the program's ROM size) selects its valid prefix.
     */
    public static CdlData parseCdl(Path file, long romLen) throws IOException {
        byte[] all = Files.readAllBytes(file);
        boolean headerless = true;
        long crc = -1;
        byte[] flags = all;
        if (all.length >= CDL_HEADER && all[0] == 'C' && all[1] == 'D' && all[2] == 'L'
                && all[3] == 'v' && all[4] == '2') {
            headerless = false;
            crc = (all[5] & 0xFFL) | ((all[6] & 0xFFL) << 8) | ((all[7] & 0xFFL) << 16) | ((all[8] & 0xFFL) << 24);
            flags = Arrays.copyOfRange(all, CDL_HEADER, all.length);
        }
        if (flags.length < romLen)
            throw new IOException(String.format("%s: CDL holds %d flag bytes, the ROM has %d", file, flags.length, romLen));
        if (flags.length > romLen) flags = Arrays.copyOf(flags, (int) romLen);
        return new CdlData(flags, crc, headerless);
    }

    /** CRC32 of ROM bytes, comparable with a CDL header's stored CRC. */
    public static long crc32(byte[] rom) {
        java.util.zip.CRC32 c = new java.util.zip.CRC32();
        c.update(rom);
        return c.getValue();
    }

    /**
     * Linear addresses whose loader-mapping image is ROM offset {@code romOff}: the inverse of
     * {@link WSHardware#linearToRom} under the loader's C0 = 0xFF. Empty for bytes only reachable
     * through the bank windows; several for mirrored bytes of small ROMs.
     */
    public static List<Long> cdlLinears(long romOff, long romLen) {
        List<Long> out = new ArrayList<>();
        long base = ((long) (WSHardware.RESET_C0 & 0x3F)) << 20;
        long first = ((romOff - base) & (romLen - 1));
        for (long lin = first; lin < 0x100000; lin += romLen) {
            if (lin >= 0x40000) out.add(lin);
            if (romLen >= 0x100000) break;
        }
        return out;
    }
}
