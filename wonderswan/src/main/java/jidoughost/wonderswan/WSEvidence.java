// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Execution evidence for one program: which linear addresses executed (with the CS and DS values seen
 * there) and the control-flow edges static analysis cannot see (computed jumps/calls, software and
 * hardware interrupt entries). Produced by a {@link WSMachine} run or loaded from a WSEmulate output
 * directory (coverage.json + edges.tsv).
 */
public final class WSEvidence {
    /** One observed transfer. from = -1 for an injected hardware interrupt. */
    public record Edge(long from, long to, int targetCs, String kind, int count) { }

    /** Executed linear address -> CS at first execution. */
    public final Map<Long, Integer> cs = new TreeMap<>();
    /** Executed linear address -> DS values seen (first 64 visits). */
    public final Map<Long, Set<Integer>> ds = new HashMap<>();
    public final List<Edge> edges = new ArrayList<>();
    /** Executed ROM0/ROM1 window address (linear 20000-3FFFF) -> ROM bank values it executed under (rule B1). */
    public final Map<Long, Set<Integer>> windowBanks = new TreeMap<>();
    /** Free-text provenance (how the evidence was produced). */
    public String provenance = "";

    public static WSEvidence of(WSMachine m) {
        WSEvidence e = new WSEvidence();
        e.cs.putAll(m.csAt);
        for (Map.Entry<Long, Set<Integer>> x : m.executed.entrySet()) {
            Set<Integer> d = new TreeSet<>();
            for (int packed : x.getValue()) d.add(packed >>> 16);
            e.ds.put(x.getKey(), d);
        }
        for (Map.Entry<String, Integer> x : m.edges.entrySet()) e.edges.add(parse(x.getKey().split(","), x.getValue()));
        for (Map.Entry<Long, Set<Integer>> x : m.windowBanks.entrySet()) e.windowBanks.put(x.getKey(), new TreeSet<>(x.getValue()));
        e.provenance = String.format("WSMachine in-process: %d instructions", m.instructions);
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

    public boolean executed(long linear) { return cs.containsKey(linear); }
}
