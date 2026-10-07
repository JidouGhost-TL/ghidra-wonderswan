// SPDX-License-Identifier: MIT OR Apache-2.0
// Compile-only stub for wonderswan/tests/run.sh: WSEvidence.of(WSMachine) is not under test, and
// the real WSMachine needs the Ghidra classpath. This stub satisfies javac with the exact member
// shapes WSEvidence.of reads; it is never packaged (tests/ is not a Gradle source set).
package jidoughost.wonderswan;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

final class WSMachine {
    public final Map<Long, Integer> csAt = new HashMap<>();
    public final Map<Long, Set<Integer>> executed = new TreeMap<>();
    public final Map<Long, Set<Integer>> executedSs = new TreeMap<>();
    public final Map<String, Integer> edges = new TreeMap<>();
    public final Map<Long, Set<Integer>> windowBanks = new TreeMap<>();
    public final WSComputedEdges computedEdges = new WSComputedEdges();
    public long instructions;
}
