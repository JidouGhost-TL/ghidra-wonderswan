// SPDX-License-Identifier: MIT OR Apache-2.0
import java.nio.file.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import jidoughost.wonderswan.WSMerge;

/**
 * Post-analysis script for rules M1 / T1 (merge split routines back together).
 *
 * Must run in its own -noanalysis process AFTER the analysis process exits: merges made inside
 * the analysis process (analyzer or its post-scripts) are undone before save, while merges made
 * in a later process survive to the saved project. Every phase that reads function structure
 * runs after this script. Idempotent: a second run finds nothing to merge.
 *
 * Args: [evidence.jsonl path or "-"] -- the phase-2 evidence report, read for interrupt entries
 * (installed vector targets from rule F2, observed interrupt entries from rule E2), which veto
 * merges; the M1/T1 lines are appended back to the same file. "-" runs with no exclusion set.
 */
public class WSMergeRoutines extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        String ev = args.length > 0 ? args[0] : "-";
        Set<Address> handlers = new HashSet<>();
        if (!ev.equals("-") && Files.exists(Paths.get(ev))) {
            for (String l : Files.readAllLines(Paths.get(ev))) {
                if (l.contains("\"rule\":\"F2\"") && l.contains("IVT[")) addField(l, "\"target\":\"", handlers);
                else if (l.contains("\"rule\":\"E2\"")
                        && (l.contains("\"kind\":\"irq\"") || l.contains("\"kind\":\"int\""))) addField(l, "\"entry\":\"", handlers);
            }
            println("WSMergeRoutines: interrupt entries for merge veto: " + handlers.size());
        } else {
            println("WSMergeRoutines: WARNING: no evidence report, merging without the interrupt-entry veto");
        }
        List<String> lines = new ArrayList<>();
        WSMerge m = new WSMerge(currentProgram, handlers, lines::add, monitor);
        m.apply();
        println("WSMergeRoutines: " + m.summary());
        if (!ev.equals("-") && !lines.isEmpty())
            Files.write(Paths.get(ev), (String.join("\n", lines) + "\n").getBytes(), StandardOpenOption.APPEND);
    }

    void addField(String line, String key, Set<Address> out) {
        int i = line.indexOf(key);
        if (i < 0) return;
        int j = line.indexOf('"', i + key.length());
        if (j < 0) return;
        try {
            Address a = currentProgram.getAddressFactory().getAddress(line.substring(i + key.length(), j));
            if (a != null) out.add(a);
        } catch (Exception e) { /* not an address: not a veto we can use */ }
    }
}
