// SPDX-License-Identifier: MIT OR Apache-2.0
import java.nio.file.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.WSJumpTables;

/**
 * Post-analysis script for rule J1m (jump-table lock), run after WSMergeRoutines.
 *
 * At a site quarantined by rule J1l that never recovered, re-deletes any guessed reference a later
 * analysis re-derived (by the QUARANTINED address list) and locks the switch to its observed targets
 * with a stored jump-table override; with no observed target the site stays an opaque indirect branch.
 * Unresolved sites with E3 observed targets get the same lock, and recovered jump sites are re-locked
 * (J1p; merges strip the recovery override). Every lock is filtered to the site's space (J1q).
 * Must run in its own -noanalysis process like the merge script. Idempotent.
 *
 * Args: [evidence.jsonl path or "-"] -- the phase-2 evidence report, read for J1l QUARANTINED lines,
 * J1 RECOVERED/UNRESOLVED lines and E3 observed targets; the J1m lines are appended back.
 */
public class WSJumpTableFinish extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        String ev = args.length > 0 ? args[0] : "-";
        List<String> evidence = new ArrayList<>();
        if (!ev.equals("-") && Files.exists(Paths.get(ev))) evidence = Files.readAllLines(Paths.get(ev));
        else println("WSJumpTableFinish: WARNING: no evidence report, nothing to lock");
        List<String> lines = new ArrayList<>();
        String summary = WSJumpTables.lockSwitches(currentProgram, evidence, lines::add, monitor);
        println("WSJumpTableFinish: " + summary);
        if (!ev.equals("-") && !lines.isEmpty())
            Files.write(Paths.get(ev), (String.join("\n", lines) + "\n").getBytes(), StandardOpenOption.APPEND);
    }
}
