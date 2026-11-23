// SPDX-License-Identifier: MIT OR Apache-2.0
import java.lang.reflect.Field;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import jidoughost.wonderswan.*;

/**
 * Rule E0: re-invoking the evidence analyzer on the same program and inputs reuses the WSMachine evidence instead
 * of emulating again, starts from the state a fresh run has, and still emulates again when an input changes.
 * Run on a cartridge imported with the WonderSwan loader (-noanalysis).
 */
public class WSEmulationOnceFixtures extends GhidraScript {
    int checks, failures;

    void check(boolean value, String message) {
        checks++;
        if (!value) { failures++; printerr("FAIL: " + message); }
    }

    @SuppressWarnings("unchecked")
    WSEvidence evidence(Program p) throws Exception {
        Field f = WSEvidenceAnalyzer.class.getDeclaredField("EVIDENCE");
        f.setAccessible(true);
        return ((Map<Program, WSEvidence>) f.get(null)).get(p);
    }

    WSEvidence analyze(WSEvidenceAnalyzer analyzer, int frames) throws Exception {
        Options o = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(WSEvidenceAnalyzer.NAME);
        analyzer.registerOptions(o, currentProgram);
        o.setInt("Frames", frames);
        o.setInt("Instructions per frame", 2000);
        analyzer.optionsChanged(o, currentProgram);
        MessageLog log = new MessageLog();
        check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor, log), "analyzer ran, frames=" + frames);
        WSEvidence ev = evidence(currentProgram);
        check(ev != null && !ev.cs.isEmpty(), "evidence collected, frames=" + frames);
        return ev;
    }

    static boolean sameContent(WSEvidence a, WSEvidence b) {
        return a.cs.equals(b.cs) && a.ds.equals(b.ds) && a.ss.equals(b.ss) && a.edges.equals(b.edges)
            && a.windowBanks.equals(b.windowBanks) && a.provenance.equals(b.provenance);
    }

    @Override
    public void run() throws Exception {
        WSEvidenceAnalyzer analyzer = new WSEvidenceAnalyzer();
        WSEvidence first = analyze(analyzer, 20);
        first.b3resolved.add("fixture-marker");

        // A second invocation with the same inputs (Ghidra re-schedules byte analyzers after call-fixup repairs).
        WSEvidence second = analyze(analyzer, 20);
        check(second == first, "same program and inputs: evidence reused, no second emulation");
        check(!second.b3resolved.contains("fixture-marker"), "reused evidence starts from a fresh run's B3 state");

        // A changed run input emulates again.
        WSEvidence longer = analyze(analyzer, 21);
        check(longer != second, "changed frame count: emulated again");
        check(!longer.provenance.equals(second.provenance), "changed frame count: different run");

        // Back to the first inputs: a new run, identical content (the run is a function of its inputs).
        WSEvidence again = analyze(analyzer, 20);
        check(again != longer, "inputs changed back: emulated again");
        check(sameContent(first, again), "fresh run with the first inputs reproduces the reused evidence");

        println("WSEmulationOnceFixtures: checks=" + checks + " failures=" + failures);
        if (failures != 0) throw new AssertionError("WSEmulationOnceFixtures failures=" + failures);
        println("WSEmulationOnceFixtures: PASS checks=" + checks);
    }
}
