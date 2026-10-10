// SPDX-License-Identifier: MIT OR Apache-2.0
// Import Mesen 2 execution evidence (trace.tsv + coverage.tsv directory, or a .cdl file) into the
// current WonderSwan program and seed code discovery from it with the same phase-1 rules the
// WonderSwan Execution Evidence analyzer applies to WSMachine evidence (E1 executed code, E2 call
// entries, E3 computed-jump targets, B2 bank overlays, B3 window flows; trace transfers resolve
// against the disassembled sources first). Then runs analyzeChanges so functions are created for
// the new code, like the analyzer pipeline does.
// Args: <mesen evidence path> [<WSEmulate output dir for CS fallback>] [<report file>]
//   The WSEmulate dir is optional: its coverage CS values place code the trace window never reached
//   (without it those addresses get the bank-aligned CS guess). The report file gets one JSON line
//   per decision (rule "mesen" lines record what the import contributed).
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.util.Map;
import jidoughost.wonderswan.WSEvidence;
import jidoughost.wonderswan.WSEvidenceAnalyzer;

public class WSImportTrace extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) throw new IllegalArgumentException("usage: WSImportTrace <mesen evidence path> [<WSEmulate dir>] [<report>]");
        Map<Long, Integer> wsmCs = null;
        if (a.length > 1 && !a[1].equals("-")) wsmCs = WSEvidence.load(Paths.get(a[1])).cs;
        WSEvidence ev = WSEvidenceAnalyzer.loadMesenEvidence(Paths.get(a[0]), currentProgram, wsmCs);
        if (!ev.mesenStats.cdlCrcMatch())
            println("WSImportTrace: WARNING: CDL CRC does not match this ROM; its bytes are mapped anyway, check the ROM revision");
        String report = a.length > 2 ? a[2] : "";
        String sum = WSEvidenceAnalyzer.applyEvidence(currentProgram, ev, report, monitor);
        analyzeChanges(currentProgram);
        WSEvidenceAnalyzer.repairEvidence(currentProgram, ev, report, monitor);
        WSEvidence.MesenStats m = ev.mesenStats;
        println(String.format("WSImportTrace: %s; now functions=%d instructions=%d",
            sum, currentProgram.getFunctionManager().getFunctionCount(), currentProgram.getListing().getNumInstructions()));
        if (!report.isBlank()) println("WSImportTrace: report written to " + report);
    }
}
