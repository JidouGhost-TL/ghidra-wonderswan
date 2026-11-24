// SPDX-License-Identifier: MIT OR Apache-2.0
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import jidoughost.wonderswan.*;

/**
 * Rule SW1: a WonderSwan import uses the extension's ordered switch analysis instead of the stock one (whose
 * result depends on hash order and decompiler thread timing), and the ordered analyzer applies switches in
 * entry-point order however its candidates were found. Run on a cartridge imported with the WonderSwan loader
 * (-noanalysis). The repeat-import check (identical listings over repeated imports) is the job's compare gate.
 */
public class WSSwitchRepeatFixtures extends GhidraScript {
    int checks, failures;

    void check(boolean value, String message) {
        checks++;
        if (!value) { failures++; printerr("FAIL: " + message); }
    }

    @Override
    public void run() throws Exception {
        Options a = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        check(!a.getBoolean(WSDecompilerSwitchAnalyzer.STOCK, true), "loader turns the stock switch analysis off");

        WSDecompilerSwitchAnalyzer ws = new WSDecompilerSwitchAnalyzer();
        check(ws.canAnalyze(currentProgram), "ordered switch analysis applies to V30MZ programs");
        check(ws.getDefaultEnablement(currentProgram), "ordered switch analysis is on by default");

        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Analyzer stock = mgr.getAnalyzer(WSDecompilerSwitchAnalyzer.STOCK);
        Analyzer ours = mgr.getAnalyzer(WSDecompilerSwitchAnalyzer.NAME);
        check(stock != null, "stock analyzer still registered (user can re-enable it)");
        check(ours != null, "ordered analyzer registered");
        if (stock != null && ours != null)
            check(stock.getPriority().priority() == ours.getPriority().priority() && stock.getAnalysisType() == ours.getAnalysisType(),
                "ordered analyzer runs at the stock analyzer's place in the analysis order");
        check(WSDecompilerSwitchAnalyzer.CHUNK > 0, "fixed chunk size");

        println("WSSwitchRepeatFixtures: " + (checks - failures) + "/" + checks + " checks pass");
        if (failures > 0) throw new IllegalStateException(failures + " of " + checks + " checks failed");
    }
}
