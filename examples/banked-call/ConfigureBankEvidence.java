// SPDX-License-Identifier: MIT OR Apache-2.0
// Configure the analysis options before importing the synthetic bank exercise.
//@category WonderSwan.Examples

import ghidra.app.script.GhidraScript;

public class ConfigureBankEvidence extends GhidraScript {
    @Override
    public void run() throws Exception {
        var args = getScriptArgs();
        if (args.length != 2 || (!args[1].equals("observed") && !args[1].equals("static"))) {
            throw new IllegalArgumentException("Usage: evidence.jsonl observed|static");
        }
        setAnalysisOption(currentProgram,
            "WonderSwan Execution Evidence.Evidence report file (JSON lines; empty = none)", args[0]);
        setAnalysisOption(currentProgram, "WonderSwan Execution Evidence.Run WSMachine",
            Boolean.toString(args[1].equals("observed")));
    }
}
