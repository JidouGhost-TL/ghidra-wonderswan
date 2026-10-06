// SPDX-License-Identifier: MIT OR Apache-2.0
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.WSStaticCode;

/** Post-analysis static call seeding. Args: optional evidence output file. */
public class WSSeedStatic extends GhidraScript {
    @Override public void run() throws Exception {
        List<String> lines = new ArrayList<>();
        String summary = WSStaticCode.apply(currentProgram, lines::add, monitor);
        println("WSSeedStatic: " + summary);
        String[] args = getScriptArgs();
        if (args.length != 0) Files.write(Paths.get(args[0]), lines);
    }
}
