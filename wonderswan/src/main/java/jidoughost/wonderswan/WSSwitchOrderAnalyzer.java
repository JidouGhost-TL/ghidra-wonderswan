// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Rule J1u: J1 for unguarded byte-index and masked JMP tables, run on newly decoded instructions just before stock
 * Decompiler Switch Analysis ({@code AnalysisPriority.CODE_ANALYSIS}) sees them.
 *
 * <p>Ordering, from the stock analyzer: it is an instruction analyzer at CODE_ANALYSIS and collects every
 * computed jump in the newly decoded instructions, then skips a location that already has a computed
 * reference before it decompiles anything. The function it decompiles reads the jump table from a stored
 * override when one exists. Phase 2 J1 runs at LOW_PRIORITY, after stock switch analysis has already
 * decompiled every site, so for a byte-index site without a guard the stock decompiler bounded the index
 *  only by its width (or mask) and read handler bytes as slots. This analyzer runs one step earlier on the same
 * instructions: a proven table gets J1's references and, inside a function, J1's lock. Everything else
 * (sites J1 cannot prove, guarded tables, computed calls) reaches stock switch analysis as
 * before. Phase 2 J1 still re-derives every site from the final listing.
 *
 * <p>Needs the phase-1 execution evidence (EXECUTED_CODE stops, observed targets): without it, or with
 * J1 disabled in {@link WSEvidenceRepairAnalyzer}, it does nothing.
 */
public class WSSwitchOrderAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "WonderSwan Jump Tables (before switch analysis)";
    static final String J1_OPTION = WSEvidenceRepairAnalyzer.NAME + ".Recover jump tables (rule J1)";

    /** One J1 state per program and evidence run (J1f operand cache, sites already applied). */
    private static final Map<Program, WSJumpTables> STATE = Collections.synchronizedMap(new WeakHashMap<>());

    /** The J1u state of a program in this session (null when J1u did not run), for rule J1uw in phase 2. */
    static WSJumpTables beforeSwitch(Program program) { return STATE.get(program); }

    /** True when J1u already identified {@code site} as an unguarded byte-index or masked CS jump table whose
     *  extent could not be proven or safely applied (Rule C hazard). */
    static boolean isUnguardedHazard(Program program, ghidra.program.model.address.Address site) {
        WSJumpTables j = STATE.get(program);
        return j != null && j.unguardedHazards.contains(site);
    }

    public WSSwitchOrderAnalyzer() {
        super(NAME, "Applies proven CS-relative jump tables with an unguarded byte or masked index (rule J1u) before "
            + "Decompiler Switch Analysis, which would otherwise read every byte-index slot.",
            AnalyzerType.INSTRUCTION_ANALYZER);
        setPriority(AnalysisPriority.CODE_ANALYSIS.before());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().toString().equals("V30MZ");
    }

    @Override
    public void registerOptions(Options options, Program program) { }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        WSEvidence ev = WSEvidenceAnalyzer.EVIDENCE.get(program);
        if (ev == null) return false;
        Options analyzers = program.getOptions(Program.ANALYSIS_PROPERTIES);
        if (!analyzers.getBoolean(WSEvidenceRepairAnalyzer.NAME, true) || !analyzers.getBoolean(J1_OPTION, true))
            return false;
        String report = WSEvidenceAnalyzer.REPORT.getOrDefault(program, "");
        WSJumpTables j = STATE.get(program);
        if (j == null || j.ev != ev) {
            j = new WSJumpTables(program, ev, line -> emit(report, line));
            STATE.put(program, j);
        }
        try {
            int applied = j.applyBeforeSwitchAnalysis(set, monitor);
            if (applied > 0) {
                String msg = NAME + ": J1u applied " + applied + " unguarded byte-index or masked tables (total "
                    + j.beforeSwitch + ")";
                log.appendMsg(msg);
                Msg.info(this, msg);
            }
            return true;
        }
        catch (CancelledException c) { throw c; }
        catch (Exception e) {
            String msg = NAME + ": rule J1u failed: " + e;
            log.appendMsg(msg);
            Msg.error(this, msg, e);
            return false;
        }
    }

    /** Report lines from this phase carry their own rule names, so readers of phase-2 J1 lines ignore them. */
    private static void emit(String report, String line) {
        String tagged = line.replaceFirst("^\\{\"rule\":\"(J1[a-z]?)\"", "{\"rule\":\"$1-before-switch\"");
        if (tagged.contains("\"outcome\":\"RECOVERED\"")) Msg.info(WSSwitchOrderAnalyzer.class, NAME + ": " + tagged);
        if (report == null || report.isBlank()) return;
        try {
            Files.writeString(Paths.get(report), tagged + "\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        catch (java.io.IOException e) {
            Msg.error(WSSwitchOrderAnalyzer.class, NAME + ": cannot append to report " + report + ": " + e, e);
        }
    }
}
