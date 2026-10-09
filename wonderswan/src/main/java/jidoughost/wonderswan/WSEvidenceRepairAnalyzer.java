// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import java.util.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Phase 2 of {@link WSEvidenceAnalyzer}: runs after Ghidra's own analyzers and checks their results
 * against the same execution evidence (reused from phase 1, no second emulator run):
 *   C0  default code segment over undecoded ROM bytes ({@link WSCodeContext}); H2 RAM/SRAM code without an image
 *       is kept and tagged as an unknown hypothesis ({@link WSRamCode}), never cleared by the rules below;
 *   N1  clear "does not return" where a call's fall-through executed, restore the cut-off code;
 *   E1R re-seed executed addresses that later analysis removed;
 *   J1  CS-relative jump/call tables by rule ({@link WSJumpTables}), checked against observed targets;
 *   D1  DS/SS context at function entries; A1 classify decode artefacts;
 *   P1  functions whose entry has no bytes are phantoms: removed and reported with their creating references;
 *   D0  title DS/SS defaults from execution evidence ({@link WSCompilerRules}), before D1;
 *   C1  every function whose signature no user or importer set gets the title's convention: __lsic86 when
 *       rule K1 identifies LSI C-86 code, else the compiler spec's default (Ghidra's analyzers otherwise
 *       leave __cdecl16near / unknown, which the decompiler reads as stack arguments);
 *   R1  register return values from caller/callee evidence ({@link WSReturns});
 *   V1  RAM flags written by interrupt handlers and polled in spin-wait loops are volatile
 *       ({@link WSVolatile}).
 */
public class WSEvidenceRepairAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "WonderSwan Execution Evidence (repair)";
    private static final String OPT_JT = "Recover jump tables (rule J1)";
    private static final String OPT_CC = "Apply default calling convention (rule C1)";
    private static final String OPT_CP = "Follow code-pointer variables (rules F1-F4)";
    private static final String OPT_GAP = "Classify unreferenced code after terminators (rules G1/U1)";
    private boolean jumpTables = true, convention = true, codePointers = true, gapCode = true;

    public WSEvidenceRepairAnalyzer() {
        super(NAME, "Checks analysis results against the execution evidence collected by '"
            + WSEvidenceAnalyzer.NAME + "': non-returning functions, lost executed code, DS at entries, decode artefacts.",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY.after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().toString().equals("V30MZ");
    }

    @Override
    public void registerOptions(Options o, Program program) {
        o.registerOption(OPT_JT, jumpTables, null, "Recover CS-relative jump/call tables by rule, checked against observed targets");
        o.registerOption(OPT_CC, convention, null, "Set the compiler spec's default convention on functions without a user/imported signature");
        o.registerOption(OPT_GAP, gapCode, null, "Disassemble structurally proven code after RET/JMP that nothing references: dead branches (G1, no function) and unreferenced functions (U1)");
        o.registerOption(OPT_CP, codePointers, null, "Disassemble code reached through far/near code-pointer variables (constant stores, setter functions, IVT) and pushed return addresses");
    }

    @Override
    public void optionsChanged(Options o, Program program) {
        jumpTables = o.getBoolean(OPT_JT, jumpTables);
        convention = o.getBoolean(OPT_CC, convention);
        codePointers = o.getBoolean(OPT_CP, codePointers);
        gapCode = o.getBoolean(OPT_GAP, gapCode);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        try {
            log.appendMsg(NAME + ": C0 ROM context spans " + WSCodeContext.seedRomDefaults(program)
                + ", H2 unknown RAM code runs kept " + WSRamCode.classify(program));
        }
        catch (Exception e) { log.appendMsg(NAME + ": C0/H2 failed: " + e); Msg.error(this, "C0/H2 failed", e); }
        WSEvidence ev = WSEvidenceAnalyzer.EVIDENCE.get(program);
        if (ev == null) {
            // No execution evidence (emulation failed or disabled): the evidence rules cannot run, but K1/C1 decide
            // from the code alone, so the convention is still applied.
            log.appendMsg(NAME + ": no execution evidence; only K1/C1 run");
            Msg.warn(this, NAME + ": no execution evidence; only K1/C1 run");
            if (!convention) return false;
            try { log.appendMsg(NAME + ": " + applyConvention(program, line -> { })); }
            catch (Exception e) { Msg.error(this, NAME + ": rule C1 failed: " + e, e); log.appendMsg(NAME + ": rule C1 failed: " + e); }
            return true;
        }
        // Each rule runs on its own: a failing rule is reported (analysis log, Msg error, ERROR line in the
        // evidence report, error bookmark at the program's first address) and the remaining rules still run.
        // A swallowed exception here once silently skipped J1, D0, D1, A1 and C1.
        try (WSEvidenceAnalyzer.Seeder s = new WSEvidenceAnalyzer.Seeder(program, ev, WSEvidenceAnalyzer.REPORT.get(program), true, monitor, log)) {
            List<String> parts = new ArrayList<>(), failed = new ArrayList<>();
            rule("N1", s, program, log, failed, () -> s.repairNoReturn());
            rule("E1R", s, program, log, failed, () -> s.seedExecuted("E1R"));
            rule("B3", s, program, log, failed, () -> s.resolveWindowFlows());
            rule("P1", s, program, log, failed, () -> parts.add(removePhantoms(program, s)));
            // J1 and F1-F4 feed each other (a recovered table target can store a code pointer, a pointer target can hold
            // a table): alternate until neither adds code.
            WSJumpTables j = jumpTables ? new WSJumpTables(program, ev, line -> s.emit("%s", line)) : null;
            WSCodePointers cp = codePointers ? new WSCodePointers(program, line -> s.emit("%s", line), monitor) : null;
            WSGapCode gc = gapCode ? new WSGapCode(program, line -> s.emit("%s", line), monitor) : null;
            for (int round = 0; round < 8; round++) {
                long before = program.getListing().getNumInstructions();
                if (j != null) rule("J1", s, program, log, failed, () -> j.apply(monitor));
                if (cp != null) rule("F1-F4", s, program, log, failed, () -> cp.apply());
                // G1/U1 only once the reference-driven rules are stable: a gap they explain is not "unreferenced"
                if (gc != null && program.getListing().getNumInstructions() == before) rule("G1/U1", s, program, log, failed, () -> gc.apply());
                if (program.getListing().getNumInstructions() == before) break;
            }
            if (j != null) rule("J1r", s, program, log, failed, () -> j.restoreClearedSites(monitor));
            if (j != null) rule("J1l-finish", s, program, log, failed, () -> j.finish());
            if (j != null) parts.add(j.summary());
            if (cp != null) parts.add(cp.summary());
            if (gc != null) parts.add(gc.summary());
            rule("D2", s, program, log, failed, () -> {
                WSBranchContext d2 = new WSBranchContext(program, ev, line -> s.emit("%s", line), monitor);
                d2.apply();
                parts.add(d2.summary());
            });
            rule("E5", s, program, log, failed, () -> {
                WSExecutedFunctions e5 = new WSExecutedFunctions(program, ev, line -> s.emit("%s", line), monitor);
                e5.apply();
                parts.add(e5.summary());
            });
            rule("fixup", s, program, log, failed, () -> {
                for (Function f : program.getFunctionManager().getFunctions(true)) CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
            });
            rule("D0", s, program, log, failed, () -> parts.add(applyDsDefault(program, ev, s)));   // before D1: entry evidence overrides it
            rule("D1", s, program, log, failed, () -> s.seedDs());
            rule("D3", s, program, log, failed, () -> parts.add(applyCsDefault(program, s)));
            WSJumpTables jj = j;
            rule("A1", s, program, log, failed, () -> s.classifyArtefacts(jj != null ? jj.keptTargets : java.util.Set.of()));
            if (convention) rule("C1", s, program, log, failed, () -> parts.add(applyConvention(program, line -> s.emit("%s", line))));
            java.util.Set<ghidra.program.model.address.Address> ivt =
                cp == null ? java.util.Set.of() : cp.ivtHandlers;
            rule("R1", s, program, log, failed, () -> {
                WSReturns r = new WSReturns(program, line -> s.emit("%s", line), monitor);
                r.apply();
                parts.add(r.summary());
            });
            rule("V1", s, program, log, failed, () -> {
                WSVolatile v = new WSVolatile(program, ev, ivt, line -> s.emit("%s", line), monitor);
                v.apply();
                parts.add(v.summary());
            });
            String sum = NAME + ": " + s.summary() + (parts.isEmpty() ? "" : ", " + String.join(", ", parts))
                + (failed.isEmpty() ? "" : "; RULES FAILED: " + failed);
            log.appendMsg(sum);
            s.emit("{\"rule\":\"phase2\",\"summary\":\"%s\"}", sum.replace("\\", "/").replace("\"", "'"));
        }
        catch (CancelledException c) { throw c; }
        catch (Exception e) {
            Msg.error(this, NAME + ": could not start phase 2: " + e, e);
            log.appendException(e);
        }
        return true;
    }

    interface Rule { void run() throws Exception; }

    private void rule(String name, WSEvidenceAnalyzer.Seeder s, Program program, MessageLog log, List<String> failed, Rule r)
            throws CancelledException {
        try { r.run(); }
        catch (CancelledException c) { throw c; }
        catch (Exception e) {
            failed.add(name);
            Msg.error(this, NAME + ": rule " + name + " failed: " + e, e);
            log.appendMsg(NAME + ": rule " + name + " failed: " + e);
            s.emit("{\"rule\":\"%s\",\"outcome\":\"ERROR\",\"error\":\"%s\"}", name, String.valueOf(e).replace("\\", "/").replace("\"", "'"));
            program.getBookmarkManager().setBookmark(program.getMinAddress(), BookmarkType.ERROR, "WSEvidence",
                "phase-2 rule " + name + " failed: " + e);
        }
    }

    /** P1: a function whose entry has no bytes (an uninitialised block such as an empty bank window, or no
     *  memory at all) cannot be code we know; it was created from a reference into nothing (e.g. an
     *  unexecuted CALLF decode into an empty bank window). Removed, reported with the creating references, and each
     *  referencing site bookmarked; the references themselves are kept (they are what the bytes say). */
    static String removePhantoms(Program program, WSEvidenceAnalyzer.Seeder s) throws Exception {
        List<Function> phantoms = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            if (WSRamCode.isRam(program, f.getEntryPoint())) continue;
            ghidra.program.model.mem.MemoryBlock b = program.getMemory().getBlock(f.getEntryPoint());
            if (b == null || !b.isInitialized()) phantoms.add(f);
        }
        for (Function f : phantoms) {
            StringBuilder refs = new StringBuilder();
            for (ghidra.program.model.symbol.Reference r : program.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                refs.append(refs.length() > 0 ? "," : "").append('"').append(r.getFromAddress()).append('"');
                program.getBookmarkManager().setBookmark(r.getFromAddress(), ghidra.program.model.listing.BookmarkType.WARNING, "WSEvidence",
                    "P1 PHANTOM_TARGET: " + f.getEntryPoint() + " has no bytes; function removed");
            }
            s.emit("{\"rule\":\"P1\",\"function\":\"%s\",\"outcome\":\"PHANTOM_REMOVED\",\"refs_from\":[%s]}", f.getEntryPoint(), refs);
            program.getFunctionManager().removeFunction(f.getEntryPoint());
        }
        return "P1 phantom functions removed " + phantoms.size();
    }

    /** D0 ({@link WSCompilerRules}): the resolved DS/SS defaults are always applied, because the
     *  loader only stamps LIN_* blocks and the bank overlays would otherwise keep UNSET context. */
    static String applyDsDefault(Program program, WSEvidence ev, WSEvidenceAnalyzer.Seeder s) throws Exception {
        int v = WSCompilerRules.dominantDs(ev);
        int sv = WSCompilerRules.dominantSs(ev);
        int blocks = WSCompilerRules.applyDsDefault(program, v < 0 ? 0 : v);
        WSCompilerRules.applySsDefault(program, sv < 0 ? 0 : sv);
        s.emit("{\"rule\":\"D0\",\"ds_default\":\"%04x\",\"share\":%.3f,\"ss_default\":\"%04x\",\"ss_share\":%.3f,\"blocks\":%d,\"outcome\":\"%s\",\"ss_outcome\":\"%s\"}",
            v < 0 ? 0 : v, v < 0 ? WSCompilerRules.share(ev, 0) : WSCompilerRules.share(ev, v),
            sv < 0 ? 0 : sv, sv < 0 ? WSCompilerRules.shareSs(ev, 0) : WSCompilerRules.shareSs(ev, sv),
            blocks, v < 0 ? "KEPT" : "SET", sv < 0 ? "KEPT" : "SET");
        return String.format("D0 DS default %04X (%.0f%% of single-DS executed addresses), SS default %04X (%.0f%% single-SS)",
            v < 0 ? 0 : v, 100 * (v < 0 ? WSCompilerRules.share(ev, 0) : WSCompilerRules.share(ev, v)),
            sv < 0 ? 0 : sv, 100 * (sv < 0 ? WSCompilerRules.shareSs(ev, 0) : WSCompilerRules.shareSs(ev, sv)));
    }

    static String applyCsDefault(Program program, WSEvidenceAnalyzer.Seeder s) throws Exception {
        int[] n = WSCompilerRules.applyCsDefault(program);
        s.emit("{\"rule\":\"D3\",\"register\":\"CS\",\"spans\":%d,\"blocks\":%d,\"outcome\":\"SET\"}", n[0], n[1]);
        return String.format("D3 CS default %d spans over %d blocks", n[0], n[1]);
    }

    /** C1, convention chosen by rule K1 ({@link WSCompilerRules}): LSI C-86 register convention or the cspec default. */
    static String applyConvention(Program program, java.util.function.Consumer<String> emit) throws Exception {
        PrototypeModel def = program.getCompilerSpec().getDefaultCallingConvention();
        if (def == null) return "C1 no default convention";
        WSCompilerRules k = WSCompilerRules.measure(program);
        boolean lsi = k.lsi() && program.getCompilerSpec().getCallingConvention("__lsic86") != null;
        String cc = lsi ? "__lsic86" : def.getName();
        emit.accept(String.format("{\"rule\":\"K1\",\"family\":\"%s\",\"evidence\":\"%s\"}", lsi ? "LSI C-86" : "default", k.evidence()));
        int set = 0, kept = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            SourceType src = f.getSignatureSource();
            if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED) { kept++; continue; }
            if (!cc.equals(f.getCallingConventionName())) { f.setCallingConvention(cc); set++; }
        }
        emit.accept(String.format("{\"rule\":\"C1\",\"convention\":\"%s\",\"set\":%d,\"kept_user_or_imported\":%d}", cc, set, kept));
        return "C1 " + cc + " set on " + set + " functions (kept " + kept + ")";
    }
}
