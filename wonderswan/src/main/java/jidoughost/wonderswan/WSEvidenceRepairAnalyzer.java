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
 *   N1  clear "does not return" where a call's fall-through executed, restore the cut-off code (a J4 saved-yield
 *       helper is kept: its caller's next instruction runs through the saved continuation, not by return);
 *   E1R re-seed executed addresses that later analysis removed;
 *   J1  CS-relative jump/call tables by rule ({@link WSJumpTables}), checked against observed targets;
 *   D1  DS/SS context at function entries; A1 preserve and tag unresolved decode hypotheses;
 *   P1  preserve functions without a current memory image and record the unresolved hypothesis;
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
            + WSEvidenceAnalyzer.NAME + "': non-returning functions, lost executed code, DS at entries, decode hypotheses.",
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
            rule("J3", s, program, log, failed, () -> parts.add(WSInlineTables.apply(program, line -> s.emit("%s", line), monitor)));
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
            rule("Z1", s, program, log, failed, () -> parts.add(WSFillRuns.apply(program, ev, line -> s.emit("%s", line), monitor)));
            rule("A2", s, program, log, failed, () -> parts.add(WSDecodeRepair.boundaries(program, line -> s.emit("%s", line), monitor)));
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

    private static String quote(String text) {
        if (text == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }

    private static String address(ghidra.program.model.address.Address at) {
        return at == null ? "null" : "{\"space\":" + quote(at.getAddressSpace().getName())
            + ",\"address\":" + quote(at.toString()) + "}";
    }

    /** P1: an absent image leaves the existing function unresolved, with all original state intact. */
    static String removePhantoms(Program program, WSEvidenceAnalyzer.Seeder s) throws Exception {
        int preserved = 0;
        // The function iterator omits entries outside mapped memory; their symbols still exist.
        var symbols = program.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getSymbolType() != ghidra.program.model.symbol.SymbolType.FUNCTION
                || !(symbol.getObject() instanceof Function f)) continue;
            s.monitor.checkCancelled();
            if (f.isExternal() || f.isThunk() || WSRamCode.isRam(program, f.getEntryPoint())) continue;
            var entry = f.getEntryPoint();
            var block = program.getMemory().getBlock(entry);
            if (block != null && block.isInitialized()) continue;
            List<String> refs = new ArrayList<>();
            var destinations = program.getReferenceManager().getReferenceDestinationIterator(f.getBody(), true);
            while (destinations.hasNext()) {
                for (var ref : program.getReferenceManager().getReferencesTo(destinations.next())) {
                    var from = ref.getFromAddress();
                    var instruction = program.getListing().getInstructionContaining(from);
                    List<String> context = new ArrayList<>();
                    for (String name : new String[]{"csval", "CS", "DS", "SS"}) {
                        var reg = program.getRegister(name);
                        if (reg != null) context.add(quote(name) + ":" + quote(String.valueOf(
                            program.getProgramContext().getRegisterValue(reg, from))));
                    }
                    refs.add("{\"from\":" + address(from) + ",\"to\":" + address(ref.getToAddress())
                        + ",\"type\":" + quote(ref.getReferenceType().toString())
                        + ",\"source\":" + quote(ref.getSource().toString())
                        + ",\"operand\":" + ref.getOperandIndex() + ",\"primary\":" + ref.isPrimary()
                        + ",\"instruction_start\":" + address(instruction == null ? null : instruction.getAddress())
                        + ",\"instruction\":" + quote(instruction == null ? null : instruction.toString())
                        + ",\"instruction_bytes\":" + quote(instruction == null ? null : HexFormat.of().formatHex(instruction.getBytes()))
                        + ",\"context\":{" + String.join(",", context) + "}}");
                }
            }
            Collections.sort(refs);
            String detail = "{\"rule\":\"P1\",\"outcome\":\"UNKNOWN_UNIMAGED_FUNCTION_PRESERVED\","
                + "\"reason\":\"MISSING_CURRENT_IMAGE_IS_NOT_EXCLUSIVE_INVALIDITY_EVIDENCE\",\"entry\":" + address(entry)
                + ",\"symbol_id\":" + f.getSymbol().getID() + ",\"name\":" + quote(f.getName(true))
                + ",\"symbol_source\":" + quote(f.getSymbol().getSource().toString())
                + ",\"signature_source\":" + quote(f.getSignatureSource().toString())
                + ",\"signature\":" + quote(f.getPrototypeString(true, true)) + ",\"body\":" + quote(f.getBody().toString())
                + ",\"block\":" + quote(block == null ? null : block.getName())
                + ",\"block_start\":" + address(block == null ? null : block.getStart())
                + ",\"overlay\":" + (block == null ? "null" : block.isOverlay())
                + ",\"image_state\":" + quote(block == null ? "ABSENT_BLOCK" : "UNINITIALIZED")
                + ",\"target_bytes_sha256\":null,\"evidence_source\":" + quote(s.ev.provenance)
                + ",\"observed_cs\":" + s.ev.cs.get(entry.getOffset())
                + ",\"incoming_references\":[" + String.join(",", refs) + "]}";
            String hash = HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(detail.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            var bm = program.getBookmarkManager();
            for (int suffix = 0; ; suffix++) {
                String category = "WSP1Hypothesis:" + hash + (suffix == 0 ? "" : ":" + suffix);
                var old = bm.getBookmark(entry, BookmarkType.ANALYSIS, category);
                if (old == null) { bm.setBookmark(entry, BookmarkType.ANALYSIS, category, detail); break; }
                if (detail.equals(old.getComment())) break;
            }
            s.emit("%s", detail);
            preserved++;
        }
        return "P1 unimaged function hypotheses preserved " + preserved;
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
        s.emit("{\"rule\":\"D3\",\"register\":\"CS\",\"spans\":%d,\"blocks\":%d,\"outcome\":\"KEPT\",\"why\":\"DISPLAY_IS_NOT_ARCHITECTURAL_CS\"}", n[0], n[1]);
        return "D3 CS context kept; address display supplies no architectural evidence";
    }

    /** C1, convention chosen by rule K1 ({@link WSCompilerRules}): LSI C-86 register convention or the cspec default. */
    static String applyConvention(Program program, java.util.function.Consumer<String> emit) throws Exception {
        PrototypeModel def = program.getCompilerSpec().getDefaultCallingConvention();
        if (def == null) return "C1 no default convention";
        WSCompilerRules k = WSCompilerRules.measure(program);
        boolean lsi = k.lsi() && program.getCompilerSpec().getCallingConvention("__lsic86") != null;
        String cc = lsi ? "__lsic86" : def.getName();
        emit.accept(String.format("{\"rule\":\"K1\",\"family\":\"%s\",\"evidence\":\"%s\"}", lsi ? "LSI C-86" : "default", k.evidence()));
        int set = 0, kept = 0, specialized = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            SourceType src = f.getSignatureSource();
            if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED) { kept++; continue; }
            if (WSLsiLiveThrough.apply(f, cc, emit)) { specialized++; continue; }
            if (WSAsmAxLiveThrough.reconcileConvention(f, cc, emit)) { specialized++; continue; }
            if (WSAsmBxLiveThrough.reconcileConvention(f, cc, emit)) { specialized++; continue; }
            if (!cc.equals(f.getCallingConventionName())) { f.setCallingConvention(cc); set++; }
        }
        emit.accept(String.format("{\"rule\":\"C1\",\"convention\":\"%s\",\"set\":%d,\"kept_user_or_imported\":%d,\"specialized\":%d}", cc, set, kept, specialized));
        return "C1 " + cc + " set on " + set + " functions (kept " + kept + ")";
    }
}
