// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Seeds analysis with execution evidence (WSMachine run in-process, or WSEmulate outputs) and classifies
 * the decode artefacts that disassembly produces when it follows never-taken paths into data.
 *
 * Rules (every decision is evidence-backed and can be written to a JSON-lines report):
 *   C0  before any flow, undecoded ROM bytes (linear blocks and executable bank overlays) get a default code
 *       segment ({@link WSCodeContext}); existing instructions and stored segment observations are kept.
 *   E0b a computed JMP/CALL resolves to the next instruction in its own interrupt context: edges
 *       pre-empted by an interrupt are carried across the handler flow (WSMachine) and recorded at
 *       the post-IRET instruction, never inside the handler.
 *   B3  a direct call/jump into a window (no bytes there) whose target executed under exactly one bank is
 *       resolved to that bank's overlay (and disassembled there): calls get a call-override reference the
 *       decompiler follows; jumps get a data reference (a cross-space jump override is un-followable and
 *       fails every decompile it reaches). Targets that ran under several banks or never ran are reported.
 *   E1  an executed linear address is an instruction start: csval = the CS observed there; disassemble.
 *       Executed RAM is H1 instead (no image).
 *   H1  executed work RAM is never decoded (load-time bytes are loader zero-fill, not the ran code):
 *       each run is bookmarked ("RAM code, no image yet") and reported, nothing is disassembled there.
 *   H2  RAM/SRAM code decoded anyway, with no captured image, is an unresolved hypothesis ({@link WSRamCode}):
 *       kept, bookmarked and tagged "ram-code: unknown, no evidence"; artefact cleanup never clears it.
 *   E2  a call / int / irq edge target is a function entry (RAM and last-overlay-byte targets excluded).
 *   E3  a computed JMP site gets COMPUTED_JUMP references to every observed target, and a JumpTable
 *       override listing them (observed targets only; a static table rule may add more later).
 *   D1  a function entry where only one non-zero DS (SS) value was observed gets that DS (SS) as context.
 *   B2  ROM0/ROM1 window code: for every (window, bank) the evidence executed in (rule B1, WSMachine), an
 *       overlay block of that ROM bank is created over the window, and E1/E2/E3 seed into it. A window
 *       address that executed under several banks is seeded in each of them.
 *   S1  a code seed file (TSV: address, class, method, start, start_kind, ...; e.g. a save-RAM byte search) is
 *       evidence input: class function, or code-strong with start_kind prologue / after-terminator, seeds a function at
 *       its start column (not inside an existing function); other code-strong, executed* and code seeds are
 *       instruction starts; csval = the seed's segment. Other classes (e.g. code-weak) and seeds
 *       that conflict with existing decode are reported, not applied.
 *   A1  a bad decode (ERROR bookmark) reached by fall-through from unexecuted instructions: the maximal
 *       unexecuted fall-through run ending at it is a data artefact. Its decode is cleared (bytes kept),
 *       a "WSEvidence" bookmark records the evidence. Executed instructions are never cleared.
 *
 * <p>Mesen 2 evidence (option "Mesen trace directory or CDL file", off by default) merges into the
 * same rules: executed addresses seed E1 (CS from the trace, else WSMachine, else the bank-aligned
 * guess), trace transfers resolve into E2/E3 edges, observed window banks seed B2 overlays, and the
 * merged edges feed J1's observed-target checks. Rule "mesen" report lines record what it contributed.
 */
public class WSEvidenceAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "WonderSwan Execution Evidence";
    private static final String OPT_RUN = "Run WSMachine";
    private static final String OPT_FRAMES = "Frames";
    private static final String OPT_SLICE = "Instructions per frame";
    private static final String OPT_DIR = "Evidence directory (WSEmulate output; overrides running)";
    private static final String OPT_REPORT = "Evidence report file (JSON lines; empty = none)";
    private static final String OPT_ARTEFACTS = "Classify decode artefacts (rule A1)";
    private static final String OPT_SEEDS = "Code seed file (TSV, rule S1; empty = none)";
    private static final String OPT_MESEN = "Mesen trace directory or CDL file (empty = none)";

    /** Evidence collected in phase 1, reused by {@link WSEvidenceRepairAnalyzer} (phase 2). */
    static final Map<Program, WSEvidence> EVIDENCE = Collections.synchronizedMap(new WeakHashMap<>());
    static final Map<Program, String> REPORT = Collections.synchronizedMap(new WeakHashMap<>());

    private boolean run = true, artefacts = true;
    private int frames = 1500, slice = 15000;
    private String dir = "", report = "", seeds = "", mesen = "";

    public WSEvidenceAnalyzer() {
        super(NAME, "Seeds code discovery from emulator execution evidence (executed code, indirect "
            + "targets, interrupt entries, DS at entries) and classifies decode artefacts.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().toString().equals("V30MZ")
            && !program.getMemory().getAllFileBytes().isEmpty()
            && program.getOptions(WonderSwanLoader.OPTIONS_CATEGORY).contains("Color");
    }

    @Override
    public void registerOptions(Options o, Program program) {
        o.registerOption(OPT_RUN, run, null, "Run the WSMachine emulator in-process to collect evidence");
        o.registerOption(OPT_FRAMES, frames, null, "Frames to emulate (scripted Start/A input)");
        o.registerOption(OPT_SLICE, slice, null, "Instructions per frame (Mesen-measured rates are ~12000-15000)");
        o.registerOption(OPT_DIR, dir, null, "Load coverage.json + edges.tsv from this directory instead of running");
        o.registerOption(OPT_REPORT, report, null, "Write one JSON line per decision to this file");
        o.registerOption(OPT_ARTEFACTS, artefacts, null, "Clear unexecuted fall-through runs that decode into a bad instruction");
        o.registerOption(OPT_SEEDS, seeds, null, "Seed code from this TSV (address, class, method, start, ...): code-strong/function -> function at start, executed*/code -> instruction start");
        o.registerOption(OPT_MESEN, mesen, null, "Merge Mesen 2 execution evidence (trace.tsv + coverage.tsv directory, or a .cdl file) into the same rules");
    }

    @Override
    public void optionsChanged(Options o, Program program) {
        run = o.getBoolean(OPT_RUN, run);
        frames = o.getInt(OPT_FRAMES, frames);
        slice = o.getInt(OPT_SLICE, slice);
        dir = o.getString(OPT_DIR, dir);
        report = o.getString(OPT_REPORT, report);
        artefacts = o.getBoolean(OPT_ARTEFACTS, artefacts);
        seeds = o.getString(OPT_SEEDS, seeds);
        mesen = o.getString(OPT_MESEN, mesen);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        WSEvidence wsmEv = null;
        try {
            if (dir != null && !dir.isBlank()) wsmEv = WSEvidence.load(Paths.get(dir));
            else if (run) {
                monitor.setMessage("WonderSwan: emulating " + frames + " frames");
                boolean color = program.getOptions(WonderSwanLoader.OPTIONS_CATEGORY).getBoolean("Color", true);
                WSMachine m = new WSMachine(program, color);
                try {
                    m.run(frames, slice, f -> {
                        int ph = f % 40;
                        m.buttons = (f >= 100 && ph < 3) ? 0x02 : (f >= 100 && ph >= 20 && ph < 23) ? 0x04 : 0;
                    });
                    wsmEv = WSEvidence.of(m);
                }
                catch (Exception e) {
                    // Rule E4: a run that fails part-way is still evidence up to the failure. Keep it, minus the
                    // untrusted tail that led into the error; report the failure loudly (not silent).
                    Set<Long> tail = m.untrustedTail();
                    wsmEv = WSEvidence.of(m, tail);
                    String msg = NAME + ": emulation ended in an error after " + m.instructions + " instructions (" + e
                        + "); rule E4 keeps the evidence before it (" + wsmEv.ds.size() + " executed addresses, "
                        + tail.size() + " tail addresses dropped)";
                    log.appendMsg(msg);
                    ghidra.util.Msg.error(this, msg, e);
                    program.getBookmarkManager().setBookmark(program.getMinAddress(), BookmarkType.ERROR, "WSEvidence", msg);
                }
            }
        }
        catch (Exception e) {
            // not silent: headless does not print the analysis MessageLog
            String msg = NAME + ": no evidence (" + e + "); nothing seeded, evidence rules skipped";
            log.appendMsg(msg);
            ghidra.util.Msg.error(this, msg, e);
            program.getBookmarkManager().setBookmark(program.getMinAddress(), BookmarkType.ERROR, "WSEvidence", msg);
            return false;
        }
        WSEvidence ev = wsmEv;
        if (mesen != null && !mesen.isBlank()) {
            try {
                WSEvidence mEv = loadMesenEvidence(Paths.get(mesen), program, wsmEv == null ? null : wsmEv.cs);
                if (!mEv.mesenStats.cdlCrcMatch())
                    log.appendMsg(NAME + ": Mesen CDL CRC does not match this ROM; its bytes are mapped anyway, check the ROM revision");
                ev = wsmEv == null ? mEv : WSEvidence.merge(mEv, wsmEv);
            }
            catch (Exception e) {
                if (wsmEv == null) {
                    String msg = NAME + ": no evidence (" + e + "); nothing seeded, evidence rules skipped";
                    log.appendMsg(msg);
                    ghidra.util.Msg.error(this, msg, e);
                    program.getBookmarkManager().setBookmark(program.getMinAddress(), BookmarkType.ERROR, "WSEvidence", msg);
                    return false;
                }
                String msg = NAME + ": Mesen evidence ignored (" + e + "); continuing with WSMachine evidence";
                log.appendMsg(msg);
                ghidra.util.Msg.warn(this, msg);
            }
        }
        if (ev == null) return false;
        EVIDENCE.put(program, ev);
        REPORT.put(program, report == null ? "" : report);
        try (Seeder s = new Seeder(program, ev, report, false, monitor, log)) {
            WSFillRuns.restoreExecuted(program, ev, line -> s.emit("%s", line));
            s.seed();
            if (seeds != null && !seeds.isBlank()) s.seedFile(Paths.get(seeds));
            log.appendMsg(NAME + " (phase 1): " + s.summary()
                + (ev.mesenStats != null ? "; " + s.mesenSummary() : ""));
        }
        catch (CancelledException c) { throw c; }
        catch (Exception e) { log.appendException(e); ghidra.util.Msg.error(this, NAME + " (phase 1) failed: " + e, e); }
        return true;
    }

    /**
     * Load Mesen 2 evidence for a program: {@code path} is a trace directory (trace.tsv +
     * coverage.tsv, plus a CDL when exactly one is present), a lone .tsv's directory, or a .cdl
     * file. {@code wsmCs} (nullable) is WSMachine coverage CS evidence used where the trace has no
     * CS for an address.
     */
    public static WSEvidence loadMesenEvidence(Path path, Program program, Map<Long, Integer> wsmCs) throws Exception {
        WSMesenTrace.Resolved r = WSMesenTrace.resolve(path);
        WSMesenTrace.TraceData trace = r.trace() == null ? null : WSMesenTrace.parseTrace(r.trace());
        WSMesenTrace.CovData cov = r.coverage() == null ? null : WSMesenTrace.parseCoverage(r.coverage());
        List<ghidra.program.database.mem.FileBytes> fbs = program.getMemory().getAllFileBytes();
        if (fbs.isEmpty()) throw new IllegalStateException("program has no stored ROM bytes (import with the WonderSwan loader)");
        long romLen = fbs.get(0).getSize();
        byte[] rom = new byte[(int) romLen];
        fbs.get(0).getOriginalBytes(0, rom);
        WSMesenTrace.CdlData cdl = r.cdl() == null ? null : WSMesenTrace.parseCdl(r.cdl(), romLen);
        return WSEvidence.fromMesen(trace, cov, cdl, path.toString(), romLen, wsmCs, WSMesenTrace.crc32(rom));
    }

    /**
     * Apply the phase-1 evidence rules (E1/E2/E3, B2/B3) to a program: the headless import path
     * used by {@code WSImportTrace}. Returns the seeding summary.
     */
    public static String applyEvidence(Program program, WSEvidence ev, String report, TaskMonitor monitor) throws Exception {
        try (Seeder s = new Seeder(program, ev, report == null ? "" : report, false, monitor, new MessageLog())) {
            WSFillRuns.restoreExecuted(program, ev, line -> s.emit("%s", line));
            s.seed();
            String sum = s.summary();
            if (ev.mesenStats != null) sum += "; " + s.mesenSummary();
            return sum;
        }
    }

    /** Run the repair rules after imported evidence has been followed by ordinary analysis. */
    public static void repairEvidence(Program program, WSEvidence ev, String report, TaskMonitor monitor) throws Exception {
        try (Seeder s = new Seeder(program, ev, report == null ? "" : report, true, monitor, new MessageLog())) {
            s.seedExecuted("E1R");
            s.resolveWindowFlows();
            WSJumpTables tables = new WSJumpTables(program, ev, line -> s.emit("%s", line));
            tables.apply(monitor);
            tables.restoreClearedSites(monitor);
            tables.finish();
            WSDecodeRepair.align(program, ev, line -> s.emit("%s", line), monitor);
            s.classifyArtefacts(tables.keptTargets);
            WSExecutedFunctions functions = new WSExecutedFunctions(program, ev, line -> s.emit("%s", line), monitor);
            functions.apply();
            WSRomEvidence.classifyUnmappedWindows(program, ev, line -> s.emit("%s", line));
            WSFillRuns.apply(program, ev, line -> s.emit("%s", line), monitor);
            // Fencing a body can expose played code to E5. Settle those existing
            // repairs before save, rather than creating its functions on re-import.
            String boundaries;
            int previousFunctions;
            do {
                previousFunctions = program.getFunctionManager().getFunctionCount();
                boundaries = WSDecodeRepair.boundaries(program, line -> s.emit("%s", line), monitor);
                functions.apply();
            } while (program.getFunctionManager().getFunctionCount() != previousFunctions);
            s.emit("{\"rule\":\"import-repair\",\"summary\":\"%s; %s; %s\"}", tables.summary(), functions.summary(),
                boundaries);
        }
    }

    /** Applies the rules to one program. */
    static final class Seeder implements AutoCloseable {
        final Program p;
        final WSEvidence ev;
        final TaskMonitor monitor;
        final MessageLog log;
        final SegmentedAddressSpace space;
        final ProgramContext ctx;
        final Register csval, rDS, rSS, colorsoc;
        final boolean colorHw;
        final PrintWriter out;
        int e1, e1skip, e2, e2conflict, e3, e3t, d1, d1ss, a1runs, a1insns, n1, n1sites, b2, b2ambiguous, b3, b3multi, b3unobserved, b3conflict, b3jump, h1runs;
        /** Mesen-sourced edges (resolved trace transfers, CDL sub-entries), by identity. */
        final Set<WSEvidence.Edge> mesenEdges = Collections.newSetFromMap(new IdentityHashMap<>());
        int e1already, e1alreadyM, e1m, e2m, e3m, e3tm, xferFall, xferIrq, xferCall, xferJump, xferInt, xferDrop, xferNoSrc;

        Seeder(Program p, WSEvidence ev, String report, boolean append, TaskMonitor monitor, MessageLog log) throws Exception {
            this.p = p; this.ev = ev; this.monitor = monitor; this.log = log;
            space = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
            ctx = p.getProgramContext();
            csval = ctx.getRegister("csval");
            rDS = ctx.getRegister("DS");
            rSS = ctx.getRegister("SS");
            colorsoc = ctx.getRegister("colorsoc");
            colorHw = p.getOptions(WonderSwanLoader.OPTIONS_CATEGORY).getBoolean("Color", false);
            out = report == null || report.isBlank() ? null : new PrintWriter(append
                ? Files.newBufferedWriter(Paths.get(report), java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)
                : Files.newBufferedWriter(Paths.get(report)));
            emit("{\"rule\":\"provenance\",\"evidence\":\"%s\",\"executed\":%d,\"edges\":%d}", ev.provenance.replace("\"", "'"), ev.cs.size(), ev.edges.size());
        }

        void emit(String fmt, Object... args) { if (out != null) out.println(String.format(fmt, args)); }

        Address at(long linear, int cs) {
            return space.getAddress(cs, (int) ((linear - ((long) cs << 4)) & 0xFFFF));
        }

        /** Program addresses for an executed linear address: the bank overlays for window code (B2), else seg:off. */
        List<Address> addrs(long linear, int cs) throws Exception {
            Set<Integer> banks = linear >= 0x20000 && linear < 0x40000 ? ev.windowBanks.get(linear) : null;
            if (banks == null || banks.isEmpty()) return List.of(at(linear, cs));
            List<Address> out = new ArrayList<>();
            for (int bank : banks) {
                MemoryBlock b = overlay(linear < 0x30000 ? WSHardware.SEG_ROM0 : WSHardware.SEG_ROM1, bank);
                if (b != null) out.add(b.getStart().add(linear & 0xFFFF));
            }
            return out;
        }

        /** B2: overlay block of one ROM bank over a window, created on first use. */
        MemoryBlock overlay(int seg, int bank) throws Exception {
            String name = WSRomWindows.name(seg, bank);
            boolean existed = p.getMemory().getBlock(name) != null;
            MemoryBlock b = WSRomWindows.view(p, seg, bank, true, monitor);
            if (b != null && !existed) {
                b2++;
                emit("{\"rule\":\"B2\",\"overlay\":\"%s\",\"window\":\"%04x\",\"bank\":\"%04x\"}", name, seg, bank);
            }
            return b;
        }

        /** Instruction containing an observed edge source (window sources: each bank overlay it executed under). */
        List<Instruction> sites(long from) throws Exception {
            List<Instruction> out = new ArrayList<>();
            for (Address a : addrs(from, ev.cs.getOrDefault(from, (int) (from >> 4) & 0xF000))) {
                Instruction i = p.getListing().getInstructionContaining(a);
                if (i != null) out.add(i);
            }
            return out;
        }

        /** Decode context for code the machine executed at a: the observed CS, and the SoC it ran on. */
        void setCodeContext(Address a, int cs) throws Exception {
            ctx.setValue(csval, a, a, BigInteger.valueOf(cs));
            if (colorsoc != null && colorHw) ctx.setValue(colorsoc, a, a, BigInteger.ONE);
        }

        /** setCodeContext that reports a conflict with an existing decode instead of throwing (false = not set). */
        boolean trySetCodeContext(Address a, int cs) throws Exception {
            try { setCodeContext(a, cs); return true; }
            catch (ContextChangeException e) { return false; }
        }

        boolean inProgram(Address a) { return p.getMemory().contains(a) && p.getMemory().getBlock(a).isInitialized(); }

        /** H1: an address in work RAM, whose load-time bytes (loader zero-fill) are never code. */
        boolean isRamNoImage(Address a) {
            MemoryBlock b = p.getMemory().getBlock(a);
            return b != null && !b.isOverlay() && b.getName().equals("RAM");
        }

        /** J1o: the last byte of a bank overlay: no case entry can live there (any instruction either
         *  overruns the block or falls out of its address space, which the decompiler cannot follow). */
        boolean isOverlayEnd(Address a) {
            MemoryBlock b = p.getMemory().getBlock(a);
            return b != null && b.isOverlay() && a.getOffset() == b.getEnd().getOffset();
        }

        void seed() throws Exception {
            WSRomWindows.mapAll(p, monitor);
            WSRomEvidence.prepare(p, ev, line -> emit("%s", line), monitor);
            int defaults = WSCodeContext.seedRomDefaults(p);
            emit("{\"rule\":\"C0\",\"rom_context_spans\":%d}", defaults);
            if (ev.e0bKnown)
                emit("{\"rule\":\"E0b\",\"carried\":%d,\"resumed\":%d,\"max_depth\":%d}", ev.e0bCarried, ev.e0bResumed, ev.e0bMaxDepth);
            seedExecuted("E1");
            seedEdges();
            resolveWindowFlows();
            WSRomEvidence.seedWindows(p, ev, line -> emit("%s", line), monitor);
            if (ev.mesenStats != null) emitMesen();
        }

        boolean isMesen(long linear) {
            return ev.mesenStats != null && ev.mesenStats.linears().contains(linear);
        }

        /** Mesen contribution report (rule "mesen" lines) after the shared rules ran. */
        void emitMesen() {
            WSEvidence.MesenStats m = ev.mesenStats;
            emit("{\"rule\":\"mesen\",\"source\":\"%s\",\"trace_steps\":%d,\"coverage_addrs\":%d,"
                + "\"cs_from_trace\":%d,\"cs_from_wsm\":%d,\"cs_guessed\":%d,"
                + "\"c0_skipped\":%d,\"multi_c0\":%d,\"window_no_bank\":%d,\"window_banked\":%d,"
                + "\"sram\":%d,\"ram\":%d,\"transfers\":%d,\"cdl_code\":%d,\"cdl_data\":%d,"
                + "\"cdl_jump_targets\":%d,\"cdl_sub_entries\":%d,\"cdl_seeded_new\":%d,"
                + "\"cdl_mirror_ambiguous\":%d,\"cdl_window_only\":%d,\"cdl_not_seeded\":%d,\"cdl_crc\":\"%s\",\"cdl_headerless\":%b,\"cdl_crc_match\":%b}",
                m.source().replace("\"", "'"), m.traceSteps(), m.coverageAddrs(),
                m.csFromTrace(), m.csFromWsm(), m.csGuessed(), m.c0Skipped(), m.multiC0(),
                m.windowNoBank(), m.windowBanked(), m.sramAddrs(), m.ramAddrs(), m.transfers(),
                m.cdlCode(), m.cdlData(), m.cdlJumpTargets(), m.cdlSubEntries(), m.cdlSeededNew(),
                m.cdlAmbiguousMirror(), m.cdlWindowOnly(), m.cdlNotSeeded(),
                m.cdlCode() + m.cdlData() == 0 ? "none" : String.format("%08x", m.cdlCrcStored()),
                m.cdlHeaderless(), m.cdlCrcMatch());
            emit("{\"rule\":\"mesen\",\"e1_seeded\":%d,\"e1_already\":%d,\"e2\":%d,\"e3\":%d,\"e3_targets\":%d,"
                + "\"xfer_fallthrough\":%d,\"xfer_call\":%d,\"xfer_jump\":%d,\"xfer_int\":%d,\"xfer_irq\":%d,"
                + "\"xfer_dropped\":%d,\"xfer_no_source\":%d}",
                e1m, e1alreadyM, e2m, e3m, e3tm, xferFall, xferCall, xferJump, xferInt, xferIrq, xferDrop, xferNoSrc);
        }

        String mesenSummary() {
            WSEvidence.MesenStats m = ev.mesenStats;
            return String.format("Mesen %s: E1 seeded %d (already %d), E2 functions %d, E3 sites %d (%d targets), "
                + "transfers %d (fallthrough %d, call %d, jump %d, int %d, irq %d, dropped %d, no source %d), "
                + "window-banked %d (no bank %d), C0-skipped %d, CDL new code %d",
                m.source(), e1m, e1alreadyM, e2m, e3m, e3tm, m.transfers(),
                xferFall, xferCall, xferJump, xferInt, xferIrq, xferDrop, xferNoSrc,
                m.windowBanked(), m.windowNoBank(), m.c0Skipped(), m.cdlSeededNew());
        }

        int s1fn, s1code, s1skip;

        /** S1: code seeds from a TSV file (see the class comment). */
        void seedFile(Path file) throws Exception {
            Listing listing = p.getListing();
            for (String line : Files.readAllLines(file)) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] f = line.split("\t");
                String cls = f.length > 1 ? f[1] : "";
                String startKind = f.length > 4 ? f[4] : "-";
                // a function only where the seed file gives function-start evidence (a prologue, or the first byte after a
                // terminator); an "aligned" hit is an instruction start inside some routine, not an entry
                boolean fn = cls.equals("function") || cls.equals("code-strong") && (startKind.equals("prologue") || startKind.equals("after-terminator"));
                boolean code = fn || cls.equals("code-strong") || cls.startsWith("executed") || cls.equals("code");
                String where = fn && f.length > 3 && !f[3].equals("-") ? f[3] : f[0];
                Address a = p.getAddressFactory().getAddress(where);
                String outcome;
                if (!fn && !code) outcome = "SKIPPED_CLASS";
                else if (!(a instanceof SegmentedAddress sa) || !inProgram(a)) outcome = "NOT_IN_PROGRAM";
                else if (isRamNoImage(a)) outcome = "RAM_NO_IMAGE";   // H1: seed files cannot image RAM either
                else if (listing.getInstructionAt(a) == null && listing.getInstructionContaining(a) != null) outcome = "CONFLICT_EXISTING_DECODE";
                else {
                    if (listing.getInstructionAt(a) == null) {
                        setCodeContext(a, sa.getSegment());
                        new DisassembleCommand(a, null, true).applyTo(p, monitor);
                    }
                    if (listing.getInstructionAt(a) == null) outcome = "UNDECODABLE";
                    else if (fn && p.getFunctionManager().getFunctionContaining(a) != null && p.getFunctionManager().getFunctionAt(a) == null) outcome = "CODE_INSIDE_FUNCTION";
                    else if (fn && p.getFunctionManager().getFunctionAt(a) == null) {
                        new CreateFunctionCmd(a).applyTo(p, monitor);
                        outcome = p.getFunctionManager().getFunctionAt(a) != null ? "FUNCTION" : "CODE";
                    }
                    else outcome = fn ? "EXISTING_FUNCTION" : "CODE";
                }
                if (outcome.equals("FUNCTION") || outcome.equals("CODE"))
                    p.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS, "WSEvidence", "S1 SEED " + cls + " from " + file.getFileName() + ": " + outcome);
                if (outcome.equals("RAM_NO_IMAGE"))
                    p.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS, "WSEvidence", "RAM code, no image yet");
                if (outcome.equals("FUNCTION")) s1fn++;
                else if (outcome.equals("CODE")) s1code++;
                else s1skip++;
                emit("{\"rule\":\"S1\",\"seed\":\"%s\",\"class\":\"%s\",\"at\":\"%s\",\"outcome\":\"%s\"}", f[0], cls, where, outcome);
            }
            emit("{\"rule\":\"S1\",\"file\":\"%s\",\"functions\":%d,\"code\":%d,\"not_applied\":%d}", file.getFileName(), s1fn, s1code, s1skip);
        }

        /** B3. */
        void resolveWindowFlows() throws Exception {
            Listing listing = p.getListing();
            Memory mem = p.getMemory();
            List<Instruction> sitesToFix = new ArrayList<>();
            for (Instruction i : listing.getInstructions(true)) {
                monitor.checkCancelled();
                for (Address f : i.getFlows()) {
                    MemoryBlock b = mem.getBlock(f);
                    if (b != null && !b.isOverlay() && !f.getAddressSpace().isOverlaySpace() && f.getOffset() >= 0x20000 && f.getOffset() < 0x40000) { sitesToFix.add(i); break; }
                }
            }
            for (Instruction i : sitesToFix) {
                for (Address f : i.getFlows()) {
                    MemoryBlock b = mem.getBlock(f);
                    if (b == null || b.isOverlay() || f.getAddressSpace().isOverlaySpace() || f.getOffset() < 0x20000 || f.getOffset() >= 0x40000) continue;
                    long lin = f.getOffset();
                    // Terminal outcomes never change (the evidence is fixed), so a site resolved by an
                    // earlier pass is done; without this the repair pass re-emits every line (phase 1 ran first).
                    // CONTEXT_CONFLICT is not terminal: later passes may clear the bad decode and resolve it.
                    String doneKey = i.getAddress() + "|" + lin;
                    if (ev.b3resolved.contains(doneKey)) continue;
                    Integer selected = WSRomEvidence.staticBank(p, i, lin);
                    Set<Integer> banks = selected == null ? ev.windowBanks.get(lin) : Set.of(selected);
                    if (banks == null || banks.isEmpty()) {
                        b3unobserved++;
                        ev.b3resolved.add(doneKey);
                        emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%05x\",\"outcome\":\"UNOBSERVED\"}", i.getAddress(), lin);
                        continue;
                    }
                    if (banks.size() > 1) {
                        b3multi++;
                        ev.b3resolved.add(doneKey);
                        emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%05x\",\"outcome\":\"MULTI_BANK\",\"banks\":\"%s\"}", i.getAddress(), lin, banks);
                        continue;
                    }
                    Address o = overlay(lin < 0x30000 ? 0x2000 : 0x3000, banks.iterator().next()).getStart().add(lin & 0xffff);
                    boolean call = i.getFlowType().isCall();
                    if (listing.getInstructionAt(o) == null) {
                        try {
                            setCodeContext(o, ev.cs.getOrDefault(lin, (int) (lin >> 4) & 0xF000));
                        }
                        catch (ContextChangeException e) {
                            // the target lies inside an existing instruction (offcut): report this site, keep going;
                            // one conflict must not abort the rest of phase 1
                            b3conflict++;
                            Instruction in = listing.getInstructionContaining(o);
                            emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"CONTEXT_CONFLICT\",\"inside\":\"%s\"}",
                                i.getAddress(), o, in == null ? "-" : in.getAddress());
                            continue;
                        }
                        new DisassembleCommand(o, null, true).applyTo(p, monitor);
                    }
                    WSRomEvidence.relocateWindowStub(p, f, o, ev, line -> emit("%s", line), monitor);
                    ev.b3resolved.add(doneKey);
                    if (call) {
                        Reference r = p.getReferenceManager().addMemoryReference(i.getAddress(), o,
                            RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
                        p.getReferenceManager().setPrimary(r, true);
                        if (p.getFunctionManager().getFunctionAt(o) == null && listing.getInstructionAt(o) != null)
                            new CreateFunctionCmd(o).applyTo(p, monitor);
                        b3++;
                        emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"OVERRIDE\",\"kind\":\"call\"}", i.getAddress(), o);
                        continue;
                    }
                    // A jump override into another address space is un-followable: every function whose flow
                    // reaches it fails to decompile ("could not find op at target address") even with the
                    // target disassembled. The target stays disassembled (coverage needs it) and is recorded
                    // here plus a data reference (navigation without flow); calls above are unaffected.
                    p.getReferenceManager().addMemoryReference(i.getAddress(), o,
                        RefType.DATA, SourceType.ANALYSIS, Reference.MNEMONIC);
                    b3jump++;
                    emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"JUMP_DATAREF\",\"kind\":\"jump\"}", i.getAddress(), o);
                }
            }
        }

        /** E1 (also used by phase 2 as E1R to restore executed code removed by later analysis). */
        void seedExecuted(String rule) throws Exception {
            WSDecodeRepair.align(p, ev, line -> emit("%s", line), monitor);
            Listing listing = p.getListing();
            AddressSet seeds = new AddressSet();
            Set<Long> ram = new TreeSet<>();
            int seeded = 0, skipped = 0;
            for (Map.Entry<Long, Integer> e : ev.cs.entrySet()) for (Address a : addrs(e.getKey(), e.getValue())) {
                if (!inProgram(a)) { skipped++; continue; }
                if (isRamNoImage(a)) { ram.add(e.getKey()); skipped++; continue; }   // H1: no image yet
                if (listing.getInstructionAt(a) != null) {
                    e1already++;
                    if (isMesen(e.getKey())) e1alreadyM++;
                    continue;
                }
                if (listing.getInstructionContaining(a) != null) {          // conflicts with an existing decode
                    skipped++;
                    emit("{\"rule\":\"%s\",\"addr\":\"%s\",\"outcome\":\"CONFLICT_EXISTING_DECODE\"}", rule, a);
                    continue;
                }
                setCodeContext(a, e.getValue());
                seeds.add(a);
                seeded++;
                if (rule.equals("E1") && isMesen(e.getKey())) e1m++;
            }
            if (!seeds.isEmpty()) new DisassembleCommand(seeds, null, true).applyTo(p, monitor);
            h1runs += bookmarkRamRuns(ram);
            emit("{\"rule\":\"%s\",\"seeded\":%d,\"skipped\":%d}", rule, seeded, skipped);
            e1 += seeded; e1skip += skipped;
        }

        /** H1: work RAM holds loader zero-fill at analysis time, never the bytes the game ran there
         *  (copied in later), so executed RAM is bookmarked per run instead of decoded. E1R re-runs this
         *  with the same evidence: runs already bookmarked are left alone (returns only new runs). */
        int bookmarkRamRuns(Set<Long> ram) throws Exception {
            int runs = 0;
            Long start = null, prev = null;
            List<long[]> spans = new ArrayList<>();
            for (long lin : ram) {
                if (start == null || lin != prev + 1) {
                    if (start != null) spans.add(new long[] { start, prev });
                    start = lin;
                }
                prev = lin;
            }
            if (start != null) spans.add(new long[] { start, prev });
            for (long[] s : spans) {
                Address a = at(s[0], ev.cs.getOrDefault(s[0], 0));
                boolean marked = false;
                for (Bookmark b : p.getBookmarkManager().getBookmarks(a))
                    if (b.getComment() != null && b.getComment().startsWith("RAM code, no image yet")) { marked = true; break; }
                if (marked) continue;
                int n = (int) (s[1] - s[0] + 1);
                p.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS, "WSEvidence",
                    n == 1 ? "RAM code, no image yet"
                        : String.format("RAM code, no image yet (%s..%s, %d executed addresses)",
                            a, at(s[1], ev.cs.getOrDefault(s[1], 0)), n));
                emit("{\"rule\":\"H1\",\"run\":\"%s..%s\",\"addresses\":%d}", a, at(s[1], ev.cs.getOrDefault(s[1], 0)), n);
                runs++;
            }
            return runs;
        }

        /**
         * Resolve raw Mesen trace transfers into edges (runs first in seedEdges, after E1
         * disassembled the sources): fall-through flows are dropped, INTs become int edges,
         * computed calls/jumps become call/jump edges, direct branches and returns are dropped
         * (static analysis follows them; their targets are E1 code), and straight-line
         * discontinuities become irq entries. CDL sub-entries join as call edges. Consumes
         * ev.transfers/ev.cdlEntries so a second pass is a no-op.
         */
        void resolveTransfers() throws Exception {
            for (WSEvidence.Edge x : ev.cdlEntries) {
                ev.edges.add(x);
                mesenEdges.add(x);
            }
            ev.cdlEntries.clear();
            if (ev.transfers.isEmpty()) return;
            Listing listing = p.getListing();
            for (WSEvidence.Transfer t : ev.transfers) {
                monitor.checkCancelled();
                Instruction src = listing.getInstructionAt(at(t.from(), t.fromCs()));
                if (src == null) { xferNoSrc++; continue; }
                Address fall = src.getFallThrough();
                if (fall != null && fall.getOffset() == t.to()) { xferFall++; continue; }
                String mn = src.getMnemonicString();
                WSEvidence.Edge x;
                if (mn.equals("INT") || mn.equals("INT3") || mn.equals("INTO")) {
                    x = new WSEvidence.Edge(t.from(), t.to(), t.toCs(), "int", t.count());
                    xferInt++;
                } else if (src.getFlowType().isCall() && src.getFlowType().isComputed()) {
                    x = new WSEvidence.Edge(t.from(), t.to(), t.toCs(), "call", t.count());
                    xferCall++;
                } else if (src.getFlowType().isJump() && src.getFlowType().isComputed()) {
                    x = new WSEvidence.Edge(t.from(), t.to(), t.toCs(), "jump", t.count());
                    xferJump++;
                } else if (src.getFlowType().isCall() || src.getFlowType().isJump()) {
                    xferDrop++;
                    continue;
                } else if (src.getFlowType().isTerminal()) {
                    // returns and other terminals: the target is a resume site, E1 code
                    xferDrop++;
                    continue;
                } else {
                    x = new WSEvidence.Edge(-1, t.to(), t.toCs(), "irq", t.count());
                    xferIrq++;
                }
                ev.edges.add(x);
                mesenEdges.add(x);
            }
            ev.transfers.clear();
        }

        void seedEdges() throws Exception {
            Listing listing = p.getListing();
            resolveTransfers();

            Map<Address, LinkedHashSet<Address>> jumps = new LinkedHashMap<>();
            Map<Address, LinkedHashSet<Address>> jumpsMesen = new LinkedHashMap<>();
            for (WSEvidence.Edge ed : ev.edges) {
                monitor.checkCancelled();
                List<Address> tas = addrs(ed.to(), ed.targetCs());
                List<Instruction> srcs = ed.from() < 0 ? List.of() : sites(ed.from());
                if (tas.size() > 1) b2ambiguous++;   // target ran under several banks; the edge does not say which
                for (Address ta : tas) {
                    if (!inProgram(ta)) continue;
                    if (isRamNoImage(ta)) {   // H1: executed RAM has no image; the H1 run bookmark covers it
                        emit("{\"rule\":\"E2\",\"target\":\"%s\",\"kind\":\"%s\",\"outcome\":\"RAM_NO_IMAGE\"}", ta, ed.kind());
                        continue;
                    }
                    if (isOverlayEnd(ta)) {   // J1o: no case entry can live on the last overlay byte
                        emit("{\"rule\":\"J1o\",\"from\":\"%x\",\"target\":\"%s\",\"kind\":\"%s\",\"outcome\":\"EXCLUDED\"}", ed.from(), ta, ed.kind());
                        continue;
                    }
                    if (ed.kind().equals("jump")) {
                        for (Instruction site : srcs) {
                            jumps.computeIfAbsent(site.getAddress(), k -> new LinkedHashSet<>()).add(ta);
                            if (mesenEdges.contains(ed))
                                jumpsMesen.computeIfAbsent(site.getAddress(), k -> new LinkedHashSet<>()).add(ta);
                        }
                        continue;
                    }
                    if (listing.getInstructionAt(ta) == null) {
                        Instruction in = listing.getInstructionContaining(ta);
                        if (in != null || !trySetCodeContext(ta, ed.targetCs())) {
                            // target inside an existing decode (offcut): report it, do not abort phase 1
                            e2conflict++;
                            emit("{\"rule\":\"E2\",\"target\":\"%s\",\"outcome\":\"CONFLICT_EXISTING_DECODE\",\"inside\":\"%s\"}",
                                ta, in == null ? "-" : in.getAddress());
                            continue;
                        }
                        new DisassembleCommand(ta, null, true).applyTo(p, monitor);
                    }
                    if (ed.kind().equals("call"))
                        for (Instruction site : srcs) site.addMnemonicReference(ta, RefType.COMPUTED_CALL, SourceType.ANALYSIS);
                    if (p.getFunctionManager().getFunctionAt(ta) == null && listing.getInstructionAt(ta) != null) {
                        new CreateFunctionCmd(ta).applyTo(p, monitor);
                        e2++;
                        boolean m = mesenEdges.contains(ed);
                        if (m) e2m++;
                        emit("{\"rule\":\"E2\",\"entry\":\"%s\",\"kind\":\"%s\",\"from\":\"%x\",\"count\":%d%s}", ta, ed.kind(), ed.from(), ed.count(),
                            m ? ",\"src\":\"mesen\"" : "");
                    }
                }
            }
            for (Map.Entry<Address, LinkedHashSet<Address>> j : jumps.entrySet()) {
                Instruction site = listing.getInstructionAt(j.getKey());
                if (site == null) continue;
                WSObservedSwitches.remember(p, site.getAddress(), j.getValue());
                for (Address t : j.getValue()) site.addMnemonicReference(t, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
                Function f = p.getFunctionManager().getFunctionContaining(site.getAddress());
                if (f != null) {
                    // J1q: the override stays in the site's space (references above keep every bank);
                    // without an own-space target there is nothing to lock yet (rule J1m retries post-merge).
                    List<Address> own = WSJumpTables.ownSpace(site.getAddress(), j.getValue());
                    if (!own.isEmpty()) {
                        new JumpTable(site.getAddress(), new ArrayList<>(own), true, 0).writeOverride(f);
                        CreateFunctionCmd.fixupFunctionBody(p, f, monitor);
                    }
                }
                e3++; e3t += j.getValue().size();
                int nm = jumpsMesen.getOrDefault(j.getKey(), new LinkedHashSet<>()).size();
                if (nm > 0) { e3m++; e3tm += nm; }
                StringBuilder tb = new StringBuilder();
                for (Address t : j.getValue()) { if (tb.length() > 0) tb.append(','); tb.append('"').append(t).append('"'); }
                emit("{\"rule\":\"E3\",\"site\":\"%s\",\"observed_targets\":%d,\"targets\":[%s]%s}", site.getAddress(), j.getValue().size(), tb,
                    nm == 0 ? "" : nm == j.getValue().size() ? ",\"src\":\"mesen\"" : ",\"src\":\"mixed\"");
            }

        }

        /**
         * N1: a function flagged non-returning whose call site's fall-through executed does return: clear
         * the flag and the call-terminator overrides, and re-disassemble the fall-throughs.
         */
        void repairNoReturn() throws Exception {
            Listing listing = p.getListing();
            AddressSet refall = new AddressSet();
            for (Function f : p.getFunctionManager().getFunctions(true)) {
                if (!f.hasNoReturn()) continue;
                boolean contradicted = false;
                List<Instruction> sites = new ArrayList<>();
                for (Reference r : p.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                    if (!r.getReferenceType().isCall()) continue;
                    Instruction call = listing.getInstructionAt(r.getFromAddress());
                    if (call == null) continue;
                    sites.add(call);
                    if (ev.executed(call.getMaxAddress().getOffset() + 1)) contradicted = true;
                }
                if (!contradicted) continue;
                f.setNoReturn(false);
                n1++;
                for (Instruction call : sites) {
                    if (call.getFlowOverride() != FlowOverride.NONE) call.setFlowOverride(FlowOverride.NONE);
                    Address ft = call.getMaxAddress().add(1);
                    if (listing.getInstructionAt(ft) == null) refall.add(ft);
                    n1sites++;
                }
                emit("{\"rule\":\"N1\",\"function\":\"%s\",\"call_sites\":%d}", f.getEntryPoint(), sites.size());
            }
            if (!refall.isEmpty()) new DisassembleCommand(refall, null, true).applyTo(p, monitor);
        }

        /** D1: DS/SS context at function entries with a single non-zero observed DS/SS. */
        void seedDs() throws Exception {
            for (Function f : p.getFunctionManager().getFunctions(true)) {
                long lin = f.getEntryPoint().getOffset();
                Set<Integer> d = ev.ds.get(lin);
                if (d != null && d.size() == 1) {
                    int v = d.iterator().next();
                    if (v != 0) {
                        ctx.setValue(rDS, f.getEntryPoint(), f.getEntryPoint(), BigInteger.valueOf(v));
                        d1++;
                        emit("{\"rule\":\"D1\",\"entry\":\"%s\",\"ds\":\"%04x\"}", f.getEntryPoint(), v);
                    }
                }
                Set<Integer> s = ev.ss.get(lin);
                if (s != null && s.size() == 1) {
                    int v = s.iterator().next();
                    if (v != 0) {
                        ctx.setValue(rSS, f.getEntryPoint(), f.getEntryPoint(), BigInteger.valueOf(v));
                        d1ss++;
                        emit("{\"rule\":\"D1\",\"entry\":\"%s\",\"ss\":\"%04x\"}", f.getEntryPoint(), v);
                    }
                }
            }
        }

        void classifyArtefacts(java.util.Set<Address> keptTargets) throws Exception {
            int ramRuns = WSRamCode.classify(p);
            emit("{\"rule\":\"H2\",\"unknown_ram_runs\":%d,\"outcome\":\"KEPT\"}", ramRuns);
            Listing listing = p.getListing();
            BookmarkManager bm = p.getBookmarkManager();
            List<Address> bad = new ArrayList<>();
            Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.ERROR);
            while (it.hasNext()) bad.add(it.next().getAddress());
            for (Address b : bad) {
                monitor.checkCancelled();
                // walk back along fall-through while instructions were never executed; a kept jump-table
                // target is proven code (table + bound + stops), so the walk stops before it instead of
                // clearing a real handler that merely flows toward a bad decode
                List<Instruction> run = new ArrayList<>();
                boolean keptStop = false;
                Instruction prev = listing.getInstructionBefore(b);
                while (prev != null && b.equals(prev.getFallThrough()) && !WSRomEvidence.executed(p, ev, prev.getAddress())) {
                    if (WSRamCode.isRam(p, prev.getAddress())) break;
                    if (keptTargets.contains(prev.getAddress())) { keptStop = true; break; }
                    run.add(0, prev);
                    b = prev.getAddress();
                    prev = listing.getInstructionBefore(b);
                }
                if (run.isEmpty()) continue;
                Address start = run.get(0).getAddress(), end = run.get(run.size() - 1).getMaxAddress();
                StringBuilder refs = new StringBuilder();
                for (Reference r : p.getReferenceManager().getReferencesTo(start)) {
                    boolean exec = ev.executed(r.getFromAddress().getOffset());
                    refs.append(refs.length() > 0 ? "," : "").append(String.format("{\"from\":\"%s\",\"executed\":%b}", r.getFromAddress(), exec));
                }
                Function f = p.getFunctionManager().getFunctionContaining(start);
                listing.clearCodeUnits(start, end, false);
                bm.setBookmark(start, "Analysis", "WSEvidence",
                    "A1 DATA_ARTEFACT: " + run.size() + " unexecuted fall-through instructions ending in a bad decode; decode cleared");
                if (f != null && !f.getEntryPoint().equals(start)) CreateFunctionCmd.fixupFunctionBody(p, f, monitor);
                else if (f != null) p.getFunctionManager().removeFunction(start);
                a1runs++; a1insns += run.size();
                emit("{\"rule\":\"A1\",\"start\":\"%s\",\"end\":\"%s\",\"instructions\":%d,\"refs_to_start\":[%s]%s}", start, end, run.size(), refs,
                    keptStop ? ",\"stopped\":\"KEPT_TARGET\"" : "");
            }
        }

        String summary() {
            return String.format("B2 bank overlays %d (edges into multi-bank code %d), B3 window flows overridden %d (jumps fenced %d, multi-bank %d, unobserved %d, context conflicts %d), E1 seeded %d (skipped %d), H1 RAM runs %d, E2 functions %d (offcut targets skipped %d), E3 jump sites %d (targets %d), N1 no-return cleared %d (%d call sites), D1 DS entries %d (SS %d), A1 artefact runs %d (%d instructions cleared)",
                b2, b2ambiguous, b3, b3jump, b3multi, b3unobserved, b3conflict, e1, e1skip, h1runs, e2, e2conflict, e3, e3t, n1, n1sites, d1, d1ss, a1runs, a1insns);
        }

        @Override public void close() { if (out != null) out.close(); }
    }
}
