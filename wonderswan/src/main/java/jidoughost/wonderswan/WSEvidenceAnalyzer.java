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
 *   B3  a direct call/jump into a window (no bytes there) whose target executed under exactly one bank gets a
 *       call/jump override reference to that bank's overlay (decompiler follows it); targets that ran under
 *       several banks or never ran are reported, not guessed.
 *   E1  an executed linear address is an instruction start: csval = the CS observed there; disassemble.
 *   E2  a call / int / irq edge target is a function entry.
 *   E3  a computed JMP site gets COMPUTED_JUMP references to every observed target, and a JumpTable
 *       override listing them (observed targets only; a static table rule may add more later).
 *   D1  a function entry where only one non-zero DS value was observed gets that DS as context.
 *   B2  ROM0/ROM1 window code: for every (window, bank) the evidence executed in (rule B1, WSMachine), an
 *       overlay block of that ROM bank is created over the window, and E1/E2/E3 seed into it. A window
 *       address that executed under several banks is seeded in each of them.
 *   A1  a bad decode (ERROR bookmark) reached by fall-through from unexecuted instructions: the maximal
 *       unexecuted fall-through run ending at it is a data artefact. Its decode is cleared (bytes kept),
 *       a "WSEvidence" bookmark records the evidence. Executed instructions are never cleared.
 */
public class WSEvidenceAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "WonderSwan Execution Evidence";
    private static final String OPT_RUN = "Run WSMachine";
    private static final String OPT_FRAMES = "Frames";
    private static final String OPT_SLICE = "Instructions per frame";
    private static final String OPT_DIR = "Evidence directory (WSEmulate output; overrides running)";
    private static final String OPT_REPORT = "Evidence report file (JSON lines; empty = none)";
    private static final String OPT_ARTEFACTS = "Classify decode artefacts (rule A1)";

    /** Evidence collected in phase 1, reused by {@link WSEvidenceRepairAnalyzer} (phase 2). */
    static final Map<Program, WSEvidence> EVIDENCE = Collections.synchronizedMap(new WeakHashMap<>());
    static final Map<Program, String> REPORT = Collections.synchronizedMap(new WeakHashMap<>());

    private boolean run = true, artefacts = true;
    private int frames = 1500, slice = 15000;
    private String dir = "", report = "";

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
    }

    @Override
    public void optionsChanged(Options o, Program program) {
        run = o.getBoolean(OPT_RUN, run);
        frames = o.getInt(OPT_FRAMES, frames);
        slice = o.getInt(OPT_SLICE, slice);
        dir = o.getString(OPT_DIR, dir);
        report = o.getString(OPT_REPORT, report);
        artefacts = o.getBoolean(OPT_ARTEFACTS, artefacts);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        WSEvidence ev;
        try {
            if (dir != null && !dir.isBlank()) ev = WSEvidence.load(Paths.get(dir));
            else if (run) {
                monitor.setMessage("WonderSwan: emulating " + frames + " frames");
                boolean color = program.getOptions(WonderSwanLoader.OPTIONS_CATEGORY).getBoolean("Color", true);
                WSMachine m = new WSMachine(program, color);
                m.run(frames, slice, f -> {
                    int ph = f % 40;
                    m.buttons = (f >= 100 && ph < 3) ? 0x02 : (f >= 100 && ph >= 20 && ph < 23) ? 0x04 : 0;
                });
                ev = WSEvidence.of(m);
            }
            else return false;
        }
        catch (Exception e) {
            // not silent: headless does not print the analysis MessageLog
            String msg = NAME + ": no evidence (" + e + "); nothing seeded, evidence rules skipped";
            log.appendMsg(msg);
            ghidra.util.Msg.error(this, msg, e);
            program.getBookmarkManager().setBookmark(program.getMinAddress(), BookmarkType.ERROR, "WSEvidence", msg);
            return false;
        }
        EVIDENCE.put(program, ev);
        REPORT.put(program, report == null ? "" : report);
        try (Seeder s = new Seeder(program, ev, report, false, monitor, log)) {
            s.seed();
            log.appendMsg(NAME + " (phase 1): " + s.summary());
        }
        catch (CancelledException c) { throw c; }
        catch (Exception e) { log.appendException(e); ghidra.util.Msg.error(this, NAME + " (phase 1) failed: " + e, e); }
        return true;
    }

    /** Applies the rules to one program. */
    static final class Seeder implements AutoCloseable {
        final Program p;
        final WSEvidence ev;
        final TaskMonitor monitor;
        final MessageLog log;
        final SegmentedAddressSpace space;
        final ProgramContext ctx;
        final Register csval, rDS, colorsoc;
        final boolean colorHw;
        final PrintWriter out;
        int e1, e1skip, e2, e3, e3t, d1, a1runs, a1insns, n1, n1sites, b2, b2ambiguous, b3, b3multi, b3unobserved;

        Seeder(Program p, WSEvidence ev, String report, boolean append, TaskMonitor monitor, MessageLog log) throws Exception {
            this.p = p; this.ev = ev; this.monitor = monitor; this.log = log;
            space = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
            ctx = p.getProgramContext();
            csval = ctx.getRegister("csval");
            rDS = ctx.getRegister("DS");
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
            String name = String.format("ROM%d_BANK_%04X", seg == WSHardware.SEG_ROM0 ? 0 : 1, bank);
            Memory mem = p.getMemory();
            MemoryBlock b = mem.getBlock(name);
            if (b != null) return b;
            if (mem.getAllFileBytes().isEmpty()) return null;
            ghidra.program.database.mem.FileBytes fb = mem.getAllFileBytes().get(0);
            long off = WSHardware.bankToRom(bank, fb.getSize());
            long len = Math.min(0x10000, fb.getSize() - off);
            b = mem.createInitializedBlock(name, space.getAddress(seg, 0), fb, off, len, true);
            b.setPermissions(true, false, true);
            b.setComment(String.format("ROM bank 0x%04X (file offset 0x%06X) in the %s window: code executed here under this bank (evidence rule B1/B2)",
                bank, off, seg == WSHardware.SEG_ROM0 ? "ROM0" : "ROM1"));
            b2++;
            emit("{\"rule\":\"B2\",\"overlay\":\"%s\",\"window\":\"%04x\",\"bank\":\"%04x\",\"rom_offset\":\"%06x\"}", name, seg, bank, off);
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

        boolean inProgram(Address a) { return p.getMemory().contains(a) && p.getMemory().getBlock(a).isInitialized(); }

        void seed() throws Exception {
            seedExecuted("E1");
            seedEdges();
            resolveWindowFlows();
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
                    if (b != null && !b.isInitialized() && !b.isOverlay() && f.getOffset() >= 0x20000 && f.getOffset() < 0x40000) { sitesToFix.add(i); break; }
                }
            }
            for (Instruction i : sitesToFix) {
                for (Address f : i.getFlows()) {
                    MemoryBlock b = mem.getBlock(f);
                    if (b == null || b.isInitialized() || b.isOverlay()) continue;
                    long lin = f.getOffset();
                    Set<Integer> banks = ev.windowBanks.get(lin);
                    if (banks == null || banks.isEmpty()) {
                        b3unobserved++;
                        emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%05x\",\"outcome\":\"UNOBSERVED\"}", i.getAddress(), lin);
                        continue;
                    }
                    if (banks.size() > 1) {
                        b3multi++;
                        emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%05x\",\"outcome\":\"MULTI_BANK\",\"banks\":\"%s\"}", i.getAddress(), lin, banks);
                        continue;
                    }
                    Address o = addrs(lin, (int) (lin >> 4) & 0xF000).get(0);
                    boolean call = i.getFlowType().isCall();
                    if (listing.getInstructionAt(o) == null) {
                        setCodeContext(o, ev.cs.getOrDefault(lin, (int) (lin >> 4) & 0xF000));
                        new DisassembleCommand(o, null, true).applyTo(p, monitor);
                    }
                    Reference r = p.getReferenceManager().addMemoryReference(i.getAddress(), o,
                        call ? RefType.CALL_OVERRIDE_UNCONDITIONAL : RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
                    p.getReferenceManager().setPrimary(r, true);
                    if (call && p.getFunctionManager().getFunctionAt(o) == null && listing.getInstructionAt(o) != null)
                        new CreateFunctionCmd(o).applyTo(p, monitor);
                    b3++;
                    emit("{\"rule\":\"B3\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"OVERRIDE\",\"kind\":\"%s\"}", i.getAddress(), o, call ? "call" : "jump");
                }
            }
        }

        /** E1 (also used by phase 2 as E1R to restore executed code removed by later analysis). */
        void seedExecuted(String rule) throws Exception {
            Listing listing = p.getListing();
            AddressSet seeds = new AddressSet();
            int seeded = 0, skipped = 0;
            for (Map.Entry<Long, Integer> e : ev.cs.entrySet()) for (Address a : addrs(e.getKey(), e.getValue())) {
                if (!inProgram(a)) { skipped++; continue; }
                if (listing.getInstructionAt(a) != null) continue;
                if (listing.getInstructionContaining(a) != null) {          // conflicts with an existing decode
                    skipped++;
                    emit("{\"rule\":\"%s\",\"addr\":\"%s\",\"outcome\":\"CONFLICT_EXISTING_DECODE\"}", rule, a);
                    continue;
                }
                setCodeContext(a, e.getValue());
                seeds.add(a);
                seeded++;
            }
            if (!seeds.isEmpty()) new DisassembleCommand(seeds, null, true).applyTo(p, monitor);
            emit("{\"rule\":\"%s\",\"seeded\":%d,\"skipped\":%d}", rule, seeded, skipped);
            e1 += seeded; e1skip += skipped;
        }

        void seedEdges() throws Exception {
            Listing listing = p.getListing();

            Map<Address, LinkedHashSet<Address>> jumps = new LinkedHashMap<>();
            for (WSEvidence.Edge ed : ev.edges) {
                monitor.checkCancelled();
                List<Address> tas = addrs(ed.to(), ed.targetCs());
                List<Instruction> srcs = ed.from() < 0 ? List.of() : sites(ed.from());
                if (tas.size() > 1) b2ambiguous++;   // target ran under several banks; the edge does not say which
                for (Address ta : tas) {
                    if (!inProgram(ta)) continue;
                    if (ed.kind().equals("jump")) {
                        for (Instruction site : srcs) jumps.computeIfAbsent(site.getAddress(), k -> new LinkedHashSet<>()).add(ta);
                        continue;
                    }
                    if (listing.getInstructionAt(ta) == null) {
                        setCodeContext(ta, ed.targetCs());
                        new DisassembleCommand(ta, null, true).applyTo(p, monitor);
                    }
                    if (ed.kind().equals("call"))
                        for (Instruction site : srcs) site.addMnemonicReference(ta, RefType.COMPUTED_CALL, SourceType.ANALYSIS);
                    if (p.getFunctionManager().getFunctionAt(ta) == null && listing.getInstructionAt(ta) != null) {
                        new CreateFunctionCmd(ta).applyTo(p, monitor);
                        e2++;
                        emit("{\"rule\":\"E2\",\"entry\":\"%s\",\"kind\":\"%s\",\"from\":\"%x\",\"count\":%d}", ta, ed.kind(), ed.from(), ed.count());
                    }
                }
            }
            for (Map.Entry<Address, LinkedHashSet<Address>> j : jumps.entrySet()) {
                Instruction site = listing.getInstructionAt(j.getKey());
                if (site == null) continue;
                for (Address t : j.getValue()) site.addMnemonicReference(t, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
                Function f = p.getFunctionManager().getFunctionContaining(site.getAddress());
                if (f != null) {
                    new JumpTable(site.getAddress(), new ArrayList<>(j.getValue()), true, 0).writeOverride(f);
                    CreateFunctionCmd.fixupFunctionBody(p, f, monitor);
                }
                e3++; e3t += j.getValue().size();
                emit("{\"rule\":\"E3\",\"site\":\"%s\",\"observed_targets\":%d}", site.getAddress(), j.getValue().size());
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

        /** D1: DS context at function entries with a single non-zero observed DS. */
        void seedDs() throws Exception {
            for (Function f : p.getFunctionManager().getFunctions(true)) {
                long lin = f.getEntryPoint().getOffset();
                Set<Integer> d = ev.ds.get(lin);
                if (d == null || d.size() != 1) continue;
                int v = d.iterator().next();
                if (v == 0) continue;
                ctx.setValue(rDS, f.getEntryPoint(), f.getEntryPoint(), BigInteger.valueOf(v));
                d1++;
                emit("{\"rule\":\"D1\",\"entry\":\"%s\",\"ds\":\"%04x\"}", f.getEntryPoint(), v);
            }
        }

        void classifyArtefacts() throws Exception {
            Listing listing = p.getListing();
            BookmarkManager bm = p.getBookmarkManager();
            List<Address> bad = new ArrayList<>();
            Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.ERROR);
            while (it.hasNext()) bad.add(it.next().getAddress());
            for (Address b : bad) {
                monitor.checkCancelled();
                // walk back along fall-through while instructions were never executed
                List<Instruction> run = new ArrayList<>();
                Instruction prev = listing.getInstructionBefore(b);
                while (prev != null && b.equals(prev.getFallThrough()) && !ev.executed(prev.getAddress().getOffset())) {
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
                emit("{\"rule\":\"A1\",\"start\":\"%s\",\"end\":\"%s\",\"instructions\":%d,\"refs_to_start\":[%s]}", start, end, run.size(), refs);
            }
        }

        String summary() {
            return String.format("B2 bank overlays %d (edges into multi-bank code %d), B3 window flows overridden %d (multi-bank %d, unobserved %d), E1 seeded %d (skipped %d), E2 functions %d, E3 jump sites %d (targets %d), N1 no-return cleared %d (%d call sites), D1 DS entries %d, A1 artefact runs %d (%d instructions cleared)",
                b2, b2ambiguous, b3, b3multi, b3unobserved, e1, e1skip, e2, e3, e3t, n1, n1sites, d1, a1runs, a1insns);
        }

        @Override public void close() { if (out != null) out.close(); }
    }
}
