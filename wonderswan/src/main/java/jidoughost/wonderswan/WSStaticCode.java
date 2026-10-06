// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.util.task.TaskMonitor;

/**
 * Static call evidence in undefined ROM, applied after ordinary analysis.
 * A direct call to an existing entry anchors a routine with a frame prologue,
 * a reference from existing code, or a preceding decoded flow terminator.
 * Trial decoding is strict: every reachable branch is walked, every path must
 * reach a return or an existing instruction, and transfers may not enter the
 * middle of an instruction. Defined data and inconsistent file-backed aliases
 * veto a candidate. Computed transfers and unresolved bank contexts are kept
 * as unknown, with a rejection reason. No execution evidence is synthesized.
 */
public final class WSStaticCode {
    public static final String PROPERTY = "WS_STATIC_UNEXECUTED";
    private static final int BACKWARD_BYTES = 1024, MAX_INSTRUCTIONS = 1500;
    private static final Set<String> WEAK_OPCODES = Set.of("INSB", "INSW", "OUTSB", "OUTSW", "BOUND", "INTO", "ESC", "WAIT", "INT3");
    private final Program program;
    private final Listing listing;
    private final Memory memory;
    private final ProgramContext context;
    private final Register csval, hwundef;
    private final PseudoDisassembler decoder;
    private final TaskMonitor monitor;
    private final Consumer<String> emit;
    private final Set<Long> definedData = new HashSet<>();
    private final Set<Long> codeBytes = new HashSet<>();
    private final Map<String, Integer> rejects = new TreeMap<>();
    private final Set<Address> known = new HashSet<>();
    private final IntPropertyMap provenance;
    private int passes, accepted, instructions, bytes, candidates;

    private record Start(Address address, String evidence) { }
    private record Walk(TreeMap<Address, PseudoInstruction> code, AddressSet body,
                        Set<Address> ends, Map<Address, Set<Address>> edges,
                        Set<Address> transfers) { }
    private static final class Reject extends Exception {
        Reject(String reason) { super(reason); }
    }

    private WSStaticCode(Program p, Consumer<String> output, TaskMonitor m) throws Exception {
        program = p; listing = p.getListing(); memory = p.getMemory();
        context = p.getProgramContext(); monitor = m; emit = output;
        csval = context.getRegister("csval"); hwundef = context.getRegister("hwundef");
        if (csval == null || hwundef == null) throw new IllegalArgumentException("Strict segmented language required");
        decoder = new PseudoDisassembler(p);
        var maps = p.getUsrPropertyManager();
        IntPropertyMap map = maps.getIntPropertyMap(PROPERTY);
        provenance = map == null ? maps.createIntPropertyMap(PROPERTY) : map;
        for (Data d : listing.getDefinedData(true)) {
            long ro = romOffset(d.getAddress());
            if (ro >= 0) for (int k = 0; k < d.getLength(); k++) definedData.add(ro + k);
        }
        for (Instruction i : listing.getInstructions(true)) index(i);
    }

    public static String apply(Program p, Consumer<String> output, TaskMonitor monitor) throws Exception {
        WSStaticCode rule = new WSStaticCode(p, output, monitor);
        rule.run();
        return String.format("passes=%d candidates=%d accepted=%d instructions=%d bytes=%d rejects=%s",
            rule.passes, rule.candidates, rule.accepted, rule.instructions, rule.bytes, rule.rejects);
    }

    private long romOffset(Address a) {
        MemoryBlock block = memory.getBlock(a);
        if (block != null) for (MemoryBlockSourceInfo source : block.getSourceInfos())
            if (source.getFileBytes().isPresent() && source.contains(a)) return source.getFileBytesOffset(a);
        return -1;
    }

    private void index(Instruction i) {
        long ro = romOffset(i.getAddress());
        if (ro < 0) return;
        for (int k = 0; k < i.getLength(); k++) codeBytes.add(ro + k);
    }

    private boolean unknown(Address a) {
        CodeUnit unit = listing.getCodeUnitContaining(a);
        long ro = romOffset(a);
        return ro >= 0 && !definedData.contains(ro) && !codeBytes.contains(ro)
            && unit instanceof Data d && !d.isDefined();
    }

    private int cs(Address a) {
        BigInteger value = context.getValue(csval, a, false);
        if (value != null && value.intValue() != 0) return value.intValue();
        return a instanceof SegmentedAddress sa ? sa.getSegment() : -1;
    }

    private PseudoInstruction decode(Address a, int segment) throws Exception {
        PseudoDisassemblerContext trial = new PseudoDisassemblerContext(context);
        trial.setFutureRegisterValue(a, new RegisterValue(csval, BigInteger.valueOf(segment)));
        trial.setFutureRegisterValue(a, new RegisterValue(hwundef, BigInteger.ZERO));
        PseudoInstruction i = decoder.disassemble(a, trial, false);
        if (i == null || i.getMnemonicString().contains("UNDEF") || i.getMnemonicString().equals("ESC"))
            throw new Reject("invalid-or-undefined");
        return i;
    }

    private void run() throws Exception {
        while (true) {
            monitor.checkCancelled(); passes++;
            known.clear();
            for (Function f : program.getFunctionManager().getFunctions(true)) known.add(f.getEntryPoint());
            int before = accepted;
            Set<Address> tried = new HashSet<>();
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized() || !block.isExecute() || WonderSwanLoader.isDataOverlay(block)) continue;
                if (block.getSize() > 65536 || romOffset(block.getStart()) < 0) continue;
                byte[] raw = new byte[(int)block.getSize()]; memory.getBytes(block.getStart(), raw);
                for (int k = 0; k < raw.length; k++) {
                    monitor.checkCancelled();
                    int opcode = raw[k] & 255;
                    if (opcode != 0x9a && opcode != 0xe8) continue;
                    int size = opcode == 0x9a ? 5 : 3;
                    if (k + size > raw.length) continue;
                    Address anchor = block.getStart().add(k);
                    if (!unknown(anchor)) continue;
                    int segment = cs(anchor);
                    if (segment < 0) { rejects.merge("unknown-code-segment", 1, Integer::sum); continue; }
                    PseudoInstruction call;
                    try { call = decode(anchor, segment); }
                    catch (Exception ex) { continue; }
                    if (!call.getFlowType().isCall() || Arrays.stream(call.getFlows()).noneMatch(known::contains)) continue;
                    candidates++;
                    for (Start start : starts(block, raw, k, segment)) {
                        if (!tried.add(start.address()) || !unknown(start.address())) continue;
                        try {
                            Walk walk = walk(start.address(), anchor, segment, block);
                            commit(start, anchor, segment, walk);
                            break;
                        } catch (Reject ex) {
                            rejects.merge(ex.getMessage(), 1, Integer::sum);
                        }
                    }
                }
            }
            emit.accept(String.format("{\"rule\":\"static-call\",\"pass\":%d,\"accepted_total\":%d}", passes, accepted));
            if (accepted == before) break;
        }
    }

    private List<Start> starts(MemoryBlock block, byte[] raw, int at, int segment) throws Exception {
        List<Start> frames = new ArrayList<>(), savesFound = new ArrayList<>(), boundaries = new ArrayList<>();
        for (int k = at; k >= Math.max(0, at-BACKWARD_BYTES); k--) {
            Address a = block.getStart().add(k);
            if (!unknown(a)) break;
            if (k+2 < raw.length && raw[k] == 0x55 &&
                ((raw[k+1] == (byte)0x89 && raw[k+2] == (byte)0xe5) ||
                 (raw[k+1] == (byte)0x8b && raw[k+2] == (byte)0xec)))
                frames.add(new Start(a, "frame-prologue"));
            // At least three register saves, or a segment save plus PUSHA,
            // establishes a save prologue without needing a BP frame.
            int saves = 0, width = 0;
            boolean all = false;
            while (k+width < raw.length && width < 6) {
                int op = raw[k+width] & 255;
                if (op == 0x60) { saves += 2; all = true; }
                else if (op >= 0x50 && op <= 0x57 && op != 0x54 || op == 0x06 || op == 0x0e || op == 0x16 || op == 0x1e) saves++;
                else break;
                width++;
            }
            boolean previousSave = k > 0 && isSave(raw[k-1] & 255);
            if (!previousSave && saves >= 3 && (width >= 3 || all)) savesFound.add(new Start(a, "save-prologue"));
            for (Reference ref : program.getReferenceManager().getReferencesTo(a)) {
                if (ref.getReferenceType().isFlow() && listing.getInstructionAt(ref.getFromAddress()) != null) {
                    boundaries.add(new Start(a, "code-reference")); break;
                }
            }
            Instruction previous = listing.getInstructionContaining(a.subtract(1));
            if (previous != null && previous.getMaxAddress().next().equals(a) && !previous.hasFallthrough())
                boundaries.add(new Start(a, "defined-terminator"));
            // The boundary is supporting evidence, never a seed by itself: the
            // forward walk must actually reach the known-call anchor and end.
            for (int len : new int[] {1, 2, 3, 5}) {
                int q = k-len;
                if (q < 0) continue;
                int op = raw[q] & 255;
                if (!((len == 1 && (op == 0xc3 || op == 0xcb)) ||
                      (len == 2 && op == 0xeb) ||
                      (len == 3 && (op == 0xc2 || op == 0xca || op == 0xe9)) ||
                      (len == 5 && op == 0xea))) continue;
                try {
                    PseudoInstruction term = decode(block.getStart().add(q), segment);
                    if (term.getLength() == len && (term.getFlowType().isTerminal() ||
                        term.getFlowType().isJump() && term.getFlowType().isUnConditional()) &&
                        !term.hasFallthrough() && !term.getFlowType().isComputed() &&
                        boundaryAligned(block, raw, q, segment))
                        boundaries.add(new Start(a, term.getFlowType().isJump() ? "aligned-jump-boundary" : "aligned-return-boundary"));
                } catch (Exception ex) { /* not a boundary */ }
            }
        }
        frames.addAll(savesFound); frames.addAll(boundaries);
        return frames;
    }

    private static boolean isSave(int op) {
        return op == 0x60 || op >= 0x50 && op <= 0x57 && op != 0x54 ||
            op == 0x06 || op == 0x0e || op == 0x16 || op == 0x1e;
    }

    private boolean boundaryAligned(MemoryBlock block, byte[] raw, int at, int segment) {
        // A boundary byte alone does not establish its alignment. Decode from
        // the nearest existing instruction or a frame prologue before it.
        Address boundary = block.getStart().add(at);
        Instruction previous = listing.getInstructionBefore(boundary);
        List<Address> origins = new ArrayList<>();
        if (previous != null && block.contains(previous.getAddress()) && boundary.subtract(previous.getAddress()) <= BACKWARD_BYTES)
            origins.add(previous.getAddress());
        for (int k = at-1; k >= Math.max(0, at-BACKWARD_BYTES); k--)
            if (k+2 < raw.length && raw[k] == 0x55 &&
                ((raw[k+1] == (byte)0x89 && raw[k+2] == (byte)0xe5) ||
                 (raw[k+1] == (byte)0x8b && raw[k+2] == (byte)0xec))) {
                origins.add(block.getStart().add(k)); break;
            }
        for (Address origin : origins) {
            Address a = origin;
            try {
                while (a.compareTo(boundary) < 0) {
                    PseudoInstruction i = decode(a, segment);
                    for (int k = 0; k < i.getLength(); k++) {
                        long ro = romOffset(a.add(k));
                        if (definedData.contains(ro)) throw new Reject("data-before-boundary");
                    }
                    a = a.add(i.getLength());
                }
                if (a.equals(boundary)) return true;
            } catch (Exception ex) { /* try another aligned origin */ }
        }
        return false;
    }

    private Walk walk(Address start, Address anchor, int segment, MemoryBlock block) throws Exception {
        TreeMap<Address, PseudoInstruction> code = new TreeMap<>();
        AddressSet body = new AddressSet();
        Set<Address> ends = new HashSet<>(), transfers = new HashSet<>();
        Map<Address, Set<Address>> edges = new HashMap<>();
        Deque<Address> queue = new ArrayDeque<>(); queue.add(start);
        while (!queue.isEmpty()) {
            monitor.checkCancelled(); Address a = queue.removeFirst();
            if (code.containsKey(a) || ends.contains(a)) continue;
            if (body.contains(a)) throw new Reject("transfer-into-operand");
            if (listing.getInstructionAt(a) != null) { ends.add(a); continue; }
            if (!block.contains(a)) throw new Reject("unresolved-cross-block-flow");
            if (!unknown(a)) throw new Reject("defined-overlap");
            if (code.size() >= MAX_INSTRUCTIONS) throw new Reject("region-limit");
            PseudoInstruction i;
            try { i = decode(a, segment); }
            catch (Exception ex) { throw new Reject("invalid-or-undefined"); }
            if (!block.contains(i.getMaxAddress())) throw new Reject("cross-block-instruction");
            for (int k = 0; k < i.getLength(); k++) {
                Address q = a.add(k);
                if (!unknown(q) || body.contains(q)) throw new Reject("defined-or-trial-overlap");
            }
            String text = i.toString().toUpperCase().replace(" ", "");
            if (WEAK_OPCODES.contains(i.getMnemonicString()) || text.startsWith("LOCK"))
                throw new Reject("weak-opcode-evidence");
            byte[] raw = i.getBytes();
            if (raw.length == 2 && raw[0] == 0 && raw[1] == 0)
                throw new Reject("zero-fill-instruction");
            if (text.matches("(MOV|POP)CS.*")) throw new Reject("code-segment-write");
            var flow = i.getFlowType();
            if (flow.isComputed()) throw new Reject("computed-transfer");
            code.put(a, i); body.add(a, i.getMaxAddress());
            Set<Address> next = new HashSet<>(); edges.put(a, next);
            Address[] targets = i.getFlows();
            if (flow.isCall() || flow.isJump()) {
                if (targets.length == 0) throw new Reject("unresolved-transfer");
                for (Address target : targets) {
                    transfers.add(target);
                    byte[] encoded = i.getBytes();
                    if (flow.isJump() && encoded[0] == (byte)0xea && listing.getInstructionAt(target) == null)
                        throw new Reject("unresolved-far-jump-context");
                    if (flow.isJump()) { next.add(target); queue.add(target); }
                    else if (listing.getInstructionAt(target) == null && !unknown(target))
                        throw new Reject("call-not-start-or-unknown");
                }
            }
            if (flow.isTerminal()) {
                if (!i.getMnemonicString().startsWith("RET") && !i.getMnemonicString().equals("IRET"))
                    throw new Reject("non-return-terminal");
                ends.add(a);
            } else if (i.getFallThrough() != null) {
                next.add(i.getFallThrough()); queue.add(i.getFallThrough());
            } else if (!flow.isJump()) throw new Reject("no-flow-end");
        }
        if (!code.containsKey(anchor)) throw new Reject("anchor-not-reached");
        PseudoInstruction call = code.get(anchor);
        if (!call.getFlowType().isCall() || Arrays.stream(call.getFlows()).noneMatch(known::contains))
            throw new Reject("anchor-not-known-call");
        for (Address target : transfers)
            if (body.contains(target) && !code.containsKey(target)) throw new Reject("transfer-into-operand");
        // Reverse reachability requires a flow end even for a branch cycle.
        Set<Address> reachesEnd = new HashSet<>(ends);
        boolean changed;
        do {
            changed = false;
            for (var e : edges.entrySet())
                if (e.getValue().stream().anyMatch(reachesEnd::contains)) changed |= reachesEnd.add(e.getKey());
        } while (changed);
        if (!reachesEnd.containsAll(code.keySet())) throw new Reject("no-flow-end");
        // Incoming references cannot silently become references into new operands.
        for (Address a : body.getAddresses(true)) {
            if (!code.containsKey(a) && program.getReferenceManager().getReferencesTo(a).hasNext())
                throw new Reject("incoming-reference-into-operand");
        }
        return new Walk(code, body, ends, edges, transfers);
    }

    private void commit(Start start, Address anchor, int segment, Walk walk) throws Exception {
        // Insert precisely the trial instructions. Never launch unrestricted flow
        // disassembly, which could claim unvalidated callees or branch targets.
        for (PseudoInstruction i : walk.code().values()) {
            Address a = i.getAddress();
            context.setValue(csval, a, i.getMaxAddress(), BigInteger.valueOf(segment));
            context.setValue(hwundef, a, i.getMaxAddress(), BigInteger.ZERO);
            Instruction inserted = listing.createInstruction(a, i.getPrototype(), i, i.getProcessorContext(), 0);
            provenance.add(a, inserted.getLength()); index(inserted);
            instructions++; bytes += inserted.getLength();
        }
        Function f = program.getFunctionManager().getFunctionAt(start.address());
        boolean routine = !start.evidence().equals("aligned-jump-boundary") && !start.evidence().equals("code-reference");
        if (f == null && routine && program.getFunctionManager().getFunctionContaining(start.address()) == null)
            f = program.getFunctionManager().createFunction(null, start.address(), walk.body(), SourceType.ANALYSIS);
        if (f != null) { f.addTag(PROPERTY); known.add(f.getEntryPoint()); }
        program.getBookmarkManager().setBookmark(start.address(), BookmarkType.ANALYSIS, PROPERTY,
            "Static call evidence; " + start.evidence() + "; no execution observation");
        accepted++;
        StringBuilder ranges = new StringBuilder();
        for (AddressRange range : walk.body()) {
            if (!ranges.isEmpty()) ranges.append(',');
            ranges.append('"').append(range.getMinAddress()).append('-').append(range.getMaxAddress()).append('"');
        }
        emit.accept(String.format("{\"rule\":\"static-call\",\"start\":\"%s\",\"anchor\":\"%s\",\"start_evidence\":\"%s\",\"instructions\":%d,\"bytes\":%d,\"classification\":\"static-unexecuted\",\"ranges\":[%s]}",
            start.address(), anchor, start.evidence(), walk.code().size(), walk.body().getNumAddresses(), ranges));
    }
}
