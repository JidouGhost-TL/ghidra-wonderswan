// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** R1b: caller reads before redefinition and callee value sources reaching every return.
 * Byte halves are independent; status flags are real one-byte custom storage. A return
 * needs two consuming callers (one for a routine with a single decoded caller).
 * Callers that ignore a result are neutral. Every return path must define the value;
 * entry-value, saved/restored and unresolved paths veto an output, including callers
 * expecting their own pre-call value. Register inputs come from use before definition.
 * Explicit signatures and compiler conventions other than the register convention win.
 * L2 (H2): after a call or interrupt whose outputs are not proven, a read of a unit it may write
 * leaves the input set unknown; no lock is written, and an earlier lock of this rule is reset.
 * Status flags are never inputs. Stack arguments stay outside R1b: the register convention cannot
 * bind them at a call either way, so a frame read does not withdraw a proven register result.
 */
public final class WSReturns {
    static final List<String> UNITS = List.of("AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH",
        "SI", "DI", "BP", "ES", "CF", "ZF", "SF", "OF", "PF", "AF");
    private static final Set<String> SAVE_REGISTERS = Set.of("AX", "BX", "CX", "DX", "SI", "DI", "BP");
    private static final Set<String> FRAME_REGISTERS = Set.of("SP", "BP", "SS");
    static final int WINDOW = 12, MAX_BODY = 4096, MAX_PATH = 400, MAX_WALK = MAX_BODY * 32;
    final Program p;
    final Listing listing;
    final boolean selectableLinearRom;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    final Map<String, Register> units = new LinkedHashMap<>();
    final Map<Function, Graph> graphs = new HashMap<>();
    final Map<String, Integer> supplyCache = new HashMap<>();
    int functions, unchanged, skippedSig, reverted;
    String unknownReason;
    Address unknownAt;
    final Map<String, Integer> regCounts = new TreeMap<>();

    WSReturns(Program p, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor; listing = p.getListing();
        long size = WSRom.size(p), effective = WSHardware.effectiveSize(size);
        long firstLinear = (long) WSHardware.SEG_LINEAR_FIRST << 4;
        selectableLinearRom = size <= 0 || WSHardware.linearToRom(firstLinear, 0, effective)
            != WSHardware.linearToRom(firstLinear, 1, effective);
        for (String n : UNITS) { Register r = p.getRegister(n); if (r != null) units.put(n, r); }
    }
    public static String apply(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        WSReturns r = new WSReturns(p, emit, monitor); r.apply(); return r.summary();
    }
    String summary() {
        return String.format("R1b signatures changed %d, unchanged %d, explicit/compiler signatures skipped %d, reverted %d %s",
            functions, unchanged, skippedSig, reverted, regCounts);
    }
    Set<String> mask(Object[] objects) {
        Set<String> s = new LinkedHashSet<>();
        for (Object o : objects) if (o instanceof Register r)
            for (var u : units.entrySet()) if (r.equals(u.getValue()) || r.contains(u.getValue())) s.add(u.getKey());
        return s;
    }
    Set<String> reads(Instruction i) {
        String m = i.getMnemonicString().toUpperCase();
        if (m.equals("PUSHA") || m.equals("PUSHF") || m.equals("PUSH") || m.startsWith("RET") || m.equals("IRET")) return Set.of();
        if ((m.equals("XOR") || m.equals("SUB")) && i.getNumOperands() == 2
                && i.getDefaultOperandRepresentation(0).equalsIgnoreCase(i.getDefaultOperandRepresentation(1))) return Set.of();
        return mask(i.getInputObjects());
    }
    Set<String> writes(Instruction i) {
        Set<String> result = mask(i.getResultObjects());
        String m = i.getMnemonicString().toUpperCase();
        // A variable-count shift can leave flags untouched when the count is zero.
        // Result objects describe possible writes, rather than writes on every path.
        if (Set.of("SHL", "SHR", "SAR", "SAL", "ROL", "ROR", "RCL", "RCR").contains(m)) {
            var count = i.getNumOperands() > 1 ? i.getScalar(1) : null;
            if (count == null || (count.getUnsignedValue() & 31) == 0)
                result.removeIf(u -> u.endsWith("F"));
        }
        return result;
    }
    boolean explicit(Function f) {
        if (f.getSignatureSource() == SourceType.USER_DEFINED || f.getSignatureSource() == SourceType.IMPORTED) return true;
        for (Parameter v : f.getParameters()) if (v.getSource() == SourceType.USER_DEFINED || v.getSource() == SourceType.IMPORTED) return true;
        String cc = f.getCallingConventionName();
        return cc != null && !cc.equals("unknown") && !cc.equals("default") && !cc.equals("__wsasm")
            && !cc.startsWith(WSCallLocks.PREFIX);
    }
    /** An R1b-shaped lock: analysis custom storage on the register convention with in_ inputs. */
    static boolean ownedLock(Function f) {
        String cc = f.getCallingConventionName();
        if (f.getSignatureSource() != SourceType.ANALYSIS || !f.hasCustomVariableStorage()
                || (cc != null && !cc.equals("unknown") && !cc.equals("default") && !cc.equals("__wsasm"))) return false;
        for (Parameter v : f.getParameters())
            if (v.getSource() != SourceType.ANALYSIS || !v.getName().startsWith("in_")) return false;
        return true;
    }
    void apply() throws Exception {
        // A later callee can acquire inputs needed by an earlier caller. Settle the
        // monotone parameter additions now, rather than on the next trace import.
        int previous;
        do { previous = functions; applyPass(); } while (functions != previous);
        // Established output signatures take precedence over a void leaf with
        // proved AX live-through.
        boolean axLiveThrough = p.getCompilerSpec().getCallingConvention(WSAsmAxLiveThrough.CONVENTION) != null;
        boolean bxLiveThrough = p.getCompilerSpec().getCallingConvention(WSAsmBxLiveThrough.CONVENTION) != null;
        if (axLiveThrough || bxLiveThrough) {
            for (Function f : p.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (axLiveThrough) WSAsmAxLiveThrough.apply(f, emit);
                if (bxLiveThrough) WSAsmBxLiveThrough.apply(f, emit);
            }
        }
    }
    void applyPass() throws Exception {
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isExternal() || f.isThunk()) continue;
            if (explicit(f)) { skippedSig++; continue; }
            Graph g = graph(f); if (g == null || g.returns.isEmpty()) continue;
            List<Instruction> calls = new ArrayList<>();
            for (Reference ref : p.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                if (!ref.getReferenceType().isCall()) continue;
                Instruction call = listing.getInstructionAt(ref.getFromAddress());
                if (call != null && call.getFlowType().isCall() && !call.getFlowType().isComputed()
                        && calls.stream().noneMatch(c -> c.getAddress().equals(call.getAddress()))) calls.add(call);
            }
            if (calls.isEmpty()) continue;
            int required = calls.size() == 1 ? 1 : 2;
            Map<String, List<String>> consumers = new LinkedHashMap<>();
            Map<String, Integer> linearVotes = new HashMap<>();
            boolean selectable = false;
            for (Instruction call : calls) {
                selectable |= selectableInstruction(call)
                    || Arrays.stream(call.getDefaultFlows()).anyMatch(this::selectableAddress);
                selectable |= consumeAfter(call, consumers, linearVotes);
            }
            // A mapped caller or continuation keeps the full prior set and quorum.
            if (!selectable && calls.removeIf(call -> !agreesWithDecodedTarget(call, f.getEntryPoint()))) {
                if (calls.isEmpty()) continue;
                consumers.clear();
                linearVotes.clear();
                for (Instruction call : calls) consumeAfter(call, consumers, linearVotes);
            }
            Set<String> outs = new LinkedHashSet<>(), jumpOutputs = new LinkedHashSet<>();
            for (String u : UNITS) {
                int n = consumers.getOrDefault(u, List.of()).size();
                if (n < required) continue;
                int source = sources(f, u, new HashSet<>());
                if (source == 1) {
                    if (linearVotes.getOrDefault(u, 0) >= required) outs.add(u);
                    else jumpOutputs.add(u);
                }
                else emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"unit\":\"%s\",\"outcome\":\"VETO_SOURCE\",\"sources\":%d,\"consuming_callers\":%d,\"neutral_callers\":%d,\"reads\":\"%s\"}",
                    f.getEntryPoint(), u, source, n, calls.size() - n, consumers.get(u)));
            }
            if (!jumpOutputs.isEmpty()) {
                if (continuationInputsCovered(g)) {
                    outs.addAll(jumpOutputs);
                } else {
                    emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"outcome\":\"VETO_CONTINUATION_INPUTS\",\"units\":\"%s\"}",
                        f.getEntryPoint(), jumpOutputs));
                }
            }
            if (outs.isEmpty()) continue;
            // A rule-owned L1 lock carries the proven inputs; R1b only supplies its return.
            boolean l1 = f.getCallingConventionName() != null && f.getCallingConventionName().startsWith(WSCallLocks.PREFIX);
            Set<String> ins = l1 ? Set.of() : inputs(g);
            if (ins == null) {
                emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"outcome\":\"VETO_INPUTS_UNKNOWN\",\"reason\":\"%s\",\"at\":\"%s\",\"units\":\"%s\"}",
                    f.getEntryPoint(), unknownReason, unknownAt, outs));
                if (ownedLock(f)) {
                    f.updateFunction(f.getCallingConventionName(), new ReturnParameterImpl(DefaultDataType.dataType, p), List.of(),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.DEFAULT);
                    reverted++;
                    emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"outcome\":\"REVERT\",\"reason\":\"%s\"}",
                        f.getEntryPoint(), unknownReason));
                }
                continue;
            }
            setSignature(f, coalesce(outs), coalesce(ins), consumers, calls.size());
        }
    }
    private boolean selectableAddress(Address address) {
        if (address.getAddressSpace().isOverlaySpace()) return true;
        if (!address.isMemoryAddress()) return false;
        long linear = address.getOffset();
        return linear >= ((long) WSHardware.SEG_SRAM << 4)
            && (linear < ((long) WSHardware.SEG_LINEAR_FIRST << 4) || selectableLinearRom);
    }
    private boolean selectableInstruction(Instruction instruction) {
        return selectableAddress(instruction.getMinAddress()) || selectableAddress(instruction.getMaxAddress());
    }
    private static boolean agreesWithDecodedTarget(Instruction call, Address target) {
        Address[] decoded = call.getDefaultFlows();
        if (decoded.length != 1 || !decoded[0].equals(target)
                || call.getFlowType().isConditional() || call.getFlowOverride() != FlowOverride.NONE
                || call.isFallThroughOverridden()) return false;
        for (Reference ref : call.getReferencesFrom()) {
            var type = ref.getReferenceType();
            if (ref.isPrimary() && type.isFlow() && !type.isFallthrough()
                    && (!type.isCall() || type == RefType.CALL_OVERRIDE_UNCONDITIONAL
                        || !target.equals(ref.getToAddress()))) return false;
        }
        return true;
    }
    boolean consumeAfter(Instruction call, Map<String, List<String>> consumers, Map<String, Integer> linearVotes) {
        Set<String> seen = new HashSet<>(), killed = new HashSet<>();
        Set<Address> visited = new HashSet<>();
        Function caller = null;
        boolean followedJump = false, selectable = false;
        Address a = call.getFallThrough();
        for (int n = 0; n < WINDOW && a != null && visited.add(a); n++) {
            if (caller != null && !caller.getBody().contains(a)) break;
            Instruction i = listing.getInstructionAt(a); if (i == null) break;
            selectable |= selectableInstruction(i);
            Set<String> read = reads(i);
            // A single PUSH is a real caller consumption; bulk saves are excluded.
            if (i.getMnemonicString().equalsIgnoreCase("PUSH")) read = mask(i.getInputObjects());
            for (String u : read) if (!killed.contains(u) && seen.add(u)) {
                consumers.computeIfAbsent(u, k -> new ArrayList<>()).add(call.getAddress() + "->" + i.getAddress());
                if (!followedJump) linearVotes.merge(u, 1, Integer::sum);
            }
            killed.addAll(writes(i));
            if (i.getFlowType().isCall() || i.getFlowType().isTerminal()
                    || i.getMnemonicString().toUpperCase().startsWith("INT")) break;
            if (i.getFlowType().isJump()) {
                // A local direct JMP can join this call's continuation with another
                // path. Follow only the instruction's own single, unchanged edge.
                if (caller == null) caller = p.getFunctionManager().getFunctionContaining(call.getAddress());
                Address[] flows = i.getFlows(), defaults = i.getDefaultFlows();
                if (caller == null || !caller.getBody().contains(a) || i.getFlowOverride() != FlowOverride.NONE
                        || !i.getMnemonicString().equals("JMP") || i.getFlowType().isComputed() || i.getFlowType().isConditional()
                        || i.getFallThrough() != null
                        || flows.length != 1 || defaults.length != 1 || !flows[0].equals(defaults[0])
                        || !flows[0].getAddressSpace().equals(a.getAddressSpace())) break;
                a = flows[0];
                followedJump = true;
            } else a = i.getFallThrough();
        }
        return selectable;
    }

    /**
     * Extending caller evidence can newly lock a callee's inputs. The usual input
     * scan ignores pushes and treats pops as definitions. Require a closed leaf
     * whose only stack operations are entry saves and matching terminal restores.
     */
    private boolean continuationInputsCovered(Graph g) {
        Instruction next = g.code.get(g.f.getEntryPoint());
        if (next == null) return false;
        var saved = new ArrayList<String>();
        var frame = new HashSet<Address>();
        Address preceding = null;
        String reg;
        while ((reg = stackRegister(next, "PUSH")) != null) {
            Set<Address> expected = preceding == null ? Set.of() : Set.of(preceding);
            if (!g.pred.getOrDefault(next.getAddress(), Set.of()).equals(expected)
                    || !frame.add(next.getAddress())) return false;
            saved.add(reg);
            preceding = next.getAddress();
            next = g.code.get(next.getFallThrough());
        }
        if (next == null) return false;
        if (!saved.isEmpty()) {
            if (g.returns.size() != 1) return false;
            next = g.returns.get(0);
            for (String register : saved) {
                Address previous = next.getFallFrom();
                if (previous == null || !g.pred.getOrDefault(next.getAddress(), Set.of()).equals(Set.of(previous))) return false;
                next = g.code.get(previous);
                if (!register.equals(stackRegister(next, "POP")) || !frame.add(previous)) return false;
            }
        }
        for (Instruction i : g.code.values()) {
            if (frame.contains(i.getAddress())) continue;
            String mnemonic = i.getMnemonicString();
            if (i.getFlowOverride() != FlowOverride.NONE || i.isFallThroughOverridden()) return false;
            if (mnemonic.equals("RET") || mnemonic.equals("RETF")) {
                if (i.getLength() != 1) return false;
                continue;
            }
            var flow = i.getFlowType();
            if (mnemonic.startsWith("PUSH") || mnemonic.startsWith("POP") || mnemonic.startsWith("INT")
                    || mnemonic.equals("ENTER") || mnemonic.equals("LEAVE")
                    || flow.isCall() || flow.isComputed() || flow.isTerminal()) return false;
            // Operand lists can omit the implicit stack segment of a memory access.
            for (var op : i.getPcode()) {
                if (frameRegister(op.getOutput())) return false;
                for (var input : op.getInputs()) if (frameRegister(input)) return false;
            }
            if (i.getFallThrough() != null && !g.code.containsKey(i.getFallThrough())) return false;
            if (flow.isJump()) {
                Address[] targets = i.getFlows();
                if (!Arrays.equals(targets, i.getDefaultFlows())
                        || targets.length == 0 || Arrays.stream(targets).anyMatch(a -> !g.code.containsKey(a))) return false;
            }
        }
        return true;
    }

    private boolean frameRegister(Varnode storage) {
        if (storage == null || !storage.isRegister()) return false;
        Register register = p.getRegister(storage.getAddress(), storage.getSize());
        return register != null && FRAME_REGISTERS.contains(register.getName());
    }

    private static String stackRegister(Instruction i, String mnemonic) {
        if (i == null || i.getFlowOverride() != FlowOverride.NONE || i.isFallThroughOverridden()
                || !i.getMnemonicString().equals(mnemonic) || i.getNumOperands() != 1 || i.getLength() != 1) return null;
        Object[] operand = i.getOpObjects(0);
        return operand.length == 1 && operand[0] instanceof Register r && SAVE_REGISTERS.contains(r.getName())
            ? r.getName() : null;
    }
    final class Graph {
        final Function f;
        final Map<Address, Instruction> code = new LinkedHashMap<>();
        final Map<Address, Set<Address>> pred = new HashMap<>();
        final List<Instruction> returns = new ArrayList<>();
        final Map<String, Map<Address, Integer>> sources = new HashMap<>();
        Graph(Function f) {
            this.f = f;
            for (Instruction i : listing.getInstructions(f.getBody(), true)) {
                code.put(i.getAddress(), i);
                if (i.getMnemonicString().toUpperCase().startsWith("RET")) returns.add(i);
                if (code.size() > MAX_BODY) break;
            }
            for (Instruction i : code.values()) {
                if (i.getFallThrough() != null && code.containsKey(i.getFallThrough()))
                    pred.computeIfAbsent(i.getFallThrough(), k -> new LinkedHashSet<>()).add(i.getAddress());
                if (i.getFlowType().isJump()) for (Address a : i.getFlows()) if (code.containsKey(a))
                    pred.computeIfAbsent(a, k -> new LinkedHashSet<>()).add(i.getAddress());
            }
        }
    }
    Graph graph(Function f) {
        Graph g = graphs.computeIfAbsent(f, Graph::new);
        return g.code.size() > MAX_BODY ? null : g;
    }
    Function directCallee(Instruction i) {
        if (!i.getFlowType().isCall() || i.getFlowType().isComputed() || i.getFlows().length != 1) return null;
        return p.getFunctionManager().getFunctionAt(i.getFlows()[0]);
    }
    // Definition, entry value, restore, or unresolved source; mixed paths retain input storage.
    boolean supplied(Function f, String unit, Set<String> visiting) {
        int source = sources(f, unit, visiting);
        return source == 1;
    }
    int sources(Function f, String unit, Set<String> visiting) {
        String key = f.getEntryPoint() + "/" + unit;
        Integer cached = supplyCache.get(key); if (cached != null) return cached;
        if (visiting.size() >= 8 || !visiting.add(key)) return 8;
        Graph g = graph(f); int source = 0;
        if (g == null || g.returns.isEmpty()) source = 8;
        else {
            int[] remaining = { MAX_WALK };
            for (Instruction ret : g.returns) {
                source |= before(g, ret.getAddress(), unit, new HashSet<>(), visiting, remaining);
                if ((source & 12) != 0) break;
            }
        }
        visiting.remove(key);
        if ((source & 8) == 0) supplyCache.put(key, source);
        return source;
    }
    int before(Graph g, Address a, String unit, Set<Address> path, Set<String> visiting, int[] remaining) {
        if (--remaining[0] < 0 || path.size() >= MAX_PATH || !path.add(a)) return 8;
        Map<Address, Integer> memo = g.sources.computeIfAbsent(unit, k -> new HashMap<>());
        Integer known = memo.get(a);
        if (known != null) { path.remove(a); return known; }
        Set<Address> pred = g.pred.getOrDefault(a, Set.of());
        if (pred.isEmpty()) { path.remove(a); return 2; }
        int source = 0;
        for (Address b : pred) {
            Instruction i = g.code.get(b); String mn = i.getMnemonicString().toUpperCase();
            if (i.getFlowType().isCall()) {
                Function callee = directCallee(i);
                int callSource = callee == null ? 8 : sources(callee, unit, visiting);
                source |= callSource & 13;
                if ((callSource & 2) != 0) source |= before(g, b, unit, path, visiting, remaining);
            } else if (mn.startsWith("INT") || mn.equals("IRET")) source |= 8;
            else if (writes(i).contains(unit))
                source |= mn.equals("POP") || mn.equals("POPA") || mn.equals("POPF") ? 4 : 1;
            else source |= before(g, b, unit, path, visiting, remaining);
            if ((source & 12) != 0) break;
        }
        // Only completed acyclic proofs are independent of the current path/call stack.
        if ((source & 8) == 0) memo.put(a, source);
        path.remove(a); return source;
    }
    static boolean flag(String unit) { return unit.length() == 2 && unit.endsWith("F") && !unit.equals("DF"); }
    /** Register inputs from use before definition, or null when L2 leaves them unknown. */
    Set<String> inputs(Graph g) {
        Map<Address, Set<String>> defined = new HashMap<>(), tainted = new HashMap<>();
        ArrayDeque<Address> work = new ArrayDeque<>();
        Address entry = g.f.getEntryPoint(); defined.put(entry, new HashSet<>()); tainted.put(entry, new HashSet<>()); work.add(entry);
        Set<String> inputs = new LinkedHashSet<>();
        int steps = 0;
        while (!work.isEmpty() && steps++ < MAX_BODY * 32) {
            Address a = work.remove(); Instruction i = g.code.get(a); if (i == null) continue;
            Set<String> have = new HashSet<>(defined.get(a)), taint = new HashSet<>(tainted.get(a));
            for (String u : reads(i)) if (!have.contains(u) && !flag(u)) {
                if (taint.contains(u)) { unknownReason = "READ_AFTER_UNPROVEN_CALL"; unknownAt = a; return null; }
                inputs.add(u);
            }
            have.addAll(writes(i)); taint.removeAll(writes(i));
            String mn = i.getMnemonicString().toUpperCase();
            if (i.getFlowType().isCall()) {
                Function callee = directCallee(i);
                if (callee != null) {
                    for (Parameter param : callee.getParameters()) for (var vn : param.getVariableStorage().getVarnodes()) {
                        Register r = p.getRegister(vn.getAddress(), vn.getSize());
                        if (r != null) for (String u : mask(new Object[]{r})) if (!have.contains(u) && !flag(u)) {
                            if (taint.contains(u)) { unknownReason = "READ_AFTER_UNPROVEN_CALL"; unknownAt = a; return null; }
                            inputs.add(u);
                        }
                    }
                    for (String u : UNITS) {
                        int source = sources(callee, u, new HashSet<>());
                        if (source == 1) { have.add(u); taint.remove(u); }
                        else if (source != 2) taint.add(u);
                    }
                } else taint.addAll(UNITS);
            } else if (mn.startsWith("INT")) taint.addAll(UNITS);
            List<Address> next = new ArrayList<>();
            if (i.getFallThrough() != null) next.add(i.getFallThrough());
            if (i.getFlowType().isJump()) next.addAll(Arrays.asList(i.getFlows()));
            for (Address b : next) {
                if (!g.code.containsKey(b) || b.equals(entry)) continue;
                Set<String> old = defined.get(b), merged = new HashSet<>(have);
                if (old != null) merged.retainAll(old);
                Set<String> oldTaint = tainted.get(b), mergedTaint = new HashSet<>(taint);
                if (oldTaint != null) mergedTaint.addAll(oldTaint);
                if (old == null || !old.equals(merged) || !oldTaint.equals(mergedTaint)) {
                    defined.put(b, merged); tainted.put(b, mergedTaint); work.add(b);
                }
            }
        }
        return inputs;
    }
    List<Register> coalesce(Set<String> set) {
        List<Register> regs = new ArrayList<>(); Set<String> done = new HashSet<>();
        for (String u : UNITS) {
            if (!set.contains(u) || done.contains(u)) continue;
            if (u.length() == 2 && u.endsWith("L") && set.contains(u.charAt(0) + "H")) {
                regs.add(p.getRegister(u.charAt(0) + "X")); done.add(u.charAt(0) + "H");
            } else regs.add(units.get(u));
        }
        return regs;
    }
    DataType type(Register r) { return r.getBitLength() <= 8 ? (r.getName().endsWith("F") ? BooleanDataType.dataType : ByteDataType.dataType) : WordDataType.dataType; }
    void setSignature(Function f, List<Register> outputs, List<Register> inputs,
            Map<String, List<String>> consumers, int callers) throws Exception {
        int bytes = outputs.stream().mapToInt(r -> Math.max(1, r.getBitLength() / 8)).sum();
        DataType result;
        if (outputs.size() == 1) result = type(outputs.get(0));
        else {
            CategoryPath category = new CategoryPath("/WonderSwan/Registers");
            // The native join receives VariableStorage pieces from most to least significant.
            // Little-endian structure offsets start at the least significant byte.
            List<Register> fields = p.getLanguage().isBigEndian() ? outputs : outputs.reversed();
            String shape = String.join("_", fields.stream().map(Register::getName).toList());
            StructureDataType st = new StructureDataType(category, "result_joined_" + shape, 0);
            for (Register r : fields) st.add(type(r), "out_" + r.getName(), null);
            // Keep the legacy type intact, including references outside this analysis.
            DataType existing = p.getDataTypeManager().getDataType(category, st.getName());
            if (existing != null && !st.isEquivalent(existing)) {
                emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"outcome\":\"VETO_RESULT_LAYOUT\"}",
                    f.getEntryPoint()));
                return;
            }
            result = existing == null ? st : existing;
        }
        VariableStorage storage = new VariableStorage(p, outputs.toArray(new Register[0]));
        if (storage.size() != bytes || result.getLength() != bytes) throw new IllegalStateException("R1b result size mismatch");
        List<Variable> params = new ArrayList<>(Arrays.asList(f.getParameters()));
        if (f.getCallingConventionName() != null && f.getCallingConventionName().startsWith(WSCallLocks.PREFIX)) inputs = List.of();
        for (Register r : inputs) {
            VariableStorage s = new VariableStorage(p, r);
            if (params.stream().anyMatch(v -> v.getVariableStorage().intersects(s))) continue;
            params.add(new ParameterImpl("in_" + r.getName(), type(r), s, p, SourceType.ANALYSIS));
        }
        boolean same = f.hasCustomVariableStorage() && storage.equals(f.getReturn().getVariableStorage())
            && result.isEquivalent(f.getReturnType()) && params.size() == f.getParameterCount();
        if (same) { unchanged++; return; }
        ReturnParameterImpl ret = new ReturnParameterImpl(result, storage, p);
        f.updateFunction(f.getCallingConventionName(), ret, params, Function.FunctionUpdateType.CUSTOM_STORAGE, true,
            SourceType.ANALYSIS);
        functions++;
        for (Register r : outputs) regCounts.merge(r.getName(), 1, Integer::sum);
        List<String> votes = new ArrayList<>(), neutral = new ArrayList<>();
        for (String u : UNITS) if (outputs.stream().anyMatch(r -> r.equals(units.get(u)) || r.contains(units.get(u)))) {
            int n = consumers.getOrDefault(u, List.of()).size();
            votes.add("\"" + u + "\":" + n); neutral.add("\"" + u + "\":" + (callers - n));
        }
        emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"outcome\":\"SET\",\"returns\":\"%s\",\"inputs\":\"%s\",\"callers\":%d,\"consuming_callers\":{%s},\"neutral_callers\":{%s},\"reads\":\"%s\"}",
            f.getEntryPoint(), storage, inputs, callers, String.join(",", votes), String.join(",", neutral), consumers));
    }
}
