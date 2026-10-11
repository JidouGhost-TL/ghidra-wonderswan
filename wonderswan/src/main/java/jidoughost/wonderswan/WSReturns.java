// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** R1b: caller reads before redefinition and callee value sources reaching every return.
 * Byte halves are independent; status flags are real one-byte custom storage. A return
 * needs two consuming callers (one for a routine with a single decoded caller).
 * Callers that ignore a result are neutral. Every return path must define the value;
 * entry-value, saved/restored and unresolved paths veto an output, including callers
 * expecting their own pre-call value. Register inputs come from use before definition.
 * Explicit signatures and compiler conventions other than the register convention win.
 */
public final class WSReturns {
    static final List<String> UNITS = List.of("AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH",
        "SI", "DI", "BP", "ES", "CF", "ZF", "SF", "OF", "PF", "AF");
    static final int WINDOW = 12, MAX_BODY = 4096, MAX_PATH = 400, MAX_WALK = MAX_BODY * 32;
    final Program p;
    final Listing listing;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    final Map<String, Register> units = new LinkedHashMap<>();
    final Map<Function, Graph> graphs = new HashMap<>();
    final Map<String, Integer> supplyCache = new HashMap<>();
    int functions, unchanged, skippedSig;
    final Map<String, Integer> regCounts = new TreeMap<>();

    WSReturns(Program p, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor; listing = p.getListing();
        for (String n : UNITS) { Register r = p.getRegister(n); if (r != null) units.put(n, r); }
    }
    public static String apply(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        WSReturns r = new WSReturns(p, emit, monitor); r.apply(); return r.summary();
    }
    String summary() {
        return String.format("R1b signatures changed %d, unchanged %d, explicit/compiler signatures skipped %d %s",
            functions, unchanged, skippedSig, regCounts);
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
        return cc != null && !cc.equals("unknown") && !cc.equals("default") && !cc.equals("__wsasm");
    }
    void apply() throws Exception {
        // A later callee can acquire inputs needed by an earlier caller. Settle the
        // monotone parameter additions now, rather than on the next trace import.
        int previous;
        do { previous = functions; applyPass(); } while (functions != previous);
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
            Map<String, List<String>> consumers = new LinkedHashMap<>();
            for (Instruction call : calls) consumeAfter(call, consumers);
            Set<String> outs = new LinkedHashSet<>();
            for (String u : UNITS) {
                int n = consumers.getOrDefault(u, List.of()).size();
                if (n < (calls.size() == 1 ? 1 : 2)) continue;
                int source = sources(f, u, new HashSet<>());
                if (source == 1) outs.add(u);
                else emit.accept(String.format("{\"rule\":\"R1b\",\"function\":\"%s\",\"unit\":\"%s\",\"outcome\":\"VETO_SOURCE\",\"sources\":%d,\"consuming_callers\":%d,\"neutral_callers\":%d,\"reads\":\"%s\"}",
                    f.getEntryPoint(), u, source, n, calls.size() - n, consumers.get(u)));
            }
            if (outs.isEmpty()) continue;
            Set<String> ins = inputs(g);
            setSignature(f, coalesce(outs), coalesce(ins), consumers, calls.size());
        }
    }
    void consumeAfter(Instruction call, Map<String, List<String>> consumers) {
        Set<String> seen = new HashSet<>(), killed = new HashSet<>();
        Address a = call.getFallThrough();
        for (int n = 0; n < WINDOW && a != null; n++) {
            Instruction i = listing.getInstructionAt(a); if (i == null) break;
            Set<String> read = reads(i);
            // A single PUSH is a real caller consumption; bulk saves are excluded.
            if (i.getMnemonicString().equalsIgnoreCase("PUSH")) read = mask(i.getInputObjects());
            for (String u : read) if (!killed.contains(u) && seen.add(u))
                consumers.computeIfAbsent(u, k -> new ArrayList<>()).add(call.getAddress() + "->" + i.getAddress());
            killed.addAll(writes(i));
            if (i.getFlowType().isCall() || i.getFlowType().isJump() || i.getFlowType().isTerminal()
                    || i.getMnemonicString().toUpperCase().startsWith("INT")) break;
            a = i.getFallThrough();
        }
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
    Set<String> inputs(Graph g) {
        Map<Address, Set<String>> defined = new HashMap<>();
        ArrayDeque<Address> work = new ArrayDeque<>();
        Address entry = g.f.getEntryPoint(); defined.put(entry, new HashSet<>()); work.add(entry);
        Set<String> inputs = new LinkedHashSet<>();
        int steps = 0;
        while (!work.isEmpty() && steps++ < MAX_BODY * 32) {
            Address a = work.remove(); Instruction i = g.code.get(a); if (i == null) continue;
            Set<String> have = new HashSet<>(defined.get(a));
            for (String u : reads(i)) if (!have.contains(u)) inputs.add(u);
            have.addAll(writes(i));
            if (i.getFlowType().isCall()) {
                Function callee = directCallee(i);
                if (callee != null) {
                    for (Parameter param : callee.getParameters()) for (var vn : param.getVariableStorage().getVarnodes()) {
                        Register r = p.getRegister(vn.getAddress(), vn.getSize());
                        if (r != null) for (String u : mask(new Object[]{r})) if (!have.contains(u)) inputs.add(u);
                    }
                    for (String u : UNITS) if (supplied(callee, u, new HashSet<>())) have.add(u);
                }
            }
            List<Address> next = new ArrayList<>();
            if (i.getFallThrough() != null) next.add(i.getFallThrough());
            if (i.getFlowType().isJump()) next.addAll(Arrays.asList(i.getFlows()));
            for (Address b : next) {
                if (!g.code.containsKey(b) || b.equals(entry)) continue;
                Set<String> old = defined.get(b), merged = new HashSet<>(have);
                if (old != null) merged.retainAll(old);
                if (old == null || !old.equals(merged)) { defined.put(b, merged); work.add(b); }
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
            String shape = String.join("_", outputs.stream().map(Register::getName).toList());
            StructureDataType st = new StructureDataType(new CategoryPath("/WonderSwan/Registers"), "result_" + shape, 0);
            for (Register r : outputs) st.add(type(r), "out_" + r.getName(), null);
            result = st;
        }
        VariableStorage storage = new VariableStorage(p, outputs.toArray(new Register[0]));
        if (storage.size() != bytes || result.getLength() != bytes) throw new IllegalStateException("R1b result size mismatch");
        List<Variable> params = new ArrayList<>(Arrays.asList(f.getParameters()));
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
