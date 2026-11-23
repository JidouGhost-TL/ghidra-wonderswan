// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;

import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * L1 + P1: lock proven register interfaces of register-convention routines.
 *
 * <p>The proof is an abstract walk of the routine's own instructions on every path. Each register
 * byte unit carries the set of entry values it may hold; a stack slot carries the same for both of
 * its bytes. A PUSH copies, a POP restores, a register-to-register move copies. An input is an
 * entry value that an instruction reads; a save (PUSH r ... POP r) is therefore no read. A call to a
 * routine with its own proof reads that routine's inputs and keeps the units it preserves. A unit is
 * preserved when every return yields exactly its entry value, and killed otherwise.
 *
 * <p>Vetoes (the interface stays unknown and keeps the default): unresolved or indirect calls,
 * callees without a proof, computed jumps, flow outside the body or overridden, interrupts, RAM or
 * writable bodies, an unresolved bank window, stack frames or reads at or above the return address,
 * unbalanced stacks, entry flag reads, a changed DS, and an AX result some caller may consume when
 * R1b proved no return.
 *
 * <p>A lock writes custom-storage parameters, keeps an R1b return or writes VOID, and assigns a
 * generated prototype model __wsasm_p&lt;mask&gt; whose killed and unaffected lists are this routine's
 * killed and preserved units. Signatures owned by the rule are reset when the proof goes away.
 * Explicit (user or imported) signatures and other conventions are never touched.
 */
public final class WSCallLocks {
    public static final String PREFIX = "__wsasm_p";
    static final String BASE = "__wsasm";
    /** Model units in mask order: bit i = preserved, bit 12+i = killed. */
    static final List<String> MODEL_UNITS = List.of("AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH", "SI", "DI", "BP", "ES");
    static final List<String> FLAGS = List.of("CF", "PF", "AF", "ZF", "SF", "OF");
    static final Set<String> WORD_UNITS = Set.of("SI", "DI", "BP", "ES", "DS");
    static final String OTHER = "*";
    static final int MAX_BODY = 4096, MAX_STEPS = 200_000, MAX_DEPTH = 24, DEMAND_STEPS = 512;

    final Program p;
    final Listing listing;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    final Map<Long, String> unitAt = new HashMap<>();
    final Map<Function, Summary> summaries = new HashMap<>();
    final Set<Function> active = new HashSet<>();
    int set, unchanged, vetoed, reverted, skipped, models;
    final Map<String, Integer> reasons = new TreeMap<>();

    /** Proof result: null veto means proven. */
    static final class Summary {
        String veto;
        Address at;
        boolean far;
        final Set<String> inputs = new LinkedHashSet<>(), preserved = new LinkedHashSet<>(), killed = new LinkedHashSet<>();
        static Summary veto(String reason, Address at) { Summary s = new Summary(); s.veto = reason; s.at = at; return s; }
    }

    static final class Veto extends Exception {
        final String reason; final Address at;
        Veto(String reason, Address at) { super(reason, null, false, false); this.reason = reason; this.at = at; }
    }

    /** Entry-value sets per unit and a word stack of (low, high) byte sets. */
    static final class State {
        final Map<String, Set<String>> units = new HashMap<>();
        final ArrayList<Set<String>[]> stack = new ArrayList<>();
        State copy() {
            State s = new State();
            units.forEach((k, v) -> s.units.put(k, new HashSet<>(v)));
            for (Set<String>[] slot : stack) s.stack.add(slot(new HashSet<>(slot[0]), new HashSet<>(slot[1])));
            return s;
        }
        /** Union into this; true when anything grew. */
        boolean join(State o, Address at) throws Veto {
            if (o.stack.size() != stack.size()) throw new Veto("STACK_JOIN", at);
            boolean grew = false;
            for (var e : o.units.entrySet()) grew |= units.computeIfAbsent(e.getKey(), k -> new HashSet<>()).addAll(e.getValue());
            for (int i = 0; i < stack.size(); i++) {
                grew |= stack.get(i)[0].addAll(o.stack.get(i)[0]);
                grew |= stack.get(i)[1].addAll(o.stack.get(i)[1]);
            }
            return grew;
        }
    }

    @SuppressWarnings("unchecked")
    static Set<String>[] slot(Set<String> lo, Set<String> hi) { return new Set[] { lo, hi }; }

    WSCallLocks(Program p, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor; listing = p.getListing();
        List<String> names = new ArrayList<>(MODEL_UNITS);
        names.addAll(List.of("SP", "CS", "SS", "DS"));
        names.addAll(FLAGS);
        for (String n : names) {
            Register r = p.getRegister(n);
            if (r == null) continue;
            for (int b = 0; b < r.getMinimumByteSize(); b++) unitAt.put((long) r.getOffset() + b, n);
        }
    }

    /** R1b (with its L2 veto) then L1 + P1; R1b runs again when L1 reset a signature. */
    public static String applyAll(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        String r1 = WSReturns.apply(p, emit, monitor);
        WSCallLocks l = new WSCallLocks(p, emit, monitor);
        l.apply();
        if (l.reverted > 0) r1 = WSReturns.apply(p, emit, monitor);
        return r1 + ", " + l.summary();
    }

    /** L1 + P1 only (the analyzer runs R1b as its own rule first). */
    public static String applyLocks(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        WSCallLocks l = new WSCallLocks(p, emit, monitor);
        l.apply();
        String r = l.summary();
        if (l.reverted > 0) r += ", " + WSReturns.apply(p, emit, monitor);
        return r;
    }

    String summary() {
        return String.format("L1 locks set %d, unchanged %d, vetoed %d, reverted %d, explicit skipped %d, P1 models added %d %s",
            set, unchanged, vetoed, reverted, skipped, models, reasons);
    }

    static boolean owned(Function f) {
        String cc = f.getCallingConventionName();
        return cc != null && cc.startsWith(PREFIX) && f.getSignatureSource() == SourceType.ANALYSIS;
    }

    /** C1: a rule-owned model outside the register convention family is reset to that family. */
    static boolean reconcileConvention(Function f, String family, Consumer<String> emit) throws Exception {
        String cc = f.getCallingConventionName();
        if (cc == null || !cc.startsWith(PREFIX)) return false;
        if (!BASE.equals(family) && owned(f)) {
            reset(f, family);
            emit.accept(String.format("{\"rule\":\"L1\",\"function\":\"%s\",\"outcome\":\"REVERT\",\"reason\":\"CONVENTION_%s\"}",
                f.getEntryPoint(), family));
        }
        return true;
    }

    static void reset(Function f, String convention) throws Exception {
        f.updateFunction(convention, new ReturnParameterImpl(DefaultDataType.dataType, f.getProgram()), List.of(),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.DEFAULT);
    }

    static boolean explicit(Function f) {
        if (f.getSignatureSource() == SourceType.USER_DEFINED || f.getSignatureSource() == SourceType.IMPORTED) return true;
        for (Parameter v : f.getParameters())
            if (v.getSource() == SourceType.USER_DEFINED || v.getSource() == SourceType.IMPORTED) return true;
        String cc = f.getCallingConventionName();
        return cc != null && !cc.equals("unknown") && !cc.equals("default") && !cc.equals(BASE) && !cc.startsWith(PREFIX);
    }

    void apply() throws Exception {
        WSReturns r = new WSReturns(p, emit, monitor);
        List<Function> all = new ArrayList<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) all.add(f);
        for (Function f : all) {
            monitor.checkCancelled();
            if (f.isExternal() || f.isThunk()) continue;
            if (explicit(f)) { skipped++; continue; }
            boolean owned = owned(f);
            List<Instruction> calls = callSites(f);
            if (calls.isEmpty()) {
                if (owned) revert(f, "NO_DIRECT_CALLERS");
                continue;
            }
            Summary s = summary(f, 0);
            if (s.veto != null) { veto(f, s.veto, s.at, owned); continue; }
            Parameter oldReturn = f.getReturn();
            boolean proven = f.hasCustomVariableStorage() && f.getSignatureSource() == SourceType.ANALYSIS
                && !oldReturn.getVariableStorage().isVoidStorage() && !oldReturn.getVariableStorage().isUnassignedStorage()
                && !Undefined.isUndefined(oldReturn.getDataType()) && !(oldReturn.getDataType() instanceof VoidDataType);
            ReturnParameterImpl ret;
            if (proven) {
                Set<String> out = units(oldReturn.getVariableStorage());
                if (out.contains("?") || !s.killed.containsAll(out)) { veto(f, "RETURN_NOT_WRITTEN", f.getEntryPoint(), owned); continue; }
                ret = new ReturnParameterImpl(oldReturn.getDataType(), oldReturn.getVariableStorage(), p);
            } else {
                Instruction consumer = null;
                for (String u : List.of("AL", "AH")) {
                    if (!s.killed.contains(u)) continue;
                    for (Instruction call : calls) if (demand(call, u) != 0) { consumer = call; break; }
                    if (consumer != null) break;
                }
                if (consumer != null) { veto(f, "UNPROVEN_OUTPUT", consumer.getAddress(), owned); continue; }
                ret = new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, p);
            }
            List<Variable> params = new ArrayList<>();
            for (Register reg : r.coalesce(s.inputs))
                params.add(new ParameterImpl("in_" + reg.getName(), r.type(reg), new VariableStorage(p, reg), p, SourceType.ANALYSIS));
            String model = model(s);
            boolean same = model.equals(f.getCallingConventionName()) && f.hasCustomVariableStorage()
                && f.getSignatureSource() == SourceType.ANALYSIS
                && ret.getVariableStorage().equals(oldReturn.getVariableStorage()) && ret.getDataType().isEquivalent(oldReturn.getDataType())
                && params.size() == f.getParameterCount();
            for (int i = 0; same && i < params.size(); i++)
                same = params.get(i).getVariableStorage().equals(f.getParameter(i).getVariableStorage());
            if (same) { unchanged++; continue; }
            f.updateFunction(model, ret, params, Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
            set++;
            emit.accept(String.format("{\"rule\":\"L1\",\"function\":\"%s\",\"outcome\":\"SET\",\"inputs\":\"%s\",\"return\":\"%s\",\"model\":\"%s\",\"preserved\":\"%s\",\"killed\":\"%s\",\"far\":%b,\"callers\":%d,\"r1b_return\":%b}",
                f.getEntryPoint(), s.inputs, ret.getVariableStorage(), model, s.preserved, s.killed, s.far, calls.size(), proven));
        }
    }

    void veto(Function f, String reason, Address at, boolean owned) throws Exception {
        vetoed++;
        reasons.merge(reason, 1, Integer::sum);
        emit.accept(String.format("{\"rule\":\"L1\",\"function\":\"%s\",\"outcome\":\"VETO\",\"reason\":\"%s\",\"at\":\"%s\"}",
            f.getEntryPoint(), reason, at));
        if (owned) revert(f, reason);
    }

    void revert(Function f, String reason) throws Exception {
        reset(f, BASE);
        reverted++;
        emit.accept(String.format("{\"rule\":\"L1\",\"function\":\"%s\",\"outcome\":\"REVERT\",\"reason\":\"%s\"}", f.getEntryPoint(), reason));
    }

    List<Instruction> callSites(Function f) {
        List<Instruction> calls = new ArrayList<>();
        for (Reference ref : p.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
            if (!ref.getReferenceType().isCall()) continue;
            Instruction call = listing.getInstructionAt(ref.getFromAddress());
            if (call == null || !call.getFlowType().isCall() || call.getFlowType().isComputed()
                    || call.getFlowOverride() != FlowOverride.NONE) continue;
            Address[] flows = call.getFlows();
            if (flows.length != 1 || !flows[0].equals(f.getEntryPoint())) continue;
            if (calls.stream().noneMatch(c -> c.getAddress().equals(call.getAddress()))) calls.add(call);
        }
        return calls;
    }

    // ---- P1 models -------------------------------------------------------------------------------

    static int mask(Collection<String> preserved, Collection<String> killed) {
        int m = 0;
        for (int i = 0; i < MODEL_UNITS.size(); i++) {
            if (preserved.contains(MODEL_UNITS.get(i))) m |= 1 << i;
            if (killed.contains(MODEL_UNITS.get(i))) m |= 1 << (12 + i);
        }
        return m;
    }

    static String modelName(int mask) { return PREFIX + String.format("%06x", mask); }

    /** Registers for a unit set: the word register when both halves are present, else the byte. */
    static List<String> registers(Collection<String> units) {
        List<String> out = new ArrayList<>();
        for (String w : List.of("A", "B", "C", "D")) {
            boolean lo = units.contains(w + "L"), hi = units.contains(w + "H");
            if (lo && hi) out.add(w + "X");
            else if (lo) out.add(w + "L");
            else if (hi) out.add(w + "H");
        }
        for (String u : List.of("SI", "DI", "BP", "ES")) if (units.contains(u)) out.add(u);
        return out;
    }

    static String modelXml(int mask) {
        Set<String> preserved = new LinkedHashSet<>(), killed = new LinkedHashSet<>();
        for (int i = 0; i < MODEL_UNITS.size(); i++) {
            if ((mask & (1 << i)) != 0) preserved.add(MODEL_UNITS.get(i));
            if ((mask & (1 << (12 + i))) != 0) killed.add(MODEL_UNITS.get(i));
        }
        StringBuilder x = new StringBuilder("<prototype name=\"").append(modelName(mask))
            .append("\" extrapop=\"unknown\" stackshift=\"2\" strategy=\"register\"><input>");
        for (String r : List.of("AX", "BX", "CX", "DX", "SI", "DI"))
            x.append("<pentry minsize=\"1\" maxsize=\"2\"><register name=\"").append(r).append("\"/></pentry>");
        for (String r : List.of("ES", "BP"))
            x.append("<pentry minsize=\"2\" maxsize=\"2\"><register name=\"").append(r).append("\"/></pentry>");
        x.append("</input><output><pentry minsize=\"1\" maxsize=\"2\"><register name=\"AX\"/></pentry></output>");
        List<String> k = registers(killed);
        // The cspec grammar rejects an empty list: no killed register means no element.
        if (!k.isEmpty()) {
            x.append("<killedbycall>");
            for (String r : k) x.append("<register name=\"").append(r).append("\"/>");
            x.append("</killedbycall>");
        }
        x.append("<unaffected>");
        for (String r : List.of("SP", "DS", "CS", "SS", "DF")) x.append("<register name=\"").append(r).append("\"/>");
        for (String r : registers(preserved)) x.append("<register name=\"").append(r).append("\"/>");
        return x.append("</unaffected></prototype>").toString();
    }

    String model(Summary s) throws Exception {
        int mask = mask(s.preserved, s.killed);
        String name = modelName(mask);
        if (p.getCompilerSpec().getCallingConvention(name) == null) {
            new SpecExtension(p).addReplaceCompilerSpecExtension(modelXml(mask), monitor);
            models++;
        }
        return name;
    }

    // ---- proof -----------------------------------------------------------------------------------

    Set<String> units(VariableStorage storage) {
        Set<String> out = new LinkedHashSet<>();
        for (Varnode v : storage.getVarnodes()) {
            if (!v.isRegister()) { out.add("?"); continue; }
            out.addAll(unitsOf(v));
        }
        return out;
    }

    Set<String> unitsOf(Varnode v) {
        Set<String> out = new LinkedHashSet<>();
        for (int b = 0; b < v.getSize(); b++) {
            String u = unitAt.get(v.getOffset() + b);
            if (u != null) out.add(u);
        }
        return out;
    }

    static boolean bankWindow(Address a) {
        if (a.getAddressSpace().isOverlaySpace() || !a.isMemoryAddress()) return false;
        long linear = a.getOffset();
        return linear >= ((long) WSHardware.SEG_SRAM << 4) && linear < ((long) WSHardware.SEG_LINEAR_FIRST << 4);
    }

    Summary summary(Function f, int depth) {
        Summary known = summaries.get(f);
        if (known != null) return known;
        if (depth > MAX_DEPTH) return Summary.veto("CALL_DEPTH", f.getEntryPoint());
        if (!active.add(f)) return Summary.veto("RECURSION", f.getEntryPoint());
        Summary s;
        try { s = prove(f, depth); }
        catch (Veto v) { s = Summary.veto(v.reason, v.at); }
        finally { active.remove(f); }
        // A cycle veto depends on the current call stack; keep only final results.
        if (s.veto == null || active.isEmpty() || !s.veto.endsWith("RECURSION")) summaries.put(f, s);
        return s;
    }

    Summary prove(Function f, int depth) throws Veto {
        Address entry = f.getEntryPoint();
        if (f.isExternal() || f.isThunk()) throw new Veto("THUNK_OR_EXTERNAL", entry);
        if (f.getCallFixup() != null) throw new Veto("CALL_FIXUP", entry);
        var block = p.getMemory().getBlock(entry);
        if (block == null || !block.isInitialized() || block.isWrite() || WSRamCode.isRam(p, entry)) throw new Veto("RAM_BODY", entry);
        if (bankWindow(entry)) throw new Veto("UNRESOLVED_BANK", entry);
        if (f.getBody().getNumAddresses() > MAX_BODY) throw new Veto("BODY_LIMIT", entry);

        Summary s = new Summary();
        State start = new State();
        for (String u : unitAt.values()) start.units.put(u, new HashSet<>(Set.of(u)));
        Map<Address, State> in = new HashMap<>();
        in.put(entry, start);
        ArrayDeque<Address> work = new ArrayDeque<>(List.of(entry));
        List<State> exits = new ArrayList<>();
        Boolean far = null;
        int steps = 0;
        while (!work.isEmpty()) {
            if (++steps > MAX_STEPS) throw new Veto("STEP_LIMIT", entry);
            Address a = work.poll();
            Instruction i = listing.getInstructionAt(a);
            if (i == null) throw new Veto("NO_INSTRUCTION", a);
            if (!f.getBody().contains(i.getMinAddress(), i.getMaxAddress())) throw new Veto("FLOW_OUTSIDE_BODY", a);
            if (i.getFlowOverride() != FlowOverride.NONE || i.isFallThroughOverridden()) throw new Veto("FLOW_OVERRIDE", a);
            State st = in.get(a).copy();
            String m = i.getMnemonicString().toUpperCase(Locale.ROOT);
            var flow = i.getFlowType();
            List<Address> next = new ArrayList<>();
            if (m.equals("RET") || m.equals("RETF")) {
                if (i.getNumOperands() != 0) throw new Veto("STACK_ARGUMENTS", a);
                if (!st.stack.isEmpty()) throw new Veto("STACK_UNBALANCED", a);
                boolean isFar = m.equals("RETF");
                if (far != null && far != isFar) throw new Veto("RETURN_KIND", a);
                far = isFar;
                exits.add(st);
                continue;
            }
            if (m.equals("IRET") || m.startsWith("INT")) throw new Veto("INTERRUPT", a);
            if (m.equals("ENTER") || m.equals("LEAVE")) throw new Veto("STACK_FRAME", a);
            if (flow.isComputed()) throw new Veto(flow.isCall() ? "UNRESOLVED_CALL" : "COMPUTED_FLOW", a);
            if (flow.isCall()) call(i, st, s, depth);
            else if (!stackOp(i, m, st, s) && !copy(i, m, st, s)) generic(i, m, st, s);
            if (flow.isTerminal() && !flow.isCall()) continue;
            if (i.getFallThrough() != null) next.add(i.getFallThrough());
            if (flow.isJump()) next.addAll(Arrays.asList(i.getFlows()));
            for (Address b : next) {
                if (!f.getBody().contains(b)) throw new Veto("FLOW_OUTSIDE_BODY", b);
                State old = in.get(b);
                if (old == null) { in.put(b, st.copy()); work.add(b); }
                else if (old.join(st, b)) work.add(b);
            }
        }
        if (exits.isEmpty()) throw new Veto("NO_RETURN", entry);
        s.far = far;
        for (String u : MODEL_UNITS) {
            boolean kept = true;
            for (State e : exits) kept &= e.units.getOrDefault(u, Set.of()).equals(Set.of(u));
            (kept ? s.preserved : s.killed).add(u);
        }
        for (State e : exits) if (!e.units.getOrDefault("DS", Set.of()).equals(Set.of("DS"))) throw new Veto("DS_CHANGED", entry);
        return s;
    }

    /** An instruction reads unit u: every entry value it may hold is an input. */
    void read(State st, String u, Summary s, Address at) throws Veto {
        for (String t : st.units.getOrDefault(u, Set.of())) {
            if (t.equals(OTHER) || t.equals("DS") || t.equals("CS") || t.equals("SS") || t.equals("SP")) continue;
            if (FLAGS.contains(t)) throw new Veto("FLAG_INPUT", at);
            s.inputs.add(t);
        }
    }

    void effects(Instruction i, Set<String> reads, Set<String> writes) {
        Set<String> written = new HashSet<>();
        for (PcodeOp op : i.getPcode()) {
            for (Varnode v : op.getInputs())
                if (v.isRegister()) for (String u : unitsOf(v)) if (!written.contains(u)) reads.add(u);
            Varnode out = op.getOutput();
            if (out != null && out.isRegister()) for (String u : unitsOf(out)) { written.add(u); writes.add(u); }
        }
    }

    void generic(Instruction i, String m, State st, Summary s) throws Veto {
        Set<String> reads = new LinkedHashSet<>(), writes = new LinkedHashSet<>();
        effects(i, reads, writes);
        if ((m.equals("XOR") || m.equals("SUB")) && i.getNumOperands() == 2
                && i.getDefaultOperandRepresentation(0).equalsIgnoreCase(i.getDefaultOperandRepresentation(1)))
            reads.removeAll(writes);
        if (reads.contains("SP")) throw new Veto("STACK_FRAME", i.getAddress());
        if (writes.contains("SP") || writes.contains("SS")) throw new Veto("STACK_POINTER", i.getAddress());
        for (String u : reads) read(st, u, s, i.getAddress());
        for (String u : writes) st.units.put(u, new HashSet<>(Set.of(OTHER)));
    }

    /** Byte halves of a register: (low, high) unit names; word units name themselves twice. */
    static String[] halves(Register r) {
        String n = r.getName();
        if (n.length() == 2 && "ABCD".indexOf(n.charAt(0)) >= 0) {
            char c = n.charAt(1);
            if (c == 'X') return new String[] { n.charAt(0) + "L", n.charAt(0) + "H" };
            if (c == 'L' || c == 'H') return new String[] { n };
        }
        if (WORD_UNITS.contains(n)) return new String[] { n, n };
        return null;
    }

    Set<String>[] value(State st, Register r) {
        String[] h = halves(r);
        if (h == null || h.length != 2) return slot(new HashSet<>(Set.of(OTHER)), new HashSet<>(Set.of(OTHER)));
        return slot(new HashSet<>(st.units.get(h[0])), new HashSet<>(st.units.get(h[1])));
    }

    void assign(State st, Register r, Set<String>[] v) {
        String[] h = halves(r);
        if (h[0].equals(h[1])) {
            Set<String> both = new HashSet<>(v[0]); both.addAll(v[1]);
            st.units.put(h[0], both);
        } else { st.units.put(h[0], new HashSet<>(v[0])); st.units.put(h[1], new HashSet<>(v[1])); }
    }

    static Register register(Instruction i, int operand) {
        if (operand >= i.getNumOperands() || !OperandType.isRegister(i.getOperandType(operand))) return null;
        Object[] o = i.getOpObjects(operand);
        return o.length == 1 && o[0] instanceof Register r ? r : null;
    }

    /** Address registers of a memory operand are reads; SP-based addressing is a frame access. */
    void operandReads(Instruction i, State st, Summary s) throws Veto {
        Set<String> reads = new LinkedHashSet<>(), writes = new LinkedHashSet<>();
        effects(i, reads, writes);
        reads.remove("SP"); reads.remove("SS");
        for (int k = 0; k < i.getNumOperands(); k++) {
            if (OperandType.isRegister(i.getOperandType(k))) {
                Register r = register(i, k);
                if (r != null) for (String u : unitsOf(r)) reads.remove(u);
            }
        }
        for (String u : reads) read(st, u, s, i.getAddress());
    }

    Set<String> unitsOf(Register r) {
        Set<String> out = new LinkedHashSet<>();
        for (int b = 0; b < r.getMinimumByteSize(); b++) { String u = unitAt.get((long) r.getOffset() + b); if (u != null) out.add(u); }
        return out;
    }

    boolean stackOp(Instruction i, String m, State st, Summary s) throws Veto {
        Address a = i.getAddress();
        switch (m) {
            case "PUSH" -> {
                Register r = register(i, 0);
                if (r != null && halves(r) != null && halves(r).length == 2) st.stack.add(value(st, r));
                else {
                    if (r == null) operandReads(i, st, s);
                    st.stack.add(slot(new HashSet<>(Set.of(OTHER)), new HashSet<>(Set.of(OTHER))));
                }
                return true;
            }
            case "POP" -> {
                if (st.stack.isEmpty()) throw new Veto("STACK_UNDERFLOW", a);
                Set<String>[] v = st.stack.remove(st.stack.size() - 1);
                Register r = register(i, 0);
                if (r != null) {
                    if (halves(r) == null || halves(r).length != 2) throw new Veto("STACK_POINTER", a);
                    assign(st, r, v);
                } else operandReads(i, st, s);
                return true;
            }
            case "PUSHA" -> {
                for (String n : List.of("AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI")) st.stack.add(value(st, p.getRegister(n)));
                return true;
            }
            case "POPA" -> {
                if (st.stack.size() < 8) throw new Veto("STACK_UNDERFLOW", a);
                for (String n : List.of("DI", "SI", "BP", "SP", "BX", "DX", "CX", "AX")) {
                    Set<String>[] v = st.stack.remove(st.stack.size() - 1);
                    if (!n.equals("SP")) assign(st, p.getRegister(n), v);
                }
                return true;
            }
            case "PUSHF" -> {
                st.stack.add(slot(new HashSet<>(Set.of(OTHER)), new HashSet<>(Set.of(OTHER))));
                return true;
            }
            case "POPF" -> {
                if (st.stack.isEmpty()) throw new Veto("STACK_UNDERFLOW", a);
                st.stack.remove(st.stack.size() - 1);
                // The restored flags may be the entry flags: a later read stays an entry read.
                for (String flag : FLAGS) st.units.computeIfAbsent(flag, k -> new HashSet<>()).addAll(Set.of(flag, OTHER));
                return true;
            }
            default -> { return false; }
        }
    }

    boolean copy(Instruction i, String m, State st, Summary s) throws Veto {
        if (!m.equals("MOV") && !m.equals("XCHG")) return false;
        Register d = register(i, 0), r = register(i, 1);
        if (d == null || r == null || d.getMinimumByteSize() != r.getMinimumByteSize()) return false;
        if (r.getName().equals("SP")) throw new Veto("STACK_FRAME", i.getAddress());
        if (Set.of("SP", "SS").contains(d.getName()) || (m.equals("XCHG") && r.getName().equals("SS")))
            throw new Veto("STACK_POINTER", i.getAddress());
        if (halves(d) == null || (m.equals("XCHG") && halves(r) == null)) return false;
        Set<String>[] v = value(st, r);
        if (m.equals("XCHG")) {
            Set<String>[] w = value(st, d);
            assign(st, r, w);
        }
        assign(st, d, v);
        return true;
    }

    void call(Instruction i, State st, Summary s, int depth) throws Veto {
        Address a = i.getAddress();
        Address[] flows = i.getFlows();
        if (flows.length != 1) throw new Veto("UNRESOLVED_CALL", a);
        if (bankWindow(flows[0])) throw new Veto("UNRESOLVED_BANK", a);
        Function callee = p.getFunctionManager().getFunctionAt(flows[0]);
        if (callee == null) throw new Veto("UNRESOLVED_CALL", a);
        if (explicit(callee)) throw new Veto("EXPLICIT_CALLEE", a);
        Summary c = summary(callee, depth + 1);
        if (c.veto != null) throw new Veto("CALLEE_" + c.veto, a);
        boolean farCall = i.getMnemonicString().toUpperCase(Locale.ROOT).equals("CALLF");
        if (farCall != c.far) throw new Veto("RETURN_KIND", a);
        operandReads(i, st, s);
        for (String u : c.inputs) read(st, u, s, a);
        for (String u : c.killed) st.units.put(u, new HashSet<>(Set.of(OTHER)));
        for (String flag : FLAGS) st.units.put(flag, new HashSet<>(Set.of(OTHER)));
    }

    // ---- caller demand ---------------------------------------------------------------------------

    /** 0: every path redefines unit u before reading it; 1: a path reads it; 2: unknown. */
    int demand(Instruction call, String u) {
        Function caller = p.getFunctionManager().getFunctionContaining(call.getAddress());
        if (caller == null || call.getFallThrough() == null) return 2;
        ArrayDeque<Address> work = new ArrayDeque<>(List.of(call.getFallThrough()));
        Set<Address> seen = new HashSet<>();
        boolean unknown = false;
        int steps = 0;
        while (!work.isEmpty()) {
            Address a = work.poll();
            if (!seen.add(a)) continue;
            if (++steps > DEMAND_STEPS) return 2;
            Instruction i = listing.getInstructionAt(a);
            if (i == null || !caller.getBody().contains(a) || i.getFlowOverride() != FlowOverride.NONE
                    || i.isFallThroughOverridden()) { unknown = true; continue; }
            var flow = i.getFlowType();
            if (flow.isCall()) {
                Function callee = flow.isComputed() || i.getFlows().length != 1 ? null
                    : p.getFunctionManager().getFunctionAt(i.getFlows()[0]);
                Summary c = callee == null || explicit(callee) ? null : summary(callee, 0);
                if (c == null || c.veto != null) { unknown = true; continue; }
                if (c.inputs.contains(u)) return 1;
                if (c.killed.contains(u)) continue;
            } else {
                Set<String> reads = new HashSet<>(), writes = new HashSet<>();
                effects(i, reads, writes);
                String m = i.getMnemonicString().toUpperCase(Locale.ROOT);
                if ((m.equals("XOR") || m.equals("SUB")) && i.getNumOperands() == 2
                        && i.getDefaultOperandRepresentation(0).equalsIgnoreCase(i.getDefaultOperandRepresentation(1)))
                    reads.removeAll(writes);
                if (reads.contains(u)) return 1;
                if (writes.contains(u)) continue;
                if (flow.isTerminal() || flow.isComputed()) { unknown = true; continue; }
            }
            if (i.getFallThrough() != null) work.add(i.getFallThrough());
            if (flow.isJump()) work.addAll(Arrays.asList(i.getFlows()));
        }
        return unknown ? 2 : 0;
    }
}
