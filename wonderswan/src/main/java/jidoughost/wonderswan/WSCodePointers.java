// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Rules F1-F4: code reached through code-pointer variables and pushed return addresses, with per-item evidence.
 *
 * A forward constant tracker walks every fall-through chain (reset at flow joins; registers unknown after
 * CALL/INT) and records constant word stores, register/stack values and loads from constant memory addresses.
 *
 * F1  far code-pointer variable: a RAM word pair (M, M+2) whose contents are transferred to as a far pointer:
 *     CALLF/JMPF dword ptr [M], or the push-return dispatch PUSH [M+2]; PUSH [M]; RETF (directly or through a
 *     register load). The interrupt vector table (0000:0000-03FF, 4-byte entries) is a far code-pointer table by
 *     hardware definition.
 *     Near variant: CALL/JMP word ptr [M] (not CS) or PUSH [M]; RET (target segment = CS of the use site).
 * F2  constant stores: a constant offset stored to M together with a constant segment stored to M+2 in the same
 *     fall-through chain (far), or a constant stored to M (near), is a code pointer: the target is disassembled
 *     with csval = the stored segment and becomes a function.
 * F3  setter functions: a function that stores two of its input registers (not written since its entry, along
 *     its fall-through chain) into M and M+2 of a far code-pointer variable (or one into a near one) is a setter;
 *     at every call to it the constant values of those registers are code pointers (F2 applied to the call site).
 * F4  pushed return address: the constant segment:offset pair pushed directly below the dispatch pair of an F1
 *     push-return dispatch is where the dispatched code returns: code (no function, it continues the caller).
 * A target is accepted only when it lies in an initialised executable block, does not fall inside an existing
 * instruction or defined data, and decodes; otherwise it is reported (OFFCUT, DATA, UNDECODABLE, WINDOW (bank
 * unknown), RAM, OUT_OF_ROM). The rule repeats until no new targets appear (new code can hold more stores).
 */
final class WSCodePointers {
    static final Set<String> R16 = Set.of("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "DS", "ES", "SS", "CS");
    static final Pattern MEMOP = Pattern.compile("(?:(?:BYTE|WORD|DWORD)PTR)?(?:(CS|DS|ES|SS):)?\\[([^\\]]+)\\]");

    /** A tracked value: a constant (with the instruction that defined it), a load from a constant linear
     *  address, or the value a register had at the function entry (setter detection). */
    record Val(Integer c, Address def, Long load, String input) {
        static Val konst(int v, Address d) { return new Val(v & 0xFFFF, d, null, null); }
        static Val load(long m) { return new Val(null, null, m, null); }
        static Val in(String r) { return new Val(null, null, null, r); }
    }

    record Store(Address site, long m, Val v) { }
    record Target(int seg, int off, Address from, String via, boolean function) { }

    final Program p;
    final Listing listing;
    final Memory mem;
    final SegmentedAddressSpace space;
    final ProgramContext ctx;
    final Register csval, rDS, colorsoc;
    final Consumer<String> emit;
    final TaskMonitor monitor;

    final Map<Long, String> farVars = new TreeMap<>(), nearVars = new TreeMap<>();   // M -> evidence (use site)
    final Map<Long, Integer> nearVarCs = new HashMap<>();
    /** Accepted code-pointer targets installed through the interrupt vector table (for rules V1/M1/T1). */
    final Set<Address> ivtHandlers = new HashSet<>();
    final Set<String> done = new HashSet<>();
    int passes, newFunctions, newCode, existing, rejected, returnPoints;
    final Map<String, Integer> rejects = new TreeMap<>();

    WSCodePointers(Program p, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor;
        listing = p.getListing();
        mem = p.getMemory();
        space = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
        ctx = p.getProgramContext();
        csval = ctx.getRegister("csval");
        rDS = ctx.getRegister("DS");
        colorsoc = ctx.getRegister("colorsoc");
    }

    /** Applies F1-F4 until no new targets appear; returns the number of targets accepted. */
    int apply() throws Exception {
        int total = 0;
        for (int pass = 0; pass < 16; pass++) {
            monitor.checkCancelled();
            int n = pass();
            passes = pass + 1;
            total += n;
            if (n == 0) break;
        }
        return total;
    }

    String summary() {
        return String.format("F1-F4 code pointers: far variables %d, near variables %d, passes %d, new functions %d, new code %d, return points %d, existing %d, rejected %d %s",
            farVars.size(), nearVars.size(), passes, newFunctions, newCode, returnPoints, existing, rejected, rejects);
    }

    // ---- one pass ------------------------------------------------------------------------------------------

    final List<Store> stores = new ArrayList<>();
    final Map<Address, Map<String, Val>> callState = new HashMap<>();   // call site -> registers before the call
    final List<long[]> farPairs = new ArrayList<>();                     // {M, seg, off} from constant store pairs
    final Map<Long, Address> farPairSite = new HashMap<>();
    final List<Target> returns = new ArrayList<>();

    int pass() throws Exception {
        stores.clear(); callState.clear(); farPairs.clear(); farPairSite.clear(); returns.clear();
        track();
        List<Target> targets = new ArrayList<>();
        // F2: constant pairs / near constants stored into code-pointer variables
        for (long[] fp : farPairs) {
            if (isFarVar(fp[0]))
                targets.add(new Target((int) fp[1], (int) fp[2], farPairSite.get(fp[0] << 20 ^ fp[1] << 16 ^ fp[2]), "F2 store " + varName(fp[0]), true));
        }
        for (Store s : stores) {
            if (s.v().c() == null || !nearVars.containsKey(s.m())) continue;
            targets.add(new Target(nearVarCs.get(s.m()), s.v().c(), s.site(), "F2 near store " + varName(s.m()), true));
        }
        // F3: setters
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            Map<Long, String> in = setterStores(f);
            if (in.isEmpty()) continue;
            for (Map.Entry<Long, String> e : in.entrySet()) {
                long m = e.getKey();
                String offReg = e.getValue(), segReg = in.get(m + 2);
                boolean far = isFarVar(m) && segReg != null, near = nearVars.containsKey(m);
                if (!far && !near) continue;
                for (Reference r : p.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                    if (!r.getReferenceType().isCall()) continue;
                    Map<String, Val> st = callState.get(r.getFromAddress());
                    if (st == null) continue;
                    Val off = st.get(offReg), seg = far ? st.get(segReg) : null;
                    if (off == null || off.c() == null) continue;
                    if (far) {
                        if (seg == null || seg.c() == null) continue;
                        targets.add(new Target(seg.c(), off.c(), off.def() != null ? off.def() : r.getFromAddress(),
                            "F3 setter " + f.getEntryPoint() + " " + segReg + ":" + offReg + " -> " + varName(m), true));
                    } else {
                        targets.add(new Target(nearVarCs.get(m), off.c(), off.def() != null ? off.def() : r.getFromAddress(),
                            "F3 near setter " + f.getEntryPoint() + " " + offReg + " -> " + varName(m), true));
                    }
                }
            }
        }
        targets.addAll(returns);
        int accepted = 0;
        for (Target t : targets) if (accept(t)) accepted++;
        return accepted;
    }

    boolean isFarVar(long m) { return farVars.containsKey(m) || (m < 0x400 && (m & 3) == 0); }

    /** True when a target's provenance names an interrupt-vector slot (F2 prints IVT[xx], F3 the raw variable). */
    static boolean ivtVia(String via) {
        if (via.contains("IVT[")) return true;
        Matcher m = Pattern.compile("([0-9a-f]{5})$").matcher(via);
        if (!m.find()) return false;
        long v = Long.parseLong(m.group(1), 16);
        return v < 0x400 && (v & 3) == 0;
    }

    String varName(long m) { return m < 0x400 && (m & 3) == 0 && !farVars.containsKey(m) ? String.format("IVT[%02x]", m >> 2) : String.format("%05x", m); }

    // ---- the tracker ---------------------------------------------------------------------------------------

    void track() throws Exception {
        Map<String, Val> regs = new HashMap<>();
        Deque<Val> stack = new ArrayDeque<>();
        Map<Long, Val> chainStores = new HashMap<>();
        Instruction prev = null;
        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            boolean cont = prev != null && ins.getAddress().equals(prev.getFallThrough()) && !joins(ins);
            if (!cont) {
                regs.clear(); stack.clear(); chainStores.clear();
                contextDs(ins.getAddress(), regs);
            }
            prev = ins;
            step(ins, regs, stack, chainStores);
        }
    }

    /** DS from the program context (rules D0/D1 and the loader default): the value the decompiler assumes too. */
    void contextDs(Address a, Map<String, Val> regs) {
        BigInteger ds = a == null || rDS == null ? null : ctx.getValue(rDS, a, false);
        if (ds != null) regs.put("DS", Val.konst(ds.intValue(), null));
    }

    boolean joins(Instruction ins) {
        for (Reference r : p.getReferenceManager().getReferencesTo(ins.getAddress()))
            if (r.getReferenceType().isFlow()) return true;
        return false;
    }

    static String norm(Instruction i) { return i.toString().toUpperCase().replace(" ", ""); }

    void step(Instruction ins, Map<String, Val> regs, Deque<Val> stack, Map<Long, Val> chainStores) throws Exception {
        String t = norm(ins);
        String mn = ins.getMnemonicString().toUpperCase();
        Address a = ins.getAddress();
        int cs = csOf(a);
        // uses of code-pointer variables (F1)
        if (mn.equals("RETF") && stack.size() >= 2) {
            Iterator<Val> it = stack.iterator();
            Val off = it.next(), seg = it.next();
            if (off != null && seg != null && off.load() != null && seg.load() != null && seg.load() == off.load() + 2) {
                long m = off.load();
                if (farVars.putIfAbsent(m, a.toString()) == null)
                    emit.accept(String.format("{\"rule\":\"F1\",\"var\":\"%05x\",\"kind\":\"far\",\"use\":\"%s\",\"shape\":\"PUSH_RETF\"}", m, a));
                if (it.hasNext()) {                                                    // F4: return address below the pair
                    Val roff = it.next(), rseg = it.hasNext() ? it.next() : null;
                    if (roff != null && rseg != null && roff.c() != null && rseg.c() != null)
                        returns.add(new Target(rseg.c(), roff.c(), a, "F4 return point of dispatch " + a, false));
                }
            }
        }
        if (mn.equals("RET") && !stack.isEmpty()) {
            Val off = stack.peek();
            if (off != null && off.load() != null) addNear(off.load(), cs, a, "PUSH_RET");
        }
        Matcher mm = MEMOP.matcher(t);
        if ((mn.equals("CALLF") || mn.equals("JMPF")) && mm.find()) {
            Long m = ea(mm, regs);
            if (m != null && farVars.putIfAbsent(m, a.toString()) == null)
                emit.accept(String.format("{\"rule\":\"F1\",\"var\":\"%05x\",\"kind\":\"far\",\"use\":\"%s\",\"shape\":\"%s_MEM\"}", m, a, mn));
        }
        else if ((mn.equals("CALL") || mn.equals("JMP")) && mm.find() && !"CS".equals(mm.group(1))) {
            Long m = ea(mm, regs);
            if (m != null) addNear(m, cs, a, mn + "_MEM");
        }
        mm.reset();

        if (mn.startsWith("CALL") || mn.startsWith("INT")) {
            callState.put(a, new HashMap<>(regs));
            regs.clear();
            contextDs(ins.getFallThrough(), regs);   // the DS the analysis assumes after the call (context)
            return;
        }
        // stores: MOV mem,imm16 / MOV mem,reg16
        int close = t.indexOf("],");
        if (mn.equals("MOV") && close > 0 && t.indexOf('[') < close && !t.startsWith("MOVBYTEPTR")) {
            String dst = t.substring(3, close + 1), src = t.substring(close + 2);
            boolean word = dst.startsWith("WORDPTR") || R16.contains(src);
            Matcher d = MEMOP.matcher(dst);
            if (word && d.matches()) {
                Long m = ea(d, regs);
                if (m != null) {
                    Val v = src.startsWith("0X") ? Val.konst(Integer.parseInt(src.substring(2), 16), a) : regs.get(src);
                    if (v == null) v = new Val(null, null, null, null);
                    else if (v.c() != null && v.def() == null) v = Val.konst(v.c(), a);
                    stores.add(new Store(a, m, v));
                    chainStores.put(m, v);
                    pair(m, chainStores, a);
                }
            }
        }
        // register / stack effects
        if (mn.equals("PUSH")) {
            String op = t.substring(4);
            Matcher d = MEMOP.matcher(op);
            if (R16.contains(op)) stack.push(orNull(regs.get(op)));
            else if (op.startsWith("0X")) stack.push(Val.konst(Integer.parseInt(op.substring(2), 16), a));
            else if (d.matches()) { Long m = ea(d, regs); stack.push(m == null ? new Val(null, null, null, null) : Val.load(m)); }
            else stack.push(new Val(null, null, null, null));
            return;
        }
        if (mn.equals("POP")) {
            String op = t.substring(3);
            Val v = stack.isEmpty() ? null : stack.pop();
            if (R16.contains(op)) { if (v == null || isUnknown(v)) regs.remove(op); else regs.put(op, v); }
            return;
        }
        if (mn.equals("PUSHA")) { for (int k = 0; k < 8; k++) stack.push(new Val(null, null, null, null)); return; }
        if (mn.equals("POPA")) { for (int k = 0; k < 8 && !stack.isEmpty(); k++) stack.pop(); regs.keySet().removeAll(List.of("AX", "BX", "CX", "DX", "SI", "DI", "BP")); return; }
        if (mn.equals("PUSHF")) { stack.push(new Val(null, null, null, null)); return; }
        if (mn.equals("POPF")) { if (!stack.isEmpty()) stack.pop(); return; }
        if (mn.startsWith("RET") || mn.equals("IRET")) { stack.clear(); return; }

        String set = null; Val nv = null;
        Matcher mv = Pattern.compile("MOV(AX|BX|CX|DX|SI|DI|BP|DS|ES|SS),(.+)").matcher(t);
        Matcher z = Pattern.compile("(?:XOR|SUB)(AX|BX|CX|DX|SI|DI|BP),\\1").matcher(t);
        if (mv.matches()) {
            set = mv.group(1);
            String src = mv.group(2);
            Matcher d = MEMOP.matcher(src);
            if (src.startsWith("0X")) nv = Val.konst(Integer.parseInt(src.substring(2), 16), a);
            else if (R16.contains(src)) nv = regs.get(src);
            else if (d.matches()) { Long m = ea(d, regs); nv = m == null ? null : Val.load(m); }
        }
        else if (z.matches()) { set = z.group(1); nv = Val.konst(0, a); }
        else {
            Matcher m8 = Pattern.compile("MOV([ABCD])([LH]),0X([0-9A-F]+)").matcher(t);
            if (m8.matches()) {
                set = m8.group(1) + "X";
                Val old = regs.get(set);
                int b = Integer.parseInt(m8.group(3), 16) & 0xFF;
                nv = old == null || old.c() == null ? null
                    : Val.konst(m8.group(2).equals("L") ? (old.c() & 0xFF00) | b : (old.c() & 0xFF) | b << 8, a);
            }
        }
        // every register the instruction writes (p-code results) becomes unknown unless set above
        for (Object o : ins.getResultObjects()) {
            if (!(o instanceof Register r)) continue;
            Register base = r.getBaseRegister();
            String n = base == null ? r.getName() : base.getName();
            if (n.length() == 3 && n.startsWith("E")) n = n.substring(1);   // EAX-style bases, if any
            regs.remove(n.toUpperCase());
            regs.remove(r.getName().toUpperCase());
        }
        if (set != null) { if (nv == null) regs.remove(set); else regs.put(set, nv); }
    }

    static boolean isUnknown(Val v) { return v.c() == null && v.load() == null && v.input() == null; }
    static Val orNull(Val v) { return v == null ? new Val(null, null, null, null) : v; }

    void addNear(long m, int cs, Address a, String shape) {
        if (nearVars.putIfAbsent(m, a.toString()) == null) {
            nearVarCs.put(m, cs);
            emit.accept(String.format("{\"rule\":\"F1\",\"var\":\"%05x\",\"kind\":\"near\",\"cs\":\"%04x\",\"use\":\"%s\",\"shape\":\"%s\"}", m, cs, a, shape));
        }
    }

    /** F2 pairing: offset at M and segment at M+2, both constant, stored in the same chain. */
    void pair(long m, Map<Long, Val> chainStores, Address site) {
        for (long lo : new long[] { m, m - 2 }) {
            Val off = chainStores.get(lo), seg = chainStores.get(lo + 2);
            if (off == null || seg == null || off.c() == null || seg.c() == null) continue;
            farPairs.add(new long[] { lo, seg.c(), off.c() });
            farPairSite.put(lo << 20 ^ (long) seg.c() << 16 ^ off.c(), off.def() != null ? off.def() : site);
        }
    }

    /** Linear address of a memory operand with every register part constant (segment: override, SS for BP, else DS). */
    Long ea(Matcher d, Map<String, Val> regs) {
        String segName = d.group(1) != null ? d.group(1) : d.group(2).contains("BP") ? "SS" : "DS";
        Val seg = regs.get(segName);
        if (seg == null || seg.c() == null) return null;
        long off = 0;
        Matcher term = Pattern.compile("([+-]?)(0X[0-9A-F]+|AX|BX|CX|DX|SI|DI|BP)").matcher(d.group(2));
        int pos = 0;
        while (term.find()) {
            if (term.start() != pos) return null;
            pos = term.end();
            long v;
            if (term.group(2).startsWith("0X")) v = Long.parseLong(term.group(2).substring(2), 16);
            else { Val r = regs.get(term.group(2)); if (r == null || r.c() == null) return null; v = r.c(); }
            off += term.group(1).equals("-") ? -v : v;
        }
        if (pos != d.group(2).length()) return null;
        return (((long) seg.c() << 4) + (off & 0xFFFF)) & 0xFFFFF;
    }

    /** F3: stores of entry-input registers along the function's entry chain (no joins, no calls). */
    Map<Long, String> setterStores(Function f) {
        Map<Long, String> out = new HashMap<>();
        Map<String, Val> regs = new HashMap<>();
        for (String r : List.of("AX", "BX", "CX", "DX", "SI", "DI", "BP", "ES")) regs.put(r, Val.in(r));
        BigInteger ds = rDS == null ? null : ctx.getValue(rDS, f.getEntryPoint(), false);
        if (ds != null) regs.put("DS", Val.konst(ds.intValue(), null));
        Instruction ins = listing.getInstructionAt(f.getEntryPoint());
        Deque<Val> stack = new ArrayDeque<>();
        Map<Long, Val> chain = new HashMap<>();
        int before = stores.size();
        for (int n = 0; ins != null && n < 48; n++) {
            if (n > 0 && joins(ins)) break;
            String mn = ins.getMnemonicString().toUpperCase();
            if (mn.startsWith("CALL") || mn.startsWith("INT") || mn.startsWith("RET") || mn.equals("IRET")) break;
            try { step(ins, regs, stack, chain); } catch (Exception e) { break; }
            Address ft = ins.getFallThrough();
            if (ft == null || ins.getFlowType().isJump()) break;
            ins = listing.getInstructionAt(ft);
        }
        for (Store s : stores.subList(before, stores.size())) if (s.v().input() != null) out.put(s.m(), s.v().input());
        stores.subList(before, stores.size()).clear();
        return out;
    }

    // ---- accepting a target --------------------------------------------------------------------------------

    int csOf(Address a) {
        if (a instanceof SegmentedAddress sa) {
            BigInteger v = csval == null ? null : ctx.getValue(csval, a, false);
            return v != null && v.intValue() != 0 ? v.intValue() : sa.getSegment();
        }
        return (int) (a.getOffset() >> 4) & 0xF000;
    }

    boolean accept(Target t) throws Exception {
        String key = String.format("%04x:%04x", t.seg(), t.off());
        long lin = (((long) t.seg() << 4) + t.off()) & 0xFFFFF;
        String why = null;
        if (t.seg() == 0 && t.off() == 0) why = "NULL_POINTER";      // a cleared variable, not a target
        else if (lin < 0x10000) why = "RAM";
        else if (lin < 0x40000) why = "WINDOW";
        Address a = why == null ? space.getAddress(t.seg(), t.off()) : null;
        MemoryBlock b = a == null ? null : mem.getBlock(a);
        if (why == null && (b == null || !b.isInitialized() || !b.isExecute())) why = "OUT_OF_ROM";
        // Loader data overlays (ROM_xx) are pure data views: never code targets, even if executable.
        if (why == null && WonderSwanLoader.isDataOverlay(b)) why = "DATA_OVERLAY";
        Instruction at = a == null ? null : listing.getInstructionAt(a);
        if (why == null && at == null) {
            Instruction c = listing.getInstructionContaining(a);
            Data d = listing.getDataContaining(a);
            if (c != null) why = "OFFCUT";
            else if (d != null && d.isDefined()) why = "DATA";
            else {
                try { if (new ghidra.app.util.PseudoDisassembler(p).disassemble(a) == null) why = "UNDECODABLE"; }
                catch (Exception e) { why = "UNDECODABLE"; }
            }
        }
        if (!done.add(key + (t.function() ? "f" : "r"))) return false;
        if (why == null && ivtVia(t.via())) ivtHandlers.add(a);
        if (why != null) {
            if (!why.equals("NULL_POINTER")) rejected++;
            rejects.merge(why, 1, Integer::sum);
            emit.accept(String.format("{\"rule\":\"%s\",\"target\":\"%s\",\"from\":\"%s\",\"via\":\"%s\",\"outcome\":\"%s\"}",
                t.via().substring(0, 2), key, t.from(), t.via(), why));
            return false;
        }
        String outcome;
        if (at == null) {
            ctx.setValue(csval, a, a, BigInteger.valueOf(t.seg()));
            BigInteger soc = colorsoc == null || t.from() == null ? null : ctx.getValue(colorsoc, t.from(), false);
            if (soc != null) ctx.setValue(colorsoc, a, a, soc);
            new DisassembleCommand(a, null, true).applyTo(p, monitor);
            outcome = "NEW_CODE";
            newCode++;
        }
        else outcome = "EXISTING_CODE";
        if (t.function() && p.getFunctionManager().getFunctionAt(a) == null && listing.getInstructionAt(a) != null) {
            new CreateFunctionCmd(a).applyTo(p, monitor);
            if (p.getFunctionManager().getFunctionAt(a) != null) { outcome = "NEW_FUNCTION"; newFunctions++; }
        }
        if (!t.function()) returnPoints++;
        if (outcome.equals("EXISTING_CODE")) existing++;
        if (t.from() != null && listing.getInstructionAt(t.from()) != null)
            p.getReferenceManager().addMemoryReference(t.from(), a, t.function() ? RefType.DATA : RefType.DATA, SourceType.ANALYSIS, -1);
        if (listing.getInstructionAt(a) != null)
            p.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS, "WSEvidence", t.via() + " from " + t.from());
        emit.accept(String.format("{\"rule\":\"%s\",\"target\":\"%s\",\"from\":\"%s\",\"via\":\"%s\",\"outcome\":\"%s\"}",
            t.via().substring(0, 2), key, t.from(), t.via(), outcome));
        return !outcome.equals("EXISTING_CODE") || t.function() && outcome.equals("NEW_FUNCTION");
    }
}
