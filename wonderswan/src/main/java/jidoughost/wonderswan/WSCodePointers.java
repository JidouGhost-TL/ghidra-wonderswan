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
 * F5  unreferenced short data that an accepted target's straight-line flow runs through is cleared first (see
 *     clearWeakDataInFlow), so a loose analysis guess cannot cut a pointer-proven routine down to one instruction.
 * F2v (vector proof): a pair stored into an interrupt-vector slot (0000:0000-03FF, not otherwise known as a far
 *     variable by F1) seeds a handler only when the segment register of both stores is proven 0000: set to 0000 by
 *     an instruction of the same chain, or (DS) every DS value the execution evidence observed at the store is 0000 -
 *     the DS/ES context default alone is no proof - and the vector is one the hardware or the
 *     program uses: CPU vectors 00-07, the eight vectors from each constant written to the interrupt base port 0xB0,
 *     or the number of an immediate INT in the listing. Other pairs are rejected (IVT_UNPROVEN, one F2v line each):
 *     a word pair at a low DS offset under a defaulted DS is an ordinary variable, not a vector. F3 setters into
 *     vector slots follow the same rule.
 * F6  far code-pointer fields: a far pointer held in a register-relative word pair (an array or structure slot such as
 *     [BX+SI+9Eh]/[BX+SI+0A0h], whose address is not constant) that kept code transfers to: PUSH of the two words
 *     (directly or through register loads) then RETF, or CALLF/JMPF dword ptr [field]. The dispatch fixes which word
 *     is the segment (pushed first for RETF; the high word for CALLF/JMPF). A constant segment and a constant offset
 *     stored into exactly that field pair (same segment register, same index registers, same displacements) in one
 *     fall-through chain, with none of those registers written between the two stores, is a code pointer (as F2).
 *     Fields are matched by their addressing form, so the rule runs after F1 and never applies to CS-relative words
 *     (CS tables are rule J1's). Return points pushed below a field dispatch are F4 return points as well.
 * A target is accepted only when it lies in an initialised executable block, does not fall inside an existing
 * instruction or defined data, and decodes; otherwise it is reported (OFFCUT, DATA, UNDECODABLE, WINDOW (bank
 * unknown), RAM, OUT_OF_ROM). The rule repeats until no new targets appear (new code can hold more stores).
 */
final class WSCodePointers {
    static final Set<String> R16 = Set.of("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "DS", "ES", "SS", "CS");
    static final Pattern MEMOP = Pattern.compile("(?:(?:BYTE|WORD|DWORD)PTR)?(?:(CS|DS|ES|SS):)?\\[([^\\]]+)\\]");

    /** A tracked value: a constant (with the instruction that defined it), a load from a constant linear
     *  address, or the value a register had at the function entry (setter detection). */
    record Val(Integer c, Address def, Long load, String input, Field fld) {
        Val(Integer c, Address def, Long load, String input) { this(c, def, load, input, null); }
        static Val field(Field f) { return new Val(null, null, null, null, f); }
        static Val konst(int v, Address d) { return new Val(v & 0xFFFF, d, null, null); }
        static Val load(long m) { return new Val(null, null, m, null); }
        static Val in(String r) { return new Val(null, null, null, r); }
    }

    record Store(Address site, long m, Val v) { }
    /** F6: a register-relative memory word by its addressing form: segment register, sorted index registers,
     *  16-bit displacement. */
    record Field(String seg, String regs, int disp) {
        Field plus(int d) { return new Field(seg, regs, (disp + d) & 0xFFFF); }
        boolean sameBase(Field o) { return o != null && seg.equals(o.seg) && regs.equals(o.regs); }
        boolean uses(String reg) { return seg.equals(reg) || Arrays.asList(regs.split("\\+")).contains(reg); }
        @Override public String toString() { return String.format("%s:[%s+0x%x]", seg, regs, disp); }
    }
    /** F6: the segment word of a far code-pointer field and the dispatch that proved it. */
    record FieldUse(Field seg, Address site) { }
    /** F6: a constant segment and offset stored into a candidate field pair in one chain. */
    record FieldPair(Field off, Field seg, int segValue, int offValue, Address site) { }
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
    final Map<Field, FieldUse> farFields = new LinkedHashMap<>();   // F6: offset word -> segment word + use site
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
        return String.format("F1-F6 code pointers: far variables %d, near variables %d, far fields %d, field targets %d, passes %d, new functions %d, new code %d, return points %d, existing %d, rejected %d %s, weak data cleared %d",
            farVars.size(), nearVars.size(), farFields.size(), fieldTargets, passes, newFunctions, newCode, returnPoints, existing, rejected, rejects, weakDataCleared);
    }

    // ---- one pass ------------------------------------------------------------------------------------------

    final List<Store> stores = new ArrayList<>();
    final Map<Address, Map<String, Val>> callState = new HashMap<>();   // call site -> registers before the call
    final List<long[]> farPairs = new ArrayList<>();                     // {M, seg, off} from constant store pairs
    final Map<Long, Address> farPairSite = new HashMap<>();
    final List<Target> returns = new ArrayList<>();
    final List<FieldPair> fieldPairs = new ArrayList<>();
    /** F6: field stores of the current fall-through chain (dropped when a register of the field is written). */
    final Map<Field, Val> chainFields = new HashMap<>();
    int fieldTargets;

    /** F2v: true for an interrupt-vector slot not otherwise known as a far variable. */
    boolean ivtOnly(long m) { return m < 0x400 && (m & 3) == 0 && !farVars.containsKey(m); }

    /** F2v: vectors the hardware or the program uses (CPU 00-07, port 0xB0 bases + 0..7, immediate INT numbers). */
    Set<Integer> usedVectors() {
        Set<Integer> v = new TreeSet<>();
        for (int k = 0; k < 8; k++) v.add(k);
        for (Instruction i : listing.getInstructions(true)) {
            String t = norm(i);
            if (t.startsWith("INT0X")) { try { v.add(Integer.parseInt(t.substring(5), 16)); } catch (Exception e) { } }
            if (t.equals("OUT0XB0,AL") || t.equals("OUT0X00B0,AL")) {
                Address ff = i.getFallFrom();
                Instruction q = ff == null ? null : listing.getInstructionAt(ff);
                String qt = q == null ? "" : norm(q);
                if (qt.startsWith("MOVAL,0X")) {
                    try { int b = Integer.parseInt(qt.substring(8), 16) & 0xF8; for (int k = 0; k < 8; k++) v.add(b + k); }
                    catch (Exception e) { }
                }
            }
        }
        return v;
    }

    boolean vectorRejected(long m, boolean proven, Set<Integer> used, Address site, String via) {
        if (!ivtOnly(m) || proven && used.contains((int) (m >> 2))) return false;
        String why = !proven ? "SEGMENT_NOT_PROVEN_0000" : "VECTOR_NOT_USED";
        if (ivtRejected.add(site + ":" + m)) {
            rejected++;
            rejects.merge("IVT_UNPROVEN", 1, Integer::sum);
            emit.accept(String.format("{\"rule\":\"F2v\",\"var\":\"IVT[%02x]\",\"site\":\"%s\",\"via\":\"%s\",\"outcome\":\"IVT_UNPROVEN\",\"why\":\"%s\"}",
                m >> 2, site, via, why));
        }
        return true;
    }
    final Set<String> ivtRejected = new HashSet<>();
    final Map<Long, Boolean> segProven = new HashMap<>();
    boolean lastSegProven;
    String lastSegName;
    /** F2v: execution evidence (observed DS at a store), when the repair analyzer has it. */
    WSEvidence evidence;

    /** F2v: every DS value observed at this executed address is 0000. */
    boolean observedDs0(Address a) {
        if (evidence == null) return false;
        Set<Integer> v = evidence.ds.get(a.getOffset());
        return v != null && !v.isEmpty() && v.equals(Set.of(0));
    }

    int pass() throws Exception {
        stores.clear(); callState.clear(); farPairs.clear(); farPairSite.clear(); returns.clear(); fieldPairs.clear();
        track();
        Set<Integer> used = usedVectors();
        List<Target> targets = new ArrayList<>();
        // F2: constant pairs / near constants stored into code-pointer variables
        for (long[] fp : farPairs) {
            Address site = farPairSite.get(fp[0] << 20 ^ fp[1] << 16 ^ fp[2]);
            if (isFarVar(fp[0]) && !vectorRejected(fp[0], fp[3] != 0, used, site, "F2 store " + varName(fp[0])))
                targets.add(new Target((int) fp[1], (int) fp[2], farPairSite.get(fp[0] << 20 ^ fp[1] << 16 ^ fp[2]), "F2 store " + varName(fp[0]), true));
        }
        // F6: constant pairs stored into far code-pointer fields
        Set<String> seen = new HashSet<>();
        for (FieldPair fp : fieldPairs) {
            FieldUse u = farFields.get(fp.off());
            if (u == null || !u.seg().equals(fp.seg())) continue;
            if (!seen.add(fp.site() + "/" + fp.segValue() + ":" + fp.offValue())) continue;
            fieldTargets++;
            targets.add(new Target(fp.segValue(), fp.offValue(), fp.site(),
                "F6 field store " + fp.seg() + "/" + fp.off() + " (dispatch " + u.site() + ")", true));
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
                if (far && vectorRejected(m, segProven.getOrDefault(m, false) && segProven.getOrDefault(m + 2, false), used,
                        f.getEntryPoint(), "F3 setter " + f.getEntryPoint())) continue;
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

    /** F5: unreferenced defined data inside a pointer target's straight-line flow does not block it. The target is
     *  decoded ahead (no listing change) up to its first terminator; every defined datum the decode crosses must be
     *  short (at most 8 bytes), have no references and not be user-defined. Only if the whole run decodes to a
     *  terminator is that data cleared, so the code-pointer evidence wins over an analysis guess about loose bytes.
     *  Anything else (a decode error, an existing instruction, referenced or long data) leaves the listing as it is. */
    void clearWeakDataInFlow(Address a, Target t) throws Exception {
        ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(p);
        List<Data> weak = new ArrayList<>();
        Address cur = a;
        for (int n = 0; n < 64 && cur != null; n++) {
            ghidra.app.util.PseudoInstruction pi;
            try { pi = pd.disassemble(cur); } catch (Exception e) { return; }
            if (pi == null) return;
            for (Address x = pi.getMinAddress(); x.compareTo(pi.getMaxAddress()) <= 0; x = x.next()) {
                if (listing.getInstructionContaining(x) != null) return;
                Data d = listing.getDefinedDataContaining(x);
                if (d == null) continue;
                if (weak.contains(d)) continue;
                if (d.getLength() > 8 || p.getReferenceManager().getReferencesTo(d.getMinAddress()).hasNext()
                        || d.getMinAddress().compareTo(a) < 0) return;
                SourceType src = null;
                Symbol sym = p.getSymbolTable().getPrimarySymbol(d.getMinAddress());
                if (sym != null) src = sym.getSource();
                if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED) return;
                weak.add(d);
            }
            ghidra.program.model.symbol.FlowType ft = pi.getFlowType();
            if (ft.isTerminal() || (ft.isJump() && !ft.isConditional())) {
                for (Data d : weak) {
                    listing.clearCodeUnits(d.getMinAddress(), d.getMaxAddress(), false);
                    weakDataCleared++;
                    emit.accept(String.format("{\"rule\":\"F5\",\"target\":\"%s\",\"data\":\"%s\",\"length\":%d,\"via\":\"%s\",\"outcome\":\"DATA_CLEARED\"}",
                        a, d.getMinAddress(), d.getLength(), t.via()));
                }
                return;
            }
            cur = pi.getFallThrough();
        }
    }

    int weakDataCleared;

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
                regs.clear(); stack.clear(); chainStores.clear(); segProven.clear(); chainFields.clear();
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
            boolean dispatch = false;
            if (off != null && seg != null && off.load() != null && seg.load() != null && seg.load() == off.load() + 2) {
                long m = off.load();
                dispatch = true;
                if (farVars.putIfAbsent(m, a.toString()) == null)
                    emit.accept(String.format("{\"rule\":\"F1\",\"var\":\"%05x\",\"kind\":\"far\",\"use\":\"%s\",\"shape\":\"PUSH_RETF\"}", m, a));
            }
            else if (off != null && seg != null && off.fld() != null && off.fld().sameBase(seg.fld())
                    && (seg.fld().equals(off.fld().plus(2)) || seg.fld().equals(off.fld().plus(-2)))) {
                dispatch = true;
                addFarField(off.fld(), seg.fld(), a, "PUSH_RETF");
            }
            if (dispatch) {
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
            Field f = m == null ? field(mm) : null;
            if (f != null) addFarField(f, f.plus(2), a, mn + "_MEM");
        }
        else if ((mn.equals("CALL") || mn.equals("JMP")) && mm.find() && !"CS".equals(mm.group(1))) {
            Long m = ea(mm, regs);
            if (m != null) addNear(m, cs, a, mn + "_MEM");
        }
        mm.reset();

        if (mn.startsWith("CALL") || mn.startsWith("INT")) {
            callState.put(a, new HashMap<>(regs));
            regs.clear();
            chainFields.clear();   // the callee may change any register of a field
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
                    segProven.put(m, lastSegProven || "DS".equals(lastSegName) && observedDs0(a));
                    pair(m, chainStores, a);
                }
                else {
                    Field f = field(d);
                    if (f != null) {
                        Val v = src.startsWith("0X") ? Val.konst(Integer.parseInt(src.substring(2), 16), a) : regs.get(src);
                        if (v != null && v.c() != null && v.def() == null) v = Val.konst(v.c(), a);
                        if (v == null || v.c() == null) chainFields.remove(f);
                        else { chainFields.put(f, v); pairField(f, a); }
                    }
                }
            }
        }
        // register / stack effects
        if (mn.equals("PUSH")) {
            String op = t.substring(4);
            Matcher d = MEMOP.matcher(op);
            if (R16.contains(op)) stack.push(orNull(regs.get(op)));
            else if (op.startsWith("0X")) stack.push(Val.konst(Integer.parseInt(op.substring(2), 16), a));
            else if (d.matches()) { Long m = ea(d, regs); Field f = m == null ? field(d) : null;
                stack.push(m != null ? Val.load(m) : f != null ? Val.field(f) : new Val(null, null, null, null)); }
            else stack.push(new Val(null, null, null, null));
            return;
        }
        if (mn.equals("POP")) {
            String op = t.substring(3);
            Val v = stack.isEmpty() ? null : stack.pop();
            if (R16.contains(op)) { dropFields(op); if (v == null || isUnknown(v)) regs.remove(op); else regs.put(op, v); }
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
            else if (d.matches()) { Long m = ea(d, regs); Field f = m == null ? field(d) : null;
                nv = m != null ? Val.load(m) : f != null ? Val.field(f) : null; }
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
            dropFields(n.toUpperCase());
            dropFields(r.getName().toUpperCase());
        }
        if (set != null) dropFields(set);
        if (set != null) { if (nv == null) regs.remove(set); else regs.put(set, nv); }
    }

    static boolean isUnknown(Val v) { return v.c() == null && v.load() == null && v.input() == null && v.fld() == null; }

    /** F6: a far code-pointer field proven by a dispatch (first proof wins; a second, different segment word for
     *  the same offset word is reported and the field is dropped as ambiguous). */
    final Set<Field> ambiguousFields = new HashSet<>();
    void addFarField(Field off, Field seg, Address a, String shape) {
        if (ambiguousFields.contains(off)) return;
        FieldUse old = farFields.get(off);
        if (old != null) {
            if (old.seg().equals(seg)) return;
            farFields.remove(off);
            ambiguousFields.add(off);
            emit.accept(String.format("{\"rule\":\"F6\",\"field\":\"%s\",\"use\":\"%s\",\"shape\":\"%s\",\"outcome\":\"AMBIGUOUS\",\"other\":\"%s\"}", off, a, shape, old.site()));
            return;
        }
        farFields.put(off, new FieldUse(seg, a));
        emit.accept(String.format("{\"rule\":\"F6\",\"field\":\"%s\",\"segment\":\"%s\",\"kind\":\"far\",\"use\":\"%s\",\"shape\":\"%s\"}", off, seg, a, shape));
    }

    /** F6: a register write ends the chain's knowledge of every field addressed through it. */
    void dropFields(String reg) {
        if (chainFields.isEmpty()) return;
        String r = reg.length() == 2 && (reg.endsWith("L") || reg.endsWith("H")) && "ABCD".indexOf(reg.charAt(0)) >= 0
            ? reg.charAt(0) + "X" : reg;
        chainFields.keySet().removeIf(f -> f.uses(r));
    }

    /** F6 pairing: a constant stored at a field and one at the same base, displacement +-2, in this chain. Both
     *  orientations are kept; the dispatch decides which word is the segment. */
    void pairField(Field f, Address site) {
        for (int dd : new int[] { 2, -2 }) {
            Field o = f.plus(dd);
            Val here = chainFields.get(f), there = chainFields.get(o);
            if (here == null || there == null || here.c() == null || there.c() == null) continue;
            Address s = here.def() != null ? here.def() : site;
            fieldPairs.add(new FieldPair(f, o, there.c(), here.c(), s));   // offset here, segment there
            fieldPairs.add(new FieldPair(o, f, here.c(), there.c(), s));   // offset there, segment here
        }
    }

    /** F6: the addressing form of a memory operand with at least one index register (CS-relative: none, rule J1). */
    Field field(Matcher d) {
        String expr = d.group(2);
        String segName = d.group(1) != null ? d.group(1) : expr.contains("BP") ? "SS" : "DS";
        if (segName.equals("CS")) return null;
        Matcher term = Pattern.compile("([+-]?)(0X[0-9A-F]+|AX|BX|CX|DX|SI|DI|BP)").matcher(expr);
        int pos = 0, disp = 0;
        List<String> regsUsed = new ArrayList<>();
        while (term.find()) {
            if (term.start() != pos) return null;
            pos = term.end();
            if (term.group(2).startsWith("0X")) {
                int v = Integer.parseInt(term.group(2).substring(2), 16);
                disp += term.group(1).equals("-") ? -v : v;
            }
            else if (term.group(1).equals("-")) return null;
            else regsUsed.add(term.group(2));
        }
        if (pos != expr.length() || regsUsed.isEmpty()) return null;
        Collections.sort(regsUsed);
        return new Field(segName, String.join("+", regsUsed), disp & 0xFFFF);
    }
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
            farPairs.add(new long[] { lo, seg.c(), off.c(),
                segProven.getOrDefault(lo, false) && segProven.getOrDefault(lo + 2, false) ? 1 : 0 });
            farPairSite.put(lo << 20 ^ (long) seg.c() << 16 ^ off.c(), off.def() != null ? off.def() : site);
        }
    }

    /** Linear address of a memory operand with every register part constant (segment: override, SS for BP, else DS). */
    Long ea(Matcher d, Map<String, Val> regs) {
        String segName = d.group(1) != null ? d.group(1) : d.group(2).contains("BP") ? "SS" : "DS";
        Val seg = regs.get(segName);
        if (seg == null || seg.c() == null) return null;
        lastSegProven = seg.def() != null && seg.c() == 0;   // F2v: set to 0000 by an instruction of this chain
        lastSegName = segName;
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
        segProven.clear();
        chainFields.clear();
        int before = stores.size();
        int pairsBefore = fieldPairs.size();
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
        fieldPairs.subList(pairsBefore, fieldPairs.size()).clear();   // setter chains carry inputs, not pointers
        chainFields.clear();
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
            clearWeakDataInFlow(a, t);
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
