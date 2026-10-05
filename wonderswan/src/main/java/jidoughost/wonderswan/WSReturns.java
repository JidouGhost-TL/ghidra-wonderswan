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

/**
 * Rule R1: register return values inferred from evidence, set as function signatures.
 *
 * Hand-written register code returns values in AX, BX, CX, ... (often several at once), but the
 * default convention only models AX and new functions carry no return at all, so the decompiler
 * drops the defining code (a getter decompiles to an empty body) and callers show {@code extraout_}
 * values or lose whole dispatch blocks. A register R (AX, BX, CX, DX, SI, DI) is a return of a
 * function F when both hold:
 * <ul>
 * <li>callers consume it: at least 3 direct call sites read R (or a half of it) before writing it
 * within 6 instructions after the call (single PUSH counts as a read; PUSHA/PUSHF bulk saves do
 * not; the scan stops at the next CALL/INT/RET/JMP).</li>
 * <li>the callee provides it: walking back from a RET of F (fall-through chain, at most 400
 * instructions) reaches a write of R before any POP R. A CALL/INT counts as a write of the
 * call-clobbered AX/BX/CX (a wrapper passes its callee's value through); a restore (POP R) first
 * means R is preserved, not returned.</li>
 * </ul>
 * The return is a byte when every consuming read and every write of R in F is 8-bit, else a word;
 * several registers become one multi-register storage (the decompiler slices the pieces back out).
 * The function is switched to custom variable storage first, else the return would be reallocated
 * from the convention's output model. Functions with a user/imported signature and thunks are left alone.
 */
final class WSReturns {
    static final List<String> REGS = List.of("AX", "BX", "CX", "DX", "SI", "DI");
    static final Set<String> CLOBBERED = Set.of("AX", "BX", "CX");
    static final int MIN_SITES = 3, WINDOW = 6, BACK_WALK = 400;

    final Program p;
    final Listing listing;
    final Consumer<String> emit;
    final TaskMonitor monitor;
    int functions, multiReg, skippedSig;
    final Map<String, Integer> regCounts = new TreeMap<>();

    WSReturns(Program p, Consumer<String> emit, TaskMonitor monitor) {
        this.p = p; this.emit = emit; this.monitor = monitor;
        listing = p.getListing();
    }

    String summary() {
        return String.format("R1 register returns: functions with inferred returns %d (multi-register %d), skipped with user/imported signature %d %s",
            functions, multiReg, skippedSig, regCounts);
    }

    void apply() throws Exception {
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (f.isExternal() || f.isThunk()) continue;
            SourceType src = f.getSignatureSource();
            if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED) { skippedSig++; continue; }
            Map<String, Set<Address>> consumers = new HashMap<>();
            Map<String, Boolean> fullRead = new HashMap<>();
            for (Reference r : p.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
                if (!r.getReferenceType().isCall()) continue;
                Instruction call = listing.getInstructionAt(r.getFromAddress());
                if (call == null) continue;
                consumeAfter(call, consumers, fullRead);
            }
            List<String> returns = new ArrayList<>();
            for (String reg : REGS) {
                Set<Address> sites = consumers.getOrDefault(reg, Set.of());
                if (sites.size() < MIN_SITES) continue;
                if (!providedByCallee(f, reg)) continue;
                returns.add(reg);
            }
            if (returns.isEmpty()) continue;
            setReturn(f, returns, consumers, fullRead);
        }
    }

    /** Registers read-before-written in the WINDOW instructions after a call. */
    void consumeAfter(Instruction call, Map<String, Set<Address>> consumers, Map<String, Boolean> fullRead) {
        Address a = call.getFallThrough();
        Set<String> read = new HashSet<>(), written = new HashSet<>();
        Set<String> full = new HashSet<>();
        for (int n = 0; n < WINDOW && a != null; n++) {
            Instruction ins = listing.getInstructionAt(a);
            if (ins == null) break;
            String mn = ins.getMnemonicString().toUpperCase();
            if (!mn.equals("PUSHA") && !mn.equals("PUSHF")) {
                for (Object o : ins.getInputObjects()) reg16(o, full, read, written, false);
                for (Object o : ins.getResultObjects()) reg16(o, full, read, written, true);
            }
            if (mn.startsWith("CALL") || mn.startsWith("INT") || mn.startsWith("RET") || mn.equals("IRET")
                    || mn.equals("JMP") || mn.equals("JMPF")) break;
            a = ins.getFallThrough();
        }
        for (String r : read) {
            consumers.computeIfAbsent(r, k -> new HashSet<>()).add(call.getAddress());
            if (full.contains(r)) fullRead.put(r, true);
        }
    }

    /** Maps a register operand to its 16-bit parent (REGS only); records a read unless already written. */
    void reg16(Object o, Set<String> full, Set<String> read, Set<String> written, boolean write) {
        if (!(o instanceof Register r)) return;
        Register base = r.getBaseRegister() == null ? r : r.getBaseRegister();
        String n = base.getName().toUpperCase();
        if (n.length() == 3 && n.startsWith("E")) n = n.substring(1);
        if (!REGS.contains(n)) return;
        if (r.getName().equalsIgnoreCase(n) && r.getBitLength() == 16) full.add(n);
        else if (base.getBitLength() == 16 && r.getBitLength() == 16) full.add(n);
        if (write) written.add(n);
        else if (!written.contains(n)) read.add(n);
    }

    /** True when a write of reg reaches some RET of f before any POP reg (CALL/INT provide AX/BX/CX). */
    boolean providedByCallee(Function f, String reg) {
        Register r16 = p.getRegister(reg);
        for (Instruction ret : listing.getInstructions(f.getBody(), true)) {
            String mn = ret.getMnemonicString().toUpperCase();
            if (!mn.startsWith("RET") && !mn.equals("IRET")) continue;
            Address a = ret.getFallFrom();
            for (int n = 0; n < BACK_WALK && a != null; n++) {
                Instruction ins = listing.getInstructionAt(a);
                if (ins == null) break;
                String im = ins.getMnemonicString().toUpperCase();
                if ((im.startsWith("CALL") || im.startsWith("INT")) && CLOBBERED.contains(reg)) return true;
                boolean pop = im.equals("POP") && writesReg(ins, reg, r16);
                if (pop) break;   // restored before any write on this path: preserved, not returned
                if (writesReg(ins, reg, r16)) return true;
                if (ins.getAddress().equals(f.getEntryPoint())) break;
                a = ins.getFallFrom();
            }
        }
        return false;
    }

    static boolean writesReg(Instruction ins, String reg, Register r16) {
        for (Object o : ins.getResultObjects())
            if (o instanceof Register w) {
                Register base = w.getBaseRegister() == null ? w : w.getBaseRegister();
                String n = base.getName().toUpperCase();
                if (n.length() == 3 && n.startsWith("E")) n = n.substring(1);
                if (n.equals(reg)) return true;
                if (r16 != null && (w.contains(r16) || r16.contains(w))) return true;
            }
        return false;
    }

    void setReturn(Function f, List<String> returns, Map<String, Set<Address>> consumers, Map<String, Boolean> fullRead) throws Exception {
        List<Register> regs = new ArrayList<>();
        List<String> sizes = new ArrayList<>();
        int bytes = 0;
        for (String reg : returns) {
            // SI/DI have no 8-bit halves: byte returns exist only for AX/BX/CX/DX
            boolean full = fullRead.getOrDefault(reg, false) || fullWrite(f, reg) || reg.equals("SI") || reg.equals("DI");
            Register r = p.getRegister(full ? reg : reg.charAt(0) + "L");
            if (r == null) r = p.getRegister(reg);
            int n = r.getBitLength() / 8;
            bytes += n;
            sizes.add(reg + ":" + n);
            regs.add(r);
        }
        // the storage size must equal the type size; odd totals use an array type
        DataType type = bytes == 1 ? new ByteDataType() : bytes == 2 ? new WordDataType()
            : bytes == 4 ? new DWordDataType() : bytes == 8 ? new QWordDataType()
            : bytes % 2 == 0 ? new ArrayDataType(new WordDataType(), bytes / 2, 2) : new ArrayDataType(new ByteDataType(), bytes, 1);
        try {
            // custom storage first: without it setReturn reallocates the return from the
            // convention's output model (AX), silently discarding any other register
            f.setCustomVariableStorage(true);
            f.setReturn(type, new VariableStorage(p, regs.toArray(new Register[0])), SourceType.ANALYSIS);
        } catch (Exception e) {
            emit.accept(String.format("{\"rule\":\"R1\",\"function\":\"%s\",\"outcome\":\"STORAGE_REJECTED\",\"returns\":\"%s\",\"error\":\"%s\"}",
                f.getEntryPoint(), sizes, String.valueOf(e).replace('"', '\'')));
            return;
        }
        functions++;
        if (returns.size() > 1) multiReg++;
        for (String reg : returns) regCounts.merge(reg, 1, Integer::sum);
        StringBuilder sites = new StringBuilder();
        for (String reg : returns) sites.append(sites.length() > 0 ? ";" : "").append(reg).append("=").append(consumers.get(reg).size());
        emit.accept(String.format("{\"rule\":\"R1\",\"function\":\"%s\",\"outcome\":\"SET\",\"returns\":\"%s\",\"call_sites\":\"%s\"}",
            f.getEntryPoint(), sizes, sites));
    }

    boolean fullWrite(Function f, String reg) {
        Register r16 = p.getRegister(reg);
        for (Instruction ins : listing.getInstructions(f.getBody(), true))
            for (Object o : ins.getResultObjects())
                if (o instanceof Register w && w.getBitLength() == 16
                        && (w.getName().equalsIgnoreCase(reg) || r16 != null && (w.contains(r16) || r16.contains(w)))) return true;
        return false;
    }
}
