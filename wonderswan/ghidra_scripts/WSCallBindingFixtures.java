// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import jidoughost.wonderswan.WSReturns;

/**
 * Call-binding fixtures F1-F12 and L2a-L2d: register interfaces of hand-written callees, as the
 * caller's decompiled call op binds them. Each fixture prints RESULT id PASS|FAIL; the script fails
 * when any fixture fails. Without the L1/P1 rules (class WSCallLocks) only R1b runs.
 */
public class WSCallBindingFixtures extends GhidraScript {
    private int checks;
    private final Map<String, String> results = new LinkedHashMap<>();
    private boolean locks;

    private static final class Fx {
        final String name;
        final byte[] bytes = new byte[0x400];
        final List<Integer> functions = new ArrayList<>();
        int segment = 0x4000;
        boolean writable;
        Fx(String name) { this.name = name; Arrays.fill(bytes, (byte) 0xcc); }
        /** Tokens are hex bytes or call:XXXX (near CALL rel16 to offset XXXX). */
        Fx fn(int at, String... tokens) {
            functions.add(at);
            int pc = at;
            for (String t : tokens) {
                byte[] b;
                if (t.startsWith("call:")) {
                    int target = Integer.parseInt(t.substring(5), 16), rel = target - (pc + 3);
                    b = new byte[] { (byte) 0xe8, (byte) rel, (byte) (rel >> 8) };
                } else b = HexFormat.of().parseHex(t);
                System.arraycopy(b, 0, bytes, pc, b.length);
                pc += b.length;
            }
            return this;
        }
    }

    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
    }

    private static Address at(Program p, int segment, int offset) {
        return ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(segment, offset);
    }

    private interface Body { void run(ProgramDB p, Fx fx, List<String> lines) throws Exception; }

    private void fixture(String id, Fx fx, Body before, Body after) throws Exception {
        var p = new ProgramDB(fx.name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx = p.startTransaction(id);
        var lines = new ArrayList<String>();
        try {
            var file = p.getMemory().createFileBytes(fx.name, 0, fx.bytes.length, new ByteArrayInputStream(fx.bytes), monitor);
            p.getMemory().createInitializedBlock("code", at(p, fx.segment, 0), file, 0, fx.bytes.length, false)
                .setPermissions(true, fx.writable, true);
            var context = p.getProgramContext();
            Address lo = at(p, fx.segment, 0), hi = at(p, fx.segment, fx.bytes.length - 1);
            context.setValue(p.getRegister("csval"), lo, hi, BigInteger.valueOf(fx.segment));
            context.setValue(p.getRegister("DS"), lo, hi, BigInteger.ZERO);
            context.setValue(p.getRegister("SS"), lo, hi, BigInteger.ZERO);
            for (int start : fx.functions) {
                check(new DisassembleCommand(at(p, fx.segment, start), null, true).applyTo(p, monitor), id + " disassemble " + start);
                check(new CreateFunctionCmd(at(p, fx.segment, start)).applyTo(p, monitor), id + " create " + start);
            }
            for (int start : fx.functions) fn(p, fx, start).setCallingConvention("__wsasm");
            if (before != null) before.run(p, fx, lines);
            rules(p, lines);
            after.run(p, fx, lines);
            byte[] now = new byte[fx.bytes.length];
            p.getMemory().getBytes(at(p, fx.segment, 0), now);
            check(Arrays.equals(now, fx.bytes), id + " instruction bytes unchanged");
            results.put(id, "PASS");
        } catch (AssertionError e) {
            results.put(id, "FAIL " + e.getMessage().replace('\n', ' ') + " | emit=" + lines);
        } finally {
            p.endTransaction(tx, false);
            p.release(this);
        }
        println("RESULT " + id + " " + results.get(id));
    }

    private void rules(Program p, List<String> lines) throws Exception {
        Consumer<String> emit = lines::add;
        try {
            Class<?> c = Class.forName("jidoughost.wonderswan.WSCallLocks");
            c.getMethod("applyAll", Program.class, Consumer.class, TaskMonitor.class).invoke(null, p, emit, monitor);
            locks = true;
        } catch (ClassNotFoundException e) {
            WSReturns.apply(p, emit, monitor);
        } catch (java.lang.reflect.InvocationTargetException e) {
            throw e.getCause() instanceof Exception x ? x : new RuntimeException(e.getCause());
        }
    }

    private static Function fn(Program p, Fx fx, int offset) {
        return p.getFunctionManager().getFunctionAt(at(p, fx.segment, offset));
    }

    private HighFunction decompile(Program p, Fx fx, int offset) {
        var d = new DecompInterface();
        try {
            check(d.openProgram(p), "open decompiler");
            var r = d.decompileFunction(fn(p, fx, offset), 30, monitor);
            check(r.decompileCompleted(), "decompile " + offset + " " + r.getErrorMessage());
            return r.getHighFunction();
        } finally { d.dispose(); }
    }

    private String cText(Program p, Fx fx, int offset) {
        var d = new DecompInterface();
        try {
            d.openProgram(p);
            var r = d.decompileFunction(fn(p, fx, offset), 30, monitor);
            return r.getDecompiledFunction() == null ? r.getErrorMessage() : r.getDecompiledFunction().getC().replace('\n', ' ');
        } finally { d.dispose(); }
    }

    private PcodeOpAST callAt(HighFunction h, Program p, Fx fx, int offset) {
        for (var ops = h.getPcodeOps(at(p, fx.segment, offset)); ops.hasNext();) {
            var op = ops.next();
            if (op.getOpcode() == PcodeOp.CALL) return op;
        }
        throw new AssertionError("no CALL op at " + Integer.toHexString(offset));
    }

    private static String show(PcodeOp op) {
        var s = new StringBuilder(op.getOutput() == null ? "-" : op.getOutput().toString()).append(" CALL");
        for (int i = 1; i < op.getNumInputs(); i++) s.append(' ').append(op.getInput(i));
        return s.toString();
    }

    private static boolean constant(Varnode v, long value, int size) {
        return v != null && v.isConstant() && v.getOffset() == value && v.getSize() == size;
    }

    private static boolean passThrough(Program p, Varnode v, String register) {
        if (v == null || !v.isRegister() || !v.isInput()) return false;
        Register r = p.getRegister(v.getAddress(), v.getSize());
        return r != null && r.getName().equals(register);
    }

    /** Value stored to DS:offset (DS = 0) in the decompiled caller. */
    private static Varnode stored(HighFunction h, long offset) {
        for (var ops = h.getPcodeOps(); ops.hasNext();) {
            var op = ops.next();
            if (op.getOpcode() == PcodeOp.COPY && op.getOutput().getAddress().isMemoryAddress()
                    && op.getOutput().getOffset() == offset) return op.getInput(0);
            if (op.getOpcode() == PcodeOp.STORE && op.getInput(1).isConstant() && op.getInput(1).getOffset() == offset)
                return op.getInput(2);
        }
        return null;
    }

    private void locked(Function f, String id, String params, boolean voidReturn) {
        check(f.getSignatureSource() == SourceType.ANALYSIS && f.hasCustomVariableStorage(),
            id + " callee locked: " + f.getPrototypeString(true, true) + " " + f.getSignatureSource());
        var storage = new ArrayList<String>();
        for (var v : f.getParameters()) storage.add(v.getVariableStorage().toString());
        check(String.join(",", storage).equals(params), id + " params " + storage + " want " + params);
        if (voidReturn) check(f.getReturnType().isEquivalent(VoidDataType.dataType), id + " void return " + f.getReturnType());
        check(f.getCallingConventionName().startsWith("__wsasm_p"), id + " P1 model " + f.getCallingConventionName());
    }

    private void unlocked(Function f, String id) {
        check(!f.hasCustomVariableStorage() && f.getSignatureSource() == SourceType.DEFAULT,
            id + " callee keeps the default: " + f.getPrototypeString(true, true) + " " + f.getSignatureSource());
    }

    private void vetoed(List<String> lines, Function f, String id, String reason) {
        if (!locks) return;
        String entry = "\"function\":\"" + f.getEntryPoint() + "\"";
        check(lines.stream().anyMatch(l -> l.contains("\"rule\":\"L1\"") && l.contains(entry) && l.contains("VETO")
            && l.contains(reason)), id + " L1 veto " + reason + " emitted");
    }

    @Override public void run() throws Exception {
        final String STORE_BX = "891e0021", STORE_SI = "89360021", STORE_DX = "89160021";
        // F1 PASSTHRU: the caller passes its own entry BX.
        fixture("F1", new Fx("f1").fn(0x100, STORE_BX, "c3").fn(0x40, "call:0100", "c3"), null, (p, fx, l) -> {
            var call = callAt(decompile(p, fx, 0x40), p, fx, 0x40);
            check(call.getNumInputs() == 2 && passThrough(p, call.getInput(1), "BX"), "F1 call binds entry BX: " + show(call));
            locked(fn(p, fx, 0x100), "F1", "BX:2", true);
        });
        // F2 OTHERUSE: SI also read after the call; the callee preserves SI.
        fixture("F2", new Fx("f2").fn(0x100, STORE_SI, "c3").fn(0x40, "be3412", "call:0100", "89360221", "c3"), null, (p, fx, l) -> {
            var h = decompile(p, fx, 0x40);
            var call = callAt(h, p, fx, 0x43);
            check(call.getNumInputs() == 2 && constant(call.getInput(1), 0x1234, 2), "F2 call binds SI: " + show(call));
            check(constant(stored(h, 0x2102), 0x1234, 2), "F2 SI preserved across the call: " + stored(h, 0x2102));
            locked(fn(p, fx, 0x100), "F2", "SI:2", true);
        });
        // F3 THRUCALL: SI set before an earlier call that preserves it.
        fixture("F3", new Fx("f3").fn(0x180, "c606042101", "c3").fn(0x100, STORE_SI, "c3")
                .fn(0x40, "be3412", "call:0180", "call:0100", "c3"), null, (p, fx, l) -> {
            var call = callAt(decompile(p, fx, 0x40), p, fx, 0x46);
            check(call.getNumInputs() == 2 && constant(call.getInput(1), 0x1234, 2), "F3 call binds SI: " + show(call));
            locked(fn(p, fx, 0x100), "F3", "SI:2", true);
        });
        // F4 CALLCHAIN: g's proven AX result is passed straight to h.
        fixture("F4", new Fx("f4").fn(0x180, "a10621", "c3").fn(0x100, "a30021", "c3")
                .fn(0x40, "call:0180", "call:0100", "c3")
                .fn(0x60, "call:0180", "a30821", "c3").fn(0x80, "call:0180", "a30a21", "c3"), null, (p, fx, l) -> {
            var call = callAt(decompile(p, fx, 0x40), p, fx, 0x43);
            var arg = call.getNumInputs() == 2 ? call.getInput(1) : null;
            check(arg != null && arg.getDef() != null && arg.getDef().getOpcode() == PcodeOp.CALL,
                "F4 call binds g's result: " + show(call));
            locked(fn(p, fx, 0x100), "F4", "AX:2", true);
        });
        // F5 UNJUST: a separately written high byte.
        fixture("F5", new Fx("f5").fn(0x100, "883e0021", "c3").fn(0x40, "b705", "call:0100", "c3"), null, (p, fx, l) -> {
            var call = callAt(decompile(p, fx, 0x40), p, fx, 0x42);
            check(call.getNumInputs() == 2 && constant(call.getInput(1), 5, 1), "F5 call binds BH: " + show(call));
            locked(fn(p, fx, 0x100), "F5", "BH:1", true);
        });
        // F5b: a byte register copy carries the entry value (MOV BL,AL then a BL store reads AL).
        fixture("F5b", new Fx("f5b").fn(0x100, "88c3", "881e0021", "c3").fn(0x40, "b004", "call:0100", "c3"), null, (p, fx, l) -> {
            var call = callAt(decompile(p, fx, 0x40), p, fx, 0x42);
            check(call.getNumInputs() == 2 && constant(call.getInput(1), 4, 1), "F5b call binds AL: " + show(call));
            locked(fn(p, fx, 0x100), "F5b", "AL:1", true);
        });
        // F6 SAVE: PUSH AX ... POP AX is no input and no result; AX survives the call.
        fixture("F6", new Fx("f6").fn(0x100, "50", "a10621", "a30021", "58", "c3")
                .fn(0x40, "b83412", "call:0100", "a30221", "c3"), null, (p, fx, l) -> {
            var h = decompile(p, fx, 0x40);
            var call = callAt(h, p, fx, 0x43);
            check(call.getNumInputs() == 1 && call.getOutput() == null, "F6 call has no argument or result: " + show(call)
                + " stored=" + stored(h, 0x2102) + " " + cText(p, fx, 0x40) + " callee=" + cText(p, fx, 0x100));
            check(constant(stored(h, 0x2102), 0x1234, 2), "F6 AX preserved: " + stored(h, 0x2102));
            locked(fn(p, fx, 0x100), "F6", "", true);
        });
        // F7 KILLOUT: BX is not written by the callee, so the caller keeps its own BX.
        fixture("F7", new Fx("f7").fn(0x100, STORE_DX, "c3").fn(0x40, "ba5500", "bb0700", "call:0100", "891e0221", "c3"), null, (p, fx, l) -> {
            var h = decompile(p, fx, 0x40);
            var call = callAt(h, p, fx, 0x46);
            check(call.getNumInputs() == 2 && constant(call.getInput(1), 0x55, 2), "F7 call binds DX: " + show(call));
            check(constant(stored(h, 0x2102), 7, 2), "F7 BX preserved: " + stored(h, 0x2102));
            locked(fn(p, fx, 0x100), "F7", "DX:2", true);
        });
        // F8 veto: an unresolved call before the read leaves the interface unknown.
        fixture("F8", new Fx("f8").fn(0x100, "ff162021", STORE_BX, "c3").fn(0x40, "bb3412", "call:0100", "c3"), null, (p, fx, l) -> {
            unlocked(fn(p, fx, 0x100), "F8");
            vetoed(l, fn(p, fx, 0x100), "F8", "UNRESOLVED_CALL");
        });
        // F9 veto: a computed jump.
        fixture("F9", new Fx("f9").fn(0x100, STORE_BX, "a80174", "02", "ffe0", "c3").fn(0x40, "bb3412", "call:0100", "c3"), null, (p, fx, l) -> {
            unlocked(fn(p, fx, 0x100), "F9");
            vetoed(l, fn(p, fx, 0x100), "F9", "COMPUTED_FLOW");
        });
        // F10 nested callee input: f passes DI through to g, which reads it; DI is also read after the
        // call. Then the proof goes away and the rule resets its own signature.
        fixture("F10", new Fx("f10").fn(0x180, "893e0421", "c3").fn(0x100, "call:0180", "c3")
                .fn(0x40, "bf0900", "call:0100", "893e0621", "c3"), null, (p, fx, l) -> {
            var h = decompile(p, fx, 0x40);
            var call = callAt(h, p, fx, 0x43);
            check(call.getNumInputs() == 2 && constant(call.getInput(1), 9, 2), "F10 call binds DI: " + show(call));
            check(constant(stored(h, 0x2106), 9, 2), "F10 DI preserved: " + stored(h, 0x2106));
            locked(fn(p, fx, 0x100), "F10", "DI:2", true);
            l.clear();
            rules(p, l);
            check(l.stream().noneMatch(x -> x.contains("\"outcome\":\"SET\"") || x.contains("REVERT")), "F10 stable replay " + l);
            p.getListing().getInstructionAt(at(p, fx.segment, 0x100)).setFlowOverride(FlowOverride.BRANCH);
            rules(p, l);
            check(l.stream().anyMatch(x -> x.contains("\"rule\":\"L1\"") && x.contains("REVERT")), "F10 proof invalidation " + l);
            unlocked(fn(p, fx, 0x100), "F10 reset");
            check(fn(p, fx, 0x100).getCallingConventionName().equals("__wsasm"), "F10 reset convention");
        });
        // F11 vetoes: RAM body, stack read above the return address, explicit signature.
        Fx ram = new Fx("f11ram").fn(0x100, STORE_BX, "c3").fn(0x40, "bb3412", "call:0100", "c3");
        ram.segment = 0x0000; ram.writable = true;
        fixture("F11a", ram, null, (p, fx, l) -> {
            unlocked(fn(p, fx, 0x100), "F11a");
            vetoed(l, fn(p, fx, 0x100), "F11a", "RAM_BODY");
        });
        fixture("F11b", new Fx("f11b").fn(0x100, "55", "8bec", "8b4604", "a30021", "5d", "c3")
                .fn(0x40, "bb3412", "53", "call:0100", "5b", "c3"), null, (p, fx, l) -> {
            unlocked(fn(p, fx, 0x100), "F11b");
            vetoed(l, fn(p, fx, 0x100), "F11b", "STACK_FRAME");
        });
        fixture("F11c", new Fx("f11c").fn(0x100, STORE_BX, "c3").fn(0x40, "bb3412", "call:0100", "c3"), (p, fx, l) -> {
            var f = fn(p, fx, 0x100);
            f.setCustomVariableStorage(true);
            f.setReturn(WordDataType.dataType, new VariableStorage(p, p.getRegister("DX")), SourceType.USER_DEFINED);
            f.setSignatureSource(SourceType.USER_DEFINED);
        }, (p, fx, l) -> {
            var f = fn(p, fx, 0x100);
            check(f.getSignatureSource() == SourceType.USER_DEFINED && f.getParameterCount() == 0
                && f.getReturn().getVariableStorage().toString().equals("DX:2")
                && f.getCallingConventionName().equals("__wsasm"), "F11c user signature untouched " + f.getPrototypeString(true, true));
        });
        // F12 input on one path only (AL always, DX on one branch); DX also read after the call.
        fixture("F12", new Fx("f12").fn(0x100, "a801", "7404", STORE_DX, "c3")
                .fn(0x40, "8b161021", "b003", "call:0100", "89161221", "c3"), null, (p, fx, l) -> {
            var call = callAt(decompile(p, fx, 0x40), p, fx, 0x46);
            boolean al = false;
            for (int i = 1; i < call.getNumInputs(); i++) al |= constant(call.getInput(i), 3, 1);
            check(call.getNumInputs() == 3 && al, "F12 call binds AL and DX: " + show(call));
            locked(fn(p, fx, 0x100), "F12", "AL:1,DX:2", true);
        });
        // L2a: AL read after an unresolved call is not an entry input; no lock is written.
        final String UNRESOLVED = "ff162021";
        fixture("L2a", new Fx("l2a").fn(0x100, UNRESOLVED, "a20021", "b80100", "c3")
                .fn(0x40, "call:0100", "a30221", "c3").fn(0x60, "call:0100", "a30421", "c3"), null, (p, fx, l) -> {
            unlocked(fn(p, fx, 0x100), "L2a");
            check(l.stream().anyMatch(x -> x.contains("\"rule\":\"R1b\"") && x.contains("VETO_INPUTS_UNKNOWN")), "L2a R1b veto emitted");
        });
        // L2b: a carry read is not an input; the proven AX result is still locked.
        fixture("L2b", new Fx("l2b").fn(0x100, "b80000", "7303", "b80100", "c3")
                .fn(0x40, "call:0100", "a30221", "c3").fn(0x60, "call:0100", "a30421", "c3"), null, (p, fx, l) -> {
            var f = fn(p, fx, 0x100);
            check(f.hasCustomVariableStorage() && f.getReturn().getVariableStorage().toString().equals("AX:2"),
                "L2b AX result locked " + f.getPrototypeString(true, true));
            check(f.getParameterCount() == 0, "L2b no flag input " + f.getPrototypeString(true, true));
        });
        // L2c control: a frame read ([BP+4] after MOV BP,SP) does not withdraw the proven AX result,
        // which the register convention cannot express without the lock; no register input is invented.
        fixture("L2c", new Fx("l2c").fn(0x100, "55", "8bec", "8b4604", "5d", "c3")
                .fn(0x40, "53", "call:0100", "a30221", "5b", "c3").fn(0x60, "53", "call:0100", "a30421", "5b", "c3"), null, (p, fx, l) -> {
            var f = fn(p, fx, 0x100);
            check(f.hasCustomVariableStorage() && f.getReturn().getVariableStorage().toString().equals("AX:2")
                && f.getParameterCount() == 0, "L2c AX result kept without inputs " + f.getPrototypeString(true, true));
            check(f.getCallingConventionName().equals("__wsasm"), "L2c no L1 model on a stack frame");
        });
        // L2d: an R1b lock saved by an earlier build (in_AL after the unresolved call) is reset.
        fixture("L2d", new Fx("l2d").fn(0x100, UNRESOLVED, "a20021", "b80100", "c3")
                .fn(0x40, "call:0100", "a30221", "c3").fn(0x60, "call:0100", "a30421", "c3"), (p, fx, l) -> {
            var f = fn(p, fx, 0x100);
            var param = new ParameterImpl("in_AL", ByteDataType.dataType, new VariableStorage(p, p.getRegister("AL")), p, SourceType.ANALYSIS);
            f.updateFunction("__wsasm", new ReturnParameterImpl(WordDataType.dataType, new VariableStorage(p, p.getRegister("AX")), p),
                List.of(param), Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
        }, (p, fx, l) -> {
            unlocked(fn(p, fx, 0x100), "L2d");
            check(l.stream().anyMatch(x -> x.contains("\"rule\":\"R1b\"") && x.contains("REVERT")), "L2d R1b revert emitted");
        });

        long failed = results.values().stream().filter(v -> !v.equals("PASS")).count();
        println("WSCallBindingFixtures: locks=" + locks + " fixtures=" + results.size() + " failed=" + failed + " checks=" + checks);
        if (failed > 0) throw new AssertionError("WSCallBindingFixtures: FAIL " + failed + " of " + results.size());
        println("WSCallBindingFixtures: PASS checks=" + checks);
    }
}
