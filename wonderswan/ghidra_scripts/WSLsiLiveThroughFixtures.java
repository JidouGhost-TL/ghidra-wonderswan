// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import jidoughost.wonderswan.WSReturns;
import jidoughost.wonderswan.WSLsiLiveThrough;

/** Raw instruction controls and caller decompilation for C1b. */
public class WSLsiLiveThroughFixtures extends GhidraScript {
    private static final String BASE = "__lsic86";
    private static final String SPECIALIZED = "__lsic86_far_bx_preserved";
    private int checks;

    private void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }

    private Address at(ProgramDB program, int offset) {
        return ((SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000, offset);
    }

    private void put(byte[] bytes, int offset, String hex) {
        byte[] values = HexFormat.of().parseHex(hex);
        System.arraycopy(values, 0, bytes, offset, values.length);
    }

    private void test(String name, String leaf, String call, boolean expected, SourceType explicit,
            boolean writable, String input) throws Exception {
        byte[] bytes = new byte[0x400];
        Arrays.fill(bytes, (byte) 0xcc);
        put(bytes, 0x40, "bb0060b93412ba7856" + call + "a30010891e0210c3");
        put(bytes, 0x100, leaf);
        boolean fallThrough = name.equals("entry-fall-through");
        if (fallThrough) put(bytes, 0xfe, "9090");
        var program = new ProgramDB(name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int transaction = program.startTransaction(name);
        try {
            var file = program.getMemory().createFileBytes(name, 0, bytes.length, new ByteArrayInputStream(bytes), monitor);
            var block = program.getMemory().createInitializedBlock("fixture", at(program, 0), file, 0, bytes.length, false);
            block.setPermissions(true, writable, true);
            var context = program.getProgramContext();
            context.setValue(program.getRegister("csval"), at(program, 0), at(program, bytes.length - 1), BigInteger.valueOf(0x4000));
            context.setValue(program.getRegister("DS"), at(program, 0), at(program, bytes.length - 1), BigInteger.ZERO);
            for (int offset : new int[] {0x100, 0x40}) {
                var address = at(program, offset);
                check(new DisassembleCommand(address, null, true).applyTo(program, monitor), name + " disassembly");
                check(new CreateFunctionCmd(address).applyTo(program, monitor), name + " creation");
            }
            var function = program.getFunctionManager().getFunctionAt(at(program, 0x100));
            var caller = program.getFunctionManager().getFunctionAt(at(program, 0x40));
            if (fallThrough) {
                check(new DisassembleCommand(at(program, 0xfe), null, true).applyTo(program, monitor), name + " predecessor disassembly");
                var entry = program.getListing().getInstructionAt(at(program, 0x100));
                check(at(program, 0xff).equals(entry.getFallFrom()), name + " confirmed fall-through");
                for (var ref : program.getReferenceManager().getReferencesTo(entry.getAddress()))
                    check(!ref.getReferenceType().isFallthrough(), name + " default fall-through is implicit");
            }
            function.setCallingConvention(BASE);
            if (explicit != null) {
                function.setCustomVariableStorage(true);
                function.setReturn(WordDataType.dataType, new VariableStorage(program, program.getRegister("DX")), explicit);
                function.setSignatureSource(explicit);
            }

            String before = function.getSignature().getPrototypeString();
            List<String> receipts = new ArrayList<>();
            check(WSLsiLiveThrough.apply(function, BASE, receipts::add) == expected, name + " rule application " + receipts);
            check(function.getCallingConventionName().equals(expected ? SPECIALIZED : BASE), name + " convention");
            if (expected) {
                check(function.getParameterCount() == 1 && function.getParameter(0).getVariableStorage().toString().equals(input + ":2"),
                    name + " exact input");
                check(function.getReturn().getVariableStorage().toString().equals("AX:2"), name + " exact output");
                check(receipts.size() == 1, name + " matching rule receipt");
                verifyCaller(program, caller, at(program, 0x49), input.equals("CX") ? 0x1234 : 0x5678);
                receipts.clear();
                check(WSLsiLiveThrough.apply(function, BASE, receipts::add) && receipts.isEmpty(), name + " stable replay");
                program.getListing().getInstructionAt(at(program, 0x49)).setFlowOverride(FlowOverride.BRANCH);
                check(!WSLsiLiveThrough.apply(function, BASE, receipts::add), name + " mismatched flow removes specialization");
                check(function.getParameterCount() == 0 && !function.hasCustomVariableStorage()
                    && function.getCallingConventionName().equals(BASE) && receipts.size() == 1, name + " exact reset");
            } else {
                check(before.equals(function.getSignature().getPrototypeString()) && receipts.isEmpty(), name + " untouched");
                if (explicit != null)
                    check(function.getSignatureSource() == explicit, name + " preserved signature source");
                if (name.equals("genuine-bx-ax-result")) {
                    function.setCallingConvention("__wsasm");
                    WSReturns.apply(program, receipts::add, monitor);
                    check(function.getReturn().getVariableStorage().toString().equals("AX:2,BX:2"),
                        name + " R1b still recognizes both outputs: " + function.getReturn().getVariableStorage());
                }
            }
            byte[] after = new byte[bytes.length];
            program.getMemory().getBytes(at(program, 0), after);
            check(Arrays.equals(bytes, after), name + " raw bytes unchanged");
        } finally {
            program.endTransaction(transaction, false);
            program.release(this);
        }
    }

    private void verifyCaller(ProgramDB program, Function caller, Address callSite, int value) {
        var decompiler = new DecompInterface();
        try {
            check(decompiler.openProgram(program), "open fixture decompiler");
            var result = decompiler.decompileFunction(caller, 30, monitor);
            check(result.decompileCompleted(), "decompile caller " + result.getErrorMessage());
            boolean exactCall = false;
            boolean copiedBX = false;
            for (var ops = result.getHighFunction().getPcodeOps(); ops.hasNext();) {
                var op = ops.next();
                if (op.getOpcode() == PcodeOp.CALL && op.getSeqnum().getTarget().equals(callSite)) {
                    exactCall = op.getNumInputs() == 2 && op.getInput(1).isConstant()
                        && op.getInput(1).getOffset() == value && op.getOutput() != null
                        && op.getOutput().getOffset() == program.getRegister("AX").getOffset() && op.getOutput().getSize() == 2;
                }
                if (op.getOpcode() == PcodeOp.COPY && op.getOutput().getAddress().isMemoryAddress()
                        && op.getOutput().getOffset() == 0x1002 && op.getInput(0).isConstant())
                    copiedBX |= op.getInput(0).getOffset() == 0x6000;
            }
            println(result.getDecompiledFunction().getC());
            check(exactCall, "caller has one real input and an AX result in optimized P-code");
            check(copiedBX, "caller stores its incoming BX value in optimized P-code");
        } finally {
            decompiler.dispose();
        }
    }

    @Override
    public void run() throws Exception {
        String far = "9a00010040";
        test("far-copy-cx", "89c8cb", far, true, null, false, "CX");
        test("far-copy-dx", "89d0cb", far, true, null, false, "DX");
        test("true-bx-clobber", "89cbcb", far, false, null, false, null);
        test("genuine-bx-ax-result", "89c889d3cb", far, false, null, false, null);
        test("near-call", "89c8c3", "e8b400", false, null, false, null);
        test("near-call-far-return-mismatch", "89c8cb", "e8b400", false, null, false, null);
        test("entry-fall-through", "89c8cb", far, false, null, false, null);
        test("callee-stack-cleanup", "89c8ca0200", far, false, null, false, null);
        test("writable-code", "89c8cb", far, false, null, true, null);
        test("user-signature", "89c8cb", far, false, SourceType.USER_DEFINED, false, null);
        test("imported-signature", "89c8cb", far, false, SourceType.IMPORTED, false, null);
        println("WSLsiLiveThroughFixtures: PASS checks=" + checks);
    }
}
