// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import jidoughost.wonderswan.WSReturns;

/** Original-register and opposing controls for R1c. */
public class WSAxLiveThroughFixtures extends GhidraScript {
    private int checks;

    private void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }

    private Address at(ProgramDB program, int offset) {
        return ((SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000, offset);
    }

    private void put(byte[] bytes, int offset, String hex) {
        var decoded = HexFormat.of().parseHex(hex);
        System.arraycopy(decoded, 0, bytes, offset, decoded.length);
    }

    private void test(String name, String leaf, String call, boolean accepted, SourceType explicit) throws Exception {
        byte[] bytes = new byte[0x200];
        Arrays.fill(bytes, (byte) 0xcc);
        String observe = name.equals("genuine-other-result") ? "a30021890e0221c3" : "a30021c3";
        put(bytes, 0x40, "b83412ba30128ec2" + call + observe);
        put(bytes, 0x100, leaf);
        if (name.equals("fall-through")) put(bytes, 0xff, "90");

        var program = new ProgramDB(name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int transaction = program.startTransaction(name);
        try {
            var file = program.getMemory().createFileBytes(name, 0, bytes.length, new ByteArrayInputStream(bytes), monitor);
            program.getMemory().createInitializedBlock("code", at(program, 0), file, 0, bytes.length, false)
                .setPermissions(true, false, true);
            var context = program.getProgramContext();
            context.setValue(program.getRegister("csval"), at(program, 0), at(program, bytes.length - 1), BigInteger.valueOf(0x4000));
            context.setValue(program.getRegister("DS"), at(program, 0), at(program, bytes.length - 1), BigInteger.ZERO);
            context.setValue(program.getRegister("SS"), at(program, 0), at(program, bytes.length - 1), BigInteger.ZERO);
            for (int start : new int[] {0x100, 0x40}) {
                check(new DisassembleCommand(at(program, start), null, true).applyTo(program, monitor), name + " disassembly");
                check(new CreateFunctionCmd(at(program, start)).applyTo(program, monitor), name + " creation");
            }
            var function = program.getFunctionManager().getFunctionAt(at(program, 0x100));
            function.setCallingConvention("__wsasm");
            if (name.equals("fall-through")) {
                check(new DisassembleCommand(at(program, 0xff), null, true).applyTo(program, monitor), name + " predecessor");
                check(at(program, 0xff).equals(program.getListing().getInstructionAt(at(program, 0x100)).getFallFrom()),
                    name + " true incoming fall-through");
            }
            if (explicit != null) {
                function.setCustomVariableStorage(true);
                function.setReturn(WordDataType.dataType, new VariableStorage(program, program.getRegister("DX")), explicit);
                function.setSignatureSource(explicit);
            }
            var lines = new ArrayList<String>();
            WSReturns.apply(program, lines::add, monitor);
            check(function.getCallingConventionName().equals(accepted ? "__wsasm_near_ax_preserved" : "__wsasm"),
                name + " convention " + function.getPrototypeString(true,true) + " " + lines);
            if (explicit != null) {
                check(function.getSignatureSource() == explicit && function.getReturn().getVariableStorage().toString().equals("DX:2"),
                    name + " declared storage kept");
            }
            if (name.equals("genuine-other-result")) {
                check(function.getReturn().getVariableStorage().toString().equals("CX:2"),
                    name + " existing non-AX output won");
            }
            if (accepted) {
                check(function.getParameterCount() == 1 && function.getParameter(0).getVariableStorage().toString().equals("ES:2"),
                    name + " exact ES input");
                check(function.getReturnType().isEquivalent(VoidDataType.dataType), name + " true void");
                verifyCaller(program);
                lines.clear();
                WSReturns.apply(program, lines::add, monitor);
                check(lines.stream().noneMatch(line -> line.contains("\"rule\":\"R1c\"")), name + " stable replay");
                program.getListing().getInstructionAt(at(program, 0x48)).setFlowOverride(FlowOverride.BRANCH);
                WSReturns.apply(program, lines::add, monitor);
                check(lines.stream().anyMatch(line -> line.contains("\"outcome\":\"REVERT\"")), name + " proof invalidation");
                check(function.getCallingConventionName().equals("__wsasm") && function.getParameterCount() == 0
                    && !function.hasCustomVariableStorage(), name + " analysis-owned signature cleared");
            }
            byte[] after = new byte[bytes.length];
            program.getMemory().getBytes(at(program, 0), after);
            check(Arrays.equals(after, bytes), name + " instruction bytes unchanged");
        } finally {
            program.endTransaction(transaction, false);
            program.release(this);
        }
    }

    private void verifyCaller(ProgramDB program) {
        var decompiler = new DecompInterface();
        try {
            check(decompiler.openProgram(program), "open fixture decompiler");
            var function = program.getFunctionManager().getFunctionAt(at(program, 0x40));
            var result = decompiler.decompileFunction(function, 30, monitor);
            check(result.decompileCompleted(), "decompile " + result.getErrorMessage());
            boolean call = false, store = false;
            for (var ops = result.getHighFunction().getPcodeOps(); ops.hasNext();) {
                var op = ops.next();
                if (op.getOpcode() == PcodeOp.CALL && op.getSeqnum().getTarget().equals(at(program, 0x48))) {
                    call = op.getNumInputs() == 2 && op.getOutput() == null && op.getInput(1).isConstant()
                        && op.getInput(1).getOffset() == 0x1230;
                }
                if (op.getOpcode() == PcodeOp.COPY && op.getOutput().getAddress().isMemoryAddress()
                        && op.getOutput().getOffset() == 0x2100 && op.getInput(0).isConstant()) {
                    store |= op.getInput(0).getOffset() == 0x1234;
                }
            }
            check(call, "call has ES input and no output");
            check(store, "store keeps the original AX constant");
        } finally {
            decompiler.dispose();
        }
    }

    @Override public void run() throws Exception {
        String read = "268b0e0021";
        String leaf = read + "c3";
        String rep = "b90200be0010bf0020f3a5c3";
        String plain = "e8b500";
        test("es-read", leaf, plain, true, null);
        test("repeat-store", rep, plain, false, null);
        test("direct-saved-ip-alias", read + "c706fe7f5000c3", plain, false, null);
        test("segmented-store", read + "26c706fe7f5000c3", plain, false, null);
        test("low-byte-clobber", "b07f" + leaf, plain, false, null);
        test("other-input", "89de" + leaf, plain, false, null);
        test("return-frame", "535b" + leaf, plain, false, null);
        test("interrupt", "cd20" + leaf, plain, false, null);
        test("fall-through", leaf, plain, false, null);
        test("wrong-call-frame", leaf, "9a00010040", false, null);
        test("genuine-other-result", "8cc1c3", plain, false, null);
        test("explicit", leaf, plain, false, SourceType.USER_DEFINED);
        test("imported", leaf, plain, false, SourceType.IMPORTED);
        println("WSAxLiveThroughFixtures: PASS checks=" + checks);
    }
}
