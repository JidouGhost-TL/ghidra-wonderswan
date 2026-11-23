// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.symbol.SourceType;
import jidoughost.wonderswan.WSReturns;

/** R1b direct-jump continuation and joined return layout. */
public class WSReturnJoinFixtures extends GhidraScript {
    private record JoinedResult(String storage, Map<Integer, String> fields) {}

    private int checks;

    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
    }

    private Address at(ProgramDB p, int offset) {
        return ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000, offset);
    }

    private void write(byte[] bytes, int offset, String hex) {
        byte[] payload = HexFormat.of().parseHex(hex);
        System.arraycopy(payload, 0, bytes, offset, payload.length);
    }

    private void exercise(String name, String continuation, boolean expected, boolean explicit) throws Exception {
        exercise(name, continuation, "83c001c3", expected, explicit);
    }

    private void exercise(String name, String continuation, String body, boolean expected, boolean explicit) throws Exception {
        exercise(name, continuation, body, expected, explicit, null);
    }

    private void exercise(String name, String continuation, String body, boolean expected, boolean explicit,
            JoinedResult joined) throws Exception {
        byte[] bytes = new byte[0x200];
        Arrays.fill(bytes, (byte) 0xcc);
        write(bytes, 0x40, "b91000a10021e8b700" + continuation);
        write(bytes, 0x100, body);
        if (name.equals("other-function")) write(bytes, 0x180, "a30022890e0222c3");
        var p = new ProgramDB(name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int transaction = p.startTransaction(name);
        try {
            var file = p.getMemory().createFileBytes(name, 0, bytes.length, new ByteArrayInputStream(bytes), monitor);
            p.getMemory().createInitializedBlock("code", at(p, 0), file, 0, bytes.length, false)
                .setPermissions(true, false, true);
            var context = p.getProgramContext();
            context.setValue(p.getRegister("csval"), at(p, 0), at(p, bytes.length - 1), BigInteger.valueOf(0x4000));
            context.setValue(p.getRegister("DS"), at(p, 0), at(p, bytes.length - 1), BigInteger.ZERO);
            if (name.equals("other-function")) {
                check(new DisassembleCommand(at(p, 0x180), null, true).applyTo(p, monitor), "external target disassembled");
                check(new CreateFunctionCmd(at(p, 0x180)).applyTo(p, monitor), "external target gets a distinct body");
            }
            for (int start : new int[] {0x100, 0x40}) {
                check(new DisassembleCommand(at(p, start), null, true).applyTo(p, monitor), name + " disassemble");
                if (start == 0x40 && name.equals("other-function")) {
                    p.getFunctionManager().createFunction(null, at(p, start),
                        new AddressSet(at(p, 0x40), at(p, 0x4b)), SourceType.DEFAULT);
                } else {
                    check(new CreateFunctionCmd(at(p, start)).applyTo(p, monitor), name + " function");
                }
            }
            if (name.equals("override")) p.getListing().getInstructionAt(at(p, 0x49)).setFlowOverride(FlowOverride.BRANCH);
            if (name.equals("additional-fallthrough")) {
                p.getListing().getInstructionAt(at(p, 0x49)).setFallThrough(at(p, 0x4b));
                check(at(p, 0x4b).equals(p.getListing().getInstructionAt(at(p, 0x49)).getFallThrough()),
                    "additional continuation is present");
            }
            var leaf = p.getFunctionManager().getFunctionAt(at(p, 0x100));
            if (explicit) {
                leaf.setCustomVariableStorage(true);
                leaf.setReturn(WordDataType.dataType, new VariableStorage(p, p.getRegister("DX")), SourceType.USER_DEFINED);
                leaf.setSignatureSource(SourceType.USER_DEFINED);
            }
            var evidence = new ArrayList<String>();
            WSReturns.apply(p, evidence::add, monitor);
            String actual = leaf.getReturn().getVariableStorage().toString();
            println(name + " storage " + actual + " " + evidence);
            if (joined == null) {
                check(actual.equals("AX:2") == expected, name + " claimed AX output " + actual);
            } else {
                check(actual.equals(joined.storage()), name + " ordered return storage " + actual);
                verifyFields(p, leaf, name, joined.fields());
            }
            if (name.equals("popped-input") || name.equals("frame-address") || name.equals("stack-segment-address")) {
                check(!leaf.hasCustomVariableStorage() && leaf.getParameterCount() == 0,
                    name + " native signature remains open");
                check(evidence.stream().anyMatch(line -> line.contains("\"outcome\":\"VETO_CONTINUATION_INPUTS\"")),
                    name + " unresolved stack footprint vetoed");
            }
            if (explicit) {
                check(actual.equals("DX:2") && leaf.getSignatureSource() == SourceType.USER_DEFINED, "explicit result preserved");
            }
            if (expected) {
                check(leaf.getParameterCount() == 1 && leaf.getParameter(0).getVariableStorage().toString().equals("AX:2"),
                    name + " one actual AX input");
            }
            if (expected || joined != null) {
                verifyCaller(p, name, joined);
                evidence.clear();
                WSReturns.apply(p, evidence::add, monitor);
                check(evidence.stream().noneMatch(line -> line.contains("\"outcome\":\"SET\"")), name + " stable replay");
            }
            byte[] after = new byte[bytes.length];
            p.getMemory().getBytes(at(p, 0), after);
            check(Arrays.equals(bytes, after), name + " unchanged bytes");
        } finally {
            p.endTransaction(transaction, false);
            p.release(this);
        }
    }

    private void verifyFields(ProgramDB p, Function leaf, String name, Map<Integer, String> expected) {
        check(leaf.getReturnType() instanceof Structure, name + " joined return structure");
        var type = (Structure) leaf.getReturnType();
        check(type.getLength() == leaf.getReturn().getVariableStorage().size(), name + " joined width");
        var observed = new HashMap<Integer, String>();
        for (var field : type.getDefinedComponents()) {
            observed.put(field.getOffset(), field.getFieldName());
        }
        check(observed.equals(expected), name + " structure fields by offset " + observed);
        String shape = String.join("_", Arrays.stream(type.getDefinedComponents())
            .map(f -> f.getFieldName().substring("out_".length())).toList());
        check(type.getName().equals("result_joined_" + shape), name + " type name follows field offsets");
        for (var field : type.getDefinedComponents()) {
            var register = p.getRegister(field.getFieldName().substring("out_".length()));
            check(field.getLength() == register.getMinimumByteSize(), name + " width of " + field.getFieldName());
        }
    }

    private void verifyCaller(ProgramDB p, String name, JoinedResult joined) {
        var decompiler = new DecompInterface();
        try {
            check(decompiler.openProgram(p), "open synthetic caller");
            var caller = p.getFunctionManager().getFunctionAt(at(p, 0x40));
            var result = decompiler.decompileFunction(caller, 30, monitor);
            check(result.decompileCompleted(), "caller decompilation");
            var ops = result.getHighFunction().getPcodeOps(at(p, 0x46));
            while (ops.hasNext()) {
                var op = ops.next();
                if (op.getOpcode() != PcodeOp.CALL) continue;
                if (joined != null) {
                    var leaf = p.getFunctionManager().getFunctionAt(at(p, 0x100));
                    check(op.getOutput() != null && op.getOutput().getSize() == leaf.getReturnType().getLength(),
                        name + " joined CALL output width");
                    var numeric = new HashMap<Integer, String>();
                    var slices = new HashMap<SequenceNumber, Integer>();
                    for (var uses = op.getOutput().getDescendants(); uses.hasNext();) {
                        var use = uses.next();
                        if (use.getOpcode() != PcodeOp.SUBPIECE || !use.getInput(1).isConstant()) continue;
                        var register = p.getRegister(use.getOutput().getAddress(), use.getOutput().getSize());
                        check(register != null, name + " joined slice reaches an exact register");
                        int offset = (int) use.getInput(1).getOffset();
                        check(numeric.put(offset, "out_" + register.getName()) == null, name + " distinct slice offset");
                        slices.put(use.getSeqnum(), offset);
                    }
                    check(numeric.equals(joined.fields()), name + " High register slices " + numeric);
                    var tokens = new ArrayList<ClangNode>();
                    result.getCCodeMarkup().flatten(tokens);
                    var rendered = new HashMap<Integer, String>();
                    for (var node : tokens) {
                        if (!(node instanceof ClangFieldToken token) || token.getPcodeOp() == null) continue;
                        Integer offset = slices.get(token.getPcodeOp().getSeqnum());
                        if (offset == null) continue;
                        check(offset == token.getOffset(), name + " field token offset equals its High slice");
                        check(token.getText().equals(numeric.get(offset)), name + " field token names its High register");
                        rendered.put(offset, token.getText());
                    }
                    check(rendered.equals(numeric), name + " field tokens match High register slices " + rendered);
                    return;
                }
                check(op.getNumInputs() == 2 && op.getOutput() != null && op.getOutput().getSize() == 2,
                    name + " one input and a 16-bit result");
                var operand = op.getInput(1);
                var definition = operand.getDef();
                check(operand.getAddress().isMemoryAddress() && operand.getOffset() == 0x2100
                    || definition != null && definition.getSeqnum().getTarget().equals(at(p, 0x43)),
                    name + " argument originates at the original AX load");
                boolean stored = false;
                for (var uses = op.getOutput().getDescendants(); uses.hasNext();) {
                    var use = uses.next();
                    if (use.getOpcode() == PcodeOp.COPY && use.getOutput().getAddress().isMemoryAddress()
                            && use.getOutput().getOffset() == 0x2200) stored = true;
                }
                check(stored, name + " returned value reaches the original destination word");
                println(result.getDecompiledFunction().getC());
                return;
            }
            throw new AssertionError(name + " missing CALL in emitted caller");
        } finally {
            decompiler.dispose();
        }
    }

    @Override public void run() throws Exception {
        String direct = "a30022890e0222c3";
        String join = "eb0490909090" + direct;
        exercise("direct", direct, true, false);
        exercise("join", join, true, false);
        exercise("override", join, false, false);
        exercise("additional-fallthrough", join, false, false);
        exercise("conditional", "750490909090" + direct, false, false);
        exercise("loop", "ebfe", false, false);
        exercise("other-function", "e93401", false, false);
        exercise("explicit", join, false, true);
        exercise("terminal-restore", join, "53515283c0015a595bc3", true, false);
        exercise("popped-input", join, "53bb78565b891e002383c001c3", false, false);
        exercise("frame-address", join, "530346005bc3", false, false);
        exercise("stack-segment-address", join, "533603075bc3", false, false);
        // Each register is assigned a distinct constant and stored by the caller.
        exercise("equal-width-return", "891e0021893e0221c3", "bb1122bf3344c3", false, false,
            new JoinedResult("BX:2,DI:2", Map.of(0, "out_DI", 2, "out_BX")));
        exercise("mixed-width-return", "a2002189360221c3", "b011be3344c3", false, false,
            new JoinedResult("AL:1,SI:2", Map.of(0, "out_SI", 2, "out_AL")));
        println("WSReturnJoinFixtures: PASS checks=" + checks);
    }
}
