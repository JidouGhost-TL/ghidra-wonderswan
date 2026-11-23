// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

/** R1c: retain incoming AX through a proved stack-free ES-argument near leaf. */
public final class WSAsmAxLiveThrough {
    static final String BASE = "__wsasm";
    static final String CONVENTION = "__wsasm_near_ax_preserved";
    private static final int MAX_BODY_BYTES = 96;
    private static final Set<String> IMPLICIT_READS = Set.of("CS", "DS", "DF");
    private static final Set<String> FRAME = Set.of("SP", "BP", "SS", "CS", "DS", "DF");

    private WSAsmAxLiveThrough() {}

    static boolean reconcileConvention(Function function, String family, Consumer<String> emit) throws Exception {
        if (!CONVENTION.equals(function.getCallingConventionName())) return false;
        if (!BASE.equals(family)) {
            var program = function.getProgram();
            var es = new VariableStorage(program, program.getRegister("ES"));
            if (ownedSignature(function, es)) reset(function, family, emit);
        }
        return true;
    }

    public static boolean apply(Function function, Consumer<String> emit) throws Exception {
        String convention = function.getCallingConventionName();
        boolean specialized = CONVENTION.equals(convention);
        var program = function.getProgram();
        if (!specialized && !BASE.equals(convention)) return false;
        if (function.getSignatureSource() == SourceType.USER_DEFINED || function.getSignatureSource() == SourceType.IMPORTED)
            return false;
        var es = new VariableStorage(program, program.getRegister("ES"));
        if (specialized && !ownedSignature(function, es)) return false;
        if (!specialized && (function.getParameterCount() != 0 || function.hasCustomVariableStorage()
                || !function.getReturnType().isEquivalent(DefaultDataType.dataType))) return false;

        List<Address> calls = prove(function);
        if (calls.isEmpty()) {
            if (specialized) reset(function, BASE, emit);
            return false;
        }
        if (!specialized) {
            var param = new ParameterImpl("in_ES", WordDataType.dataType, es, program, SourceType.ANALYSIS);
            function.updateFunction(CONVENTION, new ReturnParameterImpl(VoidDataType.dataType, program),
                List.of(param), Function.FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.ANALYSIS);
            emit.accept(String.format("{\"rule\":\"R1c\",\"function\":\"%s\",\"outcome\":\"SET\",\"input\":\"ES\",\"preserved\":\"AX\",\"callers\":\"%s\"}",
                function.getEntryPoint(), calls));
        }
        return true;
    }

    private static void reset(Function function, String convention, Consumer<String> emit) throws Exception {
        function.updateFunction(convention, new ReturnParameterImpl(DefaultDataType.dataType, function.getProgram()),
            List.of(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.DEFAULT);
        emit.accept(String.format("{\"rule\":\"R1c\",\"function\":\"%s\",\"outcome\":\"REVERT\"}", function.getEntryPoint()));
    }

    private static boolean ownedSignature(Function function, VariableStorage es) {
        if (function.getSignatureSource() != SourceType.ANALYSIS || !function.hasCustomVariableStorage()
                || function.getParameterCount() != 1 || !function.getReturnType().isEquivalent(VoidDataType.dataType)) return false;
        var param = function.getParameter(0);
        return param.getSource() == SourceType.ANALYSIS && "in_ES".equals(param.getName())
            && param.getDataType().isEquivalent(WordDataType.dataType) && es.equals(param.getVariableStorage());
    }

    private static List<Address> prove(Function function) {
        var body = function.getBody();
        if (function.isExternal() || function.isThunk() || function.isInline() || function.hasNoReturn()
                || function.getCallFixup() != null || body.getNumAddressRanges() != 1
                || body.getNumAddresses() > MAX_BODY_BYTES) return List.of();
        var program = function.getProgram();
        var listing = program.getListing();
        var entry = function.getEntryPoint();
        var block = program.getMemory().getBlock(entry);
        if (!entry.equals(body.getMinAddress()) || block == null || !block.isInitialized() || block.isWrite()
                || !block.isExecute() || !block.contains(body.getMaxAddress())) return List.of();

        var ins = listing.getInstructionAt(entry);
        if (ins == null || ins.getFallFrom() != null) return List.of();
        Set<Address> definitions = new HashSet<>();
        Register ax = program.getRegister("AX");
        boolean esInput = false;
        while (ins != null && body.contains(ins.getMinAddress(), ins.getMaxAddress())) {
            String mnemonic = ins.getMnemonicString();
            if (ins.getFlowOverride() != FlowOverride.NONE || ins.isFallThroughOverridden()) return List.of();
            if (mnemonic.equals("RET") && ins.getLength() == 1 && ins.getMaxAddress().equals(body.getMaxAddress())) break;
            var flow = ins.getFlowType();
            if (flow.isCall() || flow.isJump() || flow.isTerminal()) return List.of();
            Address fallThrough = ins.getFallThrough();
            if (fallThrough == null || !body.contains(fallThrough)) return List.of();

            for (PcodeOp op : ins.getPcode()) {
                switch (op.getOpcode()) {
                    case PcodeOp.CALLOTHER -> {
                        if (!"segment".equals(program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset())))
                            return List.of();
                    }
                    // Unproved memory stores can change the saved IP through an alias.
                    case PcodeOp.STORE, PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.CALL,
                            PcodeOp.CALLIND, PcodeOp.BRANCHIND, PcodeOp.RETURN -> { return List.of(); }
                    default -> { }
                }
                for (var input : op.getInputs()) {
                    Register r = register(function, input);
                    if (input.isRegister() && r == null) return List.of();
                    if (r == null || IMPLICIT_READS.contains(r.getName())) continue;
                    if (FRAME.contains(r.getName()) || ax.equals(r) || ax.contains(r) || r.contains(ax)) return List.of();
                    for (int i = 0; i < input.getSize(); i++) {
                        if (definitions.contains(input.getAddress().add(i))) continue;
                        if (!r.getName().equals("ES")) return List.of();
                        esInput = true;
                    }
                }
                var output = op.getOutput();
                if (output != null && output.getAddress().isMemoryAddress()) return List.of();
                Register r = register(function, output);
                if (output != null && output.isRegister() && r == null) return List.of();
                if (r != null) {
                    if (FRAME.contains(r.getName()) || r.getName().equals("ES")
                            || ax.equals(r) || ax.contains(r) || r.contains(ax)) return List.of();
                    for (int i = 0; i < output.getSize(); i++) definitions.add(output.getAddress().add(i));
                }
            }
            ins = listing.getInstructionAt(fallThrough);
        }
        if (!esInput || ins == null || !ins.getMnemonicString().equals("RET")
                || ins.getLength() != 1 || !ins.getMaxAddress().equals(body.getMaxAddress())) return List.of();

        var calls = new ArrayList<Address>();
        for (var ref : program.getReferenceManager().getReferencesTo(entry)) {
            if (!ref.getReferenceType().isFlow()) continue;
            var call = listing.getInstructionAt(ref.getFromAddress());
            if (!ref.getReferenceType().isCall() || call == null || !call.getMnemonicString().equals("CALL")
                    || call.getLength() != 3 || call.getFlowOverride() != FlowOverride.NONE || call.isFallThroughOverridden()
                    || !call.getFlowType().isCall() || call.getFlowType().isComputed()
                    || call.getFlows().length != 1 || !entry.equals(call.getFlows()[0])
                    || call.getDefaultFlows().length != 1 || !entry.equals(call.getDefaultFlows()[0])) return List.of();
            calls.add(call.getAddress());
        }
        return calls;
    }

    private static Register register(Function function, Varnode node) {
        return node != null && node.isRegister() ? function.getProgram().getRegister(node.getAddress(), node.getSize()) : null;
    }
}
