// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

/** C1b: a direct far call to a complete register-copy leaf can preserve BX through the call. */
public final class WSLsiLiveThrough {
    private static final String LSI = "__lsic86";
    private static final String PRESERVED = "__lsic86_far_bx_preserved";

    private record Copy(Register input, List<Address> callers) {}

    private WSLsiLiveThrough() {}

    /** True when C1 must leave the specialization (or a change by the user) in place. */
    public static boolean apply(Function function, String family, Consumer<String> emit) throws Exception {
        var program = function.getProgram();
        boolean specialized = PRESERVED.equals(function.getCallingConventionName());
        if (!specialized && !LSI.equals(family)) return false;
        var source = function.getSignatureSource();
        if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) return specialized;
        Register ax = program.getRegister("AX");
        if (specialized && !ownsSignature(function, ax)) return true;
        if (!specialized && (function.hasCustomVariableStorage() || function.getParameterCount() != 0
                || !function.getReturnType().isEquivalent(DefaultDataType.dataType))) return false;

        Copy proof = LSI.equals(family) && program.getCompilerSpec().getCallingConvention(PRESERVED) != null
            ? proveCopy(function, ax) : null;
        if (proof == null) {
            if (specialized) {
                function.updateFunction(family, new ReturnParameterImpl(DefaultDataType.dataType, program),
                    List.of(), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.DEFAULT);
                emit.accept(String.format("{\"rule\":\"C1b\",\"function\":\"%s\",\"outcome\":\"REVERT\"}",
                    function.getEntryPoint()));
            }
            return false;
        }
        Register input = proof.input();
        if (specialized && function.getParameter(0).getName().equals("in_" + input.getName())) return true;

        var param = new ParameterImpl("in_" + input.getName(), WordDataType.dataType,
            new VariableStorage(program, input), program, SourceType.ANALYSIS);
        var result = new ReturnParameterImpl(WordDataType.dataType, new VariableStorage(program, ax), program);
        function.updateFunction(PRESERVED, result, List.of(param), Function.FunctionUpdateType.CUSTOM_STORAGE,
            false, SourceType.ANALYSIS);
        emit.accept(String.format("{\"rule\":\"C1b\",\"function\":\"%s\",\"outcome\":\"SET\",\"input\":\"%s\",\"result\":\"AX\",\"preserved\":\"BX\",\"callers\":\"%s\"}",
            function.getEntryPoint(), input.getName(), proof.callers()));
        return true;
    }

    private static boolean ownsSignature(Function function, Register ax) throws Exception {
        if (function.getSignatureSource() != SourceType.ANALYSIS || !function.hasCustomVariableStorage()
                || function.getParameterCount() != 1 || !function.getReturnType().isEquivalent(WordDataType.dataType)) return false;
        var program = function.getProgram();
        var param = function.getParameter(0);
        if (param.getSource() != SourceType.ANALYSIS || !param.getDataType().isEquivalent(WordDataType.dataType)
                || !function.getReturn().getVariableStorage().equals(new VariableStorage(program, ax))) return false;
        for (String name : List.of("CX", "DX")) {
            if (param.getName().equals("in_" + name)
                    && param.getVariableStorage().equals(new VariableStorage(program, program.getRegister(name)))) return true;
        }
        return false;
    }

    private static Copy proveCopy(Function function, Register ax) {
        if (function.isExternal() || function.isThunk() || function.isInline() || function.hasNoReturn()
                || function.getCallFixup() != null || function.getBody().getNumAddresses() != 3) return null;

        var program = function.getProgram();
        var entry = function.getEntryPoint();
        var listing = program.getListing();
        var block = program.getMemory().getBlock(entry);
        if (block == null || !block.isInitialized() || block.isWrite() || !block.isExecute()) return null;
        var copy = listing.getInstructionAt(entry);
        if (copy == null || copy.getLength() != 2 || copy.getFlowOverride() != FlowOverride.NONE
                || !copy.getMnemonicString().equals("MOV") || copy.getFallThrough() == null
                || !copy.getFallThrough().equals(copy.getDefaultFallThrough()) || copy.getFallFrom() != null) return null;
        var ret = listing.getInstructionAt(copy.getFallThrough());
        if (ret == null || ret.getLength() != 1 || ret.getFlowOverride() != FlowOverride.NONE
                || !ret.getMnemonicString().equals("RETF") || !ret.getFlowType().isTerminal()
                || !function.getBody().contains(copy.getMinAddress(), copy.getMaxAddress())
                || !function.getBody().contains(ret.getAddress()) || !block.contains(ret.getAddress())) return null;

        var ops = copy.getPcode();
        if (ops.length != 1 || ops[0].getOpcode() != PcodeOp.COPY
                || !ops[0].getOutput().getAddress().equals(ax.getAddress())
                || ops[0].getOutput().getSize() != ax.getMinimumByteSize()) return null;
        var read = ops[0].getInput(0);
        var input = program.getRegister(read.getAddress(), read.getSize());
        if (input == null || !List.of("CX", "DX").contains(input.getName())) return null;

        var callers = new ArrayList<Address>();
        for (var ref : program.getReferenceManager().getReferencesTo(entry)) {
            if (!ref.getReferenceType().isFlow()) continue;
            var call = listing.getInstructionAt(ref.getFromAddress());
            if (!ref.getReferenceType().isCall() || call == null || !call.getMnemonicString().equals("CALLF")
                    || call.getLength() != 5 || call.getFlowOverride() != FlowOverride.NONE
                    || !call.getFlowType().isCall() || call.getFlowType().isComputed()
                    || call.getFlows().length != 1 || !entry.equals(call.getFlows()[0])
                    || call.getDefaultFlows().length != 1 || !entry.equals(call.getDefaultFlows()[0])) return null;
            callers.add(call.getAddress());
        }
        return callers.isEmpty() ? null : new Copy(input, callers);
    }
}
