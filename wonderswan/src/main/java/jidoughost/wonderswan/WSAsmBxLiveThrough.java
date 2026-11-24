// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

/** R1d: retain BX across a proved read-only AX-input near leaf with established SI/ES outputs. */
final class WSAsmBxLiveThrough {
    static final String CONVENTION = "__wsasm_near_bx_preserved";
    private static final String BASE = WSAsmAxLiveThrough.BASE;
    private static final Set<String> IMPLICIT_READS = Set.of("CS", "DS", "DF");
    private static final Set<String> FRAME = Set.of("SP", "BP", "SS", "CS", "DS", "DF");
    private static final int MAX_CONTINUATION = 4;

    private WSAsmBxLiveThrough() {}

    private static boolean ownedShape(Function function) throws Exception {
        if (function.getSignatureSource() != SourceType.ANALYSIS || !function.hasCustomVariableStorage()
                || function.getParameterCount() != 1 || function.getReturnType().getLength() != 4
                || !function.getReturnType().getName().equals("result_SI_ES")) return false;
        var returnSource = function.getReturn().getSource();
        if (returnSource == SourceType.USER_DEFINED || returnSource == SourceType.IMPORTED) return false;
        var program = function.getProgram();
        var param = function.getParameter(0);
        return param.getSource() == SourceType.ANALYSIS && param.getName().equals("in_AX")
            && param.getDataType().isEquivalent(WordDataType.dataType)
            && param.getVariableStorage().equals(new VariableStorage(program, program.getRegister("AX")))
            && function.getReturn().getVariableStorage().equals(
                new VariableStorage(program, program.getRegister("SI"), program.getRegister("ES")));
    }

    static boolean reconcileConvention(Function function, String family, Consumer<String> emit) throws Exception {
        if (!CONVENTION.equals(function.getCallingConventionName())) return false;
        if (!BASE.equals(family) && ownedShape(function)) change(function, family, emit, "REVERT", null);
        return true;
    }

    static void apply(Function function, Consumer<String> emit) throws Exception {
        String convention = function.getCallingConventionName();
        boolean specialized = CONVENTION.equals(convention);
        if ((!specialized && !BASE.equals(convention)) || !ownedShape(function)) return;
        Address witness = prove(function);
        if (witness == null) {
            if (specialized) change(function, BASE, emit, "REVERT", null);
        } else if (!specialized) {
            change(function, CONVENTION, emit, "SET", witness);
        }
    }

    private static void change(Function function, String convention, Consumer<String> emit, String outcome,
            Address witness) throws Exception {
        function.setCallingConvention(convention);
        emit.accept(String.format("{\"rule\":\"R1d\",\"function\":\"%s\",\"outcome\":\"%s\","
                + "\"preserved\":\"BX\",\"caller_read\":\"%s\"}", function.getEntryPoint(), outcome,
                witness == null ? "" : witness));
    }

    private static Address prove(Function function) {
        var code = WSAsmAxLiveThrough.readOnlyLeaf(function);
        if (code.isEmpty()) return null;
        var program = function.getProgram();
        var bx = program.getRegister("BX");
        var refs = program.getReferenceManager();
        var defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        for (var ref : refs.getReferencesTo(function.getEntryPoint())) {
            if (!ref.getReferenceType().isCall()) return null;
        }

        Set<Address> definitions = new HashSet<>();
        var ax = program.getRegister("AX");
        boolean inputAX = false;
        for (var ins : code) {
            if (!ins.getAddress().equals(function.getEntryPoint()))
                for (var ref : refs.getReferencesTo(ins.getAddress()))
                    if (ref.getReferenceType().isFlow()) return null;
            for (var op : ins.getPcode()) {
                // A DX-port read (port_in userop) counts as the non-RAM LOAD it used to be.
                if (WSPortAccess.legacyOpcode(program.getLanguage(), op) == PcodeOp.LOAD
                        && (op.getOpcode() == PcodeOp.CALLOTHER || !op.getInput(0).isConstant()
                        || op.getInput(0).getOffset() != defaultSpace.getSpaceID())) return null;
                for (var input : op.getInputs()) {
                    var reg = WSAsmAxLiveThrough.register(function, input);
                    if (input.isRegister() && reg == null) return null;
                    if (reg == null || IMPLICIT_READS.contains(reg.getName())) continue;
                    if (FRAME.contains(reg.getName()) || WSAsmAxLiveThrough.overlaps(bx, reg)) return null;
                    for (int i = 0; i < input.getSize(); i++) {
                        if (definitions.contains(input.getAddress().add(i))) continue;
                        if (!WSAsmAxLiveThrough.overlaps(ax, reg)) return null;
                        inputAX = true;
                    }
                }
                var output = op.getOutput();
                var reg = WSAsmAxLiveThrough.register(function, output);
                if (output != null && output.isRegister() && reg == null) return null;
                if (reg != null) {
                    if (FRAME.contains(reg.getName()) || WSAsmAxLiveThrough.overlaps(bx, reg)) return null;
                    for (int i = 0; i < output.getSize(); i++) definitions.add(output.getAddress().add(i));
                }
            }
        }
        if (!inputAX) return null;
        for (String output : List.of("SI", "ES")) {
            var reg = program.getRegister(output);
            for (int i = 0; i < reg.getMinimumByteSize(); i++)
                if (!definitions.contains(reg.getAddress().add(i))) return null;
        }

        var ret = program.getListing().getInstructionAt(function.getBody().getMaxAddress());
        for (var ref : refs.getReferencesTo(ret.getAddress()))
            if (ref.getReferenceType().isFlow()) return null;
        for (var call : WSAsmAxLiveThrough.directNearCallers(function)) {
            var witness = bxRead(function, call);
            if (witness != null) return witness;
        }
        return null;
    }

    private static Address bxRead(Function leaf, Address site) {
        var program = leaf.getProgram();
        var listing = program.getListing();
        var owner = program.getFunctionManager().getFunctionContaining(site);
        if (owner == null) return null;
        var bx = program.getRegister("BX");
        var ins = listing.getInstructionAt(listing.getInstructionAt(site).getFallThrough());
        for (int step = 0; step < MAX_CONTINUATION && ins != null; step++) {
            if (!owner.getBody().contains(ins.getMinAddress(), ins.getMaxAddress())
                    || ins.getFlowOverride() != FlowOverride.NONE || ins.isFallThroughOverridden()
                    || !ins.getFlowType().isFallthrough()) return null;
            for (var op : ins.getPcode()) {
                switch (op.getOpcode()) {
                    case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.CALL, PcodeOp.CALLIND,
                         PcodeOp.BRANCHIND, PcodeOp.RETURN -> { return null; }
                    case PcodeOp.CALLOTHER -> {
                        if (!"segment".equals(program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset())))
                            return null;
                    }
                    default -> { }
                }
                boolean readsBX = false;
                for (var input : op.getInputs()) {
                    var r = WSAsmAxLiveThrough.register(leaf, input);
                    if (input.isRegister() && r == null) return null;
                    if (r != null && WSAsmAxLiveThrough.overlaps(bx, r)) readsBX = true;
                }
                var output = WSAsmAxLiveThrough.register(leaf, op.getOutput());
                if (op.getOutput() != null && op.getOutput().isRegister() && output == null) return null;
                if (readsBX) return ins.getAddress();
                if (output != null && WSAsmAxLiveThrough.overlaps(bx, output)) return null;
            }
            ins = listing.getInstructionAt(ins.getFallThrough());
        }
        return null;
    }
}
