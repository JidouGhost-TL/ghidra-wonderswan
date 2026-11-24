// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;

/** Classify instruction p-code I/O across direct-space and named port encodings. */
public final class WSPortAccess {
    public record Access(boolean write, int bytes, boolean indexed) {}

    private WSPortAccess() {}

    public static Access of(Language language, PcodeOp op) {
        var io = language.getAddressFactory().getAddressSpace("io");
        if (io == null) return null;
        int opcode = op.getOpcode();
        if ((opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) && op.getInput(0).isConstant()
                && (int)op.getInput(0).getOffset() == io.getSpaceID()) {
            boolean write = opcode == PcodeOp.STORE;
            return new Access(write, (write ? op.getInput(2) : op.getOutput()).getSize(), true);
        }
        if (opcode == PcodeOp.COPY) {
            var from = op.getInput(0);
            var to = op.getOutput();
            if (from.getAddress().getAddressSpace().equals(io)) return new Access(false, from.getSize(), false);
            if (to.getAddress().getAddressSpace().equals(io)) return new Access(true, to.getSize(), false);
        }
        if (opcode != PcodeOp.CALLOTHER || !op.getInput(0).isConstant()
                || !"V30MZ".equals(language.getProcessor().toString())) return null;
        long selector = op.getInput(0).getOffset();
        if (selector < 0 || selector >= language.getNumberOfUserDefinedOpNames()) return null;
        String name = language.getUserDefinedOpName((int)selector);
        boolean write;
        int size;
        switch (name) {
            case "port_in8" -> { write = false; size = 1; }
            case "port_in16" -> { write = false; size = 2; }
            case "port_out8" -> { write = true; size = 1; }
            case "port_out16" -> { write = true; size = 2; }
            default -> { return null; }
        }
        if (op.getNumInputs() != (write ? 3 : 2) || op.getInput(1).getSize() != 2) return null;
        if (write ? op.getOutput() != null || op.getInput(2).getSize() != size
                : op.getOutput() == null || op.getOutput().getSize() != size) return null;
        return new Access(write, size, true);
    }

    /** Historical raw-p-code mnemonic for callers maintaining legacy fingerprints. */
    public static int legacyOpcode(Language language, PcodeOp op) {
        if (op.getOpcode() != PcodeOp.CALLOTHER) return op.getOpcode();
        Access access = of(language, op);
        if (access == null) return op.getOpcode();
        return access.write() ? PcodeOp.STORE : PcodeOp.LOAD;
    }
}
