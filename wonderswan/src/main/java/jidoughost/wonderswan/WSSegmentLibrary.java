// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.lang.reflect.Method;
import java.util.List;

import ghidra.pcode.exec.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** Real-mode address translation without the missing-userop callback or reflective invocation. */
final class WSSegmentLibrary extends DefaultPcodeUseropLibrary<byte[]> {
    WSSegmentLibrary() { putOp(new Segment()); }

    private final class Segment implements PcodeUseropDefinition<byte[]> {
        @Override public String getName() { return "segment"; }
        @Override public int getInputCount() { return 2; }
        @Override public boolean isFunctional() { return false; }
        @Override public boolean hasSideEffects() { return false; }
        @Override public boolean modifiesContext() { return false; }
        @Override public boolean canInlinePcode() { return false; }
        @Override public Class<?> getOutputType() { return byte[].class; }
        @Override public Method getJavaMethod() { return null; }
        @Override public PcodeUseropLibrary<?> getDefiningLibrary() { return WSSegmentLibrary.this; }

        @Override
        public void execute(PcodeExecutor<byte[]> executor, PcodeUseropLibrary<byte[]> library, PcodeOp op) {
            translate(executor, op.getOutput(), op.getInput(1), op.getInput(2));
        }

        @Override
        public void execute(PcodeExecutor<byte[]> executor, PcodeUseropLibrary<byte[]> library,
                PcodeOp op, Varnode output, List<Varnode> inputs) {
            translate(executor, output, inputs.get(0), inputs.get(1));
        }

        private void translate(PcodeExecutor<byte[]> executor, Varnode output, Varnode segment, Varnode offset) {
            var state = executor.getState();
            long base = scalar(state.getVar(segment, executor.getReason()));
            long inner = scalar(state.getVar(offset, executor.getReason()));
            long address = ((base << 4) + inner) & 0xFFFFF;
            if (output != null) {
                byte[] value = new byte[output.getSize()];
                for (int i = 0; i < value.length; i++) value[i] = (byte) (address >> (8 * i));
                state.setVar(output, value);
            }
        }
    }

    private static long scalar(byte[] value) {
        long result = 0;
        for (int i = value.length - 1; i >= 0; i--) result = (result << 8) | (value[i] & 0xFF);
        return result;
    }
}
