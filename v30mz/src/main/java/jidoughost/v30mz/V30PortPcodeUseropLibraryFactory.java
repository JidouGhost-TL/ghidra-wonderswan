// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.v30mz;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.DefaultPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibraryFactory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.lang.reflect.Method;
import java.util.List;

/**
 * Supplies Ghidra's PcodeEmulator with the V30MZ DX-port userops (IN/OUT with DX, INS, OUTS):
 * {@code port_in8/16(port)} and {@code port_out8/16(port, value)} run as an io-space LOAD/STORE of
 * 1 or 2 bytes at the 16-bit port, so load/store callbacks and io-space state see the same access
 * as before these instructions used userops. Registered through the pspec {@code useropLibs}
 * property.
 */
@PcodeUseropLibraryFactory.UseropLibrary("jidoughost.v30mz.port-access")
public final class V30PortPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
    @Override
    public <T> PcodeUseropLibrary<T> create(SleighLanguage language, PcodeArithmetic<T> arithmetic) {
        var addresses = language.getAddressFactory();
        var io = addresses.getAddressSpace("io");
        var space = new Varnode(addresses.getConstantAddress(io.getSpaceID()), 4);
        return new PortLibrary<>(space);
    }

    private static final class PortLibrary<T> extends DefaultPcodeUseropLibrary<T> {
        private final Varnode space;

        PortLibrary(Varnode space) {
            this.space = space;
            putOp(new Port("port_in8", true, 1));
            putOp(new Port("port_in16", true, 2));
            putOp(new Port("port_out8", false, 1));
            putOp(new Port("port_out16", false, 2));
        }

        private final class Port implements PcodeUseropDefinition<T> {
            private final String name;
            private final boolean read;
            private final int size;

            Port(String name, boolean read, int size) {
                this.name = name;
                this.read = read;
                this.size = size;
            }

            @Override public String getName() { return name; }
            @Override public int getInputCount() { return read ? 1 : 2; }
            @Override public boolean isFunctional() { return false; }
            @Override public boolean hasSideEffects() { return true; }
            @Override public boolean modifiesContext() { return false; }
            @Override public boolean canInlinePcode() { return false; }
            @Override public Class<?> getOutputType() { return read ? Object.class : void.class; }
            @Override public Method getJavaMethod() { return null; }
            @Override public PcodeUseropLibrary<?> getDefiningLibrary() { return PortLibrary.this; }

            @Override
            public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library, PcodeOp op) {
                access(executor, op, op.getOutput(), op.getInput(1), read ? null : op.getInput(2));
            }

            @Override
            public void execute(PcodeExecutor<T> executor, PcodeUseropLibrary<T> library,
                    PcodeOp op, Varnode output, List<Varnode> inputs) {
                access(executor, op, output, inputs.getFirst(), read ? null : inputs.get(1));
            }

            private void access(PcodeExecutor<T> executor, PcodeOp op, Varnode out, Varnode port, Varnode value) {
                if (port.getSize() != 2 || (read ? out : value).getSize() != size)
                    throw new IllegalArgumentException("Invalid port operation width: " + name);
                if (read)
                    executor.executeLoad(new PcodeOp(op.getSeqnum(), PcodeOp.LOAD, new Varnode[] {space, port}, out));
                else
                    executor.executeStore(new PcodeOp(op.getSeqnum(), PcodeOp.STORE, new Varnode[] {space, port, value}, null));
            }
        }
    }
}
