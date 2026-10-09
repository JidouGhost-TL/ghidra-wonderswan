// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;

/** C0: give undecoded ROM bytes a code segment before following instruction flow. */
public final class WSCodeContext {
    private WSCodeContext() { }

    /** Existing instructions and explicit segment observations are retained. RAM images require their
     *  own run context; ROM data views must never acquire executable context. */
    public static int seedRomDefaults(Program program) throws ContextChangeException {
        ProgramContext context = program.getProgramContext();
        Register cs = context.getRegister("csval");
        if (cs == null) return 0;
        int spans = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() ||
                WonderSwanLoader.isDataOverlay(block)) continue;
            if (!block.getName().startsWith("LIN_") &&
                !block.getName().startsWith("ROM0_BANK_") &&
                !block.getName().startsWith("ROM1_BANK_")) continue;
            AddressSet gaps = new AddressSet(block.getStart(), block.getEnd());
            for (Instruction instruction : program.getListing().getInstructions(gaps, true))
                gaps.delete(instruction.getMinAddress(), instruction.getMaxAddress());
            AddressRangeIterator stored = context.getRegisterValueAddressRanges(cs,
                block.getStart(), block.getEnd());
            while (stored.hasNext()) {
                AddressRange range = stored.next();
                gaps.delete(range.getMinAddress(), range.getMaxAddress());
            }
            for (AddressRange gap : gaps) {
                Address start = gap.getMinAddress();
                while (start.compareTo(gap.getMaxAddress()) <= 0) {
                    long linear = start.getOffset();
                    long length = Math.min(0x10000 - (linear & 0xffff),
                        gap.getMaxAddress().getOffset() - linear + 1);
                    Address end = start.add(length - 1);
                    context.setValue(cs, start, end,
                        BigInteger.valueOf((linear >>> 4) & 0xf000));
                    spans++;
                    if (end.equals(gap.getMaxAddress())) break;
                    start = end.next();
                }
            }
        }
        return spans;
    }
}
