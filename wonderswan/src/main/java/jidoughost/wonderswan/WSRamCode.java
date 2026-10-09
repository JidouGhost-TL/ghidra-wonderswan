// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;

/** RAM code without a captured execution image is an unresolved hypothesis, never an artefact to erase. */
public final class WSRamCode {
    public static final String CATEGORY = "ram-code";
    public static final String UNKNOWN = "ram-code: unknown, no evidence";
    private WSRamCode() { }

    public static boolean isRam(Program program, Address address) {
        MemoryBlock block = program.getMemory().getBlock(address);
        return address.getAddressSpace().getPhysicalSpace().equals(
                program.getAddressFactory().getDefaultAddressSpace()) &&
            block != null && address.getOffset() < 0x20000 &&
            !WonderSwanLoader.isDataOverlay(block);
    }

    public static boolean hasImage(Program program, Address address) {
        MemoryBlock block = program.getMemory().getBlock(address);
        return block != null && block.isOverlay() && block.getName().startsWith("RAMCODE_");
    }

    public static int classify(Program program) {
        int runs = 0;
        Address previousEnd = null;
        for (Instruction instruction : program.getListing().getInstructions(true)) {
            Address address = instruction.getAddress();
            if (!isRam(program, address) || hasImage(program, address)) { previousEnd = null; continue; }
            if (previousEnd == null || !address.equals(previousEnd.next())) {
                program.getBookmarkManager().setBookmark(address, BookmarkType.ANALYSIS, CATEGORY, UNKNOWN);
                runs++;
            }
            previousEnd = instruction.getMaxAddress();
        }
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (isRam(program, function.getEntryPoint()) && !hasImage(program, function.getEntryPoint()))
                function.addTag(UNKNOWN);
        }
        return runs;
    }
}
