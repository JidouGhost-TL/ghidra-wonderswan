// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/** Performs a split of initialized memory without changing its bytes. */
public final class WSMemorySplit {
    private WSMemorySplit() { }

    public static final class UnsafeSplitException extends Exception {
        private static final long serialVersionUID = 1L;
        UnsafeSplitException(String message) { super(message); }
    }

    /**
     * Materialize the complete byte image, then split the initialized block.
     *
     * Sparse fill-backed blocks can expose different bytes after a split. File-backed blocks retain
     * their source bytes; a sparse-fill block with instructions is rejected before mutation because
     * Ghidra forbids writes over instructions and the unmaterialized backing cannot be proven safe.
     * For a sparse-fill block without instructions, a same-value write through the block API
     * materializes every byte, including defined data. The complete byte image is verified before
     * and after splitting. This never clears or recreates listing entries or decodes bytes.
     */
    public static void splitInitializedBlockPreservingBytes(Program program, MemoryBlock block,
            Address splitAt) throws Exception {
        Memory memory = program.getMemory();
        Address start = block.getStart();
        long size = block.getSize();
        if (!block.isInitialized()) {
            throw new IllegalArgumentException("cannot preserve bytes of an uninitialized block");
        }
        if (splitAt.equals(start) || !block.contains(splitAt)) {
            throw new IllegalArgumentException("split address must be inside the block and after its start");
        }
        if (size > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("initialized block too large for byte-preserving split: " + size);
        }

        byte[] before = new byte[(int) size];
        int read = memory.getBytes(start, before);
        if (read != before.length) {
            throw new IllegalStateException("short read before memory split: " + read + " of " + before.length);
        }

        AddressSet range = new AddressSet(start, block.getEnd());
        Listing listing = program.getListing();
        boolean hasInstructions = listing.getInstructions(range, true).hasNext();
        boolean allFileBacked = hasCompleteFileBacking(block);
        if (hasInstructions && !allFileBacked) {
            throw new UnsafeSplitException("cannot safely split memory with instructions and incomplete FileBytes backing");
        }
        if (!allFileBacked) {
            int written = block.putBytes(start, before);
            if (written != before.length) {
                throw new IllegalStateException("short same-value materialization: " + written + " of " + before.length);
            }
        }

        byte[] materialized = new byte[before.length];
        int restored = memory.getBytes(start, materialized);
        if (restored != materialized.length || !Arrays.equals(before, materialized)) {
            throw new IllegalStateException("same-value materialization changed initialized bytes before split");
        }

        memory.split(block, splitAt);

        byte[] after = new byte[before.length];
        restored = memory.getBytes(start, after);
        if (restored != after.length || !Arrays.equals(before, after)) {
            throw new IllegalStateException("initialized block bytes changed across split at " + splitAt);
        }
    }

    private static boolean hasCompleteFileBacking(MemoryBlock block) {
        List<ghidra.program.model.mem.MemoryBlockSourceInfo> sources = new ArrayList<>(block.getSourceInfos());
        if (sources.isEmpty()) return false;
        sources.sort(Comparator.comparing(ghidra.program.model.mem.MemoryBlockSourceInfo::getMinAddress));
        long length = 0;
        Address cursor = block.getStart();
        for (var source : sources) {
            if (!source.getMinAddress().equals(cursor) || source.getFileBytes().isEmpty()) return false;
            long span = source.getMaxAddress().subtract(source.getMinAddress()) + 1;
            if (span != source.getLength()) return false;
            length += span;
            cursor = source.getMaxAddress().add(1);
        }
        return length == block.getSize() && sources.get(sources.size() - 1).getMaxAddress().equals(block.getEnd());
    }

}
