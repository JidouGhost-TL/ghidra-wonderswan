// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.util.List;
import java.util.OptionalLong;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

/**
 * Read the cartridge ROM image stored with a program, independent of what the
 * loader mapped into the address space.
 *
 * <p>The loader keeps the whole ROM as the first {@link FileBytes}; banked
 * graphics live there even when no memory block maps them. All reads use the
 * original (unmodified) bytes.
 */
public final class WSRom {
    private WSRom() { }

    /** Stored ROM image, or null when the program has none. */
    public static FileBytes fileBytes(Program program) {
        if (program == null) return null;
        List<FileBytes> all = program.getMemory().getAllFileBytes();
        return all.isEmpty() ? null : all.get(0);
    }

    /** Size of the stored ROM image, or -1 when the program has none. */
    public static long size(Program program) {
        FileBytes fb = fileBytes(program);
        return fb == null ? -1 : fb.getSize();
    }

    /**
     * Read up to {@code length} bytes at a ROM file offset. Reads past the
     * end are truncated; a negative offset reads as 0.
     */
    public static byte[] read(Program program, long offset, int length) {
        FileBytes fb = fileBytes(program);
        if (fb == null || length <= 0) return new byte[0];
        long start = Math.max(0, offset);
        long size = fb.getSize();
        if (start >= size) return new byte[0];
        int n = (int) Math.min(length, size - start);
        byte[] out = new byte[n];
        try {
            int got = fb.getOriginalBytes(start, out, 0, n);
            if (got == n) return out;
            byte[] trim = new byte[Math.max(0, got)];
            System.arraycopy(out, 0, trim, 0, trim.length);
            return trim;
        } catch (IOException | IndexOutOfBoundsException e) {
            return new byte[0];
        }
    }

    /**
     * ROM file offset backing a mapped address, or empty when the address is
     * not in a block sourced from the stored ROM image (RAM, windows, padding
     * bytes of a non-power-of-two image).
     *
     * <p>Covers every ROM view the loader and rule B2 create: fixed linear blocks
     * ({@code LIN_XXXX}), executable window overlays ({@code ROM0_BANK_XXXX} /
     * {@code ROM1_BANK_XXXX}) and read-only data overlays ({@code ROM_XX}).
     * FileBytes-backed blocks resolve through their source info; materialised
     * blocks (start-padded images) resolve through the block name.
     */
    public static OptionalLong offsetOf(Program program, Address address) {
        if (program == null || address == null) return OptionalLong.empty();
        FileBytes fb = fileBytes(program);
        if (fb == null) return OptionalLong.empty();
        MemoryBlock block = program.getMemory().getBlock(address);
        if (block == null) return OptionalLong.empty();
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (!info.contains(address)) continue;
            if (info.getFileBytes().map(b -> b.equals(fb)).orElse(false)) {
                try {
                    return OptionalLong.of(info.getFileBytesOffset(address));
                } catch (Exception e) {
                    return OptionalLong.empty();
                }
            }
        }
        return offsetOfNamed(block, address, fb.getSize());
    }

    /**
     * File offset for a ROM view block without a FileBytes source (a materialised
     * start-padded image): decoded from the block name and the offset within it.
     */
    static OptionalLong offsetOfNamed(MemoryBlock block, Address address, long fileSize) {
        long within;
        try {
            within = address.subtract(block.getStart());
        } catch (Exception e) {
            return OptionalLong.empty();
        }
        if (within < 0 || within >= block.getSize()) return OptionalLong.empty();
        long effLen = WSHardware.effectiveSize(fileSize);
        String name = block.getName();
        long effective = -1;
        int dataBank = WonderSwanLoader.dataOverlayBank(block);
        if (dataBank >= 0) {
            effective = ((long) dataBank << 16) + within;
        } else if ((name.startsWith("ROM0_BANK_") || name.startsWith("ROM1_BANK_")) && name.length() > 10) {
            try {
                int bank = Integer.parseInt(name.substring(name.lastIndexOf('_') + 1), 16);
                effective = WSHardware.bankToRom(bank, effLen) + within;
            } catch (NumberFormatException e) {
                return OptionalLong.empty();
            }
        } else if (name.startsWith("LIN_") && name.length() == 8) {
            try {
                int seg = Integer.parseInt(name.substring(4), 16);
                effective = WSHardware.linearToRom(((long) seg) << 4, WSHardware.RESET_C0, effLen) + within;
            } catch (NumberFormatException e) {
                return OptionalLong.empty();
            }
        } else {
            return OptionalLong.empty();
        }
        long file = WSHardware.fileOffset(effective, fileSize);
        return file < 0 ? OptionalLong.empty() : OptionalLong.of(file);
    }

    /** Parse a hex ROM offset ("0x123456", "123456"); -1 when invalid. */
    public static long parseOffset(String text) {
        if (text == null) return -1;
        try {
            String t = text.trim().toLowerCase().replaceFirst("^0x", "");
            if (t.isEmpty()) return -1;
            return Long.parseLong(t, 16);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Format a ROM offset as {@code 0x.....}. */
    public static String formatOffset(long offset) {
        return String.format("0x%06X", offset);
    }
}
