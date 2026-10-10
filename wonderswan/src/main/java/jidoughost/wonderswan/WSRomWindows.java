// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.ByteArrayInputStream;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.task.TaskMonitor;

/** Bank-qualified views; CPU windows retain their original loader mapping.
 * Hardware: https://ws.nesdev.org/wiki/Mapper and https://ws.nesdev.org/wiki/Bandai_2003
 * C2/C3 select 64 KiB at 20000/30000; C0 selects the upper 768 KiB of a 1 MiB bank.
 * Dormant views are data until execution or a resolved static transfer selects them.
 */
public final class WSRomWindows {
    private WSRomWindows() { }

    /** Highest bank-register alias of a physical bank, including start-padded images. */
    public static int bank(long fileOffset, long size) {
        long effective = fileOffset + WSHardware.padSize(size);
        int count = (int)(WSHardware.effectiveSize(size) >>> 16);
        int top = count > 256 ? 1024 : 256;
        return top - count + (int)(effective >>> 16);
    }

    public static String name(int seg, int bank) {
        return String.format("ROM%d_BANK_%04X", seg == 0x2000 ? 0 : 1, bank);
    }

    public static MemoryBlock view(Program p, int seg, int bank, boolean executable,
                                   TaskMonitor monitor) throws Exception {
        Memory mem = p.getMemory();
        MemoryBlock b = mem.getBlock(name(seg, bank));
        if (b == null) {
            var fb = WSRom.fileBytes(p);
            if (fb == null) return null;
            long size = fb.getSize(), effective = WSHardware.effectiveSize(size);
            long off = WSHardware.bankToRom(bank, effective);
            Address base = ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(seg, 0);
            if (size == effective) b = mem.createInitializedBlock(name(seg, bank), base, fb, off, 65536, true);
            else {
                byte[] bytes = new byte[65536];
                java.util.Arrays.fill(bytes, (byte)WSHardware.PAD_BYTE);
                long first = Math.max(0, off - WSHardware.padSize(size));
                int pad = (int)Math.max(0, WSHardware.padSize(size) - off);
                int length = (int)Math.min(65536 - pad, size - first);
                if (length > 0) fb.getOriginalBytes(first, bytes, pad, length);
                b = mem.createInitializedBlock(name(seg, bank), base, new ByteArrayInputStream(bytes), 65536, monitor, true);
            }
            b.setPermissions(true, false, executable);
            b.setComment(String.format("ROM bank %04X in CPU window %04X; physical effective offset %06X. Bank-qualified view; default CPU mapping is unchanged.", bank, seg, off));
        } else if (executable) b.setExecute(true);
        return b;
    }

    /** Every physical ROM bank is addressable through both switchable windows. */
    public static int mapAll(Program p, TaskMonitor monitor) throws Exception {
        long size = WSRom.size(p);
        if (size <= 0) return 0;
        int count = (int)(WSHardware.effectiveSize(size) >>> 16), top = count > 256 ? 1024 : 256;
        int added = 0;
        for (int bank = top - count; bank < top; bank++) for (int seg : new int[]{0x2000, 0x3000}) {
            monitor.checkCancelled();
            if (p.getMemory().getBlock(name(seg, bank)) == null) { view(p, seg, bank, false, monitor); added++; }
        }
        return added;
    }
}
