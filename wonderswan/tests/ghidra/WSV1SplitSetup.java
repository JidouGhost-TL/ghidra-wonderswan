import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.io.ByteArrayInputStream;

/** Creates deterministic synthetic RAM with an initial persisted leading split. */
public class WSV1SplitSetup extends GhidraScript {
    private byte[] seed(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) ((i * 37 + (i >>> 8) * 19 + 0x5b) & 0xff);
        for (int p : new int[] { 0x400, 0x410 }) b[p] = (byte) 0x90;
        return b;
    }
    private void codeAt(Address a, Address target, String label) throws Exception {
        DisassembleCommand d = new DisassembleCommand(a, null, false);
        if (!d.applyTo(currentProgram, monitor)) throw new IllegalStateException(d.getStatusMsg());
        Instruction i = currentProgram.getListing().getInstructionAt(a);
        if (i == null) throw new IllegalStateException("synthetic NOP missing at " + a);
        currentProgram.getSymbolTable().createLabel(target, label, SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(a, target, RefType.DATA, SourceType.USER_DEFINED, 0);
    }
    private void cutPriorFlag(Memory m, Address flag) throws Exception {
        MemoryBlock b = m.getBlock(flag);
        if (b == null || !b.isInitialized()) throw new IllegalStateException("bad synthetic source block");
        Address after = flag.add(2);
        if (b.contains(after)) m.split(b, after);
        b = m.getBlock(flag);
        if (!b.getStart().equals(flag)) m.split(b, flag);
        MemoryBlock flagBlock = m.getBlock(flag);
        flagBlock.setVolatile(true);
        flagBlock.setComment("synthetic prior volatile flag");
    }
    @Override public void run() throws Exception {
        SegmentedAddressSpace s = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        Memory m = currentProgram.getMemory();
        // Remove only loader-created synthetic placeholder blocks overlapping our fixture ranges.
        for (MemoryBlock b : m.getBlocks()) {
            long start = b.getStart().getOffset(), end = b.getEnd().getOffset();
            if (b.getStart().getAddressSpace().equals(s) && ((start <= 0xffff && end >= 0) || (start <= 0x2ffff && end >= 0x20000)))
                m.removeBlock(b, monitor);
        }
        Address fileBase = s.getAddress(0x2000, 0), fillBase = s.getAddress(0, 0);
        byte[] fileSeed = seed(0x10000);
        FileBytes fb = m.createFileBytes("synthetic-file-ram-source", 0, fileSeed.length,
            new ByteArrayInputStream(fileSeed), monitor);
        MemoryBlock file = m.createInitializedBlock("SYNTH_FILE_RAM", fileBase, fb, 0, fileSeed.length, false);
        file.setPermissions(true, true, true);
        MemoryBlock fill = m.createInitializedBlock("SYNTH_FILL_RAM", fillBase, 0x8000, (byte) 0, monitor, false);
        fill.setPermissions(true, true, true);
        codeAt(fileBase.add(0x400), fileBase.add(0x410), "synthetic_file_target");
        codeAt(fileBase.add(0x410), fileBase.add(0x400), "synthetic_file_target_2");
        codeAt(fillBase.add(0x400), fillBase.add(0x410), "synthetic_fill_target");
        codeAt(fillBase.add(0x410), fillBase.add(0x400), "synthetic_fill_target_2");
        var data = currentProgram.getListing().createData(fillBase.add(0x500), ByteDataType.dataType);
        data.setComment(CodeUnit.PRE_COMMENT, "synthetic zero-fill data unit");
        cutPriorFlag(m, fileBase.add(0x30a));
        cutPriorFlag(m, fillBase.add(0x30a));
        Address denseEnd = fillBase.add(0x4fff), cursor = fillBase.add(0x4000);
        while (cursor.compareTo(denseEnd) <= 0) {
            DisassembleCommand command = new DisassembleCommand(cursor, null, false);
            if (!command.applyTo(currentProgram, monitor))
                throw new IllegalStateException("cannot decode synthetic dense fill at " + cursor + ": " + command.getStatusMsg());
            Instruction decoded = currentProgram.getListing().getInstructionAt(cursor);
            if (decoded == null) throw new IllegalStateException("missing synthetic dense instruction at " + cursor);
            cursor = decoded.getMaxAddress().add(1);
        }
        Address denseSource = fillBase.add(0x4100), denseTarget = fillBase.add(0x6000);
        currentProgram.getSymbolTable().createLabel(denseTarget, "synthetic_dense_gap_target", SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(denseSource, denseTarget,
            RefType.DATA, SourceType.USER_DEFINED, 0);

        Address noGapBase = s.getAddress(0, 0x8000);
        MemoryBlock noGap = m.createInitializedBlock("SYNTH_FULLY_DEFINED_FILL", noGapBase,
            0x1000, (byte) 0, monitor, false);
        noGap.setPermissions(true, true, true);
        var fullData = currentProgram.getListing().createData(noGapBase,
            new ArrayDataType(ByteDataType.dataType, 0x1000, 1));
        fullData.setComment(CodeUnit.PRE_COMMENT, "synthetic fully defined zero-fill range");
        Address noGapFlag = noGapBase.add(0x322), noGapTarget = noGapBase.add(0x500);
        currentProgram.getSymbolTable().createLabel(noGapFlag, "synthetic_full_range_source", SourceType.USER_DEFINED);
        currentProgram.getSymbolTable().createLabel(noGapTarget, "synthetic_full_range_target", SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(noGapFlag, noGapTarget,
            RefType.DATA, SourceType.USER_DEFINED, 0);
        Address denseNoGapBase = s.getAddress(0, 0x9000);
        MemoryBlock denseNoGap = m.createInitializedBlock("SYNTH_FULLY_DEFINED_INSTRUCTION_FILL",
            denseNoGapBase, 0x1000, (byte) 0x90, monitor, false);
        denseNoGap.setPermissions(true, true, true);
        Address instructionOnlyCursor = denseNoGapBase, instructionOnlyEnd = denseNoGapBase.add(0xfff);
        while (instructionOnlyCursor.compareTo(instructionOnlyEnd) <= 0) {
            DisassembleCommand command = new DisassembleCommand(instructionOnlyCursor, null, false);
            if (!command.applyTo(currentProgram, monitor))
                throw new IllegalStateException("cannot decode fully-defined fill instruction at " + instructionOnlyCursor + ": " + command.getStatusMsg());
            Instruction decoded = currentProgram.getListing().getInstructionAt(instructionOnlyCursor);
            if (decoded == null) throw new IllegalStateException("missing fully-defined fill instruction at " + instructionOnlyCursor);
            instructionOnlyCursor = decoded.getMaxAddress().add(1);
        }
        Address instructionOnlyTarget = denseNoGapBase.add(0x700), instructionOnlySource = denseNoGapBase.add(0x100);
        currentProgram.getSymbolTable().createLabel(instructionOnlyTarget, "synthetic_full_instruction_target", SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(instructionOnlySource, instructionOnlyTarget,
            RefType.DATA, SourceType.USER_DEFINED, 0);

        Address mixedBase = s.getAddress(0, 0xa000);
        byte[] mixedFileSeed = seed(0x1000);
        FileBytes mixedFileBytes = m.createFileBytes("synthetic-mixed-file-source", 0, mixedFileSeed.length,
            new ByteArrayInputStream(mixedFileSeed), monitor);
        MemoryBlock mixedFile = m.createInitializedBlock("SYNTH_MIXED_FILE_PART", mixedBase,
            mixedFileBytes, 0, mixedFileSeed.length, false);
        MemoryBlock mixedFill = m.createInitializedBlock("SYNTH_MIXED_FILL_PART", mixedBase.add(0x1000),
            0x1000, (byte) 0, monitor, false);
        mixedFile.setPermissions(true, true, true);
        mixedFill.setPermissions(true, true, true);
        MemoryBlock mixed = m.join(mixedFile, mixedFill);
        if (!mixed.getStart().equals(mixedFile.getStart()) || mixed.getSize() != 0x2000)
            throw new IllegalStateException("mixed FileBytes/fill join did not create one contiguous block");
        Address mixedCode = mixedBase.add(0x400), mixedTarget = mixedBase.add(0x1100);
        codeAt(mixedCode, mixedTarget, "synthetic_mixed_fill_target");
        currentProgram.getListing().createData(mixedBase.add(0x1200), ByteDataType.dataType);
        println("SYNTHETIC_SETUP	fileBytes=65536	fillBytes=65536	leadingCut=0x30c");
    }
}
