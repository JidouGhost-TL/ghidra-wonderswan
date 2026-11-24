// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

/**
 * Rule J1w: proven table slots become word data unless an existing instruction that starts before the first slot
 * runs into it (a straddling instruction vetoes; the call returns false, nothing is cleared and nothing throws).
 * A clean table in the same program still becomes words. Synthetic program; run as a headless post script.
 */
public class WSTableWordsStraddleFixtures extends GhidraScript {
    private int checks;
    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
        println("CHECK PASS " + message);
    }

    @Override public void run() throws Exception {
        ProgramDB p = new ProgramDB("straddle", currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx = p.startTransaction("straddle");
        try {
            SegmentedAddressSpace sp = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
            byte[] rom = new byte[0x1000]; Arrays.fill(rom, (byte) 0xff);
            byte[] code = HexFormat.of().parseHex("21521e");       // 00ff AND [BP+SI+1e],DX runs into 0100..0101
            System.arraycopy(code, 0, rom, 0xff, code.length);
            byte[] clean = HexFormat.of().parseHex("10021402");     // a second table at 0200, no code over it
            System.arraycopy(clean, 0, rom, 0x200, clean.length);
            MemoryBlock b = p.getMemory().createInitializedBlock("fixture", sp.getAddress(0x4000, 0),
                new ByteArrayInputStream(rom), rom.length, monitor, false);
            b.setPermissions(true, false, true);
            p.getProgramContext().setValue(p.getRegister("csval"), b.getStart(), b.getEnd(), BigInteger.valueOf(0x4000));
            Address ins = b.getStart().add(0xff), table = b.getStart().add(0x100), table2 = b.getStart().add(0x200);
            var decoded = new ghidra.app.util.PseudoDisassembler(p).disassemble(ins);
            p.getListing().createInstruction(decoded.getAddress(), decoded.getPrototype(), decoded, decoded.getProcessorContext(), 0);
            String before = p.getListing().getInstructionAt(ins).toString();
            Method words = Class.forName("jidoughost.wonderswan.WSInlineTables").getMethod("words", Program.class, Address.class, int.class);
            boolean made;
            try { made = (Boolean) words.invoke(null, p, table, 2); }
            catch (InvocationTargetException x) { throw new AssertionError("straddled table threw " + x.getCause(), x.getCause()); }
            check(!made, "straddled table vetoed");
            check(p.getListing().getInstructionAt(ins) != null && p.getListing().getInstructionAt(ins).toString().equals(before),
                "straddling instruction untouched");
            check(p.getListing().getDefinedDataContaining(table.add(2)) == null, "no words created behind the veto");
            check((Boolean) words.invoke(null, p, table2, 2), "clean table accepted");
            check(p.getListing().getDefinedDataAt(table2) != null && p.getListing().getDefinedDataAt(table2.add(2)) != null, "clean table words");
            println("WSTableWordsStraddleFixtures: PASS checks=" + checks);
        } finally { p.endTransaction(tx, false); p.release(this); }
    }
}
