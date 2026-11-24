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
 * The veto writes one J1w STRADDLE_VETO evidence line. A clean table in the same program still becomes words. Synthetic program; run as a headless post script.
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
            Method logged = Class.forName("jidoughost.wonderswan.WSInlineTables").getMethod("words", Program.class, Address.class, int.class,
                Address.class, java.util.function.Consumer.class);
            Address site = b.getStart().add(0x40);
            List<String> log = new ArrayList<>();
            java.util.function.Consumer<String> emit = log::add;
            boolean made;
            try { made = (Boolean) logged.invoke(null, p, table, 2, site, emit); }
            catch (InvocationTargetException x) { throw new AssertionError("straddled table threw " + x.getCause(), x.getCause()); }
            check(!made, "straddled table vetoed");
            check(p.getListing().getInstructionAt(ins) != null && p.getListing().getInstructionAt(ins).toString().equals(before),
                "straddling instruction untouched");
            check(p.getListing().getDefinedDataContaining(table.add(2)) == null, "no words created behind the veto");
            for (String l : log) println("EVIDENCE " + l);
            check(log.size() == 1 && log.get(0).contains("\"rule\":\"J1w\"") && log.get(0).contains("STRADDLE_VETO")
                && log.get(0).contains("\"site\":\"" + site + "\"") && log.get(0).contains("\"slot\":\"" + table + "\"")
                && log.get(0).contains("\"instruction_start\":\"" + ins + "\"") && log.get(0).contains("\"bytes\":\"21521e\""),
                "veto evidence line names site, slot and straddling instruction");
            check((Boolean) logged.invoke(null, p, table2, 2, site, emit) && log.size() == 1, "clean table accepted without a veto line");
            check(p.getListing().getDefinedDataAt(table2) != null && p.getListing().getDefinedDataAt(table2.add(2)) != null, "clean table words");
            println("WSTableWordsStraddleFixtures: PASS checks=" + checks);
        } finally { p.endTransaction(tx, false); p.release(this); }
    }
}
