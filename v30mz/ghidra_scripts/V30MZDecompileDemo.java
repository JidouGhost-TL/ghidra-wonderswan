// SPDX-License-Identifier: MIT OR Apache-2.0
// Decompile functions of a V30MZ game dump to check the io-space port model end to end.
// Args: <dump dir> <out txt> <cs:ip>[,<cs:ip>...]
//   dump dir: holds linear.bin (CPU linear 0x40000-0xFFFFF image)
// Creates a scratch V30MZ program: linear.bin at ram linear 0x40000, an uninitialized volatile
// "io" block (io:0000-00FF) with a byte label on every port the functions touch (IO_xx, and
// KEYPAD at io:00B5), sets csval at each entry, disassembles, creates the functions and writes
// listing + decompiler C to <out txt>.
// @category V30MZ
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

public class V30MZDecompileDemo extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        byte[] img = Files.readAllBytes(Paths.get(a[0], "linear.bin"));
        Language lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("V30MZ:LE:16:default"));
        Program p = new ProgramDB("demo", lang, lang.getDefaultCompilerSpec(), this);
        AddressSpace ram = p.getAddressFactory().getDefaultAddressSpace();
        AddressSpace io = p.getAddressFactory().getAddressSpace("io");
        Register csval = p.getRegister("csval");
        int tx = p.startTransaction("demo");
        p.getMemory().createInitializedBlock("rom", ram.getAddress(0x40000), new ByteArrayInputStream(img), img.length, TaskMonitor.DUMMY, false);
        MemoryBlock iob = p.getMemory().createUninitializedBlock("io", io.getAddress(0), 0x100, false);
        iob.setVolatile(true);
        List<Address> entries = new ArrayList<>();
        for (String e : a[2].split(",")) {
            String[] ci = e.split(":");
            int cs = Integer.parseInt(ci[0], 16), ip = Integer.parseInt(ci[1], 16);
            Address ad = ram.getAddress(((long) cs << 4) + ip);
            p.getProgramContext().setValue(csval, ad, ad, BigInteger.valueOf(cs));
            new DisassembleCommand(ad, null, true).applyTo(p, TaskMonitor.DUMMY);
            entries.add(ad);
        }
        // label every io port referenced by the disassembled code
        Set<Long> ports = new TreeSet<>();
        for (Instruction ins : p.getListing().getInstructions(true))
            for (PcodeOp op : ins.getPcode())
                for (Varnode v : op.getInputs()) if (v.getAddress().getAddressSpace() == io) ports.add(v.getOffset());
        for (Instruction ins : p.getListing().getInstructions(true))
            for (PcodeOp op : ins.getPcode())
                if (op.getOutput() != null && op.getOutput().getAddress().getAddressSpace() == io) ports.add(op.getOutput().getOffset());
        for (long port : ports) {
            Address pa = io.getAddress(port);
            p.getSymbolTable().createLabel(pa, port == 0xb5 ? "KEYPAD" : String.format("IO_%02X", port), SourceType.USER_DEFINED);
            p.getListing().createData(pa, ByteDataType.dataType);
        }
        for (Address ad : entries) p.getFunctionManager().createFunction(null, ad, new AddressSet(ad, ad), SourceType.USER_DEFINED);
        p.endTransaction(tx, true);
        tx = p.startTransaction("fn");
        for (Address ad : entries) {
            Function f = p.getFunctionManager().getFunctionAt(ad);
            ghidra.app.cmd.function.CreateFunctionCmd.fixupFunctionBody(p, f, TaskMonitor.DUMMY);
        }
        p.endTransaction(tx, true);
        DecompInterface di = new DecompInterface();
        di.openProgram(p);
        StringBuilder sb = new StringBuilder();
        for (Address ad : entries) {
            Function f = p.getFunctionManager().getFunctionAt(ad);
            sb.append("==== ").append(f.getName()).append(" @ ").append(ad).append(" (csval=")
              .append(p.getProgramContext().getValue(csval, ad, false).toString(16)).append(")\n");
            for (Instruction ins : p.getListing().getInstructions(f.getBody(), true))
                sb.append(String.format("  %s  %s\n", ins.getAddress(), ins));
            DecompileResults r = di.decompileFunction(f, 60, TaskMonitor.DUMMY);
            sb.append(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "DECOMPILE FAILED: " + r.getErrorMessage()).append("\n");
        }
        di.dispose();
        Files.writeString(Paths.get(a[1]), sb.toString());
        println(sb.toString());
        p.release(this);
    }
}
