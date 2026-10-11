// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.*;

/** Inherited no-image code survives fill classification and function merging. */
public class WSReseedFixtures extends GhidraScript {
    int checks, failures;
    void check(boolean value, String message) {
        checks++;
        if (!value) { failures++; printerr("FAIL: " + message); }
    }
    Address at(Program p, int segment, int offset) {
        return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(segment, offset);
    }
    void fill(int segment, int value, boolean decoded) throws Exception {
        ProgramDB p=new ProgramDB("inherited-fill", currentProgram.getLanguage(), currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx=p.startTransaction("inherited no-image function");
        try {
            byte[] bytes=new byte[0x400]; Arrays.fill(bytes,(byte)value);
            Address start=at(p,segment,0), entry=at(p,segment,0x100);
            var block=p.getMemory().createInitializedBlock("fixture",start,new ByteArrayInputStream(bytes),bytes.length,monitor,false);
            block.setPermissions(true,true,true);
            p.getProgramContext().setValue(p.getRegister("csval"),start,start.add(bytes.length-1),BigInteger.valueOf(segment));
            if(decoded) new DisassembleCommand(entry,new AddressSet(entry,entry.add(3)),false).applyTo(p,monitor);
            AddressSet body=new AddressSet(entry,entry.add(15));
            p.getFunctionManager().createFunction(null,entry,body,SourceType.DEFAULT);
            WSRamCode.classify(p);
            for(int round=0;round<2;round++) {
                WSFillRuns.apply(p,null,l->{},monitor);
                Function f=p.getFunctionManager().getFunctionAt(entry);
                boolean ram=segment<0x2000;
                check((f!=null)==ram,"fill entry segment="+segment+" value="+value+" decoded="+decoded+" round="+round);
                if(ram&&f!=null) {
                    check(f.getBody().equals(body),"inherited body retained");
                    check(f.getTags().stream().anyMatch(t->t.getName().equals(WSRamCode.UNKNOWN)),"no-image hypothesis tagged");
                    check(p.getListing().getDefinedDataAt(entry)==null,"RAM not reclassified as ROM fill");
                }
                byte[] after=new byte[bytes.length];p.getMemory().getBytes(start,after);
                check(Arrays.equals(bytes,after),"memory bytes unchanged");
            }
        } finally { p.endTransaction(tx,false);p.release(this); }
    }
    void merge() throws Exception {
        ProgramDB p=new ProgramDB("inherited-merge",currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction("RAM outlined entry");
        try {
            byte[] bytes=new byte[0x200];Arrays.fill(bytes,(byte)0xcc);
            bytes[0x40]=(byte)0xeb;bytes[0x41]=0x3e;
            bytes[0x80]=(byte)0xeb;bytes[0x81]=(byte)0xbe;
            Address start=at(p,0,0);
            var b=p.getMemory().createInitializedBlock("fixture",start,new ByteArrayInputStream(bytes),bytes.length,monitor,false);
            b.setPermissions(true,true,true);
            p.getProgramContext().setValue(p.getRegister("csval"),start,start.add(bytes.length-1),BigInteger.ZERO);
            for(int off:new int[]{0x40,0x80}) {
                Address a=start.add(off);new DisassembleCommand(a,null,false).applyTo(p,monitor);
                p.getFunctionManager().createFunction(null,a,new AddressSet(a,a.add(1)),SourceType.DEFAULT);
            }
            p.getReferenceManager().addMemoryReference(start.add(0x40),start.add(0x80),RefType.UNCONDITIONAL_JUMP,SourceType.ANALYSIS,0);
            WSRamCode.classify(p);new WSMerge(p,Set.of(),l->{},monitor).apply();
            check(p.getFunctionManager().getFunctionAt(start.add(0x80))!=null,"M1 keeps inherited RAM entry");
        } finally { p.endTransaction(tx,false);p.release(this); }
    }
    public void run() throws Exception {
        for(int segment:new int[]{0,0x1000,0x4000}) for(int value:new int[]{0,255})
            for(boolean decoded:new boolean[]{false,true}) fill(segment,value,decoded);
        merge();
        println("WSReseedFixtures: checks="+checks+" failures="+failures);
        if(failures!=0)throw new AssertionError("RAM preservation failures="+failures);
        println("WSReseedFixtures: PASS");
    }
}
