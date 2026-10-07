// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import jidoughost.wonderswan.WSStaticCode;

/** Synthetic fixtures for direct destinations without outgoing entry anchors. */
public class WSDirectFixtures extends GhidraScript {
    private int checks;
    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
    }
    private Address at(Program p, int off) {
        return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000,off);
    }
    private void put(byte[] raw, int at, String hex) {
        byte[] bytes=HexFormat.of().parseHex(hex); System.arraycopy(bytes,0,raw,at,bytes.length);
    }
    private void insert(Program p, int off) throws Exception {
        var i=new ghidra.app.util.PseudoDisassembler(p).disassemble(at(p,off));
        p.getListing().createInstruction(i.getAddress(),i.getPrototype(),i,i.getProcessorContext(),0);
    }
    private void fixture(String name, String source, String target, boolean accepted) throws Exception {
        byte[] raw=new byte[0x10000]; Arrays.fill(raw,(byte)0xff);
        put(raw,0x40,source); put(raw,0x100,target); put(raw,0x200,"b80700c3");
        ProgramDB p=new ProgramDB(name,currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction(name);
        try {
            var file=p.getMemory().createFileBytes(name,0,raw.length,new ByteArrayInputStream(raw),monitor);
            var block=p.getMemory().createInitializedBlock("fixture",at(p,0),file,0,raw.length,false);
            block.setPermissions(true,false,true);
            p.getProgramContext().setValue(p.getRegister("csval"),at(p,0),at(p,0xffff),BigInteger.valueOf(0x4000));
            p.getProgramContext().setValue(p.getRegister("hwundef"),at(p,0),at(p,0xffff),BigInteger.ZERO);
            insert(p,0x40);
            if(name.equals("defined-data")) p.getListing().createData(at(p,0x100),WordDataType.dataType);
            if(name.equals("operand-target")) insert(p,0x100);
            List<String> log=new ArrayList<>();
            String summary=WSStaticCode.apply(p,log::add,monitor);
            check((p.getListing().getInstructionAt(at(p,0x100))!=null)==(accepted||name.equals("operand-target")),name+": destination disposition; "+summary);
            if(name.equals("recursive-call")) {
                check(p.getListing().getInstructionAt(at(p,0x200))!=null,name+": transitive destination");
                check(p.getFunctionManager().getFunctionAt(at(p,0x100))!=null,name+": callee function");
                check(p.getFunctionManager().getFunctionAt(at(p,0x200))!=null,name+": recursive callee function");
            }
            if(name.equals("direct-jump"))
                check(p.getFunctionManager().getFunctionAt(at(p,0x100))==null,name+": fragment is not a call entry");
            if(name.equals("defined-data"))
                check(p.getListing().getDataAt(at(p,0x100)).getDataType().isEquivalent(WordDataType.dataType),name+": data preserved");
            if(name.equals("operand-target"))
                check(p.getListing().getInstructionContaining(at(p,0x102)).getAddress().equals(at(p,0x100)),name+": operand preserved");
            check(p.getListing().getInstructionAt(at(p,0x40))!=null,name+": source preserved");
            byte[] after=new byte[raw.length]; p.getMemory().getBytes(at(p,0),after);
            check(Arrays.equals(raw,after),name+": bytes preserved");
            WSStaticCode.apply(p,l->{},monitor);
            check((p.getListing().getInstructionAt(at(p,0x100))!=null)==(accepted||name.equals("operand-target")),name+": repeat-run disposition");
            println(name+": "+summary);
        } finally { p.endTransaction(tx,false); p.release(this); }
    }
    @Override public void run() throws Exception {
        fixture("recursive-call","e8bd00","b82a00e8fa00c3",true);
        fixture("direct-jump","e9bd00","b80100c3",true);
        fixture("defined-data","e8bd00","b80100c3",false);
        fixture("operand-target","e8bf00","b80100c3",false);
        fixture("weak-target","e8bd00","0000c3",false);
        fixture("unmapped-call","e8bd00","9a00000020c3",false);
        fixture("computed-source","ffd0","b80100c3",false);
        println("WSDirectFixtures: PASS checks="+checks);
    }
}
