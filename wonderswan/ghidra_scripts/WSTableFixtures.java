// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import jidoughost.wonderswan.WSStaticCode;

/** Synthetic segmented-program fixtures; run as a headless post script. */
public class WSTableFixtures extends GhidraScript {
    private int checks;
    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
    }
    private void put(byte[] raw, int at, String hex) {
        byte[] b=HexFormat.of().parseHex(hex); System.arraycopy(b,0,raw,at,b.length);
    }
    private Address at(Program p, int off) {
        return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000,off);
    }
    private void fixture(String name, String dispatch, int table, String entries, int width, int... targets) throws Exception {
        byte[] raw=new byte[0x10000]; Arrays.fill(raw,(byte)0xff);
        put(raw,0x40,dispatch); put(raw,table,entries);
        if(name.equals("compare-limit")) put(raw,0x55,"c3");
        for(int target : targets) put(raw,target,width==4 ? "b80100cb" : "b80100c3");
        if(name.equals("reject-weak-target")) put(raw,targets[1],"0000c3");
        ProgramDB p=new ProgramDB(name,currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction(name);
        try {
            var file=p.getMemory().createFileBytes(name,0,raw.length,new ByteArrayInputStream(raw),monitor);
            var block=p.getMemory().createInitializedBlock("fixture",at(p,0),file,0,raw.length,false);
            block.setPermissions(true,false,true);
            p.getProgramContext().setValue(p.getRegister("csval"),at(p,0),at(p,0xffff),BigInteger.valueOf(0x4000));
            p.getProgramContext().setValue(p.getRegister("hwundef"),at(p,0),at(p,0xffff),BigInteger.ZERO);
            if(name.equals("preserve-existing")) {
                p.getListing().createData(at(p,table),WordDataType.dataType);
                var kept=new ghidra.app.util.PseudoDisassembler(p).disassemble(at(p,targets[2]));
                p.getListing().createInstruction(kept.getAddress(),kept.getPrototype(),kept,kept.getProcessorContext(),0);
            }
            Address head=at(p,0x40);
            for(int k=0;k<6;k++) {
                var pi=new ghidra.app.util.PseudoDisassembler(p).disassemble(head);
                if(pi==null) break;
                println(name+" dispatch: "+pi);
                head=pi.getMaxAddress().next();
                if(pi.getMnemonicString().startsWith("RET")) break;
            }
            List<String> log=new ArrayList<>();
            String summary=WSStaticCode.apply(p,log::add,monitor);
            check(log.stream().filter(l->l.contains("\"event\":\"table\"")).count()==1,name+": one table; "+summary);
            int length=targets.length*width;
            for(int k=0;k<length;k++) {
                Data d=p.getListing().getDefinedDataContaining(at(p,table+k));
                check(d!=null,name+": data veto at slot byte "+k);
                check(p.getListing().getInstructionContaining(at(p,table+k))==null,name+": no code in table");
            }
            for(int target:targets) {
                if(name.equals("reject-weak-target") && target==targets[1])
                    check(p.getListing().getInstructionAt(at(p,target))==null,name+": weak target rejected");
                else check(p.getListing().getInstructionAt(at(p,target))!=null,name+": target seed");
            }
            if(name.equals("preserve-existing"))
                check(p.getListing().getDataAt(at(p,table)).getDataType().isEquivalent(WordDataType.dataType),name+": existing type preserved");
            check(p.getListing().getInstructionAt(at(p,0x40))!=null,name+": dispatcher accepted");
            byte[] after=new byte[raw.length]; p.getMemory().getBytes(at(p,0),after);
            check(Arrays.equals(raw,after),name+": bytes preserved");
            WSStaticCode.apply(p,l->{},monitor);
            check(p.getListing().getInstructionContaining(at(p,table))==null,name+": repeat-run precedence");
            println(name+": "+summary);
        } finally { p.endTransaction(tx,false); p.release(this); }
    }
    @Override public void run() throws Exception {
        fixture("inline-near", "8b1e100033ff03db2effa70001",0x100,"060130016001",2,0x106,0x130,0x160);
        fixture("stored-near", "bf0001d1e103f92e8b3dffd7c3",0x100,"060130016001",2,0x106,0x130,0x160);
        fixture("stored-far", "c1e3022eff9f0001c3",0x100,"200100404001004060010040",4,0x120,0x140,0x160);
        fixture("return-shaped-slots", "bf0001d1e103f92e8b3dffd7c3",0x100,"0601c202da02",2,0x106,0x2c2,0x2da);
        fixture("compare-limit", "83fb01771003db2effa70001",0x100,"200140016001",2,0x120,0x140);
        fixture("index-initial-value", "bb0100d1e32effa70001",0x100,"060130016001",2,0x106,0x130,0x160);
        fixture("preserve-existing", "8b1e100033ff03db2effa70001",0x100,"060130016001",2,0x106,0x130,0x160);
        fixture("reject-weak-target", "8b1e100033ff03db2effa70001",0x100,"060130016001",2,0x106,0x130,0x160);
        println("WSTableFixtures: PASS checks="+checks);
    }
}
