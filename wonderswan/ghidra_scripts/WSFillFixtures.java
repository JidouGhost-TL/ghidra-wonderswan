// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.*;

/** Synthetic fill boundaries, executed-byte priority and byte-preservation checks. */
public class WSFillFixtures extends GhidraScript {
    int checks;
    void check(boolean ok, String reason) { if (!ok) throw new AssertionError(reason); checks++; }
    Address at(Program p, int n) { var overlay=p.getMemory().getBlock("FILL_OVERLAY"); if(overlay!=null)return overlay.getStart().add(n); return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000,n); }
    void fixture(int value, int length, boolean played, boolean user) throws Exception {
        fixture(value,length,played,user,false);
    }
    void fixture(int value, int length, boolean played, boolean user, boolean overlay) throws Exception {
        byte[] bytes = new byte[65536]; Arrays.fill(bytes,(byte)0xcc);
        bytes[0x100]=(byte)0xb8; bytes[0x101]=1; bytes[0x102]=0;
        Arrays.fill(bytes,0x103,0x103+length,(byte)value);bytes[0x103+length]=(byte)0xc3;
        ProgramDB p=new ProgramDB("fill-fixture",currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction("fill boundary");
        try {
            var fb=p.getMemory().createFileBytes("fixture",0,bytes.length,new ByteArrayInputStream(bytes),monitor);
            var block=p.getMemory().createInitializedBlock(overlay?"FILL_OVERLAY":"LIN_4000",at(p,0),fb,0,bytes.length,overlay);block.setPermissions(true,false,true);
            if(overlay)p.getMemory().createUninitializedBlock("OCCUPIED_BASE_STOP",
                p.getAddressFactory().getDefaultAddressSpace().getAddress(0x100000),1,false);
            p.getProgramContext().setValue(p.getRegister("csval"),at(p,0),at(p,65535),BigInteger.valueOf(0x4000));
            var decoder=new ghidra.app.util.PseudoDisassembler(p);
            for(int off=0x100;off<0x103+length;) {
                var i=decoder.disassemble(at(p,off));if(i==null)break;
                p.getListing().createInstruction(at(p,off),i.getPrototype(),i,i.getProcessorContext(),0);off+=i.getLength();
            }
            Function f=p.getFunctionManager().createFunction(null,at(p,0x100),new AddressSet(at(p,0x100),at(p,0x102+length)),user?SourceType.USER_DEFINED:SourceType.DEFAULT);
            if(user)f.setName("user_fill_fixture",SourceType.USER_DEFINED);
            WSEvidence ev=new WSEvidence();ev.romFlags=new byte[bytes.length];
            if(played)Arrays.fill(ev.romFlags,0x103,0x103+length,(byte)1);
            List<String> lines=new ArrayList<>();String result=WSFillRuns.apply(p,ev,lines::add,monitor);println(result);
            boolean remove=!played&&!user&&length>=(value==0||value==255?64:256);
            check((p.getListing().getDataAt(at(p,0x103))!=null)==remove,"fill classification byte="+value+" len="+length+" played="+played+" user="+user);
            check(f.getBody().contains(at(p,0x104))!=remove,"function split at fill");
            if(remove) {
                check(!p.getMemory().getBlock(p.getListing().getInstructionAt(at(p,0x100)).getFallThrough()).isInitialized(),"empty same-space analysis boundary");
                check(p.getListing().getInstructionAt(at(p,0x100)).getFallThrough().getAddressSpace().equals(at(p,0x100).getAddressSpace()),"boundary stays in its code space despite occupied physical address");
                DecompInterface d=new DecompInterface();d.openProgram(p);var c=d.decompileFunction(f,30,monitor);
                check(c.decompileCompleted(),"prefix decompiles: "+c.getErrorMessage());String text=c.getDecompiledFunction().getC();println("FILL_C "+value+" "+text);
                check(text.split("\n").length<40 && !text.contains("unaff_DS"),"decompiler stops before any fill effects byte="+value);d.dispose();
            }
            if(remove) {
                Arrays.fill(ev.romFlags,0x103,0x103+length,(byte)1);
                check(WSFillRuns.restoreExecuted(p,ev,line->{})==1,"later execution reopens fill");
                check(p.getListing().getDefinedDataAt(at(p,0x103))==null,"data classification withdrawn");
                check(p.getListing().getInstructionAt(at(p,0x100)).getFallThrough().equals(at(p,0x103)),"original fallthrough restored");
            }
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(bytes,after),"no bytes changed");
            long count=p.getListing().getNumInstructions();WSFillRuns.apply(p,ev,line->{},monitor);check(count==p.getListing().getNumInstructions(),"idempotent");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    void jump(boolean conditional) throws Exception {
        byte[] bytes=new byte[65536];Arrays.fill(bytes,(byte)0xcc);
        bytes[0x100]=(byte)(conditional?0x74:0xeb);bytes[0x101]=0x20;bytes[0x102]=(byte)0xc3;
        Arrays.fill(bytes,0x122,0x162,(byte)0);bytes[0x162]=(byte)0xc3;
        ProgramDB p=new ProgramDB("fill-jump",currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction("jump into fill");
        try {
            var fb=p.getMemory().createFileBytes("fixture",0,bytes.length,new ByteArrayInputStream(bytes),monitor);
            var block=p.getMemory().createInitializedBlock("LIN_4000",at(p,0),fb,0,bytes.length,false);block.setPermissions(true,false,true);
            p.getProgramContext().setValue(p.getRegister("csval"),at(p,0),at(p,65535),BigInteger.valueOf(0x4000));
            var decoder=new ghidra.app.util.PseudoDisassembler(p);
            for(int off:new int[]{0x100,0x102,0x122}) {
                var i=decoder.disassemble(at(p,off));p.getListing().createInstruction(at(p,off),i.getPrototype(),i,i.getProcessorContext(),0);
            }
            var rm=p.getReferenceManager();rm.addMemoryReference(at(p,0x100),at(p,0x122),conditional?RefType.CONDITIONAL_JUMP:RefType.UNCONDITIONAL_JUMP,SourceType.ANALYSIS,0);
            AddressSet body=new AddressSet(at(p,0x100),at(p,0x102));body.add(at(p,0x122),at(p,0x161));
            Function f=p.getFunctionManager().createFunction(null,at(p,0x100),body,SourceType.DEFAULT);
            WSEvidence ev=new WSEvidence();ev.romFlags=new byte[bytes.length];ev.romFlags[0x100]=5;ev.romFlags[0x101]=1;
            WSFillRuns.apply(p,ev,line->{},monitor);
            Instruction branch=p.getListing().getInstructionAt(at(p,0x100));
            check(branch.getFlowOverride()==FlowOverride.CALL_RETURN,"fill jump becomes opaque tail transfer");
            if(conditional)check(branch.getFallThrough().equals(at(p,0x102)),"untaken conditional path retained");
            DecompInterface d=new DecompInterface();d.openProgram(p);var c=d.decompileFunction(f,30,monitor);
            check(c.decompileCompleted(),"jump prefix decompiles: "+c.getErrorMessage());
            check(!c.getDecompiledFunction().getC().contains("unaff_DS"),"fill jump has no invented memory additions");d.dispose();
            ev.romFlags[0x122]=1;WSFillRuns.restoreExecuted(p,ev,line->{});
            check(branch.getFlowOverride()==FlowOverride.NONE,"execution restores original jump");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    void thunk(boolean rebound) throws Exception {
        byte[] bytes=new byte[65536];Arrays.fill(bytes,(byte)0xcc);
        bytes[0x100]=(byte)0xe9;bytes[0x101]=(byte)0xfd;bytes[0x102]=0;
        Arrays.fill(bytes,0x200,0x240,(byte)0);bytes[0x300]=(byte)0xc3;
        ProgramDB p=new ProgramDB("fill-thunk",currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction("preserve thunk body");
        try {
            var fb=p.getMemory().createFileBytes("fixture",0,bytes.length,new ByteArrayInputStream(bytes),monitor);
            p.getMemory().createInitializedBlock("LIN_4000",at(p,0),fb,0,bytes.length,false).setPermissions(true,false,true);
            p.getProgramContext().setValue(p.getRegister("csval"),at(p,0),at(p,65535),BigInteger.valueOf(0x4000));
            var decoder=new ghidra.app.util.PseudoDisassembler(p);
            for(int off:new int[]{0x100,0x200,0x300}) {
                var i=decoder.disassemble(at(p,off));p.getListing().createInstruction(at(p,off),i.getPrototype(),i,i.getProcessorContext(),0);
            }
            var fm=p.getFunctionManager();
            Function old=fm.createFunction(null,at(p,0x200),new AddressSet(at(p,0x200),at(p,0x201)),SourceType.DEFAULT);
            Function target=fm.createFunction(null,at(p,0x300),new AddressSet(at(p,0x300)),SourceType.DEFAULT);
            Function source=fm.createFunction(null,at(p,0x100),new AddressSet(at(p,0x100),at(p,0x102)),SourceType.DEFAULT);
            source.setThunkedFunction(old);
            if(rebound) {
                Reference ref=p.getReferenceManager().addMemoryReference(at(p,0x100),at(p,0x300),RefType.JUMP_OVERRIDE_UNCONDITIONAL,SourceType.IMPORTED,-1);
                p.getReferenceManager().setPrimary(ref,true);
            }
            WSEvidence ev=new WSEvidence();ev.romFlags=new byte[bytes.length];Arrays.fill(ev.romFlags,0x100,0x103,(byte)1);
            WSFillRuns.apply(p,ev,line->{},monitor);
            source=fm.getFunctionAt(at(p,0x100));
            check(fm.getFunctionAt(at(p,0x200))==null,"speculative fill target removed");
            check(source!=null&&source.getBody().getNumAddresses()==3,"played thunk function body retained");
            check(rebound?source.isThunk()&&source.getThunkedFunction(false).equals(target):!source.isThunk(),"thunk rebinds to actual target or becomes unresolved ordinary function");
            check(p.getListing().getInstructionAt(at(p,0x100))!=null,"played thunk instruction retained");
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(bytes,after),"thunk preservation leaves bytes intact");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    public void run() throws Exception {
        fixture(0,64,false,false);fixture(255,64,false,false);fixture(0x11,256,false,false);
        fixture(0,32,false,false);fixture(0x11,64,false,false);fixture(0,64,true,false);fixture(0,64,false,true);
        fixture(0,64,false,false,true);
        jump(false);jump(true);
        thunk(false);thunk(true);
        println("WSFillFixtures: "+checks+" checks PASS");
    }
}
