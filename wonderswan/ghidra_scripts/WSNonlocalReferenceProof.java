// SPDX-License-Identifier: MIT OR Apache-2.0
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import jidoughost.wonderswan.WSEvidence;

/** Actual table recovery must preserve an independent encoded direct reference. */
public class WSNonlocalReferenceProof extends GhidraScript {
    int[] segments={0x4000,0x6000,0x8000};String[] names={"foreign-encoded","user-protected","known-code"};
    Address at(int k,int off){return ((SegmentedAddressSpace)currentProgram.getAddressFactory().getDefaultAddressSpace()).getAddress(segments[k],off);}
    void put(int k,int off,String hex)throws Exception{currentProgram.getMemory().setBytes(at(k,off),HexFormat.of().parseHex(hex));}
    void decode(int k,int off,int len)throws Exception{if(!new DisassembleCommand(at(k,off),new AddressSet(at(k,off),at(k,off+len-1)),false).applyTo(currentProgram,monitor))throw new IllegalStateException("decode "+k+":"+off);}
    void setup()throws Exception{
        for(MemoryBlock b:currentProgram.getMemory().getBlocks())currentProgram.getMemory().removeBlock(b,monitor);
        for(int k=0;k<3;k++){
            MemoryBlock b=currentProgram.getMemory().createInitializedBlock("SYNTH_"+k,at(k,0),0x1000,(byte)0xcc,monitor,false);b.setPermissions(true,true,true);
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("csval"),b.getStart(),b.getEnd(),BigInteger.valueOf(segments[k]));
            // CMP BX,1; JA return; ADD BX,BX; CALL CS:[BX+100]; RET. Two bounded slots.
            put(k,0x40,"83fb01770701db2eff970001c3");put(k,0x100,"00022002");
            // B's CALL encodes target200 directly; its reference is not a table guess.
            put(k,0x80,"e87d01c3");put(k,0x90,"90");put(k,0x220,"c3");
            if(k<2){put(k,0x200,"b8c390c3");decode(k,0x201,1);decode(k,0x203,1);currentProgram.getFunctionManager().createFunction("alternate_"+k,at(k,0x201),new AddressSet(at(k,0x201),at(k,0x201)),SourceType.USER_DEFINED);}
            else{put(k,0x200,"b83412c3");decode(k,0x200,4);currentProgram.getFunctionManager().createFunction("known",at(k,0x200),new AddressSet(at(k,0x200),at(k,0x203)),SourceType.USER_DEFINED);}
            decode(k,0x220,1);decode(k,0x40,13);decode(k,0x80,4);decode(k,0x90,1);
            currentProgram.getFunctionManager().createFunction("caller_"+k,at(k,0x80),new AddressSet(at(k,0x80),at(k,0x83)),SourceType.USER_DEFINED);
            currentProgram.getSymbolTable().createLabel(at(k,0x90),"user_"+k,SourceType.USER_DEFINED);
            currentProgram.getReferenceManager().addMemoryReference(at(k,0x90),at(k,0x300),RefType.DATA,SourceType.USER_DEFINED,0);
            if(k==1){currentProgram.getSymbolTable().createLabel(at(k,0x200),"protected_target",SourceType.USER_DEFINED);currentProgram.getReferenceManager().addMemoryReference(at(k,0x90),at(k,0x200),RefType.DATA,SourceType.USER_DEFINED,1);}
        }
    }
    Set<String> protectedMetadata(){Set<String> s=new TreeSet<>();for(Symbol y:currentProgram.getSymbolTable().getAllSymbols(true))if(y.getSource()==SourceType.USER_DEFINED)s.add("S:"+y.getAddress()+":"+y.getName(true)+":"+y.getSource()+":"+y.isPrimary());for(Instruction i:currentProgram.getListing().getInstructions(true))for(Reference r:i.getReferencesFrom())if(r.getSource()==SourceType.USER_DEFINED)s.add("R:"+r.getFromAddress()+":"+r.getToAddress()+":"+r.getReferenceType()+":"+r.getOperandIndex()+":"+r.isPrimary());for(Function f:currentProgram.getFunctionManager().getFunctions(true))s.add("F:"+f.getEntryPoint()+":"+f.getName()+":"+f.getBody()+":"+f.getSignature()+":"+f.getSymbol().getSource());return s;}
    Map<Address,String> instructions()throws Exception{Map<Address,String>s=new LinkedHashMap<>();for(Instruction i:currentProgram.getListing().getInstructions(true))s.put(i.getAddress(),i+":"+HexFormat.of().formatHex(i.getBytes()));return s;}
    boolean encoded(int k){return Arrays.stream(currentProgram.getReferenceManager().getReferencesFrom(at(k,0x80))).anyMatch(r->r.getToAddress().equals(at(k,0x200))&&r.getReferenceType()==RefType.UNCONDITIONAL_CALL&&r.getSource()==SourceType.DEFAULT);}
    @Override public void run()throws Exception{
        String[]args=getScriptArgs();if(args[0].equals("setup")){setup();println("SETUP COMPLETE");return;}
        for(int k=0;k<3;k++)if(!encoded(k))throw new IllegalStateException("missing original encoded reference "+names[k]);
        var alt=new PseudoDisassembler(currentProgram).disassemble(at(0,0x200));if(alt==null||!alt.toString().equals("MOV AX,0x90c3")||alt.getLength()!=3)throw new IllegalStateException("alternate entry invalid: "+alt);
        if(!new PseudoDisassembler(currentProgram).disassemble(at(0,0x203)).getMnemonicString().equals("RET"))throw new IllegalStateException("alternate entry lacks return");
        Map<Address,String> before=instructions();Set<String> meta=protectedMetadata();Map<Address,byte[]>bytes=new LinkedHashMap<>();for(MemoryBlock b:currentProgram.getMemory().getBlocks()){byte[]raw=new byte[(int)b.getSize()];currentProgram.getMemory().getBytes(b.getStart(),raw);bytes.put(b.getStart(),raw);}
        List<String> logs=new ArrayList<>();WSEvidence ev=new WSEvidence();if(!ev.cs.isEmpty())throw new IllegalStateException("proof must have no execution mask");
        Class<?>cls=Class.forName("jidoughost.wonderswan.WSJumpTables");Constructor<?>ctor=cls.getDeclaredConstructor(Program.class,WSEvidence.class,Consumer.class);ctor.setAccessible(true);Object rule=ctor.newInstance(currentProgram,ev,(Consumer<String>)logs::add);Method pass=cls.getDeclaredMethod("applyPass",ghidra.util.task.TaskMonitor.class);pass.setAccessible(true);pass.invoke(rule,monitor);
        List<String>rows=new ArrayList<>();for(int k=0;k<3;k++)rows.add(names[k]+"\t"+(encoded(k)?"PASS":"FAIL")+"\tencoded CALL "+at(k,0x80)+" ->"+at(k,0x200));
        boolean unchanged=true;for(var e:bytes.entrySet()){byte[]now=new byte[e.getValue().length];currentProgram.getMemory().getBytes(e.getKey(),now);unchanged&=Arrays.equals(now,e.getValue());}rows.add("bytes\t"+(unchanged?"PASS":"FAIL"));rows.add("listing\t"+(instructions().entrySet().containsAll(before.entrySet())?"PASS":"FAIL"));rows.add("user-function-metadata\t"+(protectedMetadata().containsAll(meta)?"PASS":"FAIL"));
        rows.add("actual-failed-deshadow\t"+(logs.stream().anyMatch(s->s.contains("\"rule\":\"J1n\"")&&s.contains("\"site\":\""+at(0,0x47)+"\""))&&logs.stream().anyMatch(s->s.contains("\"outcome\":\"UNRESOLVED_CONFLICT\"")&&s.contains("\"target\":\""+at(0,0x200)+"\""))?"PASS":"FAIL"));
        Files.write(Path.of(args[1]),rows);Files.write(Path.of(args[1]+".evidence"),logs);for(String r:rows)println(r);Files.writeString(Path.of(args[1]+".complete"),"COMPLETE actual table-rule proof\n");
    }
}
