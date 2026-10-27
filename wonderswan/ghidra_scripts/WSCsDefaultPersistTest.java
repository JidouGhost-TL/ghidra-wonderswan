// SPDX-License-Identifier: MIT OR Apache-2.0
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import java.math.BigInteger;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

/** Persisted actual D3 caller: prove regular-CS and csval semantics separately. */
public class WSCsDefaultPersistTest extends GhidraScript {
    int[] sites={0x7fff6,0x80040,0x90040,0x1234,0xbfff6,0xd0040};
    int[] cs={0x7ffa,0x7ffa,-1,0x100,0xbffa,0xd000};
    String[] names={"mov-known","push-context-control","unknown","ram-known","stored-context-control","aligned-control"};
    Address at(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
    void setup()throws Exception{
        for(MemoryBlock b:currentProgram.getMemory().getBlocks())currentProgram.getMemory().removeBlock(b,monitor);
        for(int k=0;k<sites.length;k++){
            Address a=at(sites[k]);MemoryBlock b=currentProgram.getMemory().createInitializedBlock("SYNTH_"+k,a,16,(byte)0x90,monitor,false);b.setPermissions(true,true,true);
            byte[] raw=k==1?new byte[]{0x0e,0x58,(byte)0xc3}:new byte[]{(byte)0x8c,(byte)0xc8,(byte)0xc3};currentProgram.getMemory().setBytes(a,raw);
            if(cs[k]>=0)for(String r:List.of("csval","CS"))currentProgram.getProgramContext().setValue(currentProgram.getRegister(r),a,a.add(15),BigInteger.valueOf(cs[k]));
            new DisassembleCommand(a,new AddressSet(a,a.add(raw.length-1)),true).applyTo(currentProgram,monitor);
            Function f=currentProgram.getFunctionManager().createFunction("fixture_"+k,a,new AddressSet(a,a.add(raw.length-1)),SourceType.USER_DEFINED);f.setReturnType(UnsignedShortDataType.dataType,SourceType.USER_DEFINED);
            currentProgram.getReferenceManager().addMemoryReference(a,a.add(8),RefType.DATA,SourceType.USER_DEFINED,0);
            currentProgram.getSymbolTable().createLabel(a,"user_"+k,SourceType.USER_DEFINED);
        }
    }
    String decompile(Address a)throws Exception{
        DecompInterface d=new DecompInterface();try{d.openProgram(currentProgram);DecompileResults result=d.decompileFunction(currentProgram.getFunctionManager().getFunctionAt(a),30,monitor);if(!result.decompileCompleted())throw new IllegalStateException(result.getErrorMessage());return result.getDecompiledFunction().getC();}finally{d.dispose();}
    }
    String snapshot(Address a)throws Exception{
        List<String> out=new ArrayList<>();for(Instruction i:currentProgram.getListing().getInstructions(currentProgram.getFunctionManager().getFunctionAt(a).getBody(),true)){out.add(i.getAddress()+":"+i+":"+HexFormat.of().formatHex(i.getBytes()));for(PcodeOp op:i.getPcode())out.add("PCODE:"+op);for(Reference r:i.getReferencesFrom())out.add("REF:"+r.getToAddress()+":"+r.getReferenceType()+":"+r.getSource()+":"+r.isPrimary());}
        for(Symbol s:currentProgram.getSymbolTable().getSymbols(a))out.add("SYMBOL:"+s.getName(true)+":"+s.getSource()+":"+s.isPrimary());
        Function f=currentProgram.getFunctionManager().getFunctionAt(a);out.add("FUNCTION:"+f.getName()+":"+f.getBody()+":"+f.getSignature()+":"+f.getSymbol().getSource());return String.join("\n",out);
    }
    @Override public void run()throws Exception{
        String[] args=getScriptArgs();if(args[0].equals("setup")){setup();println("SETUP COMPLETE");return;}
        Path out=Path.of(args[1]);Files.createDirectories(out);
        List<String> rows=new ArrayList<>();List<String> before=new ArrayList<>();List<String> beforeC=new ArrayList<>();List<BigInteger> context=new ArrayList<>();
        Map<Address,byte[]> bytes=new LinkedHashMap<>();for(MemoryBlock b:currentProgram.getMemory().getBlocks()){byte[]raw=new byte[(int)b.getSize()];currentProgram.getMemory().getBytes(b.getStart(),raw);bytes.put(b.getStart(),raw);}
        for(int k=0;k<sites.length;k++){Address a=at(sites[k]);before.add(snapshot(a));context.add(currentProgram.getProgramContext().getValue(currentProgram.getRegister("CS"),a,false));String c=decompile(a);beforeC.add(c);if(cs[k]>=0 && !c.contains("return "+(cs[k]==0?"0":"0x"+Integer.toHexString(cs[k]))+";"))throw new IllegalStateException("unexpected initial CS return "+names[k]+": "+c);if(cs[k]<0 && !c.contains("unaff_CS"))throw new IllegalStateException("unknown initial CS must remain symbolic");Files.writeString(out.resolve(names[k]+"-before.c"),c);Files.writeString(out.resolve(names[k]+"-before.pcode"),before.get(k));}
        Class<?> cls=Class.forName("jidoughost.wonderswan.WSCompilerRules");Method method=cls.getDeclaredMethod("applyCsDefault",Program.class);method.setAccessible(true);int[] counts=(int[])method.invoke(null,currentProgram);
        for(int k=0;k<sites.length;k++){Address a=at(sites[k]);String afterC=decompile(a);Files.writeString(out.resolve(names[k]+"-after.c"),afterC);Files.writeString(out.resolve(names[k]+"-after.pcode"),snapshot(a));BigInteger after=currentProgram.getProgramContext().getValue(currentProgram.getRegister("CS"),a,false);BigInteger csval=currentProgram.getProgramContext().getValue(currentProgram.getRegister("csval"),a,false);rows.add(names[k]+"-context\t"+(Objects.equals(context.get(k),after)?"PASS":"FAIL")+"\tCS-before="+context.get(k)+" CS-after="+after+" csval="+csval);
            rows.add(names[k]+"-decompile\t"+(beforeC.get(k).equals(afterC)?"PASS":"FAIL"));
            rows.add(names[k]+"-listing-metadata-pcode\t"+(before.get(k).equals(snapshot(a))?"PASS":"FAIL"));}
        boolean equal=true;for(var e:bytes.entrySet()){byte[]raw=new byte[e.getValue().length];currentProgram.getMemory().getBytes(e.getKey(),raw);equal&=Arrays.equals(raw,e.getValue());}rows.add("bytes\t"+(equal?"PASS":"FAIL")+"\tD3-spans="+counts[0]+" blocks="+counts[1]);Files.write(out.resolve("result.tsv"),rows);Files.writeString(out.resolve("EXPORT.COMPLETE"),"COMPLETE persisted actual D3 proof\n");for(String row:rows)println(row);
    }
}
