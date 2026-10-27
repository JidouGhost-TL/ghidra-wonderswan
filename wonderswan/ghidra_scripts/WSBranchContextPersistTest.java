// SPDX-License-Identifier: MIT OR Apache-2.0
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import jidoughost.wonderswan.*;

/** Saved/reopened actual D2 caller: address rendering must not supply architectural CS. */
public class WSBranchContextPersistTest extends GhidraScript {
    int[] points={0x7fff6,0x9fff6,0xb0120,0xcfff6,0xdfff6,0x1fff6,0xffff6};
    int[] segments={0x7ffa,0x9000,0xb000,-1,0xdffa,0x1ffa,-1};
    String[] names={"display-boundary","ip-wrap","ordinary","unknown-context","executed","ram","ambiguous-context"};
    Address at(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
    void setup() throws Exception {
        for(MemoryBlock b:currentProgram.getMemory().getBlocks())currentProgram.getMemory().removeBlock(b,monitor);
        for(int k=0;k<points.length;k++) {
            Address a=at(points[k]);
            MemoryBlock b=currentProgram.getMemory().createInitializedBlock("SYNTH_"+k,a,16,(byte)0x90,monitor,false);
            b.setPermissions(true,true,true);
            currentProgram.getMemory().setBytes(a,new byte[]{0x74,0x18});
            if(segments[k]>=0)currentProgram.getProgramContext().setValue(currentProgram.getRegister("csval"),a,a.add(15),BigInteger.valueOf(segments[k]));
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("hwundef"),a,a.add(15),BigInteger.ZERO);
            if(!new DisassembleCommand(a,new AddressSet(a,a),false).applyTo(currentProgram,monitor))throw new IllegalStateException("decode "+names[k]);
            currentProgram.getSymbolTable().createLabel(a,"branch_"+k,SourceType.USER_DEFINED);
            currentProgram.getReferenceManager().addMemoryReference(a,a.add(8),RefType.DATA,SourceType.USER_DEFINED,0);
            if(k==6)currentProgram.getReferenceManager().addMemoryReference(a,at(0xf0010),RefType.CONDITIONAL_JUMP,SourceType.USER_DEFINED,0);
            currentProgram.getFunctionManager().createFunction("fixture_"+k,a,new AddressSet(a,a.add(1)),SourceType.USER_DEFINED);
        }
    }
    Set<String> snapshot(Address a) throws Exception {
        Set<String> rows=new TreeSet<>();
        Instruction i=currentProgram.getListing().getInstructionAt(a);
        rows.add("I:"+i+":"+i.getLength()+":"+Arrays.toString(i.getBytes()));
        rows.add("C:"+currentProgram.getProgramContext().getValue(currentProgram.getRegister("csval"),a,false));
        for(Reference r:currentProgram.getReferenceManager().getReferencesFrom(a))rows.add("R:"+r.getFromAddress()+":"+r.getToAddress()+":"+r.getReferenceType()+":"+r.getSource()+":"+r.getOperandIndex()+":"+r.isPrimary());
        for(Symbol s:currentProgram.getSymbolTable().getSymbols(a))rows.add("S:"+s.getName(true)+":"+s.getSource()+":"+s.isPrimary());
        Function f=currentProgram.getFunctionManager().getFunctionAt(a);rows.add("F:"+f.getName()+":"+f.getBody()+":"+f.getSignature()+":"+f.getSymbol().getSource());
        return rows;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();if(args[0].equals("setup")){setup();println("SETUP COMPLETE");return;}
        int[] expected={0x80010,0x90010,0xb013a,0x10,0xe0010,0x20010,0x10};
        for(int k=0;k<points.length;k++) {
            Instruction i=currentProgram.getListing().getInstructionAt(at(points[k]));
            if(!Arrays.asList(i.getFlows()).contains(at(expected[k])))throw new IllegalStateException("fixture target arithmetic "+names[k]);
        }
        List<Set<String>> before=new ArrayList<>();for(int n:points)before.add(snapshot(at(n)));
        Map<Address,byte[]> bytes=new LinkedHashMap<>();for(MemoryBlock b:currentProgram.getMemory().getBlocks()){byte[] raw=new byte[(int)b.getSize()];currentProgram.getMemory().getBytes(b.getStart(),raw);bytes.put(b.getStart(),raw);}
        WSEvidence ev=new WSEvidence();ev.cs.put((long)points[4],segments[4]);
        List<String> logs=new ArrayList<>();WSBranchContext rule=new WSBranchContext(currentProgram,ev,logs::add,monitor);rule.apply();
        List<String> rows=new ArrayList<>();for(int k=0;k<points.length;k++){Set<String> after=snapshot(at(points[k]));rows.add(names[k]+"\t"+(before.get(k).equals(after)?"PASS":"FAIL")+"\tbefore="+before.get(k)+" after="+after);}
        boolean same=true;for(var e:bytes.entrySet()){byte[] raw=new byte[e.getValue().length];currentProgram.getMemory().getBytes(e.getKey(),raw);same&=Arrays.equals(raw,e.getValue());}
        rows.add("bytes\t"+(same?"PASS":"FAIL"));
        boolean diagnostic=currentProgram.getBookmarkManager().getBookmark(at(points[3]),BookmarkType.ANALYSIS,"branch-context")!=null && currentProgram.getBookmarkManager().getBookmark(at(points[6]),BookmarkType.ANALYSIS,"branch-context")!=null;
        rows.add("unknown-diagnostics\t"+(diagnostic?"PASS":"FAIL"));
        boolean evidence=logs.stream().filter(l->l.contains("CONTEXT_PRESERVED")).count()==1 && logs.stream().filter(l->l.contains("UNKNOWN_CS")).count()==2 && logs.stream().filter(l->l.contains("EXECUTED")).count()==1;
        rows.add("per-item-evidence\t"+(evidence?"PASS":"FAIL"));
        Files.write(Path.of(args[1]),rows);Files.write(Path.of(args[1]+".evidence"),logs);for(String r:rows)println(r);println(rule.summary());
        Files.writeString(Path.of(args[1]+".complete"),"EXPORT COMPLETE\n");
    }
}
