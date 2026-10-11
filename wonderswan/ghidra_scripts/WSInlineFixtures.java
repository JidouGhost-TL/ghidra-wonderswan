// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.*;

/** Return-address dispatch, data precedence and adjacent-body regression fixtures. */
public class WSInlineFixtures extends GhidraScript {
    int checks, failures;
    Map<ProgramDB,Integer> transactions=new HashMap<>();
    void check(boolean ok, String message) { checks++; if (!ok) { failures++; printerr("FAIL: "+message); } }
    void put(byte[] b,int off,String hex) { byte[] v=HexFormat.of().parseHex(hex);System.arraycopy(v,0,b,off,v.length); }
    Address at(Program p,int off) { return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000,off); }
    ProgramDB make(byte[] bytes) throws Exception {
        ProgramDB p=new ProgramDB("inline-fixture",currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        transactions.put(p,p.startTransaction("fixture"));
        var file=p.getMemory().createFileBytes("fixture",0,bytes.length,new ByteArrayInputStream(bytes),monitor);
        var b=p.getMemory().createInitializedBlock("fixture",at(p,0),file,0,bytes.length,false);b.setPermissions(true,false,true);
        p.getProgramContext().setValue(p.getRegister("csval"),at(p,0),at(p,bytes.length-1),BigInteger.valueOf(0x4000));return p;
    }
    void inline(int kind, boolean protectedTable, boolean duplicate) throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        boolean interrupt=kind!=0; int table=interrupt?0x42:0x43, count=duplicate?3:2, first=table+2*count;
        put(bytes,0x40,interrupt?"cd40":"e8bd01");put(bytes,table,String.format("%02x006000",first)+(duplicate?String.format("%02x00",first):""));
        put(bytes,first,"b80100c3");put(bytes,0x60,"b80200c3");
        put(bytes,0x200,kind==0?"5fb40001c001c72e8b3dffe7":kind==1?"5589e50653b400d1e0c45e0201c3268b078946025b075dcf":"c80000001e56b400d1e0c5760203f0ad8946025e1fc9cf");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x200),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x200)).applyTo(p,monitor);
            new DisassembleCommand(at(p,0x40),new AddressSet(at(p,0x40),at(p,table-1)),false).applyTo(p,monitor);
            p.getFunctionManager().createFunction(null,at(p,0x40),new AddressSet(at(p,0x40),at(p,table-1)),SourceType.DEFAULT);
            if(interrupt) p.getBookmarkManager().setBookmark(at(p,0x200),BookmarkType.ANALYSIS,"WSCodePointer","F2 store IVT[40] from "+at(p,0x20));
            var starts=p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS);starts.add(at(p,0x40),0x4000);
            if(protectedTable) starts.add(at(p,table),0x4000);
            WSEvidence ev=new WSEvidence();
            for(int round=0;round<2;round++) {
                WSEvidenceAnalyzer.repairEvidence(p,ev,"",monitor);
                WSJumpTables.pruneStaleOverrides(p,l->{},monitor);
                new WSMerge(p,Set.of(),l->{},monitor).apply();
                Function helper=p.getFunctionManager().getFunctionAt(at(p,0x200));
                boolean localModel=false;
                for(var ref:p.getReferenceManager().getReferencesFrom(at(p,0x40))) {
                    Function target=p.getFunctionManager().getFunctionAt(ref.getToAddress());
                    if(ref.isPrimary()&&target!=null&&target.getCallFixup()!=null) localModel=true;
                }
                check(localModel==!protectedTable,"kind="+kind+" fixup and protected-byte veto, round="+round);
                for(int k=0;k<2*count;k++) check((p.getListing().getDefinedDataContaining(at(p,table+k))!=null)==!protectedTable,"table byte data precedence");
                if(!protectedTable) {
                    Instruction site=p.getListing().getInstructionAt(at(p,0x40));
                    println("SITE "+site.getAddress()+" flow="+site.getFlowType()+" ft="+site.getFallThrough()+" default="+site.getDefaultFallThrough()+" helper="+helper.getCallFixup()+" noreturn="+helper.hasNoReturn());
                    check(Objects.equals(site.getFallThrough(),at(p,first)),"flow bypasses inline words");
                    var raw=site.getPcode(false);
                    check(interrupt ? Arrays.stream(raw).anyMatch(op->op.getOpcode()==ghidra.program.model.pcode.PcodeOp.CALLIND)
                        : Arrays.stream(raw).anyMatch(op->op.getOpcode()==ghidra.program.model.pcode.PcodeOp.CALL&&op.getInput(0).getOffset()==at(p,0x200).getOffset()),
                        "CPU pcode retains the original helper destination");
                    check(p.getFunctionManager().getFunctionAt(at(p,0x40))!=null,"switch owner survives merge");
                    DecompInterface d=new DecompInterface();
                    try {d.openProgram(p);var result=d.decompileFunction(p.getFunctionManager().getFunctionAt(at(p,0x40)),30,monitor);
                        String c=result.getDecompiledFunction()==null?"":result.getDecompiledFunction().getC();
                        check(result.decompileCompleted(),"decompiler completes "+result.getErrorMessage());
                        check(c.contains("switch")&&c.contains("case 0:")&&c.contains("case 1:")&&!c.contains("halt_baddata"),"finite cases without halt: "+c);
                        if(duplicate) check(c.contains("case 2:")&&c.contains("return 2;"),"trailing shared destination keeps its selector and distinct case: "+c);
                        check(c.contains("default:")&&c.contains("code *"),"selectors outside proven words retain opaque transfer: "+c);
                    } finally {d.dispose();}
                }
            }
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(bytes,after),"instruction and table bytes preserved");
        } finally {p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void multipleSites() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"e8bd0147006000");put(bytes,0x47,"b80100c3");put(bytes,0x60,"b80200c3");
        put(bytes,0x80,"e87d018900a0008900");put(bytes,0x89,"b80300c3");put(bytes,0xa0,"b80400c3");
        put(bytes,0xc0,"e83d01c3");put(bytes,0x200,"5fb40001c001c72e8b3dffe7");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x200),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x200)).applyTo(p,monitor);
            for(int off:new int[]{0x40,0x80,0xc0}) {
                new DisassembleCommand(at(p,off),new AddressSet(at(p,off),at(p,off+2)),false).applyTo(p,monitor);
                p.getFunctionManager().createFunction(null,at(p,off),new AddressSet(at(p,off),at(p,off+2)),SourceType.DEFAULT);
            }
            for(int round=0;round<2;round++) {
                WSEvidenceAnalyzer.repairEvidence(p,new WSEvidence(),"",monitor);
                WSJumpTables.pruneStaleOverrides(p,l->{},monitor);
                new WSMerge(p,Set.of(),l->{},monitor).apply();
                DecompInterface d=new DecompInterface();try {
                    d.openProgram(p);
                    for(int off:new int[]{0x40,0x80,0xc0}) {
                        var r=d.decompileFunction(p.getFunctionManager().getFunctionAt(at(p,off)),30,monitor);
                        String c=r.getDecompiledFunction()==null?"":r.getDecompiledFunction().getC();
                        check(r.decompileCompleted()&&!c.contains("halt_baddata"),"shared helper site completes: "+c);
                        check(c.contains("case 2:")==(off==0x80),"each site has its own bound: "+c);
                        if(off!=0xc0)check(c.contains("code *"),"out-of-range selectors stay opaque: "+c);
                        else check(!WSInlineTables.modeled(p,at(p,off)),"weak table remains unmodeled");
                        if(off==0x80)check(c.contains("return 4;"),"shared helper keeps distinct case: "+c);
                    }
                }finally{d.dispose();}
            }
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(bytes,after),"shared-helper bytes unchanged");
            for(Function f:p.getFunctionManager().getFunctions(true)) if(f.getTags().stream().anyMatch(t->t.getName().equals("WS_INLINE_MODEL"))) {
                check(f.getEntryPoint().isNonLoadedMemoryAddress(),"compiler delegate is non-loaded metadata");
                DecompInterface d=new DecompInterface();try {d.openProgram(p);var r=d.decompileFunction(f,30,monitor);
                    check(r.decompileCompleted()&&!r.getDecompiledFunction().getC().contains("halt_baddata"),"delegate alone decompiles cleanly: "+r.getErrorMessage()+" "+(r.getDecompiledFunction()==null?"":r.getDecompiledFunction().getC()));
                }finally{d.dispose();}
            }
        }finally{p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void jump() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"83e301d1e32effa70001");put(bytes,0x100,"04016001");put(bytes,0x104,"b80100c3");put(bytes,0x160,"b80200c3");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x40)).applyTo(p,monitor);
            for(int round=0;round<2;round++) {
                WSEvidenceAnalyzer.repairEvidence(p,new WSEvidence(),"",monitor);
                for(int k=0;k<4;k++)check(p.getListing().getDefinedDataContaining(at(p,0x100+k))!=null,"CS:[BX+table] word data, round="+round);
                Instruction site=p.getListing().getInstructionAt(at(p,0x45));
                check(site!=null&&Arrays.stream(site.getFlows()).anyMatch(a->a.equals(at(p,0x104))),"CS:[BX+table] case flow");
            }
        } finally {p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void reentry() throws Exception {
        byte[] b=new byte[0x200];Arrays.fill(b,(byte)0xcc);
        put(b,0x40,"eb0e");put(b,0x50,"85c074ec c3".replace(" ",""));put(b,0x100,"e94dff");
        ProgramDB p=make(b);
        try {
            for(int off:new int[]{0x40,0x100})new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
            AddressSet original=new AddressSet(at(p,0x40),at(p,0x41));original.add(at(p,0x50),at(p,0x54));
            Function f=p.getFunctionManager().createFunction(null,at(p,0x40),original,SourceType.DEFAULT);
            p.getFunctionManager().createFunction(null,at(p,0x100),new AddressSet(at(p,0x100),at(p,0x102)),SourceType.DEFAULT);
            var proof=p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS);
            for(int off:new int[]{0x40,0x50,0x52,0x100})proof.add(at(p,off),0x4000);
            WSDecodeRepair.decompilerBoundaries(p,List.of(),l->{},monitor);
            Function g=p.getFunctionManager().getFunctionAt(at(p,0x50));
            check(g!=null,"executed exterior re-entry split despite back edge");
            check(f.getBody().contains(at(p,0x40)),"original entry remains in prefix");
            check(g==null||!g.getBody().contains(at(p,0x40)),"back edge does not steal original entry");
            check(p.getListing().getInstructionAt(at(p,0x100)).getFlowOverride()==FlowOverride.CALL_RETURN,"exterior jump becomes tail transfer");
        } finally {p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void saved(boolean yield, boolean explicit) throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"e8bd01c744023412c3");put(bytes,0x200,yield?"588904c3":"588904ffe0");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x200),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x200)).applyTo(p,monitor);
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x40)).applyTo(p,monitor);
            Function helper=p.getFunctionManager().getFunctionAt(at(p,0x200));
            if(explicit)helper.setCallingConvention("__wsasm");
            if(explicit)helper.setSignatureSource(SourceType.USER_DEFINED);
            for(int round=0;round<2;round++) {
                WSEvidenceAnalyzer.repairEvidence(p,new WSEvidence(),"",monitor);
                new WSMerge(p,Set.of(),l->{},monitor).apply();
                check((helper.getCallFixup()!=null)==!explicit,"saved continuation metadata and explicit-signature veto");
                if(!explicit) {
                    Instruction call=p.getListing().getInstructionAt(at(p,0x40));
                    check((call.getFallThrough()==null)==yield,"yield versus immediate continuation flow");
                    check(helper.hasNoReturn()==yield,"yield does not return to this CALL");
                    DecompInterface d=new DecompInterface();try {
                        d.openProgram(p);var result=d.decompileFunction(p.getFunctionManager().getFunctionAt(at(p,0x40)),30,monitor);
                        String c=result.getDecompiledFunction()==null?"":result.getDecompiledFunction().getC();
                        check(result.decompileCompleted()&&c.contains("0x43")&&!c.contains("halt_baddata"),"saved IP store decompiles: "+c);
                        check(c.contains("0x1234")==!yield,"yield defers the saved continuation: "+c);
                    }finally{d.dispose();}
                }
            }
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(bytes,after),"continuation bytes unchanged");
        }finally{p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void pushed() throws Exception {
        byte[] bytes=new byte[0x6000];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"535783e303d1e36806012effa70001");
        put(bytes,0x100,"0002200240025f5bcb");
        for(int off:new int[]{0x200,0x220,0x240,0x5b5f})put(bytes,off,"b80100c3");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x40)).applyTo(p,monitor);
            for(int round=0;round<2;round++) {
                WSEvidenceAnalyzer.repairEvidence(p,new WSEvidence(),"",monitor);
                Instruction site=p.getListing().getInstructionAt(at(p,0x4a));
                check(site.getFlowOverride()==FlowOverride.CALL,"pushed near IP dispatch becomes call");
                check(Objects.equals(site.getFallThrough(),at(p,0x106)),"call returns to restore stub");
                Set<Address> targets=new TreeSet<>();for(var ref:site.getReferencesFrom())if(ref.getReferenceType()==RefType.COMPUTED_CALL)targets.add(ref.getToAddress());
                check(targets.equals(new TreeSet<>(List.of(at(p,0x200),at(p,0x220),at(p,0x240)))),"exact three callable cases; POP opcodes are not a fourth pointer");
                check(p.getListing().getInstructionAt(at(p,0x106))!=null,"return continuation stays code");
                check(p.getListing().getDefinedDataContaining(at(p,0x105))!=null,"last table word is data");
            }
        }finally{p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void pushedVeto(int kind) throws Exception {
        byte[] bytes=new byte[0x6000];Arrays.fill(bytes,(byte)0xcc);
        String between=kind==0?"50":kind==1?"83c402":kind==2?"368907":"";
        put(bytes,0x40,"535783e303d1e3680601"+between+"2effa70001");
        int site=0x4a+between.length()/2;
        if(kind==4)put(bytes,site,"2eff970001");
        if(kind==3)put(bytes,0x80,String.format("e9%02x%02x",(site-0x83)&0xff,((site-0x83)>>>8)&0xff));
        put(bytes,0x100,"0002200240025f5bcb");
        for(int off:new int[]{0x200,0x220,0x240,0x5b5f})put(bytes,off,"b80100c3");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x40)).applyTo(p,monitor);
            if(kind==3)new DisassembleCommand(at(p,0x80),null,true).applyTo(p,monitor);
            for(int round=0;round<2;round++) {
                WSEvidenceAnalyzer.repairEvidence(p,new WSEvidence(),"",monitor);
                check(p.getListing().getInstructionAt(at(p,site)).getFlowOverride()!=FlowOverride.CALL,
                    "stack change, aliasing store, join or actual CALL vetoes pushed-call inference, kind="+kind);
            }
        }finally{p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void weak(boolean byteBound, boolean explicit) throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);put(bytes,0x40,"2effa70001");
        ProgramDB p=make(bytes);
        try {
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x40)).applyTo(p,monitor);
            Function f=p.getFunctionManager().getFunctionAt(at(p,0x40));if(explicit)f.setSignatureSource(SourceType.USER_DEFINED);
            String line="{\"rule\":\"J1\",\"site\":\""+at(p,0x40)+"\",\"outcome\":\"UNRESOLVED\",\"shape\":\"MEM/"+(byteBound?"BYTE_INDEX_WEAK_STOP:":"UNBOUNDED_WEAK_STOP:")+"DEFINED_DATA\"}";
            for(int round=0;round<2;round++) {
                WSDecodeRepair.decompilerBoundaries(p,List.of(line),l->{},monitor);
                Instruction i=p.getListing().getInstructionAt(at(p,0x40));
                check((i.getFlowOverride()==FlowOverride.CALL_RETURN)==!explicit,"automatic weak sites remain opaque; explicit signature veto");
                check(Arrays.stream(i.getPcode(false)).anyMatch(op->op.getOpcode()==ghidra.program.model.pcode.PcodeOp.BRANCHIND),"original computed destination retained in CPU pcode");
            }
        }finally{p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    void adjacent() throws Exception {
        byte[] b=new byte[0x200];Arrays.fill(b,(byte)0xcc);put(b,0x40,"90b80100c3");
        ProgramDB p=make(b);
        try {
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);
            Function f=p.getFunctionManager().createFunction(null,at(p,0x40),new AddressSet(at(p,0x40),at(p,0x41)),SourceType.DEFAULT);
            Function g=p.getFunctionManager().createFunction(null,at(p,0x42),new AddressSet(at(p,0x42),at(p,0x44)),SourceType.DEFAULT);
            p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS).add(at(p,0x40),0x4000);
            boolean completed=true;try {WSDecodeRepair.boundaries(p,l->{},monitor);}catch(ghidra.program.database.function.OverlappingFunctionException e){completed=false;}
            check(completed,"straddling instruction does not expand into adjacent function");
            check(g.getBody().equals(new AddressSet(at(p,0x42),at(p,0x44))),"adjacent function retained");
            check(!f.getBody().intersects(g.getBody()),"body ownership remains disjoint");
        } finally {p.endTransaction(transactions.remove(p),false);p.release(this);}
    }
    public void run() throws Exception {
        for(int kind=0;kind<3;kind++){inline(kind,false,false);inline(kind,true,false);inline(kind,false,true);}multipleSites();jump();reentry();adjacent();
        for(boolean yield:new boolean[]{false,true})for(boolean explicit:new boolean[]{false,true})saved(yield,explicit);
        pushed();for(int kind=0;kind<5;kind++)pushedVeto(kind);
        for(boolean bound:new boolean[]{false,true})for(boolean explicit:new boolean[]{false,true})weak(bound,explicit);
        println("WSInlineFixtures: checks="+checks+" failures="+failures);
        if(failures>0)throw new AssertionError("inline fixture failures="+failures);
    }
}
