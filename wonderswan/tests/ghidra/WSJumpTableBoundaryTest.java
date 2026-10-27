// SPDX-License-Identifier: MIT OR Apache-2.0
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
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

/** Persisted actual-caller regression for spatial boundaries of CS-relative tables.
 * Run setup on import, then check after reopening with analysis disabled. */
public class WSJumpTableBoundaryTest extends GhidraScript {
    SegmentedAddressSpace space;
    List<Address> sites = new ArrayList<>();
    List<Integer> expected = List.of(4,4,4,4,4,2,4,4,4);
    List<String> names = List.of("segments-a","segments-b","overlay-a","overlay-b","overlay-equal",
        "following-a","following-b","disjoint-a","disjoint-b");
    Address block(String name, int cs, boolean overlay) throws Exception {
        MemoryBlock b = currentProgram.getMemory().createInitializedBlock(name, space.getAddress(cs,0),
            0x8000, (byte)0, monitor, overlay);
        b.setPermissions(true,true,true);
        currentProgram.getListing().createData(b.getStart().add(0x7000), ghidra.program.model.data.ByteDataType.dataType);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("csval"),b.getStart(),b.getEnd(),BigInteger.valueOf(cs));
        return b.getStart();
    }
    void dispatch(Address base, int cs, int code, int table, boolean repeated) throws Exception {
        Memory m = currentProgram.getMemory();
        // CMP BX,3; JA return; ADD BX,BX; ADD BX,table; JMP word ptr CS:[BX]; RET
        byte[] bytes = {(byte)0x83,(byte)0xfb,3,0x77,9,1,(byte)0xdb,(byte)0x81,(byte)0xc3,
            (byte)table,(byte)(table>>8),0x2e,(byte)0xff,0x27,(byte)0xc3};
        Address start=base.add(code);
        m.setBytes(start,bytes);
        for(int i=0;i<4;i++) {
            int target=repeated?0x6060:0x6000+i*0x10;
            m.setShort(base.add(table+2*i),(short)target);
            m.setByte(base.add(target),(byte)0xc3);
        }
        if(!new DisassembleCommand(start,null,true).applyTo(currentProgram,monitor)) throw new IllegalStateException("dispatch decode failed");
        Address site=start.add(11);
        if(currentProgram.getListing().getInstructionAt(site)==null) throw new IllegalStateException("site missing");
        sites.add(site);
        currentProgram.getSymbolTable().createLabel(start,"fixture_"+sites.size(),SourceType.USER_DEFINED);
        currentProgram.getReferenceManager().addMemoryReference(start,base.add(0x7000),RefType.DATA,SourceType.USER_DEFINED,0);
    }
    void fixture() throws Exception {
        for(MemoryBlock b:currentProgram.getMemory().getBlocks()) currentProgram.getMemory().removeBlock(b,monitor);
        dispatch(block("SEG_A",0x2000,false),0x2000,0x100,0x1000,false);
        dispatch(block("SEG_B",0x3000,false),0x3000,0x100,0x1005,false);
        dispatch(block("OVER_A",0x7000,true),0x7000,0x100,0x2000,false);
        dispatch(block("OVER_B",0x7000,true),0x7000,0x100,0x2005,false);
        dispatch(block("OVER_EQUAL",0x7000,true),0x7000,0x100,0x2000,false);
        Address same=block("FOLLOW",0x4000,false);
        dispatch(same,0x4000,0x100,0x3000,true);
        dispatch(same,0x4000,0x200,0x3005,true);
        Address disjoint=block("DISJOINT",0x5000,false);
        dispatch(disjoint,0x5000,0x100,0x4000,false);
        dispatch(disjoint,0x5000,0x200,0x4100,false);
    }
    Map<Address,String> instructions() {
        Map<Address,String> result=new LinkedHashMap<>();
        for(Instruction i:currentProgram.getListing().getInstructions(true)) result.put(i.getAddress(),i.toString());
        for(Data d:currentProgram.getListing().getDefinedData(true))
            result.put(d.getAddress(), "DATA:"+d.getLength()+":"+d.getDataType().getPathName()+":"+d.getDefaultValueRepresentation());
        return result;
    }
    Set<String> protectedMetadata() {
        Set<String> result=new TreeSet<>();
        for(Symbol s:currentProgram.getSymbolTable().getAllSymbols(true))
            result.add("S:"+s.getAddress()+":"+s.getName(true)+":"+s.getSource());
        for(Instruction i:currentProgram.getListing().getInstructions(true))
            for(Reference r:currentProgram.getReferenceManager().getReferencesFrom(i.getAddress()))
                result.add("R:"+r.getFromAddress()+":"+r.getToAddress()+":"+r.getReferenceType()+":"+r.getSource());
        return result;
    }
    @Override public void run() throws Exception {
        space=(SegmentedAddressSpace)currentProgram.getAddressFactory().getDefaultAddressSpace();
        String[] args=getScriptArgs();
        if(args[0].equals("setup")){fixture();return;}
        // Recover persisted sites independently of setup state.
        for(String name:List.of("SEG_A","SEG_B","OVER_A","OVER_B","OVER_EQUAL","FOLLOW","DISJOINT")) {
            Address b=currentProgram.getMemory().getBlock(name).getStart();
            sites.add(b.add(0x10b));
            if(name.equals("FOLLOW")||name.equals("DISJOINT")) sites.add(b.add(0x20b));
        }
        Map<Address,byte[]> before=new LinkedHashMap<>();
        for(MemoryBlock b:currentProgram.getMemory().getBlocks()) {
            byte[] data=new byte[(int)b.getSize()];currentProgram.getMemory().getBytes(b.getStart(),data);before.put(b.getStart(),data);
        }
        Map<Address,String> ins=instructions(); Set<String> metadata=protectedMetadata();
        List<String> logs=new ArrayList<>();
        Class<?> cls=Class.forName("jidoughost.wonderswan.WSJumpTables");
        Constructor<?> ctor=cls.getDeclaredConstructor(Program.class,WSEvidence.class,Consumer.class);ctor.setAccessible(true);
        Object rule=ctor.newInstance(currentProgram,new WSEvidence(),(Consumer<String>)logs::add);
        Method pass=cls.getDeclaredMethod("applyPass",ghidra.util.task.TaskMonitor.class);pass.setAccessible(true);pass.invoke(rule,monitor);
        List<String> out=new ArrayList<>();int failures=0;
        for(int n=0;n<sites.size();n++) {
            Address site=sites.get(n); String line=logs.stream().filter(s->s.contains("\"rule\":\"J1\"")&&s.contains("\"site\":\""+site+"\"")).findFirst().orElse("MISSING");
            boolean ok=line.contains("\"outcome\":\"RECOVERED\"")&&line.contains("\"slots\":"+expected.get(n)+",");
            MemoryBlock b=currentProgram.getMemory().getBlock(site);
            int[] tables={0x1000,0x1005,0x2000,0x2005,0x2000,0x3000,0x3005,0x4000,0x4100};
            Set<Address> wanted=new HashSet<>(), actual=new HashSet<>();
            for(int k=0;k<expected.get(n);k++) {
                int offset=currentProgram.getMemory().getShort(b.getStart().add(tables[n]+2*k)) & 0xffff;
                wanted.add(b.getStart().add(offset));
            }
            for(Reference ref:currentProgram.getReferenceManager().getReferencesFrom(site))
                if(ref.getReferenceType().isComputed())actual.add(ref.getToAddress());
            boolean refs=actual.equals(wanted);
            ok &= refs;
            line += " targets="+refs+" expected="+wanted+" actual="+actual;
            if(!ok)failures++;
            out.add(names.get(n)+"\t"+(ok?"PASS":"FAIL")+"\t"+line);
        }
        boolean bytes=true;for(var e:before.entrySet()){byte[] now=new byte[e.getValue().length];currentProgram.getMemory().getBytes(e.getKey(),now);bytes&=Arrays.equals(now,e.getValue());}
        boolean listing=instructions().entrySet().containsAll(ins.entrySet()), meta=protectedMetadata().containsAll(metadata);
        out.add("preservation\t"+(bytes&&listing&&meta?"PASS":"FAIL")+"\tbytes="+bytes+" listing="+listing+" metadata="+meta);
        if(!bytes||!listing||!meta)failures++;
        Files.write(Path.of(args[1]),out);for(String s:out)println(s);
        if(failures>0)throw new IllegalStateException("boundary checks failed: "+failures);
    }
}
