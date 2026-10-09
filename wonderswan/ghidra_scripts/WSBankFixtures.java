// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import jidoughost.wonderswan.*;

/** Synthetic bank placement, executed alignment and function-boundary checks. */
public class WSBankFixtures extends GhidraScript {
    private int checks;
    private void check(boolean ok, String reason) { if (!ok) throw new AssertionError(reason); checks++; }
    private Address at(Program p, int offset) {
        return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000, offset);
    }
    private void insert(Program p, Address a) throws Exception {
        var i = new ghidra.app.util.PseudoDisassembler(p).disassemble(a);
        p.getListing().createInstruction(a, i.getPrototype(), i, i.getProcessorContext(), 0);
    }
    private ProgramDB program(byte[] raw) throws Exception {
        ProgramDB p = new ProgramDB("bank-fixture", currentProgram.getLanguage(), currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx = p.startTransaction("fixture map");
        try {
            var fb = p.getMemory().createFileBytes("fixture", 0, raw.length, new ByteArrayInputStream(raw), monitor);
            var b = p.getMemory().createInitializedBlock("LIN_4000", at(p, 0), fb, 0, 65536, false);
            b.setPermissions(true, false, true);
            p.getProgramContext().setValue(p.getRegister("csval"), at(p,0), at(p,65535), BigInteger.valueOf(0x4000));
        } finally { p.endTransaction(tx, true); }
        return p;
    }
    private void banks() throws Exception {
        byte[] raw = new byte[2*65536]; Arrays.fill(raw, (byte)0xff); raw[0x69]=(byte)0xc3;raw[65536+0x69]=(byte)0xcb;
        ProgramDB p=program(raw);int tx=p.startTransaction("banks");
        try {
            check(WSRomWindows.bank(0,raw.length)==0xfe,"first bank alias");
            check(WSRomWindows.bank(65536,raw.length)==0xff,"last bank alias");
            check(WSRomWindows.mapAll(p,monitor)==4,"both windows map every bank");
            check(WSRomWindows.mapAll(p,monitor)==0,"mapping idempotent");
            var view=WSRomWindows.view(p,0x2000,0xfe,true,monitor);
            check(!p.getMemory().getBlock(WSRomWindows.name(0x3000,0xfe)).isExecute(),"unselected window dormant");
            check(WSRom.offsetOf(p,view.getStart().add(0x69)).orElse(-1)==0x69,"source ROM offset");
            check(p.getMemory().getByte(view.getStart().add(0x69))==(byte)0xc3,"correct bank bytes");
            check(p.getMemory().getByte(at(p,0x69))==(byte)0xc3,"default mapping unchanged");
            Address call=at(p,0x10);p.getMemory().setBytes(call,HexFormat.of().parseHex("b0fee6c29a69000020"));
            new DisassembleCommand(call,null,true).applyTo(p,monitor);
            check(WSRomEvidence.staticBank(p,p.getListing().getInstructionAt(call.add(4)),0x20069)==0xfe,"constant C2 write resolves bank");
            check(WSRomWindows.bank(0,0x18000)==0xfe,"start padding retained");
            check(WSRomWindows.bank(0x17fff,0x18000)==0xff,"padded final bank");
            List<String> lines=new ArrayList<>();WSEvidence ev=new WSEvidence();ev.romFlags=new byte[raw.length];ev.romFlags[0x69]=9;
            WSRomEvidence.prepare(p,ev,lines::add,monitor);WSRomEvidence.seedWindows(p,ev,lines::add,monitor);
            check(p.getFunctionManager().getFunctionAt(view.getStart().add(0x69))!=null,"physical sub-entry becomes window function");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    private void alignment(boolean executedWinner, boolean both) throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);raw[0x100]=(byte)0xb8;raw[0x101]=(byte)0x90;raw[0x102]=(byte)0xc3;
        ProgramDB p=program(raw);int tx=p.startTransaction("alignment");
        try {
            insert(p,at(p,0x100));WSEvidence ev=new WSEvidence();ev.romFlags=new byte[raw.length];
            if(executedWinner){ev.romFlags[0x101]=5;ev.romFlags[0x102]=1;}
            if(both)ev.romFlags[0x100]=9;
            List<String> lines=new ArrayList<>();WSDecodeRepair.align(p,ev,lines::add,monitor);
            check((p.getListing().getInstructionAt(at(p,0x101))!=null)==(executedWinner&&!both),"executed winner replaces only speculative alignment");
            check((p.getListing().getInstructionAt(at(p,0x100))!=null)==(!executedWinner||both),"unknown/both-executed alignment retained");
            byte[] bytes=new byte[raw.length];p.getMemory().getBytes(at(p,0),bytes);check(Arrays.equals(raw,bytes),"repair preserves bytes");
            long count=p.getListing().getNumInstructions();WSDecodeRepair.align(p,ev,lines::add,monitor);check(count==p.getListing().getNumInstructions(),"alignment idempotent");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    private void boundaries() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);raw[0x100]=(byte)0x90;raw[0x110]=(byte)0xc3;
        ProgramDB p=program(raw);int tx=p.startTransaction("boundaries");
        try {
            insert(p,at(p,0x100));insert(p,at(p,0x110));
            Function f=p.getFunctionManager().createFunction(null,at(p,0x100),new AddressSet(at(p,0x100),at(p,0x110)),SourceType.DEFAULT);
            WSEvidence ev=new WSEvidence();ev.cs.put(0x40100L,0x4000);WSRomEvidence.prepare(p,ev,line->{},monitor);
            WSDecodeRepair.boundaries(p,line->{},monitor);
            check(f.getBody().getNumAddresses()==1,"function stops at undecodable gap");
            check(p.getListing().getInstructionAt(at(p,0x110))!=null,"other decoded component retained");
            // A second independently executed component must remain inside a separate function.
            f.setBody(new AddressSet(at(p,0x100),at(p,0x110)));
            var override=p.getSymbolTable().createNameSpace(f,"override",SourceType.ANALYSIS);
            var jump=p.getSymbolTable().createNameSpace(override,"jmp_fixture",SourceType.ANALYSIS);
            var label=p.getSymbolTable().createLabel(at(p,0x110),"case_fixture",jump,SourceType.ANALYSIS);
            ev.cs.put(0x40110L,0x4000);WSRomEvidence.prepare(p,ev,line->{},monitor);
            WSDecodeRepair.boundaries(p,line->{},monitor);
            check(p.getFunctionManager().getFunctionAt(at(p,0x110))!=null,"executed component beyond gap gets separate function");
            check(f.getBody().getNumAddresses()==1,"executed island is not glued across gap");
            check(!label.isDeleted()&&label.getParentNamespace().equals(jump),"jump-override label survives global function creation");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }

    private void operandStart() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        System.arraycopy(HexFormat.of().parseHex("b890c3cb"),0,raw,0x100,4);
        ProgramDB p=program(raw);int tx=p.startTransaction("operand start");
        try {
            insert(p,at(p,0x101));
            WSEvidence ev=new WSEvidence();ev.romFlags=new byte[raw.length];ev.romFlags[0x100]=9;
            for(int off=0x101;off<=0x103;off++)ev.romFlags[off]=1;
            WSDecodeRepair.align(p,ev,line->{},monitor);
            check(p.getListing().getInstructionAt(at(p,0x100))!=null,"executed start beats speculative start inside its operands");
            check(p.getListing().getInstructionAt(at(p,0x101))==null,"later speculative operand decode removed");
            check(p.getListing().getInstructionAt(at(p,0x100)).getLength()==3,"winning instruction has complete executed bytes");
            byte[] bytes=new byte[raw.length];p.getMemory().getBytes(at(p,0),bytes);check(Arrays.equals(raw,bytes),"operand repair preserves bytes");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }

    private void decompilerBoundary() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        // Two independent entries converge on an interior dispatch. Only two case targets ran.
        System.arraycopy(HexFormat.of().parseHex("b8341290"),0,raw,0xfc,4);
        System.arraycopy(HexFormat.of().parseHex("2effa70002"),0,raw,0x100,5);
        raw[0x120]=(byte)0xc3;raw[0x130]=(byte)0xc3;
        System.arraycopy(HexFormat.of().parseHex("b83412e9aaff"),0,raw,0x150,6);
        ProgramDB p=program(raw);int tx=p.startTransaction("decompiler boundary");
        try {
            for(int off:new int[]{0xfc,0xff,0x100,0x120,0x130,0x150,0x153})insert(p,at(p,off));
            var rm=p.getReferenceManager();
            for(int off:new int[]{0x120,0x130})rm.addMemoryReference(at(p,0x100),at(p,off),RefType.COMPUTED_JUMP,SourceType.ANALYSIS,0);
            AddressSet oldBody=new AddressSet(at(p,0xfc),at(p,0xff));oldBody.add(at(p,0x100),at(p,0x104));oldBody.add(at(p,0x120));oldBody.add(at(p,0x130));
            Function parent=p.getFunctionManager().createFunction(null,at(p,0xfc),oldBody,SourceType.DEFAULT);
            p.getFunctionManager().createFunction(null,at(p,0x150),new AddressSet(at(p,0x150),at(p,0x155)),SourceType.DEFAULT);
            WSEvidence ev=new WSEvidence();
            for(int off:new int[]{0xfc,0xff,0x100,0x120,0x130,0x150,0x153})ev.cs.put(0x40000L+off,0x4000);
            WSRomEvidence.prepare(p,ev,line->{},monitor);
            List<String> report=List.of("{\"rule\":\"J1\",\"site\":\""+at(p,0x100)+"\",\"outcome\":\"UNRESOLVED\",\"shape\":\"MEM/UNBOUNDED_WEAK_STOP:UNDECODABLE\"}");
            List<String> lines=new ArrayList<>();WSDecodeRepair.decompilerBoundaries(p,report,lines::add,monitor);
            check(p.getFunctionManager().getFunctionAt(at(p,0x100))!=null,"foreign interior dispatch becomes separate function");
            check(!parent.getBody().contains(at(p,0x100)),"split bodies do not overlap");
            check(p.getListing().getInstructionAt(at(p,0x153)).getFlowOverride()==FlowOverride.CALL_RETURN,"foreign jump is explicit tail transfer");
            check(lines.stream().anyMatch(s->s.contains("EXECUTED_TABLE_LOCK")&&s.contains("\"cases\":2")),"weak table locks only supported cases");
            var overrides=p.getSymbolTable().getNamespace("override",parent);
            boolean retained=false;
            if(overrides!=null)for(var s:p.getSymbolTable().getSymbols(overrides))if(s.getSymbolType()==SymbolType.NAMESPACE){
                var table=JumpTable.readOverride((Namespace)s.getObject(),p.getSymbolTable());
                if(table!=null&&table.getSwitchAddress().equals(at(p,0x100)))retained=true;
            }
            check(retained,"original fall-through owner retains finite switch override after body split");
            DecompInterface d=new DecompInterface();
            try {
                d.openProgram(p);var result=d.decompileFunction(parent,20,monitor);
                check(result.decompileCompleted(),"split prefix still decompiles");
                String c=result.getDecompiledFunction().getC();
                check(c.length()<5000&&!c.contains("halt_baddata")&&!c.contains("overlaps instruction"),"prefix fall-through respects finite dispatch outside stored body");
            } finally {d.dispose();}
            int count=p.getFunctionManager().getFunctionCount();WSDecodeRepair.decompilerBoundaries(p,report,line->{},monitor);
            check(count==p.getFunctionManager().getFunctionCount(),"boundary split idempotent");
            byte[] bytes=new byte[raw.length];p.getMemory().getBytes(at(p,0),bytes);check(Arrays.equals(raw,bytes),"flow boundaries preserve ROM bytes");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }

    private void opaqueTable() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        System.arraycopy(HexFormat.of().parseHex("2effa70002"),0,raw,0x180,5);
        ProgramDB p=program(raw);int tx=p.startTransaction("opaque table");
        try {
            insert(p,at(p,0x180));var i=p.getListing().getInstructionAt(at(p,0x180));
            var destination=Arrays.stream(i.getPcode(false)).filter(op->op.getOpcode()==PcodeOp.BRANCHIND).findFirst().orElseThrow().getInput(0);
            p.getFunctionManager().createFunction(null,at(p,0x180),new AddressSet(at(p,0x180),at(p,0x184)),SourceType.DEFAULT);
            WSEvidence ev=new WSEvidence();ev.cs.put(0x40180L,0x4000);WSRomEvidence.prepare(p,ev,line->{},monitor);
            WSDecodeRepair.decompilerBoundaries(p,List.of("{\"rule\":\"J1\",\"site\":\""+at(p,0x180)+"\",\"outcome\":\"UNRESOLVED\",\"shape\":\"MEM/UNBOUNDED_WEAK_STOP:UNDECODABLE\"}"),line->{},monitor);
            check(i.getFlowOverride()==FlowOverride.CALL_RETURN,"unsupported table is an opaque tail transfer");
            check(Arrays.stream(i.getPcode(true)).anyMatch(op->op.getOpcode()==PcodeOp.CALLIND&&op.getInput(0).equals(destination)),"opaque transfer preserves computed destination");
            byte[] bytes=new byte[raw.length];p.getMemory().getBytes(at(p,0),bytes);check(Arrays.equals(raw,bytes),"opaque transfer preserves ROM bytes");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    @Override public void run() throws Exception {
        banks();alignment(true,false);alignment(false,false);alignment(true,true);operandStart();boundaries();decompilerBoundary();opaqueTable();
        println("WSBankFixtures: PASS checks="+checks);
    }
}
