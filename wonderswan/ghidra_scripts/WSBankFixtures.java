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
    private void unknownPort() throws Exception {
        byte[] raw=new byte[2*65536];Arrays.fill(raw,(byte)0xff);
        ProgramDB p=program(raw);int tx=p.startTransaction("unknown bank ports");
        try {
            String[] code={"b0feee9a69000020","b8fe00ef9a69000020",
                "b0fee6c2ee9a69000020","eeb0fee6c29a69000020","bac200b0feee9a69000020"};
            int[] calls={3,4,5,5,6};
            for(int n=0;n<code.length;n++) {
                Address a=at(p,0x200+n*0x20);byte[] bytes=HexFormat.of().parseHex(code[n]);
                p.getMemory().setBytes(a,bytes);
                for(int k=0;k<=calls[n];) {insert(p,a.add(k));k+=p.getListing().getInstructionAt(a.add(k)).getLength();}
                Integer bank=WSRomEvidence.staticBank(p,p.getListing().getInstructionAt(a.add(calls[n])),0x20069);
                check(n<3?bank==null:Integer.valueOf(0xfe).equals(bank),
                    "unknown DX stays unresolved/invalidate prior bank; later or known-port writes resolve case="+n);
            }
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
    private void sharedTail(boolean conditional) throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        byte[] branch=HexFormat.of().parseHex(conditional?"742ec3":"e92d00");
        System.arraycopy(branch,0,raw,0x100,branch.length);raw[0x130]=(byte)0xc3;
        ProgramDB p=program(raw);int tx=p.startTransaction("unplayed shared tail");
        try {
            insert(p,at(p,0x100));insert(p,at(p,0x130));if(conditional)insert(p,at(p,0x102));
            p.getFunctionManager().createFunction(null,at(p,0x100),new AddressSet(at(p,0x100),at(p,0x102)),SourceType.DEFAULT);
            p.getFunctionManager().createFunction(null,at(p,0x130),new AddressSet(at(p,0x130)),SourceType.DEFAULT);
            WSEvidence ev=new WSEvidence();ev.cs.put(0x40130L,0x4000);WSRomEvidence.prepare(p,ev,line->{},monitor);
            WSDecodeRepair.decompilerBoundaries(p,List.of(),line->{},monitor);
            var i=p.getListing().getInstructionAt(at(p,0x100));
            check(i.getFlowOverride()==FlowOverride.CALL_RETURN,"unplayed direct caller keeps proven shared function separate");
            check(i.getFlows()[0].equals(at(p,0x130)),"shared tail keeps actual destination");
            if(conditional)check(i.getFallThrough().equals(at(p,0x102)),"conditional shared tail retains untaken path");
            byte[] after=new byte[raw.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(raw,after),"shared tails keep bytes unchanged");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    private void quarantinedTable(boolean user) throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        System.arraycopy(HexFormat.of().parseHex("2effa70002"),0,raw,0x180,5);
        ProgramDB p=program(raw);int tx=p.startTransaction("quarantined empty table");
        try {
            insert(p,at(p,0x180));var i=p.getListing().getInstructionAt(at(p,0x180));
            var destination=Arrays.stream(i.getPcode(false)).filter(op->op.getOpcode()==PcodeOp.BRANCHIND).findFirst().orElseThrow().getInput(0);
            Function f=p.getFunctionManager().createFunction(user?"user_dispatch":null,at(p,0x180),new AddressSet(at(p,0x180),at(p,0x184)),user?SourceType.USER_DEFINED:SourceType.DEFAULT);
            check(f.getSymbol().getSource()==(user?SourceType.USER_DEFINED:SourceType.DEFAULT),"fixture creates requested function source");
            List<String> evidence=List.of("{\"rule\":\"J1l\",\"site\":\""+at(p,0x180)+"\",\"outcome\":\"QUARANTINED\",\"deleted\":[]}");
            WSJumpTables.lockSwitches(p,evidence,line->{},monitor);
            check(i.getFlowOverride()==(user?FlowOverride.NONE:FlowOverride.CALL_RETURN),"empty quarantine is opaque without changing user functions");
            if(!user)check(Arrays.stream(i.getPcode(true)).anyMatch(op->op.getOpcode()==PcodeOp.CALLIND&&op.getInput(0).equals(destination)),"empty quarantine preserves dynamic destination");
            byte[] after=new byte[raw.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(raw,after),"empty quarantine keeps bytes unchanged");
            WSJumpTables.lockSwitches(p,evidence,line->{},monitor);
            check(i.getFlowOverride()==(user?FlowOverride.NONE:FlowOverride.CALL_RETURN),"empty quarantine idempotent");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    private void cpuSegmentTable() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        System.arraycopy(HexFormat.of().parseHex("83fb002effa70002"),0,raw,0x100,8);
        // Display address 4000:0103 executes with CS=4008. CS:0200 is
        // physically 4000:0280; the other word is a convincing false table.
        raw[0x200]=0;raw[0x201]=4;raw[0x280]=0;raw[0x281]=3;
        raw[0x380]=(byte)0xc3;raw[0x400]=(byte)0xc3;
        ProgramDB p=program(raw);int tx=p.startTransaction("CPU segment table");
        try {
            p.getProgramContext().setValue(p.getRegister("csval"),at(p,0x100),at(p,0x107),BigInteger.valueOf(0x4008));
            insert(p,at(p,0x100));insert(p,at(p,0x103));
            p.getFunctionManager().createFunction(null,at(p,0x100),new AddressSet(at(p,0x100),at(p,0x107)),SourceType.DEFAULT);
            WSEvidence ev=new WSEvidence();ev.romFlags=new byte[raw.length];
            ev.cs.put(0x40100L,0x4008);ev.cs.put(0x40103L,0x4008);
            WSEvidenceAnalyzer.repairEvidence(p,ev,"",monitor);
            var refs=p.getReferenceManager().getReferencesFrom(at(p,0x103));
            check(Arrays.stream(refs).anyMatch(r->r.getReferenceType().isComputed()&&r.getToAddress().equals(at(p,0x380))),"table and near target use recorded CPU CS");
            check(Arrays.stream(refs).noneMatch(r->r.getReferenceType().isComputed()&&r.getToAddress().equals(at(p,0x400))),"canonical display segment is not a table base");
            check(p.getListing().getInstructionAt(at(p,0x380))!=null,"correct table target decoded");
            byte[] after=new byte[raw.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(raw,after),"CPU CS recovery keeps ROM bytes unchanged");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    private void tableBeforeMergedCallee() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);
        System.arraycopy(HexFormat.of().parseHex("2eff970002e8fc00c3"),0,raw,0x100,9);
        raw[0x200]=0x60;raw[0x201]=2;raw[0x202]=0x70;raw[0x203]=2;
        System.arraycopy(HexFormat.of().parseHex("b88002c3"),0,raw,0x204,4);
        raw[0x260]=(byte)0xc3;raw[0x270]=(byte)0xc3;raw[0x80b8]=(byte)0xc3;raw[0xc302]=(byte)0xc3;
        ProgramDB p=program(raw);int tx=p.startTransaction("table before merged callee");
        try {
            for(int off:new int[]{0x100,0x105,0x108,0x204,0x207})insert(p,at(p,off));
            p.getReferenceManager().addMemoryReference(at(p,0x105),at(p,0x204),RefType.UNCONDITIONAL_CALL,SourceType.DEFAULT,0);
            AddressSet body=new AddressSet(at(p,0x100),at(p,0x108));body.add(at(p,0x204),at(p,0x207));
            p.getFunctionManager().createFunction(null,at(p,0x100),body,SourceType.DEFAULT);
            check(p.getFunctionManager().getFunctionAt(at(p,0x204))==null,"merged callee has code and call without function object");
            WSEvidence ev=new WSEvidence();ev.romFlags=new byte[raw.length];WSEvidenceAnalyzer.repairEvidence(p,ev,"",monitor);
            var refs=p.getReferenceManager().getReferencesFrom(at(p,0x100));
            check(Arrays.stream(refs).filter(r->r.getReferenceType().isComputed()).count()==2,"unbounded table stops before directly called code");
            check(Arrays.stream(refs).noneMatch(r->r.getToAddress().equals(at(p,0x80b8))||r.getToAddress().equals(at(p,0xc302))),"callee instruction bytes are not table targets");
            byte[] after=new byte[raw.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(raw,after),"callee boundary preserves ROM bytes");
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    private JumpTable storedSwitch(Program p, Function f, Address site) {
        Namespace overrides=HighFunction.findOverrideSpace(f);
        if(overrides==null)return null;
        for(Symbol s:p.getSymbolTable().getSymbols(overrides))if(s.getObject() instanceof Namespace ns) {
            JumpTable t=JumpTable.readOverride(ns,p.getSymbolTable());
            if(t!=null&&t.getSwitchAddress().equals(site))return t;
        }
        return null;
    }
    private void staleSwitchOverrides() throws Exception {
        byte[] raw=new byte[65536];Arrays.fill(raw,(byte)0xff);raw[0x100]=(byte)0xc3;
        for(int off:new int[]{0x180,0x300,0x500,0x700})System.arraycopy(HexFormat.of().parseHex("2effa70002"),0,raw,off,5);
        raw[0x230]=(byte)0xc3;
        ProgramDB p=program(raw);int tx=p.startTransaction("stale switches");
        try {
            for(int off:new int[]{0x100,0x180,0x300,0x500,0x700,0x230})insert(p,at(p,off));
            AddressSet body=new AddressSet(at(p,0x100));body.add(at(p,0x180),at(p,0x184));
            Function outside=p.getFunctionManager().createFunction(null,at(p,0x100),body,SourceType.DEFAULT);
            Function opaque=p.getFunctionManager().createFunction(null,at(p,0x300),new AddressSet(at(p,0x300),at(p,0x304)),SourceType.DEFAULT);
            Function valid=p.getFunctionManager().createFunction(null,at(p,0x500),new AddressSet(at(p,0x500),at(p,0x504)),SourceType.DEFAULT);
            Function user=p.getFunctionManager().createFunction("user_switch",at(p,0x700),new AddressSet(at(p,0x700),at(p,0x704)),SourceType.USER_DEFINED);
            Function[] owners={outside,opaque,valid,user};int[] sites={0x180,0x300,0x500,0x700};
            for(int n=0;n<4;n++)new JumpTable(at(p,sites[n]),new ArrayList<>(List.of(at(p,0x230))),true,0).writeOverride(owners[n]);
            outside.setBody(new AddressSet(at(p,0x100)));user.setBody(new AddressSet(at(p,0x700)));
            p.getListing().getInstructionAt(at(p,0x300)).setFlowOverride(FlowOverride.CALL_RETURN);
            List<String> lines=new ArrayList<>();WSJumpTables.pruneStaleOverrides(p,lines::add,monitor);
            check(storedSwitch(p,outside,at(p,0x180))==null,"split owner loses outside-body switch");
            check(storedSwitch(p,opaque,at(p,0x300))==null,"opaque call cannot own jump override");
            check(storedSwitch(p,valid,at(p,0x500))!=null,"valid switch override retained");
            check(storedSwitch(p,user,at(p,0x700))!=null,"user switch override protected");
            check(lines.size()==2,"only two automatic invalid overrides removed");
            check(WSJumpTables.pruneStaleOverrides(p,line->{},monitor).endsWith(" 0"),"switch cleanup idempotent");
            check(p.getListing().getInstructionAt(at(p,0x180))!=null,"detached switch instruction retained");
            byte[] after=new byte[raw.length];p.getMemory().getBytes(at(p,0),after);check(Arrays.equals(raw,after),"switch cleanup keeps ROM bytes");
            DecompInterface d=new DecompInterface();try{d.openProgram(p);check(d.decompileFunction(outside,10,monitor).decompileCompleted(),"native decompiles split owner after cleanup");}finally{d.dispose();}
        } finally {p.endTransaction(tx,true);p.release(this);}
    }
    @Override public void run() throws Exception {
        banks();unknownPort();alignment(true,false);alignment(false,false);alignment(true,true);operandStart();boundaries();decompilerBoundary();opaqueTable();
        sharedTail(false);sharedTail(true);quarantinedTable(false);quarantinedTable(true);
        cpuSegmentTable();
        tableBeforeMergedCallee();staleSwitchOverrides();
        println("WSBankFixtures: PASS checks="+checks);
    }
}
