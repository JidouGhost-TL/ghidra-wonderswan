// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.*;

/** Behavioral fixtures for consuming-caller signatures and persistent observed targets. */
public class WSDecompFixFixtures extends GhidraScript {
    int checks;
    Map<ProgramDB,Integer> transactions = new HashMap<>();
    void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); checks++; }
    Address at(Program p, int off) {
        return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000, off);
    }
    void put(byte[] bytes, int off, String hex) {
        byte[] b = HexFormat.of().parseHex(hex); System.arraycopy(b, 0, bytes, off, b.length);
    }
    ProgramDB program(String name, byte[] bytes) throws Exception {
        ProgramDB p = new ProgramDB(name, currentProgram.getLanguage(), currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        transactions.put(p,p.startTransaction(name));
        var file = p.getMemory().createFileBytes(name, 0, bytes.length, new ByteArrayInputStream(bytes), monitor);
        var block = p.getMemory().createInitializedBlock("fixture", at(p, 0), file, 0, bytes.length, false);
        block.setPermissions(true, false, true);
        p.getProgramContext().setValue(p.getRegister("csval"), at(p,0), at(p,bytes.length-1), BigInteger.valueOf(0x4000));
        return p;
    }
    void release(ProgramDB p) { p.endTransaction(transactions.remove(p), false); p.release(this); }
    void returns(String name, String helper, String output, boolean expected, boolean explicit, String... uses) throws Exception {
        byte[] bytes = new byte[0x400]; Arrays.fill(bytes,(byte)0xcc); put(bytes,0x100,helper);
        for (int k=0;k<uses.length;k++) {
            int off=0x40+k*0x10, rel=0x100-off-3;
            put(bytes,off,String.format("e8%02x%02x",rel&255,rel>>8)+uses[k]);
        }
        ProgramDB p=program(name,bytes);
        try {
            new DisassembleCommand(at(p,0x100),null,true).applyTo(p,monitor);
            new CreateFunctionCmd(at(p,0x100)).applyTo(p,monitor);
            for(int k=0;k<uses.length;k++) new DisassembleCommand(at(p,0x40+k*0x10),null,true).applyTo(p,monitor);
            Function f=p.getFunctionManager().getFunctionAt(at(p,0x100));
            if(explicit) { f.setCustomVariableStorage(true); f.setReturn(WordDataType.dataType,new VariableStorage(p,p.getRegister("DX")),SourceType.USER_DEFINED); }
            List<String> lines=new ArrayList<>(); WSReturns.apply(p,lines::add,monitor);
            boolean has=f.getReturn().getVariableStorage().toString().equals(output);
            check(has==expected,name+": storage="+f.getReturn().getVariableStorage()+" evidence="+lines);
            if(explicit) check(f.getSignatureSource()==SourceType.USER_DEFINED,name+": user signature kept");
            String first=f.getPrototypeString(true,true)+f.getReturn().getVariableStorage();
            WSReturns.apply(p,l->{},monitor);
            check(first.equals(f.getPrototypeString(true,true)+f.getReturn().getVariableStorage()),name+": repeat signature stable");
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);
            check(Arrays.equals(bytes,after),name+": instruction bytes unchanged");
        } finally { release(p); }
    }
    void transitiveInputs() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"e8bd0089c2c3");
        put(bytes,0x100,"e8fd0085c0c3");
        put(bytes,0x200,"89d0c3");
        ProgramDB p=program("later-callee-input",bytes);
        try {
            for(int off:new int[]{0x200,0x100,0x40}) {
                new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
                new CreateFunctionCmd(at(p,off)).applyTo(p,monitor);
            }
            WSReturns.apply(p,l->{},monitor);
            List<String> signatures=new ArrayList<>();
            for(int off:new int[]{0x100,0x200}) {
                Function f=p.getFunctionManager().getFunctionAt(at(p,off));
                check(f.getParameterCount()==1&&f.getParameter(0).getVariableStorage().toString().equals("DX:2"),
                    "later callee DX input reaches "+f.getEntryPoint()+" in one apply");
                signatures.add(f.getPrototypeString(true,true)+f.getReturn().getVariableStorage());
            }
            List<String> replay=new ArrayList<>();WSReturns.apply(p,replay::add,monitor);
            check(replay.stream().noneMatch(l->l.contains("\"outcome\":\"SET\"")),"transitive input replay makes no signature changes");
            for(int n=0;n<2;n++) {
                Function f=p.getFunctionManager().getFunctionAt(at(p,n==0?0x100:0x200));
                check(signatures.get(n).equals(f.getPrototypeString(true,true)+f.getReturn().getVariableStorage()),
                    "transitive input replay keeps complete signature");
            }
        } finally { release(p); }
    }
    void boundaryReplay() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"c3");put(bytes,0x100,"89d0c3");
        ProgramDB p=program("import-boundary-replay",bytes);
        try {
            for(int off:new int[]{0x40,0x100})new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
            AddressSet body=new AddressSet(at(p,0x40));body.add(at(p,0x100),at(p,0x102));
            p.getFunctionManager().createFunction(null,at(p,0x40),body,SourceType.DEFAULT);
            p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS).add(at(p,0x40),3);
            WSEvidence evidence=new WSEvidence();evidence.cs.put(at(p,0x40).getOffset(),0x4000);
            evidence.cs.put(at(p,0x100).getOffset(),0x4000);
            WSEvidenceAnalyzer.repairEvidence(p,evidence,"",monitor);
            check(p.getFunctionManager().getFunctionAt(at(p,0x100))!=null,"first import owns code exposed by boundary repair");
            check(!p.getFunctionManager().getFunctionAt(at(p,0x40)).getBody().contains(at(p,0x100)),"boundary keeps components separate");
            int count=p.getFunctionManager().getFunctionCount();
            String first=p.getFunctionManager().getFunctionAt(at(p,0x100)).getBody().toString();
            WSEvidenceAnalyzer.repairEvidence(p,evidence,"",monitor);
            check(p.getFunctionManager().getFunctionCount()==count,"boundary replay creates no additional functions");
            check(first.equals(p.getFunctionManager().getFunctionAt(at(p,0x100)).getBody().toString()),"boundary replay keeps exposed body");
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);
            check(Arrays.equals(bytes,after),"boundary replay keeps instruction bytes");
        } finally { release(p); }
    }
    void finishedBoundaries() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"b80100c3");put(bytes,0x80,"c606002003e97800");
        put(bytes,0x100,"b80200c3");put(bytes,0x140,"e9bd00");put(bytes,0x200,"b80300c3");
        ProgramDB p=program("finished-boundary-replay",bytes);
        try {
            for(int off:new int[]{0x40,0x100,0x80,0x200,0x140})new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
            AddressSet body=new AddressSet(at(p,0x40),at(p,0x43));body.add(at(p,0x100),at(p,0x103));
            p.getFunctionManager().createFunction(null,at(p,0x40),body,SourceType.DEFAULT);
            p.getFunctionManager().createFunction(null,at(p,0x80),new AddressSet(at(p,0x80),at(p,0x87)),SourceType.DEFAULT);
            p.getFunctionManager().createFunction(null,at(p,0x140),new AddressSet(at(p,0x140),at(p,0x142)),SourceType.DEFAULT);
            new CreateFunctionCmd(at(p,0x200)).applyTo(p,monitor);
            var starts=p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS);
            for(int off:new int[]{0x40,0x85,0x100,0x140,0x200})starts.add(at(p,off),3);
            WSDecodeRepair.decompilerBoundaries(p,List.of(),l->{},monitor);
            check(p.getFunctionManager().getFunctionAt(at(p,0x100))!=null,"exterior entry separated before replay");
            Function thunk=p.getFunctionManager().getFunctionAt(at(p,0x140));
            check(thunk.isThunk()&&thunk.getThunkedFunction(false).getEntryPoint().equals(at(p,0x200)),"final tail thunk metadata completed immediately");
            new WSMerge(p,Set.of(),l->{},monitor).apply();
            check(p.getFunctionManager().getFunctionAt(at(p,0x100))!=null,"merge replay preserves A3 exterior entry");
            check(p.getListing().getInstructionAt(at(p,0x85)).getFlowOverride()==FlowOverride.CALL_RETURN,"merge replay preserves exterior tail flow");
            WSDecodeRepair.decompilerBoundaries(p,List.of(),l->{},monitor);
            check(thunk.isThunk()&&thunk.getThunkedFunction(false).getEntryPoint().equals(at(p,0x200)),"tail thunk replay stable");
        } finally { release(p); }
    }
    void observed() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"2effa70001");put(bytes,0x200,"b80100c3");put(bytes,0x220,"b80200c3");put(bytes,0x240,"b80300c3");
        put(bytes,0x60,"e89d00");put(bytes,0x80,"cd40");put(bytes,0x260,"b80400c3");
        ProgramDB p=program("observed",bytes);
        try {
            for(int off:new int[]{0x40,0x60,0x80,0x200,0x220,0x240,0x260}) new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
            AddressSet initial = new AddressSet(at(p,0x40),at(p,0x44));
            initial.add(at(p,0x260),at(p,0x263));
            p.getFunctionManager().createFunction(null,at(p,0x40),initial,SourceType.DEFAULT);
            var starts = p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS);
            starts.add(at(p,0x40),0x4000); starts.add(at(p,0x260),0x4000);
            Instruction site=p.getListing().getInstructionAt(at(p,0x40));
            site.addMnemonicReference(at(p,0x240),RefType.COMPUTED_JUMP,SourceType.ANALYSIS);
            WSObservedSwitches.remember(p,at(p,0x40),List.of(at(p,0x200)));
            WSObservedSwitches.remember(p,at(p,0x40),List.of(at(p,0x220),at(p,0x200)));
            WSObservedSwitches.remember(p,at(p,0x60),List.of(at(p,0x200)));
            WSObservedSwitches.remember(p,at(p,0x80),List.of(at(p,0x220)));
            WSJumpTables.lockSwitches(p,List.of(),l->{},monitor);
            Set<Address> actual=new TreeSet<>();
            for(Reference r:site.getReferencesFrom()) if(r.getReferenceType().isComputed()) actual.add(r.getToAddress());
            check(actual.equals(new TreeSet<>(List.of(at(p,0x200),at(p,0x220)))),"observed union only; guessed target removed");
            check(p.getFunctionManager().getFunctionAt(at(p,0x40)).getBody().contains(at(p,0x200)),"observed target joins function");
            check(p.getFunctionManager().getFunctionAt(at(p,0x40)).getBody().contains(at(p,0x260)),"detached executed body retained until boundary repair");
            WSDecodeRepair.boundaries(p,l->{},monitor);
            check(p.getFunctionManager().getFunctionAt(at(p,0x260))!=null,"boundary repair preserves detached executed component as function");
            String property=p.getUsrPropertyManager().getStringPropertyMap(WSObservedSwitches.PROPERTY).getString(at(p,0x40));
            WSJumpTables.lockSwitches(p,List.of(),l->{},monitor);
            check(property.equals(p.getUsrPropertyManager().getStringPropertyMap(WSObservedSwitches.PROPERTY).getString(at(p,0x40))),"repeat observation stable");
            for(int off:new int[]{0x60,0x80}) {
                Instruction i=p.getListing().getInstructionAt(at(p,off));
                check(Arrays.stream(i.getReferencesFrom()).noneMatch(r->r.getReferenceType()==RefType.COMPUTED_JUMP),"CALL/INT observations are not misrepresented as ordinary jump tables");
            }
            site.addMnemonicReference(at(p,0x240),RefType.COMPUTED_JUMP,SourceType.USER_DEFINED);
            WSJumpTables.lockSwitches(p,List.of(),l->{},monitor);
            check(Arrays.stream(site.getReferencesFrom()).anyMatch(r->r.getToAddress().equals(at(p,0x240))&&r.getSource()==SourceType.USER_DEFINED),"explicit computed flow kept");
        } finally { release(p); }
    }
    void fillEntry() throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xff);
        ProgramDB p=program("undecoded-fill-entry",bytes);
        try {
            p.getFunctionManager().createFunction(null,at(p,0x100),new AddressSet(at(p,0x100)),SourceType.DEFAULT);
            WSFillRuns.apply(p,null,l->{},monitor);
            check(p.getFunctionManager().getFunctionAt(at(p,0x100))==null,"automatic entry deep in undecoded FF fill removed");
            check(p.getMemory().getByte(at(p,0x100))==(byte)0xff,"fill bytes kept");
        } finally { release(p); }
    }
    void bankTail() throws Exception {
        byte[] bytes=new byte[0x10000];Arrays.fill(bytes,(byte)0xcc);put(bytes,0x40,"b0ffe6c2ea00010020");put(bytes,0x100,"b80300cb");
        put(bytes,0x10,"c606002001e92800");
        ProgramDB p=program("constant-bank-tail",bytes);
        try {
            Address base=((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x2000,0);
            byte[] bank=new byte[0x200];Arrays.fill(bank,(byte)0xcc);put(bank,0x100,"b80300cb");
            var mapped=p.getMemory().createInitializedBlock("ROM0_BANK_00FF",base,new ByteArrayInputStream(bank),bank.length,monitor,true);
            Address target=mapped.getStart().add(0x100);mapped.setPermissions(true,false,true);
            p.getProgramContext().setValue(p.getRegister("csval"),mapped.getStart(),mapped.getEnd(),BigInteger.valueOf(0x2000));
            new DisassembleCommand(target,null,true).applyTo(p,monitor);new CreateFunctionCmd(target).applyTo(p,monitor);
            new DisassembleCommand(at(p,0x40),null,true).applyTo(p,monitor);new CreateFunctionCmd(at(p,0x40)).applyTo(p,monitor);
            new DisassembleCommand(at(p,0x10),null,true).applyTo(p,monitor);
            p.getFunctionManager().createFunction(null,at(p,0x10),new AddressSet(at(p,0x10),at(p,0x17)),SourceType.DEFAULT);
            Instruction referring=p.getListing().getInstructionAt(at(p,0x15));
            referring.setFlowOverride(FlowOverride.CALL_RETURN);
            WSBankTransfers.apply(p,l->{},monitor);
            Instruction jump=p.getListing().getInstructionAt(at(p,0x44));
            check(jump.getFlowOverride()==FlowOverride.CALL_RETURN,"constant-bank jump becomes tail transfer");
            check(Arrays.stream(jump.getReferencesFrom()).anyMatch(r->r.isPrimary()&&r.getToAddress().equals(target)&&r.getReferenceType()==RefType.CALL_OVERRIDE_UNCONDITIONAL),"tail points to proved decoded bank view");
            check(Arrays.stream(p.getBookmarkManager().getBookmarks(jump.getAddress())).anyMatch(b->b.getCategory().equals(WSBankTransfers.CATEGORY)),"bank tail evidence persists in program");
            new WSMerge(p,Set.of(),l->{},monitor).apply();
            check(jump.getFlowOverride()==FlowOverride.CALL_RETURN&&p.getFunctionManager().getFunctionAt(target)!=null,"merge replay preserves proved bank tail and target");
            check(p.getFunctionManager().getFunctionAt(at(p,0x40))!=null,"M1 preserves a same-space target containing a proved bank tail");
            check(referring.getFlowOverride()==FlowOverride.CALL_RETURN,"M1 preserves its referring jump when the target contains rule evidence");
            var d=new ghidra.app.decompiler.DecompInterface();d.openProgram(p);
            var c=d.decompileFunction(p.getFunctionManager().getFunctionAt(at(p,0x40)),30,monitor);
            check(c.decompileCompleted(),"cross-bank tail decompiles: "+c.getErrorMessage());
            check(!c.getDecompiledFunction().getC().contains("halt_baddata"),"cross-bank tail has no bad-data halt");d.dispose();
            check(WSBankTransfers.apply(p,l->{},monitor).endsWith(" 0"),"tail transfer repeat is unchanged");
        } finally { release(p); }
    }
    void referringTail(boolean evidenced) throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"c606002003e9b800");put(bytes,0x100,"b80100c3");
        ProgramDB p=program(evidenced?"rule-tail-veto":"stock-tail-merge",bytes);
        try {
            for(int off:new int[]{0x40,0x100})new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
            p.getFunctionManager().createFunction(null,at(p,0x40),new AddressSet(at(p,0x40),at(p,0x47)),SourceType.DEFAULT);
            new CreateFunctionCmd(at(p,0x100)).applyTo(p,monitor);
            Instruction jump=p.getListing().getInstructionAt(at(p,0x45));
            if(evidenced) {
                p.getUsrPropertyManager().createIntPropertyMap(WSRomEvidence.STARTS).add(at(p,0x100),3);
                WSDecodeRepair.decompilerBoundaries(p,List.of(),l->{},monitor);
            } else jump.setFlowOverride(FlowOverride.CALL_RETURN);
            new WSMerge(p,Set.of(),l->{},monitor).apply();
            check((p.getFunctionManager().getFunctionAt(at(p,0x100))!=null)==evidenced,"recorded A3 tail vetoes M1; stock tail still merges");
            check(jump.getFlowOverride()==(evidenced?FlowOverride.CALL_RETURN:FlowOverride.NONE),"M1 preserves recorded referring override only");
            byte[] after=new byte[bytes.length];p.getMemory().getBytes(at(p,0),after);
            check(Arrays.equals(bytes,after),"merge veto keeps instruction bytes");
        } finally { release(p); }
    }
    void observedFallThrough(boolean observation) throws Exception {
        byte[] bytes=new byte[0x400];Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"e8bd00c3");put(bytes,0x50,"ffe0");put(bytes,0x100,"c3");put(bytes,0x200,"c3");
        ProgramDB p=program(observation?"observed-fallthrough-veto":"stored-switch-fallthrough-veto",bytes);
        try {
            for(int off:new int[]{0x40,0x50,0x100,0x200})new DisassembleCommand(at(p,off),null,true).applyTo(p,monitor);
            p.getFunctionManager().createFunction(null,at(p,0x40),new AddressSet(at(p,0x40),at(p,0x42)),SourceType.DEFAULT);
            AddressSet body=new AddressSet(at(p,0x43));body.add(at(p,0x50),at(p,0x51));
            Function continuation=p.getFunctionManager().createFunction(null,at(p,0x43),body,SourceType.DEFAULT);
            new CreateFunctionCmd(at(p,0x100)).applyTo(p,monitor);
            if(observation)WSObservedSwitches.remember(p,at(p,0x50),List.of(at(p,0x200)));
            new ghidra.program.model.pcode.JumpTable(at(p,0x50),new ArrayList<>(List.of(at(p,0x200))),true,0).writeOverride(continuation);
            new WSMerge(p,Set.of(),l->{},monitor).apply();
            check(p.getFunctionManager().getFunctionAt(at(p,0x43))!=null,"T1 preserves the function owning a recorded switch, observation="+observation);
            check(continuation.getBody().contains(at(p,0x50)),"T1 preserves recorded switch body membership");
            boolean kept=false;
            for(Symbol symbol:p.getSymbolTable().getSymbols(at(p,0x50)))
                if(symbol.getName().equals("switch")&&symbol.getParentNamespace().getName().startsWith("jmp_")
                    &&ghidra.program.model.pcode.JumpTable.readOverride(symbol.getParentNamespace(),p.getSymbolTable())!=null)kept=true;
            check(kept,"T1 preserves serialized switch override without requiring a tail flow override");
        } finally { release(p); }
    }
    public void run() throws Exception {
        returns("neutral-callers","f9c3","CF:1",true,false,"7201c3c3","7301c3c3","c3","c3","c3");
        returns("sole-caller","b103c3","CL:1",true,false,"88cac3");
        returns("one-of-many","b103c3","CL:1",false,false,"88cac3","c3");
        returns("redefined-result","b103c3","CL:1",false,false,"b10588cac3","b10788cac3");
        returns("entry-value-contradiction","7403b103c3c3","CL:1",false,false,"88cac3","88cac3");
        returns("saved-register","51b10359c3","CL:1",false,false,"88cac3","88cac3");
        returns("variable-count-flag","d3e0c3","CF:1",false,false,"7201c3c3","7301c3c3");
        returns("separate-byte-halves","b103c3","CX:2",false,false,"89cac3","89cac3");
        returns("explicit-signature","f9c3","DX:2",true,true,"7201c3c3","7301c3c3");
        returns("shared-predecessor-diamonds", "b003" + "85db740390eb0190".repeat(30) + "c3",
            "AL:1", true, false, "88c2c3");
        returns("cyclic-source", "b00385db75fcc3", "AL:1", false, false, "88c2c3");
        transitiveInputs();boundaryReplay();finishedBoundaries();observed();fillEntry();bankTail();
        referringTail(true);referringTail(false);observedFallThrough(true);observedFallThrough(false);println("WSDecompFixFixtures: PASS checks="+checks);
    }
}
