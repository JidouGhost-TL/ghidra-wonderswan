// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.*;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import jidoughost.wonderswan.*;

/** Real database/API regressions for functions whose current bank image is unavailable. */
public class WSUnimagedFunctionFixtures extends WSFillPreserveFixtures {
    final List<Map<String,Object>> cases = new ArrayList<>();
    final Map<String,Address> entries = new LinkedHashMap<>();
    final Set<String> unknown = new LinkedHashSet<>();
    protected Map<String,Object> fullState() throws Exception {
        var result = new LinkedHashMap<String,Object>(state());
        List<String> extra = new ArrayList<>();
        var symbols=currentProgram.getSymbolTable().getAllSymbols(true);
        while(symbols.hasNext()) {
            var symbol=symbols.next();
            if(symbol.getSymbolType()!=SymbolType.FUNCTION || !(symbol.getObject() instanceof Function f))continue;
            extra.add(f.getEntryPoint()+"|all-function|"+f.getBody()+"|"+f.getName(true)+"|"+f.getSymbol().getSource()+"|"+f.getSignatureSource()+"|"+f.getPrototypeString(true,true)+"|"+f.getComment()+"|"+f.getTags().stream().map(t->t.getName()).sorted().toList()+"|"+(f.isThunk()?f.getThunkedFunction(false).getEntryPoint():null));
            extra.add(f.getEntryPoint()+"|id|"+f.getSymbol().getID());
            extra.add(f.getEntryPoint()+"|repeat|"+f.getRepeatableComment()+"|purge|"+f.getStackPurgeSize());
            extra.add(f.getEntryPoint()+"|stack|"+f.getStackFrame().getLocalSize()+"|"+f.getStackFrame().getParameterSize());
            for (var v : f.getAllVariables()) extra.add(f.getEntryPoint()+"|var|"+v.getName()+"|"+v.getDataType()+"|"+v.getVariableStorage()+"|"+v.getSource()+"|"+v.getComment());
        }
        for (var i : currentProgram.getListing().getInstructions(true))
            for (int kind=0;kind<=4;kind++) extra.add(i.getAddress()+"|comment|"+kind+"|"+i.getComment(kind));
        Collections.sort(extra);result.put("extra_metadata",extra);return result;
    }
    void target(String id,long offset,boolean initialized,boolean overlay,SourceType symbol,SourceType signature,boolean expectUnknown,boolean refs) throws Exception {
        var mem=currentProgram.getMemory();
        var b=initialized ? mem.createInitializedBlock(id,base(offset),new ByteArrayInputStream(new byte[128]),128,monitor,overlay)
            : mem.createUninitializedBlock(id,base(offset),128,overlay);
        b.setPermissions(true,false,true);b.setComment("original block metadata");Address a=b.getStart();
        var f=currentProgram.getFunctionManager().createFunction(symbol==SourceType.DEFAULT?null:"kept_"+id,a,new AddressSet(a,a.add(15)),symbol);
        if(signature!=SourceType.DEFAULT)f.setReturnType(WordDataType.dataType,signature);f.setComment("original function comment \"\\\n");f.setRepeatableComment("original repeated comment");f.setStackPurgeSize(6);f.addTag("original user tag");
        var parameter=new ParameterImpl("original_parameter",WordDataType.dataType,4,currentProgram);parameter.setComment("original parameter comment");f.addParameter(parameter,signature);
        var local=new LocalVariableImpl("original_local",WordDataType.dataType,-4,currentProgram);local.setComment("original local comment");f.addLocalVariable(local,signature);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("csval"),a,b.getEnd(),BigInteger.valueOf(offset>>4));
        entries.put(id,a);if(expectUnknown)unknown.add(id);
        if(refs) {
            Address from=base(0xe0000+entries.size()*16);
            int segment=(int)(a.getOffset()>>4)&0xffff;
            currentProgram.getMemory().setBytes(from,new byte[]{(byte)0x9a,0,0,(byte)segment,(byte)(segment>>8),(byte)0xff,(byte)0xe3});
            decode(from);decode(from.add(5));
            check(getInstructionAt(from).getLength()==5&&getInstructionAt(from).getFlowType().isCall(),id+" actual far call instruction");
            check(getInstructionAt(from.add(5)).getFlowType().isComputed(),id+" actual indirect jump instruction");
            for(int kind=0;kind<=4;kind++)getInstructionAt(from).setComment(kind,"original comment kind "+kind);
            currentProgram.getReferenceManager().addMemoryReference(from,a,RefType.UNCONDITIONAL_CALL,SourceType.ANALYSIS,0);
            currentProgram.getReferenceManager().addMemoryReference(from.add(5),a.add(1),RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,-1);
            currentProgram.getReferenceManager().addMemoryReference(from.add(2),a.add(2),RefType.DATA,SourceType.IMPORTED,0);
            currentProgram.getReferenceManager().addMemoryReference(a.add(3),base(0xe0000),RefType.DATA,SourceType.USER_DEFINED,0);
            currentProgram.getProgramContext().setValue(currentProgram.getRegister("DS"),from,from.add(6),BigInteger.valueOf(0x1234));
            currentProgram.getBookmarkManager().setBookmark(from,BookmarkType.WARNING,"WSEvidence","original caller warning");
        }
        currentProgram.getBookmarkManager().setBookmark(a,BookmarkType.ERROR,"Bad Instruction","original error diagnostic");
        cases.add(new LinkedHashMap<>(Map.of("id",id,"entry",a.toString(),"expect_unknown",expectUnknown,"initialized",initialized,"overlay",overlay,"symbol_source",symbol.toString(),"signature_source",signature.toString())));
    }
    String apply(WSEvidence evidence,String report) throws Exception {
        Class<?> c=Class.forName("jidoughost.wonderswan.WSEvidenceAnalyzer$Seeder");
        var constructor=c.getDeclaredConstructor(Program.class,WSEvidence.class,String.class,boolean.class,TaskMonitor.class,MessageLog.class);constructor.setAccessible(true);
        var method=WSEvidenceRepairAnalyzer.class.getDeclaredMethod("removePhantoms",Program.class,c);method.setAccessible(true);
        try(var seeder=(AutoCloseable)constructor.newInstance(currentProgram,evidence,report,false,monitor,new MessageLog())) {
            return (String)method.invoke(null,currentProgram,seeder);
        }
    }
    List<Bookmark> hypotheses() {
        List<Bookmark> result=new ArrayList<>();currentProgram.getBookmarkManager().getBookmarksIterator().forEachRemaining(b->{if(b.getCategory().startsWith("WSP1Hypothesis:"))result.add(b);});return result;
    }
    void addedCaller() throws Exception {
        var p=new ghidra.program.database.ProgramDB("unimaged-normal-caller",currentProgram.getLanguage(),currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()),this);
        int tx=p.startTransaction("controlled normal caller");
        var field=WSEvidenceAnalyzer.class.getDeclaredField("EVIDENCE");field.setAccessible(true);
        @SuppressWarnings("unchecked") Map<Program,WSEvidence> evidence=(Map<Program,WSEvidence>)field.get(null);
        try {
            Address a=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x71000);
            var b=p.getMemory().createUninitializedBlock("normal_caller_bank",a,128,false);b.setExecute(true);
            var f=p.getFunctionManager().createFunction("retained_normal_caller",a,new AddressSet(a),SourceType.USER_DEFINED);f.setReturnType(WordDataType.dataType,SourceType.IMPORTED);f.setComment("original caller function metadata");f.addTag("original caller tag");
            String before=f.getSymbol().getID()+"|"+f.getName()+"|"+f.getBody()+"|"+f.getPrototypeString(true,true)+"|"+f.getComment()+"|"+f.getTags();
            WSEvidence ev=new WSEvidence();ev.provenance="controlled analyzer added caller";evidence.put(p,ev);
            var analyzer=new WSEvidenceRepairAnalyzer();var options=p.getOptions("controlled repair options");analyzer.registerOptions(options,p);
            for(String name:List.of("Recover jump tables (rule J1)","Follow code-pointer variables (rules F1-F4)","Classify unreferenced code after terminators (rules G1/U1)"))options.setBoolean(name,false);
            analyzer.optionsChanged(options,p);MessageLog log=new MessageLog();boolean applied=analyzer.added(p,p.getMemory(),monitor,log);var after=p.getFunctionManager().getFunctionAt(a);
            check(applied&&after!=null,"actual analyzer added caller retains function");
            if(after!=null)check(before.equals(after.getSymbol().getID()+"|"+after.getName()+"|"+after.getBody()+"|"+after.getPrototypeString(true,true)+"|"+after.getComment()+"|"+after.getTags()),"normal added caller retains owned function metadata");
            check(log.toString().contains("P1 unimaged function hypotheses preserved 1"),"normal added caller P1 summary");
            Files.writeString(Path.of("/out/added-caller.log"),log.toString());
        } finally {evidence.remove(p);p.endTransaction(tx,true);p.release(this);}
    }
    public void run() throws Exception {
        String mode=getScriptArgs().length>1?getScriptArgs()[1]:"after";
        if(!Set.of("before","after","reopen").contains(mode))throw new IllegalArgumentException("unknown fixture mode");
        if(mode.equals("reopen")) {
            Map<?,?> old=gson.fromJson(Files.readString(Path.of(getScriptArgs()[2])),Map.class);
            var original=fullState();var tags=bookmarks();boolean core=old.get("persisted").equals(original),sameTags=old.get("persisted_bookmarks").equals(tags);
            WSEvidence ev=new WSEvidence();ev.provenance="changed controlled source";
            String summary=apply(ev,"/out/reopened-direct.jsonl");boolean repeated=original.equals(fullState())&&tags.equals(bookmarks());
            WSEvidenceAnalyzer.repairEvidence(currentProgram,ev,"/out/reopened-caller.jsonl",monitor);boolean caller=original.equals(fullState())&&tags.equals(bookmarks());
            Files.writeString(Path.of(getScriptArgs()[0]),gson.toJson(Map.of("core_equal",core,"bookmarks_equal",sameTags,"new_instance_idempotent",repeated,"public_caller_idempotent",caller,"summary",summary,"persisted",fullState(),"persisted_bookmarks",bookmarks())));
            if(!core||!sameTags||!repeated||!caller)throw new AssertionError("fresh save/reopen preservation");println("UNIMAGED_REOPEN PASS");return;
        }
        byte[] callerBytes=new byte[512];Arrays.fill(callerBytes,(byte)0x90);
        var callers=currentProgram.getMemory().createInitializedBlock("fixture_callers",base(0xe0000),new ByteArrayInputStream(callerBytes),callerBytes.length,monitor,false);callers.setExecute(true);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("csval"),callers.getStart(),callers.getEnd(),BigInteger.valueOf(0xe000));
        long offset=0x51000;
        for(SourceType symbol:new SourceType[]{SourceType.ANALYSIS,SourceType.USER_DEFINED,SourceType.IMPORTED})
            for(SourceType signature:new SourceType[]{SourceType.ANALYSIS,SourceType.USER_DEFINED,SourceType.IMPORTED}) {
                target("source_"+symbol+"_"+signature,offset,false,false,symbol,signature,true,true);offset+=0x1000;
            }
        target("automatic_default",offset,false,false,SourceType.DEFAULT,SourceType.DEFAULT,true,true);offset+=0x1000;
        target("no_references",offset,false,false,SourceType.ANALYSIS,SourceType.ANALYSIS,true,false);offset+=0x1000;
        target("initialized_rom",offset,true,false,SourceType.USER_DEFINED,SourceType.IMPORTED,false,true);offset+=0x1000;
        target(WSRomWindows.name(0x2000,0x31),0x20000,false,true,SourceType.ANALYSIS,SourceType.USER_DEFINED,true,true);
        target(WSRomWindows.name(0x2000,0x32),0x20000,true,true,SourceType.ANALYSIS,SourceType.USER_DEFINED,false,true);
        target("ram",0x1000,false,false,SourceType.USER_DEFINED,SourceType.USER_DEFINED,false,true);
        target("sram",0x10000,false,false,SourceType.IMPORTED,SourceType.IMPORTED,false,true);
        target("RAMCODE_snapshot",0x1000,true,true,SourceType.USER_DEFINED,SourceType.USER_DEFINED,false,true);
        // A thunk in uninitialized memory must keep its relationship and is not a P1 candidate.
        target("thunk",offset,false,false,SourceType.ANALYSIS,SourceType.USER_DEFINED,false,true);offset+=0x1000;
        getFunctionAt(entries.get("thunk")).setThunkedFunction(getFunctionAt(entries.get("initialized_rom")));
        var external=currentProgram.getExternalManager().addExtFunction("fixture_library","external_target",null,SourceType.IMPORTED);
        check(external.getFunction()!=null&&external.getFunction().isExternal(),"supported external function control");
        // Supported function API allows an entry without a block; record the actual outcome.
        String absentOutcome;
        try {
            Address a=base(0xd1000);var f=currentProgram.getFunctionManager().createFunction("kept_absent",a,new AddressSet(a),SourceType.USER_DEFINED);
            entries.put("absent_block",a);unknown.add("absent_block");cases.add(new LinkedHashMap<>(Map.of("id","absent_block","entry",a.toString(),"expect_unknown",true)));absentOutcome="CREATED_SUPPORTED_API";
        } catch(IllegalArgumentException ex) {absentOutcome="OPEN_SUPPORTED_API_REFUSED: "+ex;}
        WSRamCode.classify(currentProgram);
        WSEvidence ev=new WSEvidence();ev.provenance="controlled source with quote \" and newline\n";
        var before=fullState();var diagnostics=bookmarks();String summary=apply(ev,"/out/direct.jsonl");var after=fullState();var first=bookmarks();
        check(before.equals(after),"all core state and metadata retained");check(first.containsAll(diagnostics),"all preexisting diagnostics retained");
        for(var row:cases) {
            String id=(String)row.get("id");Address at=entries.get(id);boolean retained=getFunctionAt(at)!=null;
            long count=hypotheses().stream().filter(b->b.getAddress().equals(at)).count();
            row.put("function_retained",retained);row.put("hypothesis_count",count);check(retained,id+" function retained");check((count>0)==unknown.contains(id),id+" exact candidate classification");
        }
        apply(ev,"/out/repeat.jsonl");check(after.equals(fullState()),"new-instance direct repeat core equality");check(first.equals(bookmarks()),"same source idempotent bookmarks");
        if(mode.equals("after")) {
            var old=hypotheses().getFirst();currentProgram.getBookmarkManager().setBookmark(old.getAddress(),old.getTypeString(),old.getCategory(),"edited same-source collision");
            var collision=bookmarks();apply(ev,"/out/collision.jsonl");var collisionAfter=bookmarks();check(collisionAfter.containsAll(collision)&&collisionAfter.size()>collision.size(),"edited exact category collision appends");apply(ev,"/out/collision-repeat.jsonl");check(collisionAfter.equals(bookmarks()),"collision repeat idempotent");
            ev.provenance="changed controlled source";var sourceBefore=bookmarks();apply(ev,"/out/changed-source.jsonl");check(bookmarks().containsAll(sourceBefore)&&bookmarks().size()>sourceBefore.size(),"changed observation source appends");
            Address ref=base(0xe0010);currentProgram.getProgramContext().setValue(currentProgram.getRegister("DS"),ref,ref,BigInteger.valueOf(0x5678));var contextBefore=bookmarks();apply(ev,"/out/changed-context.jsonl");check(bookmarks().containsAll(contextBefore)&&bookmarks().size()>contextBefore.size(),"changed referring context appends");
            // Public import-repair caller uses the same P1 rule; compare core allowing its documented cold property maps.
            var callerBefore=fullState();var callerDiagnostics=bookmarks();WSEvidenceAnalyzer.repairEvidence(currentProgram,ev,"/out/caller.jsonl",monitor);var callerAfter=fullState();
            boolean caller=true;for(String key:callerBefore.keySet())if(!key.equals("properties"))caller &= callerBefore.get(key).equals(callerAfter.get(key));
            caller &= ((List<?>)callerAfter.get("properties")).containsAll((List<?>)callerBefore.get("properties"));check(caller,"public repairEvidence core preservation");check(bookmarks().containsAll(callerDiagnostics),"public caller diagnostic preservation");
            var callerTags=bookmarks();WSEvidenceAnalyzer.repairEvidence(currentProgram,ev,"/out/caller-repeat.jsonl",monitor);check(callerAfter.equals(fullState())&&callerTags.equals(bookmarks()),"public caller repeat idempotent");
            addedCaller();
            // Late real image availability must preserve the function and old evidence, without a new unknown claim.
            var late=currentProgram.getMemory().getBlock(entries.get("no_references"));var lateBefore=bookmarks();currentProgram.getMemory().convertToInitialized(late,(byte)0x90);var imageState=fullState();apply(ev,"/out/late-image.jsonl");check(imageState.equals(fullState()),"late image core retained");check(lateBefore.equals(bookmarks()),"late image creates no unnecessary unknowns");
        }
        var result=new LinkedHashMap<String,Object>();result.put("synthetic",true);result.put("mode",mode);result.put("compiled_class",WSEvidenceRepairAnalyzer.class.getProtectionDomain().getCodeSource().getLocation().toString());result.put("cases",cases);result.put("absent_block_api",absentOutcome);result.put("before",before);result.put("after",after);result.put("core_equal",before.equals(after));result.put("summary",summary);result.put("assertions",checks);result.put("failures",failures);result.put("persisted",fullState());result.put("persisted_bookmarks",bookmarks());
        Files.writeString(Path.of(getScriptArgs()[0]),gson.toJson(result));println("WSUnimagedFunctionFixtures: checks="+checks+" failures="+failures);
        if(mode.equals("after")&&failures!=0)throw new AssertionError("unimaged function preservation failures="+failures);
        if(mode.equals("before")&&failures==0)throw new AssertionError("old compiled rule did not fail");
    }
}
