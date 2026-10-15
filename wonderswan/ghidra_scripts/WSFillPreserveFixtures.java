// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import jidoughost.wonderswan.*;

/** Controlled executable homogeneous-run and stale-property regressions; no natural occurrence claimed. */
public class WSFillPreserveFixtures extends GhidraScript {
    protected final Gson gson = new Gson();
    final List<Map<String,Object>> items = new ArrayList<>();
    int checks, failures;
    void check(boolean pass, String reason) { checks++; if (!pass) { failures++; printerr("FAIL: " + reason); } }
    Address base(long offset) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset); }
    void decode(Address at) throws Exception {
        var i = new ghidra.app.util.PseudoDisassembler(currentProgram).disassemble(at);
        if (i != null) currentProgram.getListing().createInstruction(at, i.getPrototype(), i, i.getProcessorContext(), 0);
    }
    List<String> bookmarks() {
        List<String> result = new ArrayList<>();
        currentProgram.getBookmarkManager().getBookmarksIterator().forEachRemaining(b ->
            result.add(b.getAddress()+"|"+b.getTypeString()+"|"+b.getCategory()+"|"+b.getComment()));
        Collections.sort(result); return result;
    }
    /** Complete core state excludes only the additive hypothesis diagnostics and RAM classification tags. */
    protected Map<String,Object> state() throws Exception {
        Program p = currentProgram; Map<String,Object> r = new LinkedHashMap<>();
        List<String> memory = new ArrayList<>(), instructions = new ArrayList<>(), functions = new ArrayList<>(),
            symbols = new ArrayList<>(), refs = new ArrayList<>(), context = new ArrayList<>(), data = new ArrayList<>();
        for (var b : p.getMemory().getBlocks()) {
            String bytes = "uninitialized";
            if (b.isInitialized()) { byte[] raw = new byte[(int)b.getSize()]; p.getMemory().getBytes(b.getStart(),raw); bytes=HexFormat.of().formatHex(raw); }
            memory.add(b.getName()+"|"+b.getStart()+"|"+b.getSize()+"|"+b.getFlags()+"|"+b.getComment()+"|"+bytes);
            for (var reg : p.getProgramContext().getRegisters()) {
                var it = p.getProgramContext().getRegisterValueAddressRanges(reg,b.getStart(),b.getEnd());
                while(it.hasNext()) { var q=it.next();context.add(reg.getName()+"|"+q+"|"+p.getProgramContext().getRegisterValue(reg,q.getMinAddress())); }
            }
        }
        for(var i:p.getListing().getInstructions(true)) instructions.add(i.getAddress()+"|"+HexFormat.of().formatHex(i.getBytes())+"|"+i+"|"+i.getFlowOverride()+"|"+i.getFallThrough()+"|"+i.isFallThroughOverridden()+"|"+i.getComment(CodeUnit.EOL_COMMENT)+"|"+i.getComment(CodeUnit.PRE_COMMENT));
        for(var d:p.getListing().getDefinedData(true))data.add(d.getAddress()+"|"+d.getLength()+"|"+d.getDataType().getPathName()+"|"+d.getComment(CodeUnit.EOL_COMMENT));
        for(var f:p.getFunctionManager().getFunctions(true)) functions.add(f.getEntryPoint()+"|"+f.getName(true)+"|"+f.getBody()+"|"+f.getSymbol().getSource()+"|"+f.getSignatureSource()+"|"+f.getPrototypeString(true,true)+"|"+f.getComment()+"|"+f.hasNoReturn()+"|"+f.getTags().stream().map(t->t.getName()).filter(t->!t.equals(WSRamCode.UNKNOWN)).sorted().toList()+"|"+(f.isThunk()?f.getThunkedFunction(false).getEntryPoint():null));
        var sy=p.getSymbolTable().getAllSymbols(true);while(sy.hasNext()){var s=sy.next();symbols.add(s.getAddress()+"|"+s.getName(true)+"|"+s.getSource()+"|"+s.getSymbolType()+"|"+s.isPrimary());}
        var ri=p.getReferenceManager().getReferenceSourceIterator(p.getMemory(),true);while(ri.hasNext())for(var x:p.getReferenceManager().getReferencesFrom(ri.next()))refs.add(x.getFromAddress()+"|"+x.getToAddress()+"|"+x.getReferenceType()+"|"+x.getSource()+"|"+x.getOperandIndex()+"|"+x.isPrimary());
        for(var list:List.of(memory,instructions,functions,symbols,refs,context,data))Collections.sort(list);
        List<String> properties=new ArrayList<>();var names=p.getUsrPropertyManager().propertyManagers();while(names.hasNext()){String name=names.next();var map=p.getUsrPropertyManager().getPropertyMap(name);properties.add(name+"|"+map.getValueClass());for(var it=map.getPropertyIterator();it.hasNext();){Address at=it.next();properties.add(name+"|"+at+"|"+gson.toJson(map.get(at)));}}Collections.sort(properties);r.put("properties",properties);
        r.put("memory",memory);r.put("instructions",instructions);r.put("functions",functions);r.put("symbols",symbols);r.put("references",refs);r.put("context",context);r.put("data",data);return r;
    }
    void runCase(String id, long offset, int value, int length, SourceType source, String flow, boolean overlay, boolean played, boolean legacy) throws Exception {
        byte[] bytes=new byte[1024];Arrays.fill(bytes,(byte)0xcc);Arrays.fill(bytes,0x100,0x100+length,(byte)value);bytes[0x100+length]=(byte)0xc3;
        bytes[0xf0]=(byte)0xeb;bytes[0xf1]=14;bytes[0xff]=(byte)(value==0x90?0x40:0x90);
        if(flow.equals("computed")){bytes[0xf0]=(byte)0xff;bytes[0xf1]=(byte)0xe3;}
        if(flow.equals("partial-start")){bytes[0xfe]=(byte)0xb8;bytes[0xff]=1;}
        var fb=currentProgram.getMemory().createFileBytes(id,0,bytes.length,new ByteArrayInputStream(bytes),monitor);
        var block=currentProgram.getMemory().createInitializedBlock(id,base(offset),fb,0,bytes.length,overlay);block.setPermissions(true,false,true);Address a=block.getStart();
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("csval"),a,block.getEnd(),BigInteger.valueOf(offset>>4));
        for(int n=0x100;n<0x100+length;) {decode(a.add(n));var i=getInstructionAt(a.add(n));if(i==null)break;n+=i.getLength();}
        if(flow.equals("partial-start")) {currentProgram.getListing().clearCodeUnits(a.add(0x100),a.add(0x101),false);decode(a.add(0xfe));}
        if(!flow.equals("none")) {decode(a.add(0xf0));if(!flow.equals("partial-start"))decode(a.add(0xff));}
        if(flow.equals("computed"))currentProgram.getReferenceManager().addMemoryReference(a.add(0xf0),a.add(0x100),RefType.COMPUTED_JUMP,SourceType.ANALYSIS,-1);
        if(flow.equals("user-ref"))currentProgram.getReferenceManager().addMemoryReference(a.add(0xf0),a.add(0x101),RefType.DATA,SourceType.USER_DEFINED,0);
        if(flow.equals("override")){getInstructionAt(a.add(0xf0)).setFlowOverride(FlowOverride.CALL_RETURN);getInstructionAt(a.add(0xff)).setFallThrough(a.add(0x100+length));}
        Address entry=a.add(flow.equals("body-split")?0xf0:0x100);AddressSet body=new AddressSet(a.add(0x100),a.add(0x100+length-1));if(flow.equals("body-split"))body.add(a.add(0xf0),a.add(0xf1));
        var f=currentProgram.getFunctionManager().createFunction("kept_"+id,entry,body,source);f.addTag("original fixture tag");
        f.setComment("original function comment");
        if(source==SourceType.USER_DEFINED||source==SourceType.IMPORTED)f.setReturnType(WordDataType.dataType,source);

        if(flow.equals("thunk")){var t=currentProgram.getFunctionManager().createFunction("thunk_"+id,a.add(0xf0),new AddressSet(a.add(0xf0),a.add(0xf1)),SourceType.ANALYSIS);t.setThunkedFunction(f);}
        currentProgram.getBookmarkManager().setBookmark(a.add(0x100),BookmarkType.ERROR,"Bad Instruction","original diagnostic retained");
        currentProgram.getBookmarkManager().setBookmark(a.add(0x100),BookmarkType.ANALYSIS,WSFillRuns.CATEGORY,"original category collision");
        if(getInstructionAt(a.add(0x100))!=null)getInstructionAt(a.add(0x100)).setComment(CodeUnit.EOL_COMMENT,"original instruction comment");
        WSEvidence ev=new WSEvidence();ev.provenance="controlled empty reference trace";
        if(played) {ev.cs.put(a.add(0x100).getOffset(),(int)(offset>>4));if(overlay)ev.windowBanks.put(a.add(0x100).getOffset(),Set.of(0x32));}
        if(legacy){var m=currentProgram.getUsrPropertyManager().getIntPropertyMap(WSFillRuns.PROPERTY);if(m==null)m=currentProgram.getUsrPropertyManager().createIntPropertyMap(WSFillRuns.PROPERTY);m.add(a.add(0x100),length);var e=currentProgram.getUsrPropertyManager().getIntPropertyMap(WSFillRuns.EDGES);if(e==null)e=currentProgram.getUsrPropertyManager().createIntPropertyMap(WSFillRuns.EDGES);e.add(a.add(0xf0),2);e.add(a.add(0xff),1);}
        Map<String,Object> row=new LinkedHashMap<>();row.put("id",id);row.put("address",a.toString());row.put("before",state());row.put("bookmarks_before",bookmarks());List<String> events=new ArrayList<>();
        row.put("restored",WSFillRuns.restoreExecuted(currentProgram,ev,events::add));row.put("summary",WSFillRuns.apply(currentProgram,ev,events::add,monitor));row.put("after",state());var first=bookmarks();
        WSFillRuns.restoreExecuted(currentProgram,ev,events::add);WSFillRuns.apply(currentProgram,ev,events::add,monitor);row.put("repeat",state());row.put("bookmarks_after",first);row.put("bookmarks_repeat",bookmarks());row.put("events",events);
        boolean kept=row.get("before").equals(row.get("after"))&&row.get("after").equals(row.get("repeat"));row.put("core_preserved",kept);check(kept,id+" core state preserved");check(first.equals(bookmarks()),id+" tags idempotent");check(first.containsAll((List<?>)row.get("bookmarks_before")),id+" old diagnostics retained");items.add(row);
    }
    void legacyArray() throws Exception {
        Address a=base(0xe0000);var b=currentProgram.getMemory().createInitializedBlock("legacy-array",a,new ByteArrayInputStream(new byte[128]),128,monitor,false);b.setExecute(true);
        currentProgram.getListing().createData(a,new ArrayDataType(ByteDataType.dataType,64,1));currentProgram.getUsrPropertyManager().getIntPropertyMap(WSFillRuns.PROPERTY).add(a,64);
        currentProgram.getListing().getDataAt(a).setComment(CodeUnit.EOL_COMMENT,"user edited old array; ownership unknown");WSEvidence ev=new WSEvidence();ev.cs.put(a.getOffset(),0xe000);ev.provenance="controlled later observation";
        var before=state();List<String>events=new ArrayList<>();int restored=WSFillRuns.restoreExecuted(currentProgram,ev,events::add);check(before.equals(state()),"ambiguous old array retained");check(restored==0,"no guessed legacy restoration");check(events.stream().anyMatch(s->s.contains("LEGACY_STATE_PRESERVED_OPEN")),"legacy ambiguity explicit");items.add(new LinkedHashMap<>(Map.of("id","legacy-array","core_preserved",before.equals(state()),"events",events)));
    }
    public void run() throws Exception {
        currentProgram.getUsrPropertyManager().createIntPropertyMap("fixture_user_int").add(base(0x80000),17);
        currentProgram.getUsrPropertyManager().createStringPropertyMap("fixture_user_text").add(base(0x80000),"original user property");
        long off=0x50000;
        for(int value:new int[]{0,255,0x90,0x11}) {int threshold=value==0||value==255?64:256;for(int length:new int[]{threshold-1,threshold,threshold+1}){runCase("threshold_"+value+"_"+length,off,value,length,SourceType.ANALYSIS,"none",false,false,false);off+=0x1000;}}
        for(String flow:new String[]{"direct","computed","fallthrough","override","thunk","body-split","partial-start","user-ref"}){runCase(flow,off,0,66,SourceType.ANALYSIS,flow,false,false,false);off+=0x1000;}
        for(SourceType source:new SourceType[]{SourceType.USER_DEFINED,SourceType.IMPORTED}){runCase("owned_"+source,off,0,64,source,"direct",false,false,false);off+=0x1000;}
        runCase("observed",off,0,64,SourceType.ANALYSIS,"direct",false,true,false);off+=0x1000;
        runCase(WSRomWindows.name(0x2000,0x31),0x20000,0,64,SourceType.ANALYSIS,"direct",true,true,false);
        runCase(WSRomWindows.name(0x2000,0x32),0x20000,0,64,SourceType.ANALYSIS,"direct",true,true,false);
        runCase("RAMCODE_snapshot",0x30000,0,64,SourceType.ANALYSIS,"none",true,false,false);
        runCase("ram",0x1000,0,64,SourceType.ANALYSIS,"none",false,false,false);
        runCase("sram",0x10000,0,64,SourceType.ANALYSIS,"none",false,false,false);
        runCase("legacy-fresh-code",off,0,64,SourceType.ANALYSIS,"override",false,true,true);
        var merge=new WSMerge(currentProgram,Set.of(),q->{},monitor);var guard=WSMerge.class.getDeclaredMethod("ruleOverride",Instruction.class);guard.setAccessible(true);boolean legacyGuard=(Boolean)guard.invoke(merge,getInstructionAt(base(off).add(0xf0)));check(legacyGuard,"legacy edge remains recognized by merge consumer");items.get(items.size()-1).put("legacy_merge_guard",legacyGuard);legacyArray();
        Address ua=base(0xd0000);var ub=currentProgram.getMemory().createUninitializedBlock("uninitialized-bank",ua,128,false);ub.setExecute(true);currentProgram.getFunctionManager().createFunction("uninitialized_hypothesis",ua,new AddressSet(ua),SourceType.ANALYSIS);
        var all=state();var bm=bookmarks();WSFillRuns.apply(currentProgram,new WSEvidence(),s->{},monitor);check(all.equals(state()),"whole program repeat preserves core");
        WSEvidence same=new WSEvidence();same.provenance="collision source";WSFillRuns.apply(currentProgram,same,q->{},monitor);
        var manager=currentProgram.getBookmarkManager();Bookmark own=null;
        for(var it=manager.getBookmarksIterator();it.hasNext();) {var b=it.next();if(b.getCategory().startsWith("WSZ1Hypothesis:")&&b.getComment().contains("collision source")){own=b;break;}}
        check(own!=null,"durable hypothesis exists");
        if(own!=null) {
            manager.setBookmark(own.getAddress(),BookmarkType.ANALYSIS,own.getCategory(),"user-owned collision");
            var collision=bookmarks();WSFillRuns.apply(currentProgram,same,q->{},monitor);var suffixed=bookmarks();check(suffixed.containsAll(collision)&&suffixed.size()>collision.size(),"same-source collision appends a suffix");WSFillRuns.apply(currentProgram,same,q->{},monitor);check(suffixed.equals(bookmarks()),"same-source collision idempotent");WSEvidence changed=new WSEvidence();changed.provenance="changed controlled source";
            WSFillRuns.apply(currentProgram,changed,q->{},monitor);var appended=bookmarks();check(appended.containsAll(collision),"edited collision survives");check(appended.size()>collision.size(),"changed source appends provenance");WSFillRuns.apply(currentProgram,changed,q->{},monitor);check(appended.equals(bookmarks()),"changed-source tags idempotent");
        }
        Map<String,Object> root=new LinkedHashMap<>();root.put("synthetic",true);root.put("fixture_source",getSourceFile().getAbsolutePath());root.put("compiled_class",WSFillRuns.class.getProtectionDomain().getCodeSource().getLocation().toString());root.put("items",items);root.put("assertions",checks);root.put("failures",failures);root.put("persisted",state());root.put("persisted_bookmarks",bookmarks());
        if(getScriptArgs().length>0)Files.writeString(Path.of(getScriptArgs()[0]),gson.toJson(root));println("WSFillPreserveFixtures: checks="+checks+" failures="+failures);if(failures!=0)throw new AssertionError("homogeneous preservation failures="+failures);
    }
}
