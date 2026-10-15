// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import jidoughost.wonderswan.*;

/** Controlled fixtures; synthesized diagnostics are labelled separately from actual disassembly errors. */
public class WSDecodeHypothesisFixtures extends GhidraScript {
    List<Map<String,Object>> items = new ArrayList<>();
    String mode;
    String reportPath;
    int sequence;

    Map<String,Object> core(Address start, int length) throws Exception {
        Map<String,Object> result = new LinkedHashMap<>();
        AddressSet range = new AddressSet(start, start.add(length - 1));
        byte[] bytes = new byte[length];
        currentProgram.getMemory().getBytes(start, bytes);
        result.put("memory", HexFormat.of().formatHex(bytes));
        List<Object> instructions = new ArrayList<>();
        for (Instruction i : currentProgram.getListing().getInstructions(range, true)) {
            List<Object> row = new ArrayList<>();
            row.add(i.getAddress().toString()); row.add(HexFormat.of().formatHex(i.getBytes()));
            row.add(i.toString()); row.add(i.getFlowOverride().toString());
            row.add(String.valueOf(i.getFallThrough()));
            for (int type = 0; type <= 4; type++) row.add(i.getComment(type));
            instructions.add(row);
        }
        result.put("instructions", instructions);
        List<Object> functions = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!f.getBody().intersects(range)) continue;
            Map<String,Object> row = new LinkedHashMap<>();
            row.put("entry", f.getEntryPoint().toString()); row.put("name", f.getName());
            row.put("body", f.getBody().toString()); row.put("source", f.getSymbol().getSource().toString());
            row.put("signature", f.getSignature().toString()); row.put("signature_source", f.getSignatureSource().toString());
            row.put("comment", f.getComment()); row.put("repeatable", f.getRepeatableComment());
            row.put("convention", f.getCallingConventionName()); row.put("no_return", f.hasNoReturn());
            row.put("custom_storage", f.hasCustomVariableStorage());
            row.put("parameters", Arrays.stream(f.getParameters()).map(v -> v.toString() + "|" + v.getSource()).toList());
            row.put("locals", Arrays.stream(f.getLocalVariables()).map(v -> v.toString() + "|" + v.getSource()).toList());
            functions.add(row);
        }
        result.put("functions", functions);
        List<String> symbols = new ArrayList<>(), refs = new ArrayList<>();
        for (int k = 0; k < length; k++) {
            Address at = start.add(k);
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(at))
                symbols.add(at + "|" + s.getName(true) + "|" + s.getSymbolType() + "|" + s.getSource() + "|" + s.isPrimary());
            for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(at)) refs.add("from|" + r + "|" + r.getSource() + "|" + r.isPrimary());
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(at)) refs.add("to|" + r + "|" + r.getSource() + "|" + r.isPrimary());
        }
        Collections.sort(symbols); Collections.sort(refs);
        result.put("symbols", symbols); result.put("references", refs);
        return result;
    }

    List<String> bookmarks(Address start, int length) {
        List<String> result = new ArrayList<>();
        for (int k = 0; k < length; k++) for (Bookmark b : currentProgram.getBookmarkManager().getBookmarks(start.add(k)))
            result.add(b.getAddress() + "|" + b.getTypeString() + "|" + b.getCategory() + "|" + b.getComment());
        Collections.sort(result);
        return result;
    }

    Map<String,Object> state(Address start, int length) throws Exception {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("core", core(start, length)); result.put("bookmarks", bookmarks(start, length));
        return result;
    }

    void classify(WSEvidence evidence, Set<Address> kept) throws Exception {
        Class<?> c = Class.forName("jidoughost.wonderswan.WSEvidenceAnalyzer$Seeder");
        Constructor<?> constructor = c.getDeclaredConstructor(Program.class, WSEvidence.class, String.class,
            boolean.class, TaskMonitor.class, MessageLog.class);
        constructor.setAccessible(true);
        try (AutoCloseable seeder = (AutoCloseable) constructor.newInstance(currentProgram, evidence,
                reportPath, true, monitor, new MessageLog())) {
            Method method = c.getDeclaredMethod("classifyArtefacts", Set.class);
            method.setAccessible(true); method.invoke(seeder, kept);
            Method summary = c.getDeclaredMethod("summary"); summary.setAccessible(true);
            println("A1_FIXTURE_SUMMARY " + summary.invoke(seeder));
        }
    }

    Address block(String name, long offset, boolean overlay, byte[] prefix) throws Exception {
        byte[] data = new byte[64]; Arrays.fill(data, (byte) 0xc3);
        System.arraycopy(prefix, 0, data, 0, prefix.length);
        var block = currentProgram.getMemory().createInitializedBlock(name, toAddr(offset),
            new ByteArrayInputStream(data), data.length, monitor, overlay);
        block.setExecute(true);
        Address a = block.getStart();
        currentProgram.getProgramContext().setValue(currentProgram.getProgramContext().getRegister("csval"),
            a, a.add(63), BigInteger.valueOf(offset >> 4));
        return a;
    }

    void item(String id, long offset, boolean overlay, SourceType source, byte[] prefix,
            int errorOffset, String category, int observed, int keptIndex, boolean normal) throws Exception {
        if (id.equals("user")) prefix = new byte[]{(byte)0x90,(byte)0x90,(byte)0xc3,(byte)0xc3,(byte)0x90,(byte)0xc3};
        Address a = block(id, offset, overlay, prefix);
        disassemble(a);
        if (id.equals("branch_boundary")) disassemble(a.add(2));
        int bodyEnd = id.equals("offcut_error") ? 3 : id.equals("natural_error") ? 1 : 2;
        Function f = currentProgram.getFunctionManager().createFunction("fixture_" + sequence++, a,
            new AddressSet(a, a.add(bodyEnd)), source);
        if (id.equals("user")) {
            disassemble(a.add(4)); AddressSet body = new AddressSet(f.getBody()); body.add(a.add(4), a.add(5)); f.setBody(body);
        }
        boolean overlapRefused = false;
        if (source != SourceType.ANALYSIS) {
            f.setReturnType(WordDataType.dataType, source);
            f.addParameter(new ParameterImpl("kept_argument", WordDataType.dataType, 4, currentProgram, source), source);
            f.addLocalVariable(new LocalVariableImpl("kept_local", WordDataType.dataType, -2, currentProgram, source), source);
            f.setComment("original function comment"); f.setRepeatableComment("original repeatable function comment");
        }
        for (int type = 0; type <= 4; type++) currentProgram.getListing().setComment(a, type, "original comment " + type);
        var bm = currentProgram.getBookmarkManager();
        bm.setBookmark(a, BookmarkType.ANALYSIS, "WSEvidence", "original evidence, must remain");
        if (id.equals("ram_owned_bookmark")) bm.setBookmark(a, BookmarkType.ANALYSIS, "ram-code", "user RAM evidence, must remain");
        if (errorOffset == -2 && bm.getBookmark(a.add(2), BookmarkType.ERROR, "Bad Instruction") == null)
            throw new AssertionError("Expected actual controlled decode error");
        if (errorOffset >= 0) bm.setBookmark(a.add(errorOffset), BookmarkType.ERROR, category,
            "CONTROLLED synthesized diagnostic " + id + " \"quote\"\\slash\nline");
        if (id.equals("incoming") || id.equals("offcut_error")) {
            currentProgram.getReferenceManager().addMemoryReference(a.add(32), a.add(1), RefType.DATA, SourceType.IMPORTED, 0);
            currentProgram.getSymbolTable().createLabel(a.add(1), "owned_label_" + sequence, SourceType.USER_DEFINED);
        }
        if (id.equals("disjoint_functions")) {
            try {
                currentProgram.getFunctionManager().createFunction("overlapping", a.add(1), new AddressSet(a.add(1), a.add(2)), SourceType.ANALYSIS);
                throw new AssertionError("Expected overlapping-function creation refusal");
            } catch (OverlappingFunctionException expected) { overlapRefused = true; }
            f.setBody(new AddressSet(a, a));
            currentProgram.getFunctionManager().createFunction("second_" + sequence, a.add(1), new AddressSet(a.add(1), a.add(2)), SourceType.IMPORTED);
        }
        WSEvidence evidence = new WSEvidence(); evidence.provenance = "controlled empty evidence";
        if (observed >= 0) evidence.cs.put(a.add(observed).getOffset(), (int)(offset >> 4));
        if (id.equals(WSRomWindows.name(0x2000,0x32))) evidence.windowBanks.put(a.add(observed).getOffset(), Set.of(0x32));
        if (id.equals(WSRomWindows.name(0x2000,0x33))) evidence.windowBanks.put(a.add(observed).getOffset(), Set.of(0x32));
        Set<Address> kept = keptIndex < 0 ? Set.of() : Set.of(a.add(keptIndex));
        Map<String,Object> row = new LinkedHashMap<>(); row.put("id", id); row.put("address", a.toString());
        row.put("length", 64); row.put("overlap_api_refused", overlapRefused); row.put("error_input", errorOffset == -2 ? "ACTUAL controlled disassembly error" : errorOffset < 0 ? "none" : "CONTROLLED synthesized bookmark");
        row.put("caller", normal ? "public repairEvidence" : "compiled Seeder.classifyArtefacts via reflection");
        row.put("before", state(a, 64));
        if (normal) WSEvidenceAnalyzer.repairEvidence(currentProgram, evidence, reportPath, monitor);
        else classify(evidence, kept);
        row.put("after", state(a, 64));
        if (normal) WSEvidenceAnalyzer.repairEvidence(currentProgram, evidence, reportPath, monitor);
        else classify(evidence, kept);
        row.put("repeat", state(a, 64));
        row.put("core_preserved", ((Map<?,?>)row.get("before")).get("core").equals(((Map<?,?>)row.get("after")).get("core")));
        var old = (List<?>)((Map<?,?>)row.get("before")).get("bookmarks");
        row.put("original_bookmarks_preserved", bookmarks(a, 64).containsAll(old));
        row.put("idempotent_new_instance", row.get("after").equals(row.get("repeat")));
        items.add(row);
    }

    void collisionAndChangedError() throws Exception {
        if (!mode.equals("after")) return;
        var bm = currentProgram.getBookmarkManager(); Address a = toAddr(items.get(0).get("address").toString());
        Bookmark own = Arrays.stream(bm.getBookmarks(a)).filter(b -> b.getCategory().startsWith("WSA1Hypothesis:")).findFirst().orElseThrow();
        String category = own.getCategory(); bm.setBookmark(a, BookmarkType.ANALYSIS, category, "user-owned collision value");
        WSEvidence same = new WSEvidence(); same.provenance = "controlled empty evidence";
        List<String> before = bookmarks(a, 64); classify(same, Set.of()); List<String> first = bookmarks(a, 64);
        classify(same, Set.of()); List<String> second = bookmarks(a, 64);
        if (!first.containsAll(before) || !first.equals(second)) throw new AssertionError("category collision changed original bookmark or was not stable");
        bm.setBookmark(a.add(2), BookmarkType.ERROR, "Bad Instruction", "CONTROLLED changed error identity");
        classify(same, Set.of()); List<String> changed = bookmarks(a, 64);
        if (!changed.containsAll(first.stream().filter(x -> !x.contains("|Error|")).toList()) || changed.size() <= first.size())
            throw new AssertionError("changed source did not append provenance");
        classify(same, Set.of());
        if (!changed.equals(bookmarks(a, 64))) throw new AssertionError("changed error not idempotent");
        items.get(0).put("collision_and_changed_error_pass", true);
        // Every item records its final persisted state, including the intentional user diagnostic edit.
    }

    public void run() throws Exception {
        mode = getScriptArgs()[1]; reportPath = Path.of(getScriptArgs()[0]).resolveSibling("decisions.jsonl").toString(); byte[] plain = {(byte)0x90,(byte)0x90,(byte)0xc3};
        if (mode.equals("caller")) item("normal_caller",0x81000,false,SourceType.USER_DEFINED,plain,2,"Bad Instruction",-1,-1,true);
        else {
            item("automatic",0x81000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",-1,-1,false);
            item("natural_error",0x80080,false,SourceType.ANALYSIS,new byte[]{(byte)0x90,(byte)0x90,0x64},-2,"",-1,-1,false);
            item("user",0x82000,false,SourceType.USER_DEFINED,plain,2,"Bad Instruction",-1,-1,false);
            item("imported",0x83000,false,SourceType.IMPORTED,plain,2,"Bad Instruction",-1,-1,false);
            item("incoming",0x84000,false,SourceType.USER_DEFINED,plain,2,"Bad Instruction",-1,-1,false);
            item("disjoint_functions",0x85000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",-1,-1,false);
            item("no_error",0x86000,false,SourceType.ANALYSIS,plain,-1,"",-1,-1,false);
            item("unrelated_error",0x87000,false,SourceType.ANALYSIS,plain,2,"WSEvidence",-1,-1,false);
            item("observed_stop",0x88000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",1,-1,false);
            item("observed_prefix",0x89000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",0,-1,false);
            item("kept_stop",0x8a000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",-1,1,false);
            item("kept_prefix",0x8b000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",-1,0,false);
            item("offcut_error",0x8c000,false,SourceType.IMPORTED,new byte[]{(byte)0xb8,(byte)0x90,(byte)0x90,(byte)0xc3},1,"Bad Instruction",-1,-1,false);
            item("branch_boundary",0x8d000,false,SourceType.ANALYSIS,new byte[]{(byte)0xeb,1,(byte)0x90,(byte)0xc3},3,"Bad Instruction",-1,-1,false);
            item("conditional_fallthrough",0x8e000,false,SourceType.ANALYSIS,new byte[]{0x75,1,(byte)0x90,(byte)0xc3},3,"Bad Instruction",-1,-1,false);
            item("ram",0x1000,false,SourceType.ANALYSIS,plain,2,"Bad Instruction",-1,-1,false);
            item("sram",0x10000,false,SourceType.IMPORTED,plain,2,"Bad Instruction",-1,-1,false);
            item("ram_owned_bookmark",0x2000,false,SourceType.USER_DEFINED,plain,2,"Bad Instruction",-1,-1,false);
            item(WSRomWindows.name(0x2000,0x31),0x20000,true,SourceType.ANALYSIS,plain,2,"Bad Instruction",-1,-1,false);
            // The fixture name is also the memory block's bank-qualified identity.
            items.get(items.size()-1).put("bank_case", "unobserved");
            item(WSRomWindows.name(0x2000,0x32),0x20000,true,SourceType.ANALYSIS,plain,2,"Bad Instruction",1,-1,false);
            item(WSRomWindows.name(0x2000,0x33),0x20000,true,SourceType.ANALYSIS,plain,2,"Bad Instruction",1,-1,false);
            item("bank_unqualified_offset",0x30000,true,SourceType.ANALYSIS,plain,2,"Bad Instruction",0,-1,false);
            collisionAndChangedError();
        }
        for (var row : items) row.put("persisted", state(toAddr(row.get("address").toString()),64));
        Class<?> c=Class.forName("jidoughost.wonderswan.WSEvidenceAnalyzer");
        Map<String,Object> result = new LinkedHashMap<>();result.put("controlled",true);result.put("mode",mode);
        result.put("compiled_class",c.getProtectionDomain().getCodeSource().getLocation().toString());result.put("items",items);
        Files.writeString(Path.of(getScriptArgs()[0]),new Gson().toJson(result));println("A1_ITEMS_WRITTEN "+items.size());
    }
}
