// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.*;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** J3: finite inline word dispatch through a proven return-address helper.
 * The injected semantics affect decompilation only; CPU instruction bytes stay intact.
 * Arbitrary stack manipulation and interrupt handlers with other side effects stay unknown. */
public final class WSInlineTables {
    public static final String CATEGORY = "WSInlineTable";
    public static final String CONTINUATION = "WSContinuation";
    private static final String CALL = "POPDI;MOVAH,0;ADDAX,AX;ADDDI,AX;MOVDI,WORDPTRCS:[DI];JMPDI";
    private static final String INT_ES = "PUSHBP;MOVBP,SP;PUSHES;PUSHBX;MOVAH,0;SHLAX,1;LESBX,[BP+2];ADDBX,AX;MOVAX,WORDPTRES:[BX];MOVWORDPTR[BP+2],AX;POPBX;POPES;POPBP;IRET";
    private static final String INT_DS = "ENTER0,0;PUSHDS;PUSHSI;MOVAH,0;SHLAX,1;LDSSI,[BP+2];ADDSI,AX;LODSWSI;MOVWORDPTR[BP+2],AX;POPSI;POPDS;LEAVE;IRET";
    private static final String SAVE_RETURN = "POPAX;MOVWORDPTR[SI],AX;RET";
    private static final String SAVE_CONTINUE = "POPAX;MOVWORDPTR[SI],AX;JMPAX";

    private static String text(Instruction i) {
        return i.toString().toUpperCase(Locale.ROOT).replace(" ", "").replace("0X", "");
    }
    private static boolean shape(Program p, Address entry, String expected) {
        Address a = entry;
        for (String want : expected.split(";")) {
            Instruction i = p.getListing().getInstructionAt(a);
            if (i == null || !text(i).equals(want)) return false;
            a = i.getMaxAddress().next();
        }
        return true;
    }
    private static int cs(Program p, Address a) {
        BigInteger v = p.getProgramContext().getValue(p.getRegister("csval"), a, false);
        return v == null ? (int)(a.getOffset() >>> 4) & 0xf000 : v.intValue() & 0xffff;
    }
    private static Address near(Program p, Address site, int segment, int ip) {
        Address a = ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(segment, ip);
        Address overlay = site.getAddressSpace().getAddress(a.getOffset());
        return p.getMemory().contains(overlay) ? overlay : a;
    }
    public static boolean modeled(Program p, Address site) {
        for (Bookmark b : p.getBookmarkManager().getBookmarks(site))
            if (CATEGORY.equals(b.getCategory())) return true;
        return false;
    }
    public static boolean continuation(Program p, Address site) {
        for (Bookmark b : p.getBookmarkManager().getBookmarks(site))
            if (CONTINUATION.equals(b.getCategory())) return true;
        return false;
    }
    public static List<Address> targets(Program p, Instruction i) {
        if (!modeled(p, i.getAddress())) return List.of();
        List<Address> result = new ArrayList<>();
        for (Reference r : p.getReferenceManager().getReferencesFrom(i.getAddress()))
            if (r.getReferenceType() == RefType.COMPUTED_JUMP) result.add(r.getToAddress());
        return result;
    }
    private static boolean explicit(Function f) {
        return f != null && (f.getSymbol().getSource() == SourceType.USER_DEFINED
            || f.getSymbol().getSource() == SourceType.IMPORTED
            || f.getSignatureSource() == SourceType.USER_DEFINED || f.getSignatureSource() == SourceType.IMPORTED);
    }
    private static boolean played(Program p, Address a) {
        for (String name : List.of(WSRomEvidence.STARTS, WSRomEvidence.CODE)) {
            var map = p.getUsrPropertyManager().getIntPropertyMap(name);
            if (map != null && map.hasProperty(a)) return true;
        }
        return false;
    }
    /** Shared data precedence for a structurally proven word table. Existing data stays. */
    public static boolean words(Program p, Address start, int count) throws Exception {
        if (count <= 0 || WSRamCode.isRam(p, start)) return false;
        Address end = start.add(2L * count - 1);
        for (Address a : new AddressSet(start, end).getAddresses(true)) {
            if (played(p, a) || explicit(p.getFunctionManager().getFunctionContaining(a))) return false;
            for (Reference r : p.getReferenceManager().getReferencesTo(a))
                if (r.getReferenceType().isFlow() && !new AddressSet(start, end).contains(r.getFromAddress())) return false;
        }
        // Speculative fallthrough into inline words is superseded by the proven dispatch.
        for (Instruction i : p.getListing().getInstructions(new AddressSet(start, end), true))
            if (i.getMaxAddress().compareTo(end) > 0 || explicit(p.getFunctionManager().getFunctionContaining(i.getAddress()))) return false;
        for (Function f : p.getFunctionManager().getFunctions(new AddressSet(start, end), true))
            if (new AddressSet(start, end).contains(f.getEntryPoint())) p.getFunctionManager().removeFunction(f.getEntryPoint());
        for (Instruction i : p.getListing().getInstructions(new AddressSet(start, end), true))
            p.getListing().clearCodeUnits(i.getMinAddress(), i.getMaxAddress(), false);
        for (int k = 0; k < count; k++) {
            Address a = start.add(2L * k);
            if (p.getListing().getDefinedDataContaining(a) == null
                    && p.getListing().getDefinedDataContaining(a.add(1)) == null)
                p.getListing().createData(a, WordDataType.dataType);
        }
        return true;
    }
    private static List<Address> table(Program p, Instruction site) throws Exception {
        Address start = site.getDefaultFallThrough();
        if (start == null || WSRamCode.isRam(p, start)) return List.of();
        List<Address> cases = new ArrayList<>();
        long firstForward = Long.MAX_VALUE;
        PseudoDisassembler decoder = new PseudoDisassembler(p);
        for (int k = 0; k < 256; k++) {
            Address slot = start.add(2L * k);
            if (slot.getOffset() == firstForward) return cases.size() >= 2 ? cases : List.of();
            if (slot.getOffset() > firstForward || !p.getMemory().contains(slot.add(1))) break;
            int ip = p.getMemory().getShort(slot) & 0xffff;
            Address target = near(p, site.getAddress(), cs(p, site.getAddress()), ip);
            var block = p.getMemory().getBlock(target);
            if (block == null || !block.isInitialized() || !block.isExecute() || WSRamCode.isRam(p, target)
                    || !target.getAddressSpace().equals(site.getAddress().getAddressSpace())
                    || target.compareTo(start) >= 0 && target.compareTo(slot.add(1)) <= 0) break;
            if (p.getListing().getDefinedDataContaining(target) != null) break;
            Instruction existing = p.getListing().getInstructionContaining(target);
            if (existing != null && (!existing.getAddress().equals(target) || cs(p, target) != cs(p, site.getAddress()))) break;
            try {
                var i = decoder.disassemble(target);
                if (i == null || i.getMnemonicString().contains("UNDEF") || i.getMnemonicString().equals("INT3")) break;
            } catch (Exception e) { break; }
            cases.add(target);
            if (target.compareTo(start) > 0) firstForward = Math.min(firstForward, target.getOffset());
        }
        return List.of(); // No guessed end: require the first forward case to bound the words.
    }
    private static String fixup(int segment, boolean interrupt, int count) {
        String base = String.format("0x%x", (long)segment << 4);
        String common = "local idx:2=zext(AL); AX=idx+idx; local fullip:4=inst_next-" + base
            + "; local ip:2=fullip:2; local sum:2=ip+AX; local tbl:4=(" + base + "+zext(sum))&0xfffff; ";
        String kernel = interrupt ? common + "AX=*:2 tbl; local target:4=(" + base + "+zext(AX))&0xfffff; " : common + "CF=carry(ip,AX); OF=scarry(ip,AX); AF=(((ip^AX)^sum)&0x10)!=0;"
            + " SF=sum s< 0; ZF=sum==0; PF=(popcount(sum&0xff)&1:1)==0;"
            + " DI=*:2 tbl; SP=SP+2; local target:4=(" + base + "+zext(DI))&0xfffff; ";
        // Native bounded recovery keeps repeated labels; address-only overrides
        // stop once every distinct destination has been seen. Unknown selectors
        // retain the selected address as an opaque tail transfer.
        return kernel + (count == 0 ? "" : "if(idx>=" + count + ") goto <opaque>; goto [target]; <opaque> ")
            + "call [target]; return [0:4];";
    }
    private static void install(Program p, Function function, String name, String body, TaskMonitor monitor) throws Exception {
        if (!name.equals(function.getCallFixup())) {
            new SpecExtension(p).addReplaceCompilerSpecExtension("<callfixup name=\"" + name
                + "\"><pcode><body><![CDATA[" + body + "]]></body></pcode></callfixup>", monitor);
            function.setCallFixup(name);
        }
    }

    private static String modelStem(int segment, boolean interrupt) {
        return String.format("ws_inline_models_%s_%04x", interrupt ? "int" : "call", segment);
    }
    private static boolean availableModel(Program p, int segment, boolean interrupt, int count) {
        var block = p.getMemory().getBlock(modelStem(segment, interrupt));
        if (block == null) return true;
        if (!"WSInlineTables".equals(block.getSourceName())) return false;
        Function f = p.getFunctionManager().getFunctionAt(block.getStart().add(count - 1));
        return !explicit(f) && (f == null || f.getCallFixup() == null || f.getCallFixup().startsWith("ws_inline_bound_"));
    }
    /** Compiler-only delegates live in non-loaded OTHER memory, separate from cartridge bytes. */
    private static Function model(Program p, int segment, boolean interrupt, int count, TaskMonitor monitor) throws Exception {
        String stem = modelStem(segment, interrupt);
        var block = p.getMemory().getBlock(stem);
        if (block == null) {
            byte[] bytes = new byte[256];
            Arrays.fill(bytes, (byte)0xc3); // A standalone delegate decompiles as a return.
            block = p.getMemory().createInitializedBlock(stem, AddressSpace.OTHER_SPACE.getAddress(0),
                new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, true);
            block.setPermissions(true, false, false);
            block.setSourceName("WSInlineTables");
            block.setComment("J3 compiler models; non-loaded metadata, not cartridge code");
        }
        if (!"WSInlineTables".equals(block.getSourceName())) return null;
        Address entry = block.getStart().add(count - 1);
        Function f = p.getFunctionManager().getFunctionAt(entry);
        if (explicit(f)) return null;
        if (f == null) {
            var buffer = new ghidra.program.model.mem.DumbMemBufferImpl(p.getMemory(), entry);
            var context = new ghidra.program.model.lang.ProgramProcessorContext(p.getProgramContext(), entry);
            var prototype = p.getLanguage().parse(buffer, context, false);
            p.getListing().createInstruction(entry, prototype, buffer, context, 1);
            f = p.getFunctionManager().createFunction(stem + "_" + count, entry, new AddressSet(entry), SourceType.ANALYSIS);
            f.addTag("WS_INLINE_MODEL");
        }
        String name = String.format("ws_inline_bound_%s_%04x_%d", interrupt ? "int" : "call", segment, count);
        install(p, f, name, fixup(segment, interrupt, count), monitor);
        return f;
    }
    private static boolean sameCallers(Program p, Address entry, int segment, boolean interrupt) {
        for (Reference r : p.getReferenceManager().getReferencesTo(entry)) if (r.getReferenceType().isCall()) {
            Instruction from = p.getListing().getInstructionAt(r.getFromAddress());
            if (from == null || cs(p, from.getAddress()) != segment
                || interrupt && !text(from).equals("INT40")
                || !interrupt && !from.getMnemonicString().equals("CALL")) return false;
        }
        return true;
    }
    /** J4: a pure helper saves the CALL's IP in DS:[SI], then either resumes at
     * that IP or yields by returning through the older stack word. No inline data
     * is inferred: the saved continuation remains executable code for a later entry. */
    private static int continuations(Program p, List<Instruction> sites, Consumer<String> emit,
                                     TaskMonitor monitor) throws Exception {
        int changed = 0;
        for (Instruction i : sites) {
            monitor.checkCancelled();
            if (!i.getMnemonicString().equals("CALL") || i.getDefaultFlows().length != 1) continue;
            Address entry = i.getDefaultFlows()[0];
            if (WSRamCode.isRam(p, entry)) continue;
            boolean yield = shape(p, entry, SAVE_RETURN);
            if (!yield && !shape(p, entry, SAVE_CONTINUE)) continue;
            Function helper = p.getFunctionManager().getFunctionAt(entry);
            Function owner = p.getFunctionManager().getFunctionContaining(i.getAddress());
            int segment = cs(p, i.getAddress());
            if (helper == null || owner == null || explicit(helper) || explicit(owner)
                || segment != cs(p, entry) || !sameCallers(p, entry, segment, false)
                || helper.getCallFixup() != null && !helper.getCallFixup().startsWith("ws_saved_")) continue;
            String base = String.format("0x%x", (long)segment << 4);
            String name = String.format("ws_saved_%s_%04x", yield ? "yield" : "continue", segment);
            String body = "local ip:4=inst_next-" + base + "; AX=ip:2;"
                + " local ptr:4=segment(DS,SI); *:2 ptr=AX;";
            if (yield) body += " local oldsp:2=SP+2; local stack:4=segment(SS,oldsp);"
                + " local retip:2=*:2 stack; SP=SP+4; local target:4=(" + base + "+zext(retip))&0xfffff; return [target];";
            else body += " SP=SP+2;";
            if (!name.equals(helper.getCallFixup())) {
                new SpecExtension(p).addReplaceCompilerSpecExtension("<callfixup name=\"" + name
                    + "\"><pcode><body><![CDATA[" + body + "]]></body></pcode></callfixup>", monitor);
                helper.setCallFixup(name);
            }
            helper.setNoReturn(yield); // Yield never returns to this CALL's next instruction.
            p.getBookmarkManager().setBookmark(i.getAddress(), BookmarkType.ANALYSIS, CONTINUATION,
                "J4 saved near IP in DS:[SI]; " + (yield ? "returned through older stack word" : "resumed caller")
                    + "; helper=" + entry);
            i.setFallThrough(yield ? null : i.getDefaultFallThrough());
            CreateFunctionCmd.fixupFunctionBody(p, owner, monitor);
            p.getListing().getInstructionAt(i.getAddress()).setFallThrough(yield ? null : i.getDefaultFallThrough());
            changed++;
            emit.accept(String.format("{\"rule\":\"J4\",\"site\":\"%s\",\"helper\":\"%s\",\"outcome\":\"RECOVERED\",\"yield\":%b}", i.getAddress(), entry, yield));
        }
        return changed;
    }
    public static String apply(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        List<Instruction> sites = new ArrayList<>();
        for (Instruction i : p.getListing().getInstructions(true))
            if (i.getMnemonicString().equals("CALL") || text(i).equals("INT40")) sites.add(i);
        Set<Address> vectors = new HashSet<>();
        var bookmarks = p.getBookmarkManager().getBookmarksIterator();
        while (bookmarks.hasNext()) {
            Bookmark b = bookmarks.next();
            if (b.getComment() != null && b.getComment().startsWith("F2 ") && b.getComment().contains("IVT[40]")) vectors.add(b.getAddress());
        }
        int recovered = 0;
        for (Instruction i : sites) {
            monitor.checkCancelled();
            boolean interrupt = text(i).equals("INT40");
            Address entry = interrupt ? vectors.size() == 1 ? vectors.iterator().next() : null
                : i.getDefaultFlows().length == 1 ? i.getDefaultFlows()[0] : null;
            if (entry == null || WSRamCode.isRam(p, entry)) continue;
            boolean matches = interrupt ? shape(p, entry, INT_ES) || shape(p, entry, INT_DS) : shape(p, entry, CALL);
            if (!matches) continue;
            Function owner = p.getFunctionManager().getFunctionContaining(i.getAddress());
            Function helper = p.getFunctionManager().getFunctionAt(entry);
            if (owner == null || helper == null || explicit(owner) || explicit(helper)
                || helper.getCallFixup() != null && !helper.getCallFixup().startsWith("ws_inline_")) continue;
            boolean protectedReference = false;
            for (Reference r : p.getReferenceManager().getReferencesFrom(i.getAddress()))
                if (r.isPrimary() && r.getReferenceType().isFlow()
                    && (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED)) protectedReference = true;
            if (protectedReference) continue;
            int segment = cs(p, i.getAddress());
            if (segment != cs(p, entry)) continue;
            // A function-level fixup must be correct for every caller of that helper.
            if (!sameCallers(p, entry, segment, interrupt)) continue;
            List<Address> cases = table(p, i);
            if (cases.isEmpty()) {
                emit.accept(String.format("{\"rule\":\"J3\",\"site\":\"%s\",\"outcome\":\"UNRESOLVED\",\"why\":\"NO_STRONG_TABLE_END\"}", i.getAddress()));
                continue;
            }
            Address start = i.getDefaultFallThrough();
            if (!availableModel(p, segment, interrupt, cases.size())) continue;
            if (!words(p, start, cases.size())) continue;
            Function delegate = model(p, segment, interrupt, cases.size(), monitor);
            if (delegate == null) continue;
            // Direct calls prioritize their primary ordinary call reference. Keep
            // that original destination as a non-primary reference for analysis.
            if (helper.getCallFixup() != null) helper.setCallFixup(null);
            for (Reference r : p.getReferenceManager().getReferencesFrom(i.getAddress()))
                if (r.getReferenceType().isCall() && r.isPrimary()) p.getReferenceManager().setPrimary(r, false);
            Reference localRef = p.getReferenceManager().addMemoryReference(i.getAddress(), delegate.getEntryPoint(),
                RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, -1);
            p.getReferenceManager().setPrimary(localRef, true);
            for (Address target : new LinkedHashSet<>(cases)) {
                if (p.getListing().getInstructionContaining(target) == null) {
                    p.getProgramContext().setValue(p.getRegister("csval"), target, target, BigInteger.valueOf(segment));
                    new DisassembleCommand(target, null, true).applyTo(p, monitor);
                }
                i.addMnemonicReference(target, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
            }
            p.getBookmarkManager().setBookmark(i.getAddress(), BookmarkType.ANALYSIS, CATEGORY,
                "J3 proven " + (interrupt ? "interrupt" : "CALL/pop") + " inline words; helper=" + entry + "; table=" + start + "; words=" + cases.size());
            i.setFallThrough(cases.get(0));
            CreateFunctionCmd.fixupFunctionBody(p, owner, monitor);
            p.getListing().getInstructionAt(i.getAddress()).setFallThrough(cases.get(0));
            recovered++;
            emit.accept(String.format("{\"rule\":\"J3\",\"site\":\"%s\",\"helper\":\"%s\",\"outcome\":\"RECOVERED\",\"table\":\"%s\",\"words\":%d,\"interrupt\":%b}",
                i.getAddress(), entry, start, cases.size(), interrupt));
        }
        int saved = continuations(p, sites, emit, monitor);
        return "J3 inline tables recovered " + recovered + "; J4 saved continuations " + saved;
    }
}
