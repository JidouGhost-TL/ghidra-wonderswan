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
 * Arbitrary stack manipulation and interrupt handlers with other side effects stay unknown.
 * IT1 (interrupt inline-table dispatch, general form):
 *   IT1a: any INT n whose vector has exactly one installed handler (F2 IVT[n]) is a site; the handler is proven an
 *     inline-table dispatcher from its own code by a symbolic walk ({@link #inlineInterruptHandler}): straight-line
 *     code that zero-extends AL, doubles it, loads the stacked return IP and CS (LES/LDS r,[BP+k] with BP framed so
 *     that [BP+k] is the IP slot), adds the doubled AL, reads the word at CS:table[AL] (MOV reg,ES/DS:[r] or LODSW),
 *     writes it back over the stacked IP and IRETs with the stack balanced. Register choices, saved-register order
 *     and ENTER/LEAVE framing are free; any other instruction, branch, call or stack write rejects the handler.
 *   IT1b: the table length is proven by the first forward case (as J3) or by an adjacent proven object at the next
 *     slot: the base of a CS-relative operand used anywhere (CS:[disp] / CS:[reg+disp]), a data reference from code
 *     outside the table, a flow reference from outside the table, a function entry, or executed (played) bytes. The
 *     words before that object are the table. A site still without a proven end is an H2 hypothesis: its candidate
 *     words are tagged (WSHypothesis:IT1) and nothing beyond already-decoded code is decoded.
 *   IT1c: J3 repeats until no new site is recovered: a recovered case can hold the next inline dispatch. */
public final class WSInlineTables {
    public static final String CATEGORY = "WSInlineTable";
    public static final String CONTINUATION = "WSContinuation";
    private static final String CALL = "POPDI;MOVAH,0;ADDAX,AX;ADDDI,AX;MOVDI,WORDPTRCS:[DI];JMPDI";
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
    /** J4 yield helper: it returns through the older stack word; the CALL's next instruction runs only later,
     * entered through the saved continuation, so executing it is no evidence that this helper returns. */
    public static boolean savedYield(Function f) {
        return f != null && f.getCallFixup() != null && f.getCallFixup().startsWith("ws_saved_yield_");
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
        return words(p, start, count, false, null, null);
    }

    /** As {@link #words(Program, Address, int)}; a veto by a straddling instruction is reported through
     *  {@code emit} (rule J1w STRADDLE_VETO: site, first slot, straddling instruction) when it is given. */
    public static boolean words(Program p, Address start, int count, Address site, Consumer<String> emit) throws Exception {
        return words(p, start, count, false, site, emit);
    }

    static boolean words(Program p, Address start, int count, boolean straddle) throws Exception {
        return words(p, start, count, straddle, null, null);
    }

    /** {@code straddle} (IT1b, inline interrupt words only): an unplayed speculative fall-through instruction that
     *  starts inside the proven words but runs past their end is superseded too (its start is a proven word byte);
     *  its bytes after the words return to undefined, and it is tagged WSHypothesis:IT1-superseded (H2 record). */
    static boolean words(Program p, Address start, int count, boolean straddle, Address site, Consumer<String> emit) throws Exception {
        if (count <= 0 || WSRamCode.isRam(p, start)) return false;
        Address end = start.add(2L * count - 1);
        // J1w: an instruction that starts before the first slot and runs into it straddles the table: veto.
        // The instruction stays as it is (H2); the table words are not created.
        Instruction head = p.getListing().getInstructionContaining(start);
        if (head != null && head.getAddress().compareTo(start) < 0) {
            if (emit != null)
                emit.accept(String.format("{\"rule\":\"J1w\",\"site\":\"%s\",\"slot\":\"%s\",\"slots\":%d,\"outcome\":\"STRADDLE_VETO\",\"instruction\":\"%s\",\"instruction_start\":\"%s\",\"instruction_end\":\"%s\",\"bytes\":\"%s\"}",
                    site, start, count, head.toString().replace("\"", "'"), head.getAddress(), head.getMaxAddress(),
                    HexFormat.of().formatHex(head.getBytes())));
            return false;
        }
        Instruction over = p.getListing().getInstructionContaining(end);
        if (over != null && over.getMaxAddress().compareTo(end) > 0) {
            if (!straddle || over.getAddress().compareTo(start) < 0) return false;
            for (Address a : new AddressSet(end.next(), over.getMaxAddress()).getAddresses(true)) {
                if (played(p, a)) return false;
                for (Reference r : p.getReferenceManager().getReferencesTo(a)) if (r.getReferenceType().isFlow()) return false;
            }
        } else over = null;
        for (Address a : new AddressSet(start, end).getAddresses(true)) {
            if (played(p, a) || explicit(p.getFunctionManager().getFunctionContaining(a))) return false;
            for (Reference r : p.getReferenceManager().getReferencesTo(a))
                if (r.getReferenceType().isFlow() && !new AddressSet(start, end).contains(r.getFromAddress())) return false;
        }
        // Speculative fallthrough into inline words is superseded by the proven dispatch.
        for (Instruction i : p.getListing().getInstructions(new AddressSet(start, end), true))
            if (i != null && (i.getMaxAddress().compareTo(end) > 0 && (over == null || !i.getAddress().equals(over.getAddress()))
                || explicit(p.getFunctionManager().getFunctionContaining(i.getAddress())))) return false;
        if (over != null)
            p.getBookmarkManager().setBookmark(over.getAddress(), BookmarkType.ANALYSIS, "WSHypothesis:IT1-superseded:" + over.getAddress(),
                "IT1 H2 RECORD: unplayed fall-through instruction " + over + " (bytes "
                + HexFormat.of().formatHex(over.getBytes()) + ") started inside proven inline words " + start + ".." + end
                + " and was superseded by them; its bytes past the words are left undefined");
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
    /** IT1b: a proven object starts at this table slot (it cannot be a further dispatch word). */
    private static String boundary(Program p, Address slot, Address start, Set<Address> csBases) {
        if (csBases.contains(slot)) return "CS_OPERAND_BASE";
        if (p.getFunctionManager().getFunctionAt(slot) != null) return "FUNCTION_ENTRY";
        if (played(p, slot) || played(p, slot.add(1))) return "EXECUTED";
        for (Reference r : p.getReferenceManager().getReferencesTo(slot)) {
            Address from = r.getFromAddress();
            if (!from.isMemoryAddress() || from.compareTo(start) >= 0 && from.compareTo(slot) < 0) continue;
            if (p.getListing().getInstructionAt(from) == null) continue;
            if (r.getReferenceType().isFlow()) return "FLOW_REFERENCE";
            if (r.getReferenceType().isData()) return "DATA_REFERENCE";
        }
        return null;
    }
    /** IT1b: every CS-relative operand displacement (CS:[disp] or CS:[reg+disp]) in the program, as an address. */
    private static final java.util.regex.Pattern CS_DISP = java.util.regex.Pattern.compile(
        "CS:\\[(?:(?:BX|SI|DI|BP)(?: \\+ (?:SI|DI))? \\+ )?0x([0-9a-f]+)\\]", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static Set<Address> csBases(Program p) {
        Set<Address> out = new HashSet<>();
        for (Instruction i : p.getListing().getInstructions(true)) {
            String t = i.toString();
            if (!t.contains("CS:[")) continue;
            var m = CS_DISP.matcher(t);
            if (m.find()) out.add(near(p, i.getAddress(), cs(p, i.getAddress()), Integer.parseInt(m.group(1), 16)));
        }
        return out;
    }
    private static List<Address> table(Program p, Instruction site, Set<Address> csBases, List<Address> candidates, String[] why) throws Exception {
        Address start = site.getDefaultFallThrough();
        why[0] = "NO_START";
        if (start == null || WSRamCode.isRam(p, start)) return List.of();
        List<Address> cases = new ArrayList<>();
        long firstForward = Long.MAX_VALUE;
        PseudoDisassembler decoder = new PseudoDisassembler(p);
        for (int k = 0; k < 256; k++) {
            Address slot = start.add(2L * k);
            if (slot.getOffset() == firstForward) { why[0] = "FIRST_FORWARD_CASE"; return cases.size() >= 2 ? cases : List.of(); }
            String end = k == 0 ? null : boundary(p, slot, start, csBases);
            if (end != null) { why[0] = end; return cases; }   // IT1b: adjacent proven object ends the words
            why[0] = "BREAK_AT_SLOT_" + k;
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
            candidates.add(target);
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
    private static boolean sameCallers(Program p, Address entry, int segment, int vector) {
        boolean interrupt = vector >= 0;
        for (Reference r : p.getReferenceManager().getReferencesTo(entry)) if (r.getReferenceType().isCall()) {
            Instruction from = p.getListing().getInstructionAt(r.getFromAddress());
            if (from == null || cs(p, from.getAddress()) != segment
                || interrupt && intNumber(from) != vector
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
                || segment != cs(p, entry) || !sameCallers(p, entry, segment, -1)
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
    /** IT1a: the vector number of an immediate software interrupt (CD nn), or -1. */
    static int intNumber(Instruction i) {
        try {
            byte[] b = i.getBytes();
            return i.getMnemonicString().equals("INT") && b.length == 2 && (b[0] & 0xff) == 0xcd ? b[1] & 0xff : -1;
        } catch (Exception e) { return -1; }
    }
    private static final java.util.regex.Pattern IVT = java.util.regex.Pattern.compile("IVT\\[([0-9a-f]{2})\\]");

    /**
     * IT1a: the handler at {@code entry} returns into an inline word table at its caller's return IP, indexed by AL:
     * proven by a symbolic walk of its straight-line code (see the class comment). Offsets are relative to the SP at
     * handler entry, where the stacked IP is at +0, CS at +2 and FLAGS at +4.
     */
    static boolean inlineInterruptHandler(Program p, Address entry) {
        Map<String, String> v = new HashMap<>();
        v.put("AL", "SEL");
        int depth = 0;           // bytes pushed since entry
        Integer bp = null;       // BP = entrySP - bp
        boolean replaced = false;
        Address a = entry;
        for (int n = 0; n < 32; n++) {
            Instruction i = p.getListing().getInstructionAt(a);
            if (i == null) return false;
            String t = text(i);
            String mn = i.getMnemonicString();
            java.util.regex.Matcher m;
            if (t.equals("IRET")) return replaced && depth == 0;
            if (i.getFlowType().isJump() || i.getFlowType().isCall() || i.getFlowType().isTerminal()) return false;
            if ((m = java.util.regex.Pattern.compile("PUSH(AX|BX|CX|DX|SI|DI|BP|ES|DS)").matcher(t)).matches()) {
                depth += 2;
            } else if ((m = java.util.regex.Pattern.compile("POP(AX|BX|CX|DX|SI|DI|BP|ES|DS)").matcher(t)).matches()) {
                if (depth < 2) return false;
                depth -= 2;
                String r = m.group(1);
                v.put(r, "SAVED");
                if (r.equals("AX")) v.remove("AL");
                if (r.equals("BP")) bp = null;
            } else if (t.equals("MOVBP,SP")) {
                bp = depth;
            } else if (t.equals("ENTER0,0")) {
                depth += 2; bp = depth;
            } else if (t.equals("LEAVE")) {
                if (bp == null || bp < 2) return false;
                depth = bp - 2; bp = null;
            } else if (t.equals("MOVAH,0") || t.equals("XORAH,AH") || t.equals("SUBAH,AH")) {
                if (!"SEL".equals(v.get("AL"))) return false;
                v.put("AX", "ZSEL");
            } else if (t.equals("SHLAX,1") || t.equals("ADDAX,AX")) {
                if (!"ZSEL".equals(v.get("AX"))) return false;
                v.put("AX", "IDX2"); v.remove("AL");
            } else if ((m = java.util.regex.Pattern.compile("L(ES|DS)(BX|SI|DI),\\[BP\\+([0-9A-F]+)\\]").matcher(t)).matches()) {
                if (bp == null || Integer.parseInt(m.group(3), 16) != bp) return false;   // must be the stacked IP slot
                v.put(m.group(2), "RETIP"); v.put(m.group(1), "RETCS");
            } else if ((m = java.util.regex.Pattern.compile("ADD(BX|SI|DI),AX").matcher(t)).matches()) {
                if (!"RETIP".equals(v.get(m.group(1))) || !"IDX2".equals(v.get("AX"))) return false;
                v.put(m.group(1), "TABLE");
            } else if ((m = java.util.regex.Pattern.compile("MOV(AX|CX|DX),WORDPTR(ES|DS):\\[(BX|SI|DI)\\]").matcher(t)).matches()) {
                if (!"TABLE".equals(v.get(m.group(3))) || !"RETCS".equals(v.get(m.group(2)))) return false;
                v.put(m.group(1), "WORD"); if (m.group(1).equals("AX")) v.remove("AL");
            } else if (mn.equals("LODSW")) {
                if (!t.equals("LODSWSI") && !t.equals("LODSWDS:SI")) return false;
                if (!"TABLE".equals(v.get("SI")) || !"RETCS".equals(v.get("DS"))) return false;
                v.put("AX", "WORD"); v.remove("AL"); v.put("SI", "TABLE+2");
            } else if ((m = java.util.regex.Pattern.compile("MOVWORDPTR(?:SS:)?\\[BP\\+([0-9A-F]+)\\],(AX|CX|DX)").matcher(t)).matches()) {
                if (bp == null || Integer.parseInt(m.group(1), 16) != bp || !"WORD".equals(v.get(m.group(2)))) return false;
                replaced = true;
            } else return false;
            if (i.getFallThrough() == null) return false;
            a = i.getFallThrough();
        }
        return false;
    }

    /** J3/IT1 result: sites recovered, J4 continuations, summary text. */
    public record Result(int recovered, int fresh, int saved, String summary) { }

    public static String apply(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        return applyResult(p, emit, monitor).summary();
    }

    public static Result applyResult(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        Map<Integer, Set<Address>> vectors = new HashMap<>();
        var bookmarks = p.getBookmarkManager().getBookmarksIterator();
        while (bookmarks.hasNext()) {
            Bookmark b = bookmarks.next();
            if (b.getComment() == null || !b.getComment().startsWith("F2 ")) continue;
            var m = IVT.matcher(b.getComment());
            if (m.find()) vectors.computeIfAbsent(Integer.parseInt(m.group(1), 16), k -> new HashSet<>()).add(b.getAddress());
        }
        int recovered = 0, hypotheses = 0, freshTotal = 0;
        Set<Address> unresolved = new HashSet<>();
        List<Instruction> sites = List.of();
        for (int iteration = 0; iteration < 8; iteration++) {   // IT1c
            sites = new ArrayList<>();
            for (Instruction i : p.getListing().getInstructions(true))
                if (i.getMnemonicString().equals("CALL") || intNumber(i) >= 0) sites.add(i);
            Set<Address> bases = null;
            int fresh = 0;
            for (Instruction i : sites) {
                monitor.checkCancelled();
                // iteration 0 re-applies modeled sites as before (repeat analysis repairs them after merges);
                // later iterations only look for sites the previous ones made reachable
                boolean wasModeled = modeled(p, i.getAddress());
                if (iteration > 0 && wasModeled) continue;
                int vector = intNumber(i);
                boolean interrupt = vector >= 0;
                Set<Address> handlers = interrupt ? vectors.getOrDefault(vector, Set.of()) : Set.of();
                Address entry = interrupt ? handlers.size() == 1 ? handlers.iterator().next() : null
                    : i.getDefaultFlows().length == 1 ? i.getDefaultFlows()[0] : null;
                if (entry == null || WSRamCode.isRam(p, entry)) continue;
                boolean matches = interrupt ? inlineInterruptHandler(p, entry) : shape(p, entry, CALL);
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
                // the CALL helper reads its table through CS; an interrupt handler reads the caller's stacked CS
                if (!interrupt && segment != cs(p, entry)) continue;
                // A function-level fixup must be correct for every caller of that helper.
                if (!sameCallers(p, entry, segment, interrupt ? vector : -1)) continue;
                if (bases == null) bases = csBases(p);
                List<Address> candidates = new ArrayList<>();
                String[] why = new String[1];
                List<Address> cases = table(p, i, bases, candidates, why);
                if (cases.isEmpty()) {
                    if (unresolved.add(i.getAddress())) {
                        emit.accept(String.format("{\"rule\":\"J3\",\"site\":\"%s\",\"outcome\":\"UNRESOLVED\",\"why\":\"NO_STRONG_TABLE_END\",\"break\":\"%s\",\"candidates\":%d}",
                            i.getAddress(), why[0], candidates.size()));
                        if (interrupt && !candidates.isEmpty()) {
                            // IT1b H2: candidate words stay a hypothesis; nothing is decoded from them
                            hypotheses++;
                            List<String> c = new ArrayList<>();
                            for (Address t : candidates) c.add(t.toString());
                            p.getBookmarkManager().setBookmark(i.getAddress(), BookmarkType.ANALYSIS, "WSHypothesis:IT1:" + i.getAddress(),
                                "IT1 H2 HYPOTHESIS: inline-table interrupt dispatch (handler " + entry + "), table length unproven ("
                                + why[0] + "); candidate words " + String.join(",", c) + " not decoded");
                        }
                    }
                    continue;
                }
                Address start = i.getDefaultFallThrough();
                if (!availableModel(p, segment, interrupt, cases.size())) continue;
                if (!words(p, start, cases.size(), interrupt, i.getAddress(), emit)) {
                    emit.accept(String.format("{\"rule\":\"J3\",\"site\":\"%s\",\"outcome\":\"UNRESOLVED\",\"why\":\"WORDS_VETOED\",\"words\":%d}", i.getAddress(), cases.size()));
                    continue;
                }
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
                p.getBookmarkManager().removeBookmarks(new AddressSet(i.getAddress()), BookmarkType.ANALYSIS, "WSHypothesis:IT1:" + i.getAddress(), monitor);
                p.getBookmarkManager().setBookmark(i.getAddress(), BookmarkType.ANALYSIS, CATEGORY,
                    "J3 proven " + (interrupt ? "interrupt" : "CALL/pop") + " inline words; helper=" + entry + "; table=" + start + "; words=" + cases.size()
                    + "; end=" + why[0]);
                i.setFallThrough(cases.get(0));
                CreateFunctionCmd.fixupFunctionBody(p, owner, monitor);
                p.getListing().getInstructionAt(i.getAddress()).setFallThrough(cases.get(0));
                recovered++;
                if (!wasModeled) fresh++;
                unresolved.remove(i.getAddress());
                emit.accept(String.format("{\"rule\":\"J3\",\"site\":\"%s\",\"helper\":\"%s\",\"outcome\":\"RECOVERED\",\"table\":\"%s\",\"words\":%d,\"interrupt\":%b,\"vector\":%d,\"end\":\"%s\",\"iteration\":%d}",
                    i.getAddress(), entry, start, cases.size(), interrupt, vector, why[0], iteration));
            }
            freshTotal += fresh;
            if (fresh == 0) break;
        }
        int saved = continuations(p, sites, emit, monitor);
        return new Result(recovered, freshTotal, saved, "J3 inline tables recovered " + recovered + "; IT1 hypotheses " + hypotheses + "; J4 saved continuations " + saved);
    }
}
