// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.util.task.TaskMonitor;

/**
 * Static call evidence in undefined ROM, applied after ordinary analysis.
 * A direct call to an existing entry anchors a routine with a frame prologue,
 * a reference from existing code, or a preceding decoded flow terminator.
 * Trial decoding is strict: every reachable branch is walked, every path must
 * reach a return or an existing instruction, and transfers may not enter the
 * middle of an instruction. Executable blocks that are adjacent in both the
 * linear space and the ROM file form one walk domain, since routines cross
 * such edges at runtime. Defined data and inconsistent file-backed aliases
 * veto a candidate. Computed transfers and unresolved bank contexts are kept
 * as unknown, with a rejection reason, except an immediate software interrupt,
 * which behaves like a call returning to its fallthrough. No execution
 * evidence is synthesized. Before boundary seeding, finite CS-indexed near
 * and far tables are reserved and defined as pointers. Recognized dispatches
 * are resolved transfers; their targets use the same strict walk. All table
 * bytes veto later starts in every file-backed alias.
 */
public final class WSStaticCode {
    public static final String PROPERTY = "WS_STATIC_UNEXECUTED";
    private static final int BACKWARD_BYTES = 1024, MAX_INSTRUCTIONS = 1500;
    private static final Set<String> WEAK_OPCODES = Set.of("INSB", "INSW", "OUTSB", "OUTSW", "BOUND", "INTO", "ESC", "WAIT", "INT3");
    private final Program program;
    private final Listing listing;
    private final Memory memory;
    private final ProgramContext context;
    private final Register csval, hwundef;
    private final PseudoDisassembler decoder;
    private final TaskMonitor monitor;
    private final Consumer<String> emit;
    private final Set<Long> definedData = new HashSet<>();
    private final Set<Long> codeBytes = new HashSet<>();
    private final Map<String, Integer> rejects = new TreeMap<>();
    private final Set<Address> known = new HashSet<>();
    private final Set<String> saveProfiles = new HashSet<>();
    private final IntPropertyMap provenance;
    private int passes, accepted, instructions, bytes, candidates;
    private final Map<Address, Table> tables = new LinkedHashMap<>();
    private final Set<Address> tableAttempts = new HashSet<>();
    private final Set<Long> reservedData = new HashSet<>();
    private record Table(Address site, Address setup, Address base, int width,
                         List<Address> targets, String bound, String stop) { }
    private static final Pattern TABLE_MEM = Pattern.compile(
        "(?:word|dword) ptr CS:\\[(BX|BP|SI|DI)(?: ?([+-]) ?0x([0-9a-f]+))?\\]", Pattern.CASE_INSENSITIVE);

    private record Start(Address address, String evidence) { }
    private record Walk(TreeMap<Address, PseudoInstruction> code, AddressSet body,
                        Set<Address> ends, Map<Address, Set<Address>> edges,
                        Set<Address> transfers) { }
    // A maximal run of executable blocks that are adjacent in both the linear
    // address space and the ROM file. Routines cross such edges at runtime, so
    // seeding treats the run as one walk domain instead of stopping at them.
    private record Run(List<MemoryBlock> blocks, byte[] raw, int[] prefix, AddressSet range) { }
    private final List<Run> runs = new ArrayList<>();
    private static final class Reject extends Exception {
        int evidenceCount;
        Reject(String reason) { super(reason); }
    }

    private WSStaticCode(Program p, Consumer<String> output, TaskMonitor m) throws Exception {
        program = p; listing = p.getListing(); memory = p.getMemory();
        context = p.getProgramContext(); monitor = m; emit = output;
        csval = context.getRegister("csval"); hwundef = context.getRegister("hwundef");
        if (csval == null || hwundef == null) throw new IllegalArgumentException("Strict segmented language required");
        decoder = new PseudoDisassembler(p);
        var maps = p.getUsrPropertyManager();
        IntPropertyMap map = maps.getIntPropertyMap(PROPERTY);
        provenance = map == null ? maps.createIntPropertyMap(PROPERTY) : map;
        for (Data d : listing.getDefinedData(true)) {
            long ro = romOffset(d.getAddress());
            if (ro >= 0) for (int k = 0; k < d.getLength(); k++) definedData.add(ro + k);
        }
        for (Instruction i : listing.getInstructions(true)) index(i);
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            if (provenance.hasProperty(f.getEntryPoint())) continue;
            Instruction i = listing.getInstructionAt(f.getEntryPoint());
            StringBuilder prefix = new StringBuilder(); int saves = 0;
            while (i != null && i.getLength() == 1 && isSave(i.getBytes()[0] & 255) && prefix.length() < 24) {
                int op = i.getBytes()[0] & 255;
                prefix.append(String.format("%02x", op)); saves += op == 0x60 ? 2 : 1;
                i = i.getFallThrough() == null ? null : listing.getInstructionAt(i.getFallThrough());
            }
            if (saves >= 3 && i != null && !(i.getLength() == 1 && isSave(i.getBytes()[0] & 255)))
                saveProfiles.add(prefix.toString());
        }
        List<MemoryBlock> eligible = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() || WonderSwanLoader.isDataOverlay(block)) continue;
            if (block.getSize() > 65536 || romOffset(block.getStart()) < 0) continue;
            eligible.add(block);
        }
        eligible.sort(Comparator.comparing(MemoryBlock::getStart));
        List<MemoryBlock> current = new ArrayList<>();
        for (MemoryBlock block : eligible) {
            if (!current.isEmpty() && follows(current.get(current.size()-1), block)) current.add(block);
            else {
                if (!current.isEmpty()) addRun(current);
                current = new ArrayList<>(List.of(block));
            }
        }
        if (!current.isEmpty()) addRun(current);
    }

    private boolean follows(MemoryBlock prev, MemoryBlock next) {
        if (!prev.getStart().getAddressSpace().equals(next.getStart().getAddressSpace())) return false;
        try {
            if (!next.getStart().equals(prev.getEnd().next())) return false;
        } catch (Exception ex) { return false; }
        long a = romOffset(prev.getEnd()), b = romOffset(next.getStart());
        return a >= 0 && b == a + 1;
    }

    private void addRun(List<MemoryBlock> blocks) throws Exception {
        int total = 0;
        int[] prefix = new int[blocks.size()];
        for (int b = 0; b < blocks.size(); b++) { prefix[b] = total; total += (int)blocks.get(b).getSize(); }
        byte[] raw = new byte[total];
        AddressSet range = new AddressSet();
        for (int b = 0; b < blocks.size(); b++) {
            memory.getBytes(blocks.get(b).getStart(), raw, prefix[b], (int)blocks.get(b).getSize());
            range.add(blocks.get(b).getStart(), blocks.get(b).getEnd());
        }
        runs.add(new Run(List.copyOf(blocks), raw, prefix, range));
    }

    private Address addrOf(Run run, int k) {
        List<MemoryBlock> blocks = run.blocks();
        for (int b = 0; b < blocks.size(); b++) {
            int start = run.prefix()[b], end = b + 1 < blocks.size() ? run.prefix()[b+1] : run.raw().length;
            if (k >= start && k < end) return blocks.get(b).getStart().add(k - start);
        }
        throw new IllegalArgumentException("logical index out of run");
    }

    private int indexOf(Run run, Address a) {
        MemoryBlock block = memory.getBlock(a);
        if (block == null) return -1;
        List<MemoryBlock> blocks = run.blocks();
        for (int b = 0; b < blocks.size(); b++)
            if (blocks.get(b).equals(block)) return run.prefix()[b] + (int)a.subtract(block.getStart());
        return -1;
    }

    private int segOf(Address a) {
        MemoryBlock block = memory.getBlock(a);
        if (block != null && block.getStart() instanceof SegmentedAddress sa) return sa.getSegment();
        return -1;
    }

    public static String apply(Program p, Consumer<String> output, TaskMonitor monitor) throws Exception {
        WSStaticCode rule = new WSStaticCode(p, output, monitor);
        rule.run();
        return String.format("passes=%d candidates=%d accepted=%d instructions=%d bytes=%d tables=%d rejects=%s",
            rule.passes, rule.candidates, rule.accepted, rule.instructions, rule.bytes, rule.tables.size(), rule.rejects);
    }

    private long romOffset(Address a) {
        MemoryBlock block = memory.getBlock(a);
        if (block != null) for (MemoryBlockSourceInfo source : block.getSourceInfos())
            if (source.getFileBytes().isPresent() && source.contains(a)) return source.getFileBytesOffset(a);
        return -1;
    }

    private void index(Instruction i) {
        long ro = romOffset(i.getAddress());
        if (ro < 0) return;
        for (int k = 0; k < i.getLength(); k++) codeBytes.add(ro + k);
    }

    private boolean unknown(Address a) {
        CodeUnit unit = listing.getCodeUnitContaining(a);
        long ro = romOffset(a);
        return ro >= 0 && !definedData.contains(ro) && !reservedData.contains(ro) && !codeBytes.contains(ro)
            && unit instanceof Data d && !d.isDefined();
    }

    private int cs(Address a) {
        BigInteger value = context.getValue(csval, a, false);
        if (value != null && value.intValue() != 0) return value.intValue();
        if (a instanceof SegmentedAddress sa) return sa.getSegment();
        // An executable overlay without a segment runs under its base: a 64KB
        // bank view at base B executes as segment B>>4 when mapped.
        MemoryBlock block = memory.getBlock(a);
        if (block != null && block.isExecute()) {
            long base = block.getStart().getOffset();
            if ((base & 0xffff) == 0) return (int)((base >> 4) & 0xffff);
        }
        return -1;
    }

    private PseudoInstruction decode(Address a, int segment) throws Exception {
        PseudoDisassemblerContext trial = new PseudoDisassemblerContext(context);
        trial.setFutureRegisterValue(a, new RegisterValue(csval, BigInteger.valueOf(segment)));
        trial.setFutureRegisterValue(a, new RegisterValue(hwundef, BigInteger.ZERO));
        PseudoInstruction i = decoder.disassemble(a, trial, false);
        if (i == null || i.getMnemonicString().contains("UNDEF") || i.getMnemonicString().equals("ESC"))
            throw new Reject("invalid-or-undefined");
        return i;
    }


    private Run runOf(Address a) {
        for (Run run : runs) if (run.range().contains(a)) return run;
        return null;
    }

    private Address segmented(Address site, int segment, int offset) {
        SegmentedAddressSpace space = (SegmentedAddressSpace)program.getAddressFactory().getDefaultAddressSpace();
        Address a = space.getAddress(segment, offset & 0xffff);
        AddressSpace ss = site.getAddressSpace();
        if (ss.isOverlaySpace() && memory.contains(ss.getAddress(a.getOffset())))
            return ss.getAddress(a.getOffset());
        return a;
    }

    private String compact(Instruction i) { return i.toString().toUpperCase().replace(" ", ""); }
    private int immediate(String t) { return WSJumpTables.hex(t); }

    // Decode only short, contiguous setup slices. An existing listing offcut
    // or a non-fallthrough instruction cannot be used as a slice origin.
    private List<List<Instruction>> slices(Address site, Run run, int segment) {
        List<List<Instruction>> result = new ArrayList<>();
        int at = indexOf(run, site);
        for (int k = Math.max(0, at - 48); k < at; k++) {
            Address a = addrOf(run, k);
            if (!unknown(a) && listing.getInstructionAt(a) == null) continue;
            List<Instruction> slice = new ArrayList<>();
            try {
                for (int n = 0; n < 16 && a.compareTo(site) < 0; n++) {
                    Instruction i = listing.getInstructionAt(a);
                    if (i == null) i = decode(a, segment);
                    if (i.getFallThrough() == null || !i.getFallThrough().equals(i.getMaxAddress().next()) ||
                        i.getFlowType().isCall() || i.getFlowType().isComputed() || i.getFlowType().isTerminal()) break;
                    for (int z = 0; z < i.getLength(); z++) {
                        Address q = a.add(z);
                        if (listing.getInstructionAt(a) == null && !unknown(q)) throw new Reject("slice-overlap");
                    }
                    slice.add(i); a = i.getFallThrough();
                }
                if (a.equals(site) && !slice.isEmpty()) result.add(slice);
            } catch (Exception ex) { /* not an aligned setup */ }
        }
        return result;
    }

    private Table describeTable(Instruction site, List<Instruction> slice, int segment) throws Exception {
        boolean far = site.getMnemonicString().endsWith("F");
        // Far memory operands omit the segment override in their display;
        // the encoded CS prefix supplies that evidence explicitly.
        String operand = site.toString();
        if (far && site.getBytes()[0] == (byte)0x2e)
            operand = operand.replace("[", "dword ptr CS:[");
        Matcher m = TABLE_MEM.matcher(operand);
        int width = far ? 4 : 2;
        Instruction load = site;
        int loadAt = slice.size();
        if (!m.find()) {
            if (!site.getFlowType().isCall() || site.getNumOperands() != 1 || site.getRegister(0) == null) return null;
            String dest = site.getRegister(0).getName().toUpperCase();
            load = null;
            for (int k = slice.size()-1; k >= 0; k--) {
                Instruction q = slice.get(k); String t = compact(q);
                if (t.startsWith("MOV" + dest + ",")) { load = q; loadAt = k; break; }
                if (WSJumpTables.writesReg(q, t, dest, program.getRegister(dest))) return null;
                if (slice.size()-k > 3) return null;
            }
            if (load == null) return null;
            m = TABLE_MEM.matcher(load.toString());
            if (!m.find()) return null;
            far = false; width = 2;
        }
        String idx = m.group(1).toUpperCase();
        int base = WSJumpTables.disp(m);
        boolean constant = base != 0;
        int scale = 0, firstScale = loadAt;
        String index = idx;
        Address setup = null;
        for (int k = loadAt-1; k >= 0; k--) {
            Instruction q = slice.get(k); String t = compact(q);
            if (t.startsWith("MOV"+idx+",0X")) {
                // Before scaling this is the index's initial value, whereas
                // an unscaled register receiving a constant holds the base.
                if(scale==0 || !index.equals(idx)) { base += immediate(t); constant=true; }
                setup=q.getAddress(); break;
            }
            if (t.startsWith("LEA"+idx+",[0X")) { base += immediate(t); constant = true; setup = q.getAddress(); break; }
            if (t.startsWith("ADD"+idx+",0X")) { base += immediate(t); constant = true; setup = q.getAddress(); continue; }
            if (t.matches("ADD"+idx+",(BX|CX|DX|AX|SI|DI|BP)") && !t.equals("ADD"+idx+","+idx)) {
                index = t.substring(t.indexOf(',')+1); setup = q.getAddress(); continue;
            }
            if (t.equals("ADD"+idx+","+idx) || t.equals("SHL"+idx+",1") || t.equals("SHL"+idx+",0X1") ||
                width == 4 && (t.equals("SHL"+idx+",0X2") || t.equals("SHL"+idx+",2"))) {
                scale += t.endsWith(",2") || t.endsWith(",0X2") ? 2 : 1;
                firstScale = Math.min(firstScale,k); setup = q.getAddress(); continue;
            }
            if (WSJumpTables.writesReg(q, t, idx, program.getRegister(idx))) {
                // The source index load is part of the dispatcher setup.
                if (t.startsWith("MOV") || t.startsWith("XOR")) setup = q.getAddress();
                break;
            }
        }
        if (!index.equals(idx)) {
            for (int k = 0; k < loadAt; k++) {
                String t = compact(slice.get(k));
                if (t.equals("SHL"+index+",1") || t.equals("SHL"+index+",0X1") || t.equals("ADD"+index+","+index) ||
                    width == 4 && (t.equals("SHL"+index+",2") || t.equals("SHL"+index+",0X2"))) {
                    scale += t.endsWith(",2") || t.endsWith(",0X2") ? 2 : 1;
                    firstScale = Math.min(firstScale,k);
                }
            }
        }
        if (!constant || scale != (width == 4 ? 2 : 1) || setup == null) return null;
        // Prefer the earlier byte-index load/clear immediately before scaling.
        int sk = 0;
        while (sk < slice.size() && !slice.get(sk).getAddress().equals(setup)) sk++;
        for (int k = sk-1; k >= Math.max(0, sk-2); k--) {
            Instruction q = slice.get(k); String t = compact(q);
            String low = index.length()==2 && index.endsWith("X") ? index.charAt(0)+"L" : index;
            String high = index.length()==2 && index.endsWith("X") ? index.charAt(0)+"H" : index;
            if (t.startsWith("MOV"+low+",") || t.equals("XOR"+high+","+high)) setup=q.getAddress(); else break;
        }
        int count = -1; String bound = "plausible-target-run";
        for (int k = 0; k+1 < firstScale; k++) {
            Instruction q = slice.get(k); String t = compact(q);
            if (!t.startsWith("CMP"+index+",0X")) continue;
            boolean clobbered=false;
            for(int z=k+2;z<firstScale;z++) {
                Instruction between=slice.get(z);
                if(WSJumpTables.writesReg(between,compact(between),index,program.getRegister(index))) clobbered=true;
            }
            if(clobbered) continue;
            String branch = slice.get(k+1).getMnemonicString();
            if (branch.equals("JA") || branch.equals("JBE")) count = immediate(t)+1;
            else if (branch.equals("JNC") || branch.equals("JAE") || branch.equals("JC") || branch.equals("JB")) count = immediate(t);
            else continue;
            // Only a branch away from the dispatch fallthrough is a bound.
            if (!branch.equals("JA") && !branch.equals("JNC") && !branch.equals("JAE")) { count=-1; continue; }
            bound = q + "; " + slice.get(k+1);
            if(q.getAddress().compareTo(setup)<0) setup=q.getAddress();
            break;
        }
        if (count > 256 || count == 0) return null;
        Address table = segmented(site.getAddress(), segment, base);
        if (runOf(table) == null) return null;
        if (listing.getInstructionAt(site.getAddress()) == null && Math.abs(table.subtract(site.getAddress())) > 4096) return null;
        List<Address> targets = new ArrayList<>();
        String stop = "cap"; long min = Long.MAX_VALUE, max = Long.MIN_VALUE;
        for (int k = 0; k < (count < 0 ? 256 : count); k++) {
            Address slot = table.add((long)width*k);
            Address slotEnd = slot.add(width-1);
            if (targets.stream().anyMatch(t -> t.compareTo(slot)>=0 && t.compareTo(slotEnd)<=0)) { stop="own-target"; break; }
            boolean slotOK = true;
            for (int z=0; z<width; z++) {
                Address q=slot.add(z); long ro=romOffset(q);
                if (ro<0 || codeBytes.contains(ro) || listing.getInstructionContaining(q)!=null) slotOK=false;
            }
            if (!slotOK) { stop="slot-not-data"; break; }
            int off = memory.getShort(slot)&0xffff;
            int seg = far ? memory.getShort(slot.add(2))&0xffff : segment;
            Address target = segmented(site.getAddress(), seg, off);
            MemoryBlock block = memory.getBlock(target);
            Instruction existing = listing.getInstructionContaining(target);
            if (block==null || !block.isExecute() || !block.isInitialized() || runOf(target)==null ||
                WonderSwanLoader.isDataOverlay(block) || target.equals(slot) ||
                existing!=null && !existing.getAddress().equals(target) ||
                existing==null && !unknown(target)) { stop="implausible-target"; break; }
            try { if (existing==null) decode(target, seg); }
            catch (Exception ex) { stop="undecodable-target"; break; }
            if (count<0 && !targets.isEmpty() && Math.abs(target.getOffset()-targets.get(targets.size()-1).getOffset())>8192) {
                stop="target-cluster-end"; break;
            }
            min=Math.min(min,target.getOffset()); max=Math.max(max,target.getOffset());
            if (count<0 && max-min>32768) { stop="target-cluster-end"; break; }
            targets.add(target);
        }
        if (count>=0 && targets.size()!=count || count<0 && (targets.size()<3 || stop.equals("cap"))) return null;
        if ((base & 0xffff) + targets.size()*width > 0x10000) return null;
        Address end = table.add((long)targets.size()*width-1);
        for (Address target : targets) if (target.getAddressSpace().equals(table.getAddressSpace()) &&
            target.compareTo(table)>=0 && target.compareTo(end)<=0) return null;
        return new Table(site.getAddress(),setup,table,width,List.copyOf(targets),bound,count>=0 ? "index-limit" : stop);
    }

    private void recoverTables() throws Exception {
        List<Table> found = new ArrayList<>();
        for (Run run : runs) {
            byte[] raw=run.raw();
            for (int k=0;k+2<raw.length;k++) {
                int b=raw[k]&255;
                boolean memorySite = b==0x2e && raw[k+1]==(byte)0xff && ((raw[k+2]>>3)&7)>=2 && ((raw[k+2]>>3)&7)<=5;
                boolean registerCall = b==0xff && (raw[k+1]&0xf8)==0xd0;
                if (!memorySite && !registerCall) continue;
                Address site=addrOf(run,k);
                if (tables.containsKey(site) || tableAttempts.contains(site)) continue;
                if (!unknown(site) && listing.getInstructionAt(site)==null) continue;
                int segment=cs(site); if(segment<0) continue;
                Instruction ins;
                try { ins=listing.getInstructionAt(site); if(ins==null) ins=decode(site,segment); }
                catch(Exception ex) { continue; }
                if (!ins.getFlowType().isComputed() || !(ins.getFlowType().isCall() || ins.getFlowType().isJump())) continue;
                for (List<Instruction> slice : slices(site,run,segment)) {
                    Table table;
                    try { table=describeTable(ins,slice,segment); } catch(Exception ex) { continue; }
                    if(table==null) continue;
                    tables.put(site,table);
                    List<Long> reserved=new ArrayList<>();
                    for(int z=0;z<table.targets().size()*table.width();z++) {
                        long ro=romOffset(table.base().add(z));
                        if(reservedData.add(ro)) reserved.add(ro);
                    }
                    try {
                        if(listing.getInstructionAt(site)==null) {
                            Run setupRun=runOf(table.setup());
                            walk(table.setup(),site,segment,setupRun);
                        }
                        found.add(table); tableAttempts.add(site); break;
                    } catch(Exception ex) {
                        tables.remove(site); reservedData.removeAll(reserved);
                    }
                }
            }
        }
        // Any proven dispatch target is code, including a target of another
        // table. Establish these boundaries globally before defining slots.
        Set<Long> entries = new HashSet<>();
        for (Table table : tables.values()) for(Address target : table.targets()) entries.add(romOffset(target));
        for (int n=0; n<found.size(); n++) {
            Table table=found.get(n); int limit=table.targets().size();
            for(int k=0; k<limit; k++) {
                Address slot=table.base().add((long)k*table.width());
                for(int z=0; z<table.width(); z++)
                    if(entries.contains(romOffset(slot.add(z)))) { limit=k; break; }
            }
            if(limit == 0 || limit < table.targets().size() && !table.bound().equals("plausible-target-run")) {
                tables.remove(table.site()); found.remove(n--); continue;
            }
            if(limit < table.targets().size()) {
                Table trimmed=new Table(table.site(),table.setup(),table.base(),table.width(),
                    List.copyOf(table.targets().subList(0,limit)),table.bound(),"dispatch-target-boundary");
                found.set(n,trimmed); tables.put(table.site(),trimmed);
            }
        }
        reservedData.clear();
        for(Table table : tables.values())
            for(int z=0;z<table.targets().size()*table.width();z++) reservedData.add(romOffset(table.base().add(z)));
        // Recheck provisional dispatcher walks against every reserved object.
        // Discovery must not commit code before a later table can veto it.
        for (Iterator<Table> it=found.iterator();it.hasNext();) {
            Table table=it.next();
            if(listing.getInstructionAt(table.site())!=null) continue;
            try { walk(table.setup(),table.site(),cs(table.site()),runOf(table.setup())); }
            catch(Reject ex) { tables.remove(table.site()); it.remove(); }
        }
        reservedData.clear();
        for(Table table : tables.values())
            for(int z=0;z<table.targets().size()*table.width();z++) reservedData.add(romOffset(table.base().add(z)));
        // Mark all discovered objects before walking any target. This ordering
        // also protects tables discovered in aliases of the same ROM bytes.
        for(Table table : found) {
            for(int k=0;k<table.targets().size();k++) {
                Address slot=table.base().add((long)k*table.width());
                boolean undef=true;
                for(int z=0;z<table.width();z++) {
                    CodeUnit u=listing.getCodeUnitContaining(slot.add(z));
                    if(!(u instanceof Data d) || d.isDefined()) undef=false;
                }
                if(undef) listing.createData(slot,new PointerDataType(null,table.width(),program.getDataTypeManager()),table.width());
                for(int z=0;z<table.width();z++) definedData.add(romOffset(slot.add(z)));
                program.getReferenceManager().addMemoryReference(slot,table.targets().get(k),RefType.DATA,SourceType.ANALYSIS,0);
            }
            emit.accept(String.format("{\"rule\":\"static-table\",\"event\":\"table\",\"site\":\"%s\",\"setup\":\"%s\",\"table_start\":\"%s\",\"table_end\":\"%s\",\"rom_start\":\"%06x\",\"rom_end\":\"%06x\",\"width\":%d,\"entries\":%d,\"bound\":\"%s\",\"stop\":\"%s\",\"targets\":%s}",
                table.site(),table.setup(),table.base(),table.base().add((long)table.width()*table.targets().size()-1),
                romOffset(table.base()),romOffset(table.base())+table.width()*table.targets().size(),table.width(),table.targets().size(),
                table.bound(),table.stop(),table.targets().stream().map(a->"\""+a+"\"").toList()));
        }
        for(Table table : found) {
            if(!unknown(table.setup()) || listing.getInstructionAt(table.site())!=null) continue;
            int segment=cs(table.site());
            Walk dispatch=walk(table.setup(),table.site(),segment,runOf(table.setup()));
            commit(new Start(table.setup(),"table-dispatch"),table.site(),segment,dispatch);
        }
        for(Table table : tables.values()) for(Address target : new LinkedHashSet<>(table.targets())) {
            if(!unknown(target)) continue;
            int segment=table.width()==2 ? cs(table.site()) : target instanceof SegmentedAddress sa ? sa.getSegment() : cs(target);
            try { commit(new Start(target,"table-pointer"),null,segment,walk(target,null,segment,runOf(target))); }
            catch(Reject ex) { emit.accept(String.format("{\"rule\":\"static-table\",\"event\":\"target-reject\",\"site\":\"%s\",\"target\":\"%s\",\"reason\":\"%s\"}",table.site(),target,ex.getMessage())); }
        }
    }

    private void run() throws Exception {
        while (true) {
            monitor.checkCancelled(); passes++;
            known.clear();
            for (Function f : program.getFunctionManager().getFunctions(true)) known.add(f.getEntryPoint());
            int before = accepted;
            recoverTables();
            Set<Address> tried = new HashSet<>();
            for (Run run : runs) {
                byte[] raw = run.raw();
                for (int k = 0; k < raw.length; k++) {
                    monitor.checkCancelled();
                    int opcode = raw[k] & 255;
                    if (opcode != 0x9a && opcode != 0xe8) continue;
                    int size = opcode == 0x9a ? 5 : 3;
                    if (k + size > raw.length) continue;
                    Address anchor = addrOf(run, k);
                    if (!unknown(anchor)) continue;
                    int segment = cs(anchor);
                    if (segment < 0) {
                        rejects.merge("unknown-code-segment", 1, Integer::sum);
                        logReject(anchor, null, 0, "unknown-code-segment");
                        continue;
                    }
                    PseudoInstruction call;
                    try { call = decode(anchor, segment); }
                    catch (Exception ex) { continue; }
                    if (!call.getFlowType().isCall() || Arrays.stream(call.getFlows()).noneMatch(known::contains)) {
                        logReject(anchor, null, 0, "anchor-not-known-call");
                        continue;
                    }
                    candidates++;
                    List<Start> possible = starts(run, k, segment);
                    if (possible.isEmpty()) logReject(anchor, null, 0, "no-routine-start");
                    for (Start start : possible) {
                        if (!tried.add(start.address()) || !unknown(start.address())) {
                            logReject(anchor, start, 0, "already-tried-or-defined");
                            continue;
                        }
                        try {
                            Walk walk = walk(start.address(), anchor, segment, run);
                            commit(start, anchor, segment, walk);
                            break;
                        } catch (Reject ex) {
                            rejects.merge(ex.getMessage(), 1, Integer::sum);
                            logReject(anchor, start, ex.evidenceCount, ex.getMessage());
                        }
                    }
                }
            }
            emit.accept(String.format("{\"rule\":\"static-call\",\"pass\":%d,\"accepted_total\":%d}", passes, accepted));
            if (accepted == before) break;
        }
    }

    // Evidence counts are known-entry calls in the partial trial walk. A zero
    // count means the anchor was filtered or no trial instructions reached it.
    private void logReject(Address anchor, Start start, int evidenceCount, String reason) {
        emit.accept(String.format("{\"rule\":\"static-call\",\"event\":\"reject\",\"pass\":%d,\"anchor\":\"%s\",\"candidate_start\":%s,\"start_evidence\":%s,\"evidence_count\":%d,\"reject_reason\":\"%s\"}",
            passes, anchor, start == null ? "null" : "\"" + start.address() + "\"",
            start == null ? "null" : "\"" + start.evidence() + "\"", evidenceCount, reason));
    }

    // Erased flash reads back as FF. A run of two or more FF bytes can never
    // start a valid instruction (FF FF decodes no GRP5 subcode), so inter-
    // routine fill is stepping-stone, never code. Returns the first index
    // past the run, or k when raw[k] does not open a fill run.
    private static int fillEnd(byte[] raw, int k) {
        if (k + 1 >= raw.length || raw[k] != (byte)0xff || raw[k+1] != (byte)0xff) return k;
        int j = k + 2;
        while (j < raw.length && raw[j] == (byte)0xff) j++;
        return j;
    }

    private List<Start> starts(Run run, int at, int segment) throws Exception {
        List<Start> frames = new ArrayList<>(), savesFound = new ArrayList<>(), boundaries = new ArrayList<>();
        Map<Address, Integer> saveWidths = new HashMap<>();
        byte[] raw = run.raw();
        for (int k = at; k >= Math.max(0, at-BACKWARD_BYTES); k--) {
            Address a = addrOf(run, k);
            if (!unknown(a)) break;
            int runEnd = fillEnd(raw, k);
            if (runEnd != k) {
                // Fill bytes hold no routine entry, but a terminator ending
                // exactly at the run start supports the code after the fill.
                if ((k == 0 || raw[k-1] != (byte)0xff) && runEnd < raw.length) {
                    Address after = addrOf(run, runEnd);
                    Instruction before = listing.getInstructionContaining(a.subtract(1));
                    if (before != null && before.getMaxAddress().next().equals(a) && !before.hasFallthrough())
                        boundaries.add(new Start(after, "terminator-after-fill"));
                    for (int len : new int[] {1, 2, 3, 5}) {
                        int q = k-len;
                        if (q < 0) continue;
                        try {
                            String evidence = terminalEvidence(run, q, len, segment);
                            if (evidence != null) boundaries.add(new Start(after, evidence + "-after-fill"));
                        } catch (Exception ex) { /* not a boundary */ }
                    }
                }
                continue;
            }
            if (k+2 < raw.length && raw[k] == 0x55 &&
                ((raw[k+1] == (byte)0x89 && raw[k+2] == (byte)0xe5) ||
                 (raw[k+1] == (byte)0x8b && raw[k+2] == (byte)0xec)))
                frames.add(new Start(a, "frame-prologue"));
            // Match a complete save sequence observed at an existing entry.
            // A generic run can absorb an opcode-shaped table byte before code.
            int saves = 0, width = 0;
            boolean all = false;
            StringBuilder profile = new StringBuilder();
            while (k+width < raw.length && width < 12) {
                int op = raw[k+width] & 255;
                if (op == 0x60) { saves += 2; all = true; }
                else if (op >= 0x50 && op <= 0x57 && op != 0x54 || op == 0x06 || op == 0x0e || op == 0x16 || op == 0x1e) saves++;
                else break;
                profile.append(String.format("%02x", op));
                width++;
            }
            if (saves >= 3 && (width >= 3 || all) && saveProfiles.contains(profile.toString())) {
                savesFound.add(new Start(a, "known-save-prologue")); saveWidths.put(a, width);
            }
            for (Reference ref : program.getReferenceManager().getReferencesTo(a)) {
                if (ref.getReferenceType().isFlow() && listing.getInstructionAt(ref.getFromAddress()) != null) {
                    boundaries.add(new Start(a, "code-reference")); break;
                }
            }
            Instruction previous = listing.getInstructionContaining(a.subtract(1));
            if (previous != null && previous.getMaxAddress().next().equals(a) && !previous.hasFallthrough())
                boundaries.add(new Start(a, "defined-terminator"));
            // The boundary is supporting evidence, never a seed by itself: the
            // forward walk must actually reach the known-call anchor and end.
            for (int len : new int[] {1, 2, 3, 5}) {
                int q = k-len;
                if (q < 0) continue;
                try {
                    String evidence = terminalEvidence(run, q, len, segment);
                    if (evidence != null) boundaries.add(new Start(a, evidence));
                } catch (Exception ex) { /* not a boundary */ }
            }
        }
        savesFound.sort(Comparator.comparingInt((Start s) -> saveWidths.get(s.address())).reversed());
        frames.addAll(savesFound); frames.addAll(boundaries);
        return frames;
    }

    private static boolean isSave(int op) {
        return op == 0x60 || op >= 0x50 && op <= 0x57 && op != 0x54 ||
            op == 0x06 || op == 0x0e || op == 0x16 || op == 0x1e;
    }

    private String terminalEvidence(Run run, int q, int len, int segment) throws Exception {
        byte[] raw = run.raw();
        int op = raw[q] & 255;
        if (!((len == 1 && (op == 0xc3 || op == 0xcb)) ||
              (len == 2 && op == 0xeb) ||
              (len == 3 && (op == 0xc2 || op == 0xca || op == 0xe9)) ||
              (len == 5 && op == 0xea))) return null;
        PseudoInstruction term = decode(addrOf(run, q), segment);
        if (term.getLength() == len && (term.getFlowType().isTerminal() ||
            term.getFlowType().isJump() && term.getFlowType().isUnConditional()) &&
            !term.hasFallthrough() && !term.getFlowType().isComputed() &&
            boundaryAligned(run, q, segment))
            return term.getFlowType().isJump() ? "aligned-jump-boundary" : "aligned-return-boundary";
        return null;
    }

    private boolean boundaryAligned(Run run, int at, int segment) {
        // A boundary byte alone does not establish its alignment. Decode from
        // the nearest existing instruction or a frame prologue before it.
        byte[] raw = run.raw();
        Address boundary = addrOf(run, at);
        Instruction previous = listing.getInstructionBefore(boundary);
        List<Integer> origins = new ArrayList<>();
        if (previous != null) {
            int o = indexOf(run, previous.getAddress());
            if (o >= 0 && at - o <= BACKWARD_BYTES) origins.add(o);
        }
        for (int k = at-1; k >= Math.max(0, at-BACKWARD_BYTES); k--)
            if (k+2 < raw.length && raw[k] == 0x55 &&
                ((raw[k+1] == (byte)0x89 && raw[k+2] == (byte)0xe5) ||
                 (raw[k+1] == (byte)0x8b && raw[k+2] == (byte)0xec))) {
                origins.add(k); break;
            }
        for (int origin : origins) {
            int j = origin;
            try {
                while (j < at) {
                    int runEnd = fillEnd(raw, j);
                    if (runEnd != j) {
                        for (int t = j; t < runEnd; t++) {
                            long ro = romOffset(addrOf(run, t));
                            if (definedData.contains(ro)) throw new Reject("data-before-boundary");
                        }
                        j = runEnd;
                        continue;
                    }
                    PseudoInstruction i = decode(addrOf(run, j), segment);
                    for (int k = 0; k < i.getLength(); k++) {
                        long ro = romOffset(addrOf(run, j + k));
                        if (definedData.contains(ro)) throw new Reject("data-before-boundary");
                    }
                    j += i.getLength();
                }
                if (j == at) return true;
            } catch (Exception ex) { /* try another aligned origin */ }
        }
        return false;
    }

    private Walk walk(Address start, Address anchor, int segment, Run run) throws Exception {
        int[] evidenceCount = {0};
        try {
            return trialWalk(start, anchor, segment, run, evidenceCount);
        } catch (Reject ex) {
            ex.evidenceCount = evidenceCount[0];
            throw ex;
        }
    }

    private Walk trialWalk(Address start, Address anchor, int segment, Run run, int[] evidenceCount) throws Exception {
        TreeMap<Address, PseudoInstruction> code = new TreeMap<>();
        AddressSet body = new AddressSet();
        Set<Address> ends = new HashSet<>(), transfers = new HashSet<>();
        Map<Address, Set<Address>> edges = new HashMap<>();
        Deque<Address> queue = new ArrayDeque<>(); queue.add(start);
        while (!queue.isEmpty()) {
            monitor.checkCancelled(); Address a = queue.removeFirst();
            if (code.containsKey(a) || ends.contains(a)) continue;
            if (body.contains(a)) throw new Reject("transfer-into-operand");
            if (listing.getInstructionAt(a) != null) { ends.add(a); continue; }
            if (!run.range().contains(a)) throw new Reject("unresolved-cross-block-flow");
            if (!unknown(a)) throw new Reject("defined-overlap");
            if (code.size() >= MAX_INSTRUCTIONS) throw new Reject("region-limit");
            PseudoInstruction i;
            try { i = decode(a, segment); }
            catch (Exception ex) { throw new Reject("invalid-or-undefined"); }
            if (!run.range().contains(i.getMaxAddress())) throw new Reject("cross-block-instruction");
            for (int k = 0; k < i.getLength(); k++) {
                Address q = a.add(k);
                if (!unknown(q) || body.contains(q)) throw new Reject("defined-or-trial-overlap");
            }
            String text = i.toString().toUpperCase().replace(" ", "");
            if (WEAK_OPCODES.contains(i.getMnemonicString()) || text.startsWith("LOCK"))
                throw new Reject("weak-opcode-evidence");
            byte[] raw = i.getBytes();
            if (raw.length == 2 && raw[0] == 0 && raw[1] == 0)
                throw new Reject("zero-fill-instruction");
            if (text.matches("(MOV|POP)CS.*")) throw new Reject("code-segment-write");
            var flow = i.getFlowType();
            // An immediate software interrupt transfers through a fixed
            // vector table and returns to its fallthrough like a call. The
            // language models it as an indirect call, but the destination
            // carries no data dependence, so it is opaque to the trial walk
            // rather than an unresolvable computed transfer.
            byte[] encoded = i.getBytes();
            boolean softInterrupt = flow.isComputed() && flow.isCall() && !flow.isJump()
                && i.getMnemonicString().equals("INT") && encoded.length == 2 && encoded[0] == (byte)0xcd;
            Table table = tables.get(a);
            boolean resolvedTable = flow.isComputed() && table != null;
            if (flow.isComputed() && !softInterrupt && !resolvedTable) throw new Reject("computed-transfer");
            code.put(a, i); body.add(a, i.getMaxAddress());
            if (flow.isCall() && Arrays.stream(i.getFlows()).anyMatch(known::contains)) evidenceCount[0]++;
            Set<Address> next = new HashSet<>(); edges.put(a, next);
            Address[] targets = i.getFlows();
            if ((flow.isCall() || flow.isJump()) && !softInterrupt && !resolvedTable) {
                if (targets.length == 0) throw new Reject("unresolved-transfer");
                for (Address target : targets) {
                    transfers.add(target);
                    if (flow.isJump() && encoded[0] == (byte)0xea && listing.getInstructionAt(target) == null)
                        throw new Reject("unresolved-far-jump-context");
                    if (flow.isJump()) { next.add(target); queue.add(target); }
                    else if (listing.getInstructionAt(target) == null && !unknown(target))
                        throw new Reject("call-not-start-or-unknown");
                }
            }
            if (resolvedTable && flow.isJump()) {
                // A proven finite dispatch is an end of this fragment. Its
                // destinations are each checked by this same strict walk.
                ends.add(a);
            } else if (flow.isTerminal()) {
                if (!i.getMnemonicString().startsWith("RET") && !i.getMnemonicString().equals("IRET"))
                    throw new Reject("non-return-terminal");
                ends.add(a);
            } else if (i.getFallThrough() != null) {
                next.add(i.getFallThrough()); queue.add(i.getFallThrough());
            } else if (!flow.isJump()) throw new Reject("no-flow-end");
        }
        if (anchor != null) {
            if (!code.containsKey(anchor)) throw new Reject("anchor-not-reached");
            PseudoInstruction call = code.get(anchor);
            if (!tables.containsKey(anchor) && (!call.getFlowType().isCall() ||
                Arrays.stream(call.getFlows()).noneMatch(known::contains)))
                throw new Reject("anchor-not-known-call");
        }
        for (Address target : transfers)
            if (body.contains(target) && !code.containsKey(target)) throw new Reject("transfer-into-operand");
        // Reverse reachability requires a flow end even for a branch cycle.
        Set<Address> reachesEnd = new HashSet<>(ends);
        boolean changed;
        do {
            changed = false;
            for (var e : edges.entrySet())
                if (e.getValue().stream().anyMatch(reachesEnd::contains)) changed |= reachesEnd.add(e.getKey());
        } while (changed);
        if (!reachesEnd.containsAll(code.keySet())) throw new Reject("no-flow-end");
        // Incoming references cannot silently become references into new operands.
        for (Address a : body.getAddresses(true)) {
            if (!code.containsKey(a) && program.getReferenceManager().getReferencesTo(a).hasNext())
                throw new Reject("incoming-reference-into-operand");
        }
        return new Walk(code, body, ends, edges, transfers);
    }

    private void commit(Start start, Address anchor, int segment, Walk walk) throws Exception {
        // Insert precisely the trial instructions. Never launch unrestricted flow
        // disassembly, which could claim unvalidated callees or branch targets.
        for (PseudoInstruction i : walk.code().values()) {
            Address a = i.getAddress();
            // A walk may span contiguous blocks; each address commits under its
            // own block segment so later analysis resolves it like the loader.
            // Near-target math is invariant under the trial segment, but segment-
            // relative operands are re-decoded so committed semantics match.
            int seg = segOf(a);
            if (seg < 0) seg = segment;
            context.setValue(csval, a, i.getMaxAddress(), BigInteger.valueOf(seg));
            context.setValue(hwundef, a, i.getMaxAddress(), BigInteger.ZERO);
            PseudoInstruction use = i;
            if (seg != segment) {
                try {
                    PseudoInstruction fresh = decode(a, seg);
                    if (fresh.getLength() == i.getLength() &&
                        Arrays.equals(fresh.getBytes(), i.getBytes())) use = fresh;
                } catch (Exception ex) { /* keep the validated trial decode */ }
            }
            Instruction inserted = listing.createInstruction(a, use.getPrototype(), use, use.getProcessorContext(), 0);
            provenance.add(a, inserted.getLength()); index(inserted);
            instructions++; bytes += inserted.getLength();
        }
        Function f = program.getFunctionManager().getFunctionAt(start.address());
        boolean routine = !start.evidence().equals("aligned-jump-boundary") && !start.evidence().equals("code-reference");
        // A validated code fragment can intersect an existing function's body
        // even when its first instruction lies outside that body. Preserve the
        // code and its provenance without inventing an overlapping function.
        boolean overlaps = program.getFunctionManager().getFunctionsOverlapping(walk.body()).hasNext();
        if (f == null && routine && !overlaps)
            try {
                f = program.getFunctionManager().createFunction(null, start.address(), walk.body(), SourceType.ANALYSIS);
            } catch (Exception ex) {
                rejects.merge("function-create-failed", 1, Integer::sum);
            }
        if (f != null) { f.addTag(PROPERTY); known.add(f.getEntryPoint()); }
        program.getBookmarkManager().setBookmark(start.address(), BookmarkType.ANALYSIS, PROPERTY,
            "Static call evidence; " + start.evidence() + "; no execution observation");
        accepted++;
        StringBuilder ranges = new StringBuilder();
        for (AddressRange range : walk.body()) {
            if (!ranges.isEmpty()) ranges.append(',');
            ranges.append('"').append(range.getMinAddress()).append('-').append(range.getMaxAddress()).append('"');
        }
        emit.accept(String.format("{\"rule\":\"static-call\",\"start\":\"%s\",\"anchor\":\"%s\",\"start_evidence\":\"%s\",\"instructions\":%d,\"bytes\":%d,\"classification\":\"static-unexecuted\",\"ranges\":[%s]}",
            start.address(), anchor, start.evidence(), walk.code().size(), walk.body().getNumAddresses(), ranges));
    }
}
