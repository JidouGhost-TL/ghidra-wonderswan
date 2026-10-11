// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** Z1: long homogeneous byte runs are fill unless execution or explicit user code protects them. */
public final class WSFillRuns {
    public static final String CATEGORY = "WSFillRun", PROPERTY = "WS_FILL_RUN", EDGES = "WS_FILL_EDGE";
    public static final int ZERO_FF_MIN = 64, OTHER_MIN = 256;
    private WSFillRuns() { }

    private static Address transferTarget(Instruction i) {
        // Listing flows can still describe the encoded target after an imported
        // flow override has rebound it to an initialized RAM image.
        for (Reference ref : i.getReferencesFrom())
            if (ref.isPrimary() && (ref.getReferenceType() == RefType.JUMP_OVERRIDE_UNCONDITIONAL
                || ref.getReferenceType() == RefType.CALL_OVERRIDE_UNCONDITIONAL)) return ref.getToAddress();
        return i.getFlows().length == 1 ? i.getFlows()[0] : null;
    }

    private static AddressSet protectedCode(Program p) throws Exception {
        AddressSet proof = new AddressSet();
        var maps = p.getUsrPropertyManager();
        for (String name : new String[]{WSRomEvidence.STARTS, WSRomEvidence.CODE}) {
            var map = maps.getIntPropertyMap(name);
            if (map == null) continue;
            for (var it = map.getPropertyIterator(); it.hasNext();) {
                Address a = it.next();
                int length = name.equals(WSRomEvidence.CODE) ? Math.max(1, map.getInt(a)) : 1;
                proof.add(a, a.add(length - 1));
            }
        }
        for (Function f : p.getFunctionManager().getFunctions(true))
            if (f.getSymbol().getSource() == SourceType.USER_DEFINED
                || f.getSignatureSource() == SourceType.USER_DEFINED
                || f.getSignatureSource() == SourceType.IMPORTED) proof.add(f.getBody());
        return proof;
    }

    private static boolean executed(Program p, WSEvidence ev, AddressSetView range, AddressSetView proof) {
        if (proof.intersects(range)) return true;
        if (ev != null) for (Address a : range.getAddresses(true))
            if (WSRomEvidence.executed(p, ev, a)) return true;
        return false;
    }

    private static Address boundary(Program p, AddressRange range) throws Exception {
        String name = "WS_FILL_BOUNDARY_" + range.getMinAddress().getAddressSpace().getName();
        MemoryBlock block = p.getMemory().getBlock(name);
        if (block == null) {
            // Ghidra real-mode spaces extend above the CPU's 20-bit bus. Reserve an empty
            // analysis destination there, in the same code space, so independent pseudo-
            // decoding stops with unknown flow rather than consuming the fill or inventing
            // a return. The bytes and mappings in the CPU's addressable image are untouched.
            AddressSpace space = range.getMinAddress().getAddressSpace();
            // Overlay getAddress falls back to the physical space outside its mapped
            // ranges. Keep this new stop in the code overlay even before it is mapped.
            Address a = space instanceof OverlayAddressSpace overlay
                ? overlay.getAddressInThisSpaceOnly(0x100000) : space.getAddress(0x100000);
            if (p.getMemory().contains(a)) throw new IllegalStateException("analysis boundary address is occupied");
            block = p.getMemory().createUninitializedBlock(name, a, 1, false);
            block.setPermissions(true, false, false);
            block.setComment("Analysis-only stop for unexecuted fill; outside the 20-bit CPU bus; no instruction image");
            p.getSymbolTable().createLabel(block.getStart(), name.toLowerCase(Locale.ROOT), SourceType.ANALYSIS);
        }
        return block.getStart();
    }

    /** New execution evidence reopens previously classified fill before normal code seeding. */
    public static int restoreExecuted(Program p, WSEvidence ev, Consumer<String> emit) throws Exception {
        var map = p.getUsrPropertyManager().getIntPropertyMap(PROPERTY);
        if (map == null || ev == null) return 0;
        AddressSet restored = new AddressSet();
        List<Address> starts = new ArrayList<>();
        for (var it = map.getPropertyIterator(); it.hasNext();) starts.add(it.next());
        for (Address start : starts) {
            Address end = start.add(map.getInt(start) - 1);
            AddressSet range = new AddressSet(start, end);
            if (!executed(p, ev, range, new AddressSet())) continue;
            p.getListing().clearCodeUnits(start, end, false);
            map.remove(start); restored.add(range);
            Bookmark old = p.getBookmarkManager().getBookmark(start, BookmarkType.ANALYSIS, CATEGORY);
            if (old != null) p.getBookmarkManager().removeBookmark(old);
            emit.accept(String.format("{\"rule\":\"Z1\",\"start\":\"%s\",\"end\":\"%s\",\"outcome\":\"EXECUTION_REOPENS_FILL\"}",start,end));
        }
        var edges = p.getUsrPropertyManager().getIntPropertyMap(EDGES);
        if (edges != null && !restored.isEmpty()) {
            List<Address> sites = new ArrayList<>();
            for (var it = edges.getPropertyIterator(); it.hasNext();) sites.add(it.next());
            for (Address site : sites) {
                Instruction i = p.getListing().getInstructionAt(site);
                if (i == null) continue;
                int flags = edges.getInt(site);
                if ((flags & 1) != 0 && restored.contains(i.getDefaultFallThrough())) {
                    i.clearFallThroughOverride(); flags &= ~1;
                }
                if ((flags & 2) != 0 && i.getFlowOverride() == FlowOverride.CALL_RETURN)
                    for (Address target : i.getDefaultFlows()) if (restored.contains(target)) {
                        i.setFlowOverride(FlowOverride.NONE); flags &= ~2; break;
                    }
                if (flags == 0) edges.remove(site); else edges.add(site, flags);
            }
        }
        return restored.getNumAddressRanges();
    }

    public static String apply(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        Listing listing = p.getListing();
        AddressSet fill = new AddressSet(), reached = new AddressSet();
        AddressSet proof = protectedCode(p);
        for (Instruction i : listing.getInstructions(true)) {
            reached.add(i.getMinAddress(), i.getMaxAddress());
            if (i.getFallThrough() != null) reached.add(i.getFallThrough());
            for (Address flow : i.getFlows()) reached.add(flow);
        }
        // An automatic entry is a code hypothesis even if erased bytes never decoded.
        // Include it in the existing fill test; execution and explicit code still win.
        for (Function f : p.getFunctionManager().getFunctions(true)) reached.add(f.getEntryPoint());
        int runs = 0, preserved = 0, cleared = 0, removed = 0, split = 0, edges = 0;
        for (MemoryBlock block : p.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || !block.isExecute() || WonderSwanLoader.isDataOverlay(block)
                || WSRamCode.hasImage(p, block.getStart()) || block.getSize() > Integer.MAX_VALUE) continue;
            byte[] bytes = new byte[(int)block.getSize()];
            p.getMemory().getBytes(block.getStart(), bytes);
            for (int start = 0; start < bytes.length;) {
                int end = start + 1;
                while (end < bytes.length && bytes[end] == bytes[start]) end++;
                int value = bytes[start] & 255, threshold = value == 0 || value == 255 ? ZERO_FF_MIN : OTHER_MIN;
                if (end - start >= threshold) {
                    Address lo = block.getStart().add(start), hi = block.getStart().add(end - 1);
                    // The first repeated byte may be the last operand of the preceding
                    // instruction. Keep that complete instruction; only classify whole decode
                    // units inside the homogeneous run, including when the prefix executed.
                    Instruction first = listing.getInstructionContaining(lo);
                    if (first != null && !first.getAddress().equals(lo)) lo = first.getMaxAddress().next();
                    Instruction last = listing.getInstructionContaining(hi);
                    if (last != null && last.getMaxAddress().compareTo(hi) > 0) hi = last.getAddress().previous();
                    if (lo.compareTo(hi) > 0 || hi.subtract(lo) + 1 < threshold) { start = end; continue; }
                    AddressSet range = new AddressSet(lo, hi);
                    if (reached.intersects(range)) {
                        if (executed(p, ev, range, proof)) {
                            preserved++;
                            emit.accept(String.format("{\"rule\":\"Z1\",\"start\":\"%s\",\"end\":\"%s\",\"byte\":%d,\"outcome\":\"PROTECTED_CODE\"}",lo,hi,value));
                        } else {
                            fill.add(range); runs++;
                            p.getBookmarkManager().setBookmark(lo, BookmarkType.ANALYSIS, CATEGORY,
                                String.format("Unexecuted fill byte %02x, %d bytes; speculative flow stopped",value,end-start));
                            emit.accept(String.format("{\"rule\":\"Z1\",\"start\":\"%s\",\"end\":\"%s\",\"byte\":%d,\"run_bytes\":%d,\"outcome\":\"FILL_DATA\"}",lo,hi,value,end-start));
                        }
                    }
                }
                start = end;
            }
        }
        if (fill.isEmpty()) return "Z1 fill runs 0, protected " + preserved;
        var classified = WSRomEvidence.property(p, PROPERTY);
        var stopped = WSRomEvidence.property(p, EDGES);
        Map<AddressRange, Address> boundaries = new LinkedHashMap<>();
        for (AddressRange range : fill) {
            for (Instruction i : listing.getInstructions(new AddressSet(range), true)) cleared++;
            listing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);
            long length = range.getLength();
            listing.createData(range.getMinAddress(), new ArrayDataType(ByteDataType.dataType, (int)length, 1));
            classified.add(range.getMinAddress(), (int)range.getLength());
            boundaries.put(range, boundary(p, range));
        }
        List<Instruction> instructions = new ArrayList<>();
        for (Instruction i : listing.getInstructions(true)) instructions.add(i);
        for (Instruction i : instructions) {
            if (fill.contains(i.getAddress())) { cleared++; continue; }
            Address ft = i.getFallThrough();
            if (ft != null && fill.contains(ft) && !i.isFallThroughOverridden()) {
                Address marker = boundaries.entrySet().stream().filter(e -> e.getKey().contains(ft))
                    .findFirst().orElseThrow().getValue();
                i.setFallThrough(marker); edges++;
                stopped.add(i.getAddress(), (stopped.hasProperty(i.getAddress()) ? stopped.getInt(i.getAddress()) : 0) | 1);
                p.getReferenceManager().addMemoryReference(i.getAddress(), ft, RefType.DATA, SourceType.ANALYSIS, -1);
                emit.accept(String.format("{\"rule\":\"Z1\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"OPAQUE_FILL_FALLTHROUGH\"}",i.getAddress(),ft));
            }
            for (Reference r : i.getReferencesFrom()) {
                if (r.getReferenceType().isFlow() && r.getReferenceType().isComputed()
                    && r.getSource() == SourceType.ANALYSIS && fill.contains(r.getToAddress())) {
                    p.getReferenceManager().delete(r); edges++;
                    emit.accept(String.format("{\"rule\":\"Z1\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"GUESSED_FILL_EDGE_REMOVED\"}",i.getAddress(),r.getToAddress()));
                }
            }
            Address target = transferTarget(i);
            if (i.getFlowType().isJump() && !i.getFlowType().isComputed() && target != null
                && fill.contains(target) && i.getFlowOverride() == FlowOverride.NONE) {
                i.setFlowOverride(FlowOverride.CALL_RETURN); edges++;
                stopped.add(i.getAddress(), (stopped.hasProperty(i.getAddress()) ? stopped.getInt(i.getAddress()) : 0) | 2);
                p.getReferenceManager().addMemoryReference(i.getAddress(), target, RefType.DATA, SourceType.ANALYSIS, -1);
                emit.accept(String.format("{\"rule\":\"Z1\",\"site\":\"%s\",\"target\":\"%s\",\"outcome\":\"OPAQUE_FILL_TRANSFER\"}",i.getAddress(),target));
            }
        }
        List<Function> functions = new ArrayList<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) functions.add(f);
        for (Function f : functions) {
            if (p.getFunctionManager().getFunctionAt(f.getEntryPoint()) == null) continue;
            if (!f.getBody().intersects(fill)) continue;
            if (fill.contains(f.getEntryPoint())) {
                // Removing a target also removes its thunk function objects in Ghidra.
                // Their instructions can be real code, and an imported flow override may
                // already point at an imaged RAM destination. Preserve those independent
                // bodies before deleting the speculative target.
                Address[] thunks = f.getFunctionThunkAddresses(false);
                if (thunks != null) for (Address entry : thunks) {
                    Function thunk = p.getFunctionManager().getFunctionAt(entry);
                    if (thunk == null || fill.contains(entry)) continue;
                    Instruction jump = listing.getInstructionAt(entry);
                    Function target = null;
                    Address destination = jump == null ? null : transferTarget(jump);
                    if (destination != null) target = p.getFunctionManager().getFunctionAt(destination);
                    if (target != null && fill.contains(target.getEntryPoint())) target = null;
                    thunk.setThunkedFunction(target);
                    emit.accept(String.format("{\"rule\":\"Z1\",\"entry\":\"%s\",\"outcome\":\"THUNK_BODY_RETAINED\",\"target\":\"%s\"}", entry,
                        target == null ? "unknown" : target.getEntryPoint()));
                }
                emit.accept(String.format("{\"rule\":\"Z1\",\"entry\":\"%s\",\"body_bytes\":%d,\"outcome\":\"FILL_FUNCTION_REMOVED\"}",f.getEntryPoint(),f.getBody().getNumAddresses()));
                p.getFunctionManager().removeFunction(f.getEntryPoint()); removed++;
            } else {
                AddressSet kept = new AddressSet(f.getBody()); kept.delete(fill);
                f.setBody(kept); split++;
                emit.accept(String.format("{\"rule\":\"Z1\",\"entry\":\"%s\",\"outcome\":\"BODY_SPLIT_AT_FILL\"}",f.getEntryPoint()));
            }
        }
        return String.format("Z1 fill runs %d, protected %d, instructions cleared %d, functions removed %d, bodies split %d, edges stopped %d",runs,preserved,cleared,removed,split,edges);
    }
}
