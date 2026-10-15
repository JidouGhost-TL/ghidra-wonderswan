// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Consumer;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** Z1: repeated bytes identify a dual-use hypothesis, never exclusive proof against code. */
public final class WSFillRuns {
    /** Legacy properties describe old destructive decisions; new hypotheses do not write them. */
    public static final String CATEGORY = "WSFillRun", PROPERTY = "WS_FILL_RUN", EDGES = "WS_FILL_EDGE";
    public static final String HYPOTHESIS = "WSZ1Hypothesis:";
    public static final int ZERO_FF_MIN = 64, OTHER_MIN = 256;
    private WSFillRuns() { }

    private static String quote(String text) {
        if (text == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }

    private static String address(Address at) {
        return at == null ? "null" : "{\"space\":" + quote(at.getAddressSpace().getName())
            + ",\"address\":" + quote(at.toString()) + "}";
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    /** Append source-bound evidence, preserving even a collision with an edited diagnostic. */
    private static void report(Program p, Address at, String detail, Consumer<String> emit) throws Exception {
        String base = HYPOTHESIS + digest(detail.getBytes(StandardCharsets.UTF_8));
        BookmarkManager bm = p.getBookmarkManager();
        for (int suffix = 0; ; suffix++) {
            String category = base + (suffix == 0 ? "" : ":" + suffix);
            Bookmark old = bm.getBookmark(at, BookmarkType.ANALYSIS, category);
            if (old == null) { bm.setBookmark(at, BookmarkType.ANALYSIS, category, detail); break; }
            if (detail.equals(old.getComment())) break;
        }
        emit.accept(detail);
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
                || f.getSymbol().getSource() == SourceType.IMPORTED
                || f.getSignatureSource() == SourceType.USER_DEFINED
                || f.getSignatureSource() == SourceType.IMPORTED) proof.add(f.getBody());
        return proof;
    }

    private static boolean executed(Program p, WSEvidence ev, AddressSetView range) {
        if (ev != null) for (Address a : range.getAddresses(true))
            if (WSRomEvidence.executed(p, ev, a)) return true;
        return false;
    }

    /** The legacy length/flags contain no byte hash or ownership certificate. Preserve and report ambiguity. */
    public static int restoreExecuted(Program p, WSEvidence ev, Consumer<String> emit) throws Exception {
        for (String property : new String[]{PROPERTY, EDGES}) {
            var map = p.getUsrPropertyManager().getIntPropertyMap(property);
            if (map == null) continue;
            for (var it = map.getPropertyIterator(); it.hasNext();) {
                Address start = it.next();
                Instruction instruction = p.getListing().getInstructionContaining(start);
                Data data = p.getListing().getDefinedDataContaining(start);
                CodeUnit unit = instruction == null ? data : instruction;
                MemoryBlock block = p.getMemory().getBlock(start);
                String currentBytes = unit == null || block == null || !block.isInitialized() ? null : digest(unit.getBytes());
                String detail = "{\"rule\":\"Z1-legacy\",\"outcome\":\"LEGACY_STATE_PRESERVED_OPEN\","
                    + "\"reason\":\"OWNERSHIP_AND_ORIGINAL_STATE_UNPROVED\",\"property\":" + quote(property)
                    + ",\"start\":" + address(start) + ",\"stored_value\":" + map.getInt(start)
                    + ",\"instruction\":" + quote(instruction == null ? null : instruction.toString())
                    + ",\"data\":" + quote(data == null ? null : data.toString())
                    + ",\"current_unit_sha256\":" + quote(currentBytes)
                    + ",\"flow_override\":" + quote(instruction == null ? null : instruction.getFlowOverride().toString())
                    + ",\"fall_through\":" + address(instruction == null ? null : instruction.getFallThrough())
                    + ",\"evidence_source\":" + quote(ev == null ? null : ev.provenance) + "}";
                report(p, start, detail, emit);
            }
        }
        // Neither fresh code nor old arrays/overrides can be erased on a stale property alone.
        return 0;
    }

    private static String witness(Program p, AddressSet range) throws Exception {
        List<String> instructions = new ArrayList<>(), functions = new ArrayList<>(), refs = new ArrayList<>();
        for (Instruction i : p.getListing().getInstructions(range, true)) {
            instructions.add("{\"at\":" + address(i.getAddress()) + ",\"bytes\":" + quote(HexFormat.of().formatHex(i.getBytes()))
                + ",\"decode\":" + quote(i.toString()) + ",\"flow_override\":" + quote(i.getFlowOverride().toString())
                + ",\"fall_through\":" + address(i.getFallThrough()) + "}");
        }
        for (Function f : p.getFunctionManager().getFunctions(true)) if (f.getBody().intersects(range))
            functions.add("{\"entry\":" + address(f.getEntryPoint()) + ",\"body\":" + quote(f.getBody().toString())
                + ",\"name\":" + quote(f.getName()) + ",\"source\":" + quote(f.getSymbol().getSource().toString())
                + ",\"signature\":" + quote(f.getSignature().toString()) + ",\"thunk\":"
                + address(f.isThunk() ? f.getThunkedFunction(false).getEntryPoint() : null) + "}");
        for (Address a : range.getAddresses(true)) {
            for (Reference r : p.getReferenceManager().getReferencesTo(a))
                refs.add(address(r.getFromAddress()) + "->" + address(r.getToAddress()) + "|" + r.getReferenceType() + "|" + r.getSource() + "|" + r.getOperandIndex());
        }
        Collections.sort(refs);
        return ",\"instructions\":[" + String.join(",", instructions) + "],\"functions\":[" + String.join(",", functions)
            + "],\"incoming_references\":[" + String.join(",", refs.stream().map(WSFillRuns::quote).toList()) + "]";
    }

    public static String apply(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        WSRamCode.classify(p);
        Listing listing = p.getListing();
        AddressSet reached = new AddressSet(), proof = protectedCode(p);
        for (Instruction i : listing.getInstructions(true)) {
            reached.add(i.getMinAddress(), i.getMaxAddress());
            if (i.getFallThrough() != null) reached.add(i.getFallThrough());
            for (Address flow : i.getFlows()) reached.add(flow);
        }
        for (Function f : p.getFunctionManager().getFunctions(true)) reached.add(f.getEntryPoint());
        int runs = 0, protectedRuns = 0, observed = 0, uninitialized = 0;
        for (MemoryBlock block : p.getMemory().getBlocks()) {
            monitor.checkCancelled();
            if (!block.isExecute() || WonderSwanLoader.isDataOverlay(block) || block.getSize() > Integer.MAX_VALUE) continue;
            if (!block.isInitialized()) {
                AddressSet range = new AddressSet(block.getStart(), block.getEnd());
                if (reached.intersects(range)) {
                    report(p, block.getStart(), "{\"rule\":\"Z1\",\"outcome\":\"UNINITIALIZED_CODE_PRESERVED\",\"start\":"
                        + address(block.getStart()) + ",\"end\":" + address(block.getEnd()) + witness(p, range) + "}", emit);
                    uninitialized++;
                }
                continue;
            }
            byte[] bytes = new byte[(int)block.getSize()];
            p.getMemory().getBytes(block.getStart(), bytes);
            for (int start = 0; start < bytes.length;) {
                monitor.checkCancelled();
                int end = start + 1;
                while (end < bytes.length && bytes[end] == bytes[start]) end++;
                int value = bytes[start] & 255, threshold = value == 0 || value == 255 ? ZERO_FF_MIN : OTHER_MIN;
                if (end - start >= threshold) {
                    Address lo = block.getStart().add(start), hi = block.getStart().add(end - 1);
                    Instruction first = listing.getInstructionContaining(lo), last = listing.getInstructionContaining(hi);
                    if (first != null && !first.getAddress().equals(lo)) lo = first.getMaxAddress().next();
                    if (last != null && last.getMaxAddress().compareTo(hi) > 0) hi = last.getAddress().previous();
                    if (lo.compareTo(hi) > 0 || hi.subtract(lo) + 1 < threshold) { start = end; continue; }
                    AddressSet range = new AddressSet(lo, hi);
                    if (reached.intersects(range)) {
                        String outcome = "PRESERVED_HYPOTHESIS";
                        if (proof.intersects(range)) { outcome = "PROTECTED_CODE"; protectedRuns++; }
                        else if (executed(p, ev, range)) { outcome = "OBSERVED_CODE"; observed++; }
                        String detail = "{\"rule\":\"Z1\",\"outcome\":" + quote(outcome)
                            + ",\"reason\":\"REPEATED_BYTES_DO_NOT_EXCLUDE_CODE\",\"start\":" + address(lo) + ",\"end\":" + address(hi)
                            + ",\"byte\":" + value + ",\"run_bytes\":" + (end - start) + ",\"threshold\":" + threshold
                            + ",\"block\":" + quote(block.getName()) + ",\"block_start\":" + address(block.getStart())
                            + ",\"bytes_sha256\":" + quote(digest(Arrays.copyOfRange(bytes, (int)lo.subtract(block.getStart()), (int)hi.subtract(block.getStart()) + 1)))
                            + ",\"ram\":" + WSRamCode.isRam(p, lo) + ",\"captured_ram_image\":" + WSRamCode.hasImage(p, lo)
                            + ",\"evidence_source\":" + quote(ev == null ? null : ev.provenance) + witness(p, range) + "}";
                        report(p, lo, detail, emit); runs++;
                    }
                }
                start = end;
            }
        }
        return String.format("Z1 hypothesis runs %d, protected %d, observed %d, uninitialized %d; code and flow preserved", runs, protectedRuns, observed, uninitialized);
    }
}
