// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.util.task.TaskMonitor;

/** Physical ROM evidence stays distinct from observed CPU instruction starts. */
public final class WSRomEvidence {
    public static final String STARTS = "WS_EXECUTED_START", CODE = "WS_EXECUTED_ROM";
    private WSRomEvidence() { }

    static IntPropertyMap property(Program p, String name) throws Exception {
        var maps = p.getUsrPropertyManager();
        var map = maps.getIntPropertyMap(name);
        return map == null ? maps.createIntPropertyMap(name) : map;
    }

    static int flags(Program p, WSEvidence ev, Address a) {
        if (ev.romFlags.length == 0) return 0;
        var off = WSRom.offsetOf(p, a);
        return off.isPresent() && off.getAsLong() < ev.romFlags.length ? ev.romFlags[(int)off.getAsLong()] & 255 : 0;
    }

    static boolean code(Program p, WSEvidence ev, Address a, int length) {
        if (length <= 0) return false;
        for (int k = 0; k < length; k++) if ((flags(p, ev, a.add(k)) & 1) == 0) return false;
        return true;
    }

    public static boolean executed(Program p, WSEvidence ev, Address a) {
        if ((flags(p, ev, a) & 1) != 0) return true;
        if (a.getAddressSpace().isOverlaySpace()) {
            MemoryBlock b = p.getMemory().getBlock(a);
            Set<Integer> banks = ev.windowBanks.get(a.getOffset());
            if (b == null || banks == null) return false;
            for (int bank : banks) if (b.getName().equals(WSRomWindows.name(a.getOffset() < 0x30000 ? 0x2000 : 0x3000, bank))) return ev.executed(a.getOffset());
            return false;
        }
        return ev.executed(a.getOffset());
    }

    public static void prepare(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        var starts = property(p, STARTS);
        for (var e : ev.cs.entrySet()) {
            long lin = e.getKey();
            if (lin >= 0x20000 && lin < 0x40000) {
                Set<Integer> banks = ev.windowBanks.get(lin);
                if (banks != null) for (int bank : banks) {
                    MemoryBlock b = WSRomWindows.view(p, lin < 0x30000 ? 0x2000 : 0x3000, bank, true, monitor);
                    starts.add(b.getStart().add(lin & 65535), 3);
                }
            } else {
                Address a = ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(e.getValue(), (int)(lin - ((long)e.getValue()<<4)) & 65535);
                if (p.getMemory().contains(a)) starts.add(a, 3);
            }
        }
        // Resolve known static bank selections before assigning a window to window-only bytes.
        for (Instruction i : p.getListing().getInstructions(true)) for (Address target : i.getFlows()) {
            if (target.getAddressSpace().isOverlaySpace() || target.getOffset() < 0x20000 || target.getOffset() >= 0x40000) continue;
            Integer bank = staticBank(p, i, target.getOffset());
            if (bank != null) WSRomWindows.view(p, target.getOffset() < 0x30000 ? 0x2000 : 0x3000, bank, true, monitor);
        }
        // CDL marks physical bytes, not C2 versus C3. Give otherwise unmapped executed banks a ROM0
        // analysis view, explicitly classified as unknown CPU placement; never synthesize a CPU visit.
        for (int off = 0; off < ev.romFlags.length; off++) {
            if ((ev.romFlags[off] & 1) == 0) continue;
            int bank = WSRomWindows.bank(off, ev.romFlags.length);
            long effective = off + WSHardware.padSize(ev.romFlags.length);
            long lin = effective & 0xfffff;
            long expected = WSHardware.fileOffset(WSHardware.linearToRom(lin, WSHardware.RESET_C0, WSHardware.effectiveSize(ev.romFlags.length)), ev.romFlags.length);
            if (lin >= 0x40000 && expected == off) continue;
            boolean imaged = false;
            for (int seg : new int[]{0x2000, 0x3000}) {
                MemoryBlock b = p.getMemory().getBlock(WSRomWindows.name(seg, bank));
                if (b != null && b.isExecute()) { imaged = true; break; }
            }
            if (!imaged) {
                MemoryBlock b = WSRomWindows.view(p, 0x2000, bank, true, monitor);
                p.getBookmarkManager().setBookmark(b.getStart(), BookmarkType.ANALYSIS, "WSBankEvidence", "Executed ROM bank; CPU window unknown in byte coverage. ROM0 is an analysis placement, not an observed C2 value.");
                emit.accept(String.format("{\"rule\":\"B2R\",\"bank\":\"%04x\",\"view\":\"%s\",\"placement\":\"CPU_WINDOW_UNKNOWN\"}", bank, b.getName()));
            }
        }
    }

    public static void seedWindows(Program p, WSEvidence ev, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        var starts = property(p, STARTS);
        var cs = p.getProgramContext().getRegister("csval");
        AddressSet seeds = new AddressSet();
        List<Address> entries = new ArrayList<>();
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (!b.isExecute() || !(b.getName().startsWith("ROM0_BANK_") || b.getName().startsWith("ROM1_BANK_"))) continue;
            for (int k = 0; k < b.getSize(); k++) {
                Address a = b.getStart().add(k);
                int f = flags(p, ev, a);
                if ((f & 1) == 0 || (f & 12) == 0) continue;
                starts.add(a, 2);
                if ((f & 8) != 0) entries.add(a);
                if (p.getListing().getInstructionContaining(a) == null) {
                    if (cs != null) p.getProgramContext().setValue(cs, a, a, BigInteger.valueOf(a.getOffset() < 0x30000 ? 0x2000 : 0x3000));
                    seeds.add(a);
                }
            }
        }
        WSDecodeRepair.align(p, ev, emit, monitor);
        if (!seeds.isEmpty()) new DisassembleCommand(seeds, null, true).applyTo(p, monitor);
        int created = 0;
        for (Address a : entries) {
            if (p.getListing().getInstructionAt(a) != null && p.getFunctionManager().getFunctionAt(a) == null && new CreateFunctionCmd(a).applyTo(p, monitor)) created++;
        }
        emit.accept(String.format("{\"rule\":\"B2R\",\"starts\":%d,\"functions\":%d}", seeds.getNumAddresses(), created));
    }

    /** Constant bank writes in an uninterrupted predecessor chain. Joins/calls invalidate the proof. */
    public static Integer staticBank(Program p, Instruction site, long target) throws Exception {
        List<Instruction> chain = new ArrayList<>();
        Instruction i = site;
        for (int n = 0; n < 64; n++) {
            chain.add(i);
            boolean join = false;
            for (Reference r : p.getReferenceManager().getReferencesTo(i.getAddress())) if (r.getReferenceType().isFlow() && !r.getReferenceType().isFallthrough()) { join = true; break; }
            if (join) break;
            Instruction prev = p.getListing().getInstructionBefore(i.getAddress());
            if (prev == null || !i.getAddress().equals(prev.getFallThrough()) || prev.getFlowType().isCall() && !preservesBank(p, prev, target, new HashSet<>())) break;
            i = prev;
        }
        Collections.reverse(chain);
        Integer al = null, ah = null, dx = null, low = null, high = WSRom.size(p) > 0x1000000 ? null : 0;
        int port = target < 0x30000 ? 0xc2 : 0xc3, wide = target < 0x30000 ? 0xd2 : 0xd4;
        for (Instruction ins : chain) {
            byte[] bytes = ins.getBytes();
            int op = bytes[0] & 255;
            if (op == 0xb0 && bytes.length == 2) al = bytes[1] & 255;
            else if (op == 0xb4 && bytes.length == 2) ah = bytes[1] & 255;
            else if (op == 0xb8 && bytes.length == 3) { al = bytes[1] & 255; ah = bytes[2] & 255; }
            else if (op == 0xba && bytes.length == 3) dx = (bytes[1] & 255) | ((bytes[2] & 255) << 8);
            else if ((op == 0xe6 || op == 0xe7 || op == 0xee || op == 0xef)) {
                Integer out = op == 0xe6 || op == 0xe7 ? Integer.valueOf(bytes[1] & 255) : dx;
                if (out == null) {
                    // An unknown port can change either bank register; later known writes
                    // may establish a new proof, but the old bank is no longer justified.
                    low = null;
                    high = WSRom.size(p) > 0x1000000 ? null : 0;
                } else {
                    out &= 255;
                    if (out == port || out == wide) low = al;
                    if (out == wide && (op == 0xe7 || op == 0xef)) high = ah;
                    if (out == wide + 1) high = al;
                }
            } else {
                if (ins.getFlowType().isCall()) { al = null; ah = null; dx = null; }
                for (Object result : ins.getResultObjects()) if (result instanceof Register r) {
                    switch (r.getName().toUpperCase(Locale.ROOT)) {
                        case "AX" -> { al = null; ah = null; }
                        case "AL" -> al = null;
                        case "AH" -> ah = null;
                        case "DX", "DL", "DH" -> dx = null;
                        default -> { }
                    }
                }
            }
        }
        if (low == null || high == null) return null;
        long size = WSRom.size(p);
        int raw = low | (high << 8);
        long file = WSHardware.fileOffset(WSHardware.bankToRom(raw, WSHardware.effectiveSize(size)), size);
        return file < 0 ? null : WSRomWindows.bank(file, size);
    }

    /** An automatic function in an uninitialized CPU window has no instruction image. Preserve
     * its provenance and navigation candidates; physical sub-entries live in their own banks. */
    public static int classifyUnmappedWindows(Program p, WSEvidence ev, Consumer<String> emit) throws Exception {
        List<Function> placeholders = new ArrayList<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            Address a = f.getEntryPoint(); MemoryBlock b = p.getMemory().getBlock(a);
            if (b != null && !b.isOverlay() && !b.isInitialized() && a.getOffset() >= 0x20000 && a.getOffset() < 0x40000
                && f.getSymbol().getSource() == SourceType.DEFAULT) placeholders.add(f);
        }
        for (Function f : placeholders) {
            Address a = f.getEntryPoint(); List<Address> candidates = new ArrayList<>();
            for (Function mapped : p.getFunctionManager().getFunctions(true)) {
                Address t = mapped.getEntryPoint();
                if ((t.getOffset() & 65535) == (a.getOffset() & 65535) && (flags(p, ev, t) & 8) != 0) candidates.add(t);
            }
            List<Reference> incoming = new ArrayList<>();
            for (Reference r : p.getReferenceManager().getReferencesTo(a)) incoming.add(r);
            for (Reference r : incoming) for (Address t : candidates)
                p.getReferenceManager().addMemoryReference(r.getFromAddress(), t, RefType.DATA, SourceType.ANALYSIS, Reference.MNEMONIC);
            p.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS, "WSBankEvidence",
                "UNMAPPED_WINDOW: automatic placeholder has no bytes or instructions. Bank remains unresolved; physical sub-entry candidates " + candidates);
            emit.accept(String.format("{\"rule\":\"B2R\",\"old\":\"%s\",\"classification\":\"UNMAPPED_WINDOW_PLACEHOLDER\",\"candidates\":\"%s\",\"incoming_refs_retained\":%d}", a, candidates, incoming.size()));
            p.getFunctionManager().removeFunction(a);
        }
        return placeholders.size();
    }

    private static boolean preservesBank(Program p, Instruction call, long target, Set<Address> visited) throws Exception {
        if (call.getFlowType().isComputed() || call.getFlows().length != 1 || visited.size() >= 32) return false;
        Function f = p.getFunctionManager().getFunctionAt(call.getFlows()[0]);
        if (f == null || !visited.add(f.getEntryPoint()) || f.getBody().getNumAddresses() > 2048) return false;
        int port = target < 0x30000 ? 0xc2 : 0xc3, wide = target < 0x30000 ? 0xd2 : 0xd4;
        AddressSet undecoded = new AddressSet(f.getBody());
        for (Instruction ins : p.getListing().getInstructions(f.getBody(), true)) {
            undecoded.delete(ins.getMinAddress(), ins.getMaxAddress());
            if (ins.getFlowType().isJump()) {
                if (ins.getFlowType().isComputed()) return false;
                for (Address flow : ins.getFlows()) if (!f.getBody().contains(flow)) return false;
            }
            String mnemonic = ins.getMnemonicString();
            if (mnemonic.startsWith("OUT")) {
                byte[] raw = ins.getBytes();
                if (raw.length != 2 || ((raw[0] & 255) != 0xe6 && (raw[0] & 255) != 0xe7)) return false;
                int out = raw[1] & 255;
                if (out == port || out == wide || out == wide + 1) return false;
            }
            if (ins.getFlowType().isCall() && !preservesBank(p, ins, target, visited)) return false;
        }
        visited.remove(f.getEntryPoint());
        return undecoded.isEmpty();
    }

    /** Classify the original view before removing automatic code; explicit/user functions are retained. */
    public static void relocateWindowStub(Program p, Address old, Address correct, WSEvidence ev,
                                          Consumer<String> emit, TaskMonitor monitor) throws Exception {
        Function f = p.getFunctionManager().getFunctionAt(old);
        if (f == null || old.equals(correct)) return;
        MemoryBlock b = p.getMemory().getBlock(old);
        boolean unresolved = b != null && !b.isInitialized();
        boolean executed = executed(p, ev, old);
        for (Instruction ins : p.getListing().getInstructions(f.getBody(), true)) if (executed(p, ev, ins.getAddress())) { executed = true; break; }
        p.getBookmarkManager().setBookmark(old, BookmarkType.ANALYSIS, "WSBankEvidence",
            (unresolved ? "UNMAPPED_WINDOW" : executed ? "EXECUTED_VIEW_RETAINED" : "WRONG_BANK_UNEXECUTED") + "; correct target " + correct);
        if ((unresolved || !executed) && f.getSymbol().getSource() == SourceType.DEFAULT) {
            AddressSet body = new AddressSet(f.getBody());
            p.getFunctionManager().removeFunction(old);
            for (AddressRange range : body) p.getListing().clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);
        }
        emit.accept(String.format("{\"rule\":\"B2R\",\"old\":\"%s\",\"correct\":\"%s\",\"classification\":\"%s\"}", old, correct,
            unresolved ? "UNMAPPED_WINDOW" : executed ? "EXECUTED_VIEW_RETAINED" : "WRONG_BANK_UNEXECUTED"));
    }
}
