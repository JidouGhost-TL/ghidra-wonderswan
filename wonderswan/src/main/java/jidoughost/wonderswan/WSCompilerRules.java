// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.math.BigInteger;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Title-wide rules decided from the program's own code and execution evidence (no compiler library bytes):
 *
 *   K1  compiler family for the calling convention (rule C1). LSI C-86 passes arguments in AX, BX, CX, DX and
 *       its frames save CX/DX after "PUSH BP; MOV BP,SP [; SUB SP,n]" (callee-saved argument registers),
 *       while stack-argument C reads [BP+4..] in many functions. LSI when
 *         lsiSaveRatio  = functions with that save order / ROM functions >= 0.10   and
 *         stackArgRatio = functions reading [BP+4..0x3f] after a frame / ROM functions <= 0.20.
 *       Calibrated on the licensed library: 28 of 29 titles that link the LSI C-86 runtime, no false positives
 *       (the miss has 49 % stack-argument functions).
 *   D0  title DS default: the loader's DS = 0 default holds unless execution shows another DS dominating:
 *       among executed addresses that ran with a single DS, if one value v != 0 covers >= 50 %, DS = v
 *       becomes the default context over the ROM (rule D1 still sets observed DS at function entries).
 */
final class WSCompilerRules {
    static final double LSI_SAVE_MIN = 0.10, STACK_ARGS_MAX = 0.20, DS_DOMINANT_MIN = 0.50;

    int romFns, lsiSave, stackArgs;

    boolean lsi() {
        return romFns > 0 && (double) lsiSave / romFns >= LSI_SAVE_MIN && (double) stackArgs / romFns <= STACK_ARGS_MAX;
    }

    String evidence() {
        return String.format("rom_functions=%d lsi_save_order=%d (%.3f) stack_arg_functions=%d (%.3f)", romFns, lsiSave,
            romFns == 0 ? 0.0 : (double) lsiSave / romFns, stackArgs, romFns == 0 ? 0.0 : (double) stackArgs / romFns);
    }

    /** K1: measure prologue save order and stack-argument reads over ROM functions. */
    static WSCompilerRules measure(Program p) {
        WSCompilerRules r = new WSCompilerRules();
        Listing listing = p.getListing();
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            MemoryBlock b = p.getMemory().getBlock(f.getEntryPoint());
            if (b == null || !b.isInitialized() || b.getName().equals("RAM")) continue;
            if (WonderSwanLoader.isDataOverlay(b)) continue;
            r.romFns++;
            List<String> seq = new ArrayList<>();
            Instruction c = listing.getInstructionAt(f.getEntryPoint());
            for (int k = 0; k < 10 && c != null; k++) {
                seq.add(c.toString().toUpperCase());
                if (c.getFlowType().isTerminal() || c.getFlowType().isJump() || c.getFlowType().isCall()) break;
                c = c.getNext();
            }
            boolean frame = seq.size() > 1 && seq.get(0).equals("PUSH BP") && seq.get(1).equals("MOV BP,SP");
            if (frame) {
                int k = 2;
                if (k < seq.size() && (seq.get(k).startsWith("SUB SP,") || seq.get(k).startsWith("ADD SP,-"))) k++;
                List<String> after = new ArrayList<>();
                while (k < seq.size() && seq.get(k).matches("PUSH (CX|DX|SI|DI)")) after.add(seq.get(k++).substring(5));
                String al = String.join(",", after);
                boolean tc = al.equals("SI,DI") || al.equals("SI") || al.equals("DI");
                if (!tc && (after.contains("CX") || after.contains("DX")) && "CX,DX,SI,DI".contains(al)) r.lsiSave++;
                for (Instruction i : listing.getInstructions(f.getBody(), true)) {
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\[BP \\+ 0x([0-9a-f]+)\\]").matcher(i.toString());
                    if (m.find()) { long d = Long.parseLong(m.group(1), 16); if (d >= 4 && d < 0x40) { r.stackArgs++; break; } }
                }
            }
        }
        return r;
    }

    /** D0: the dominant single DS among executed addresses, or -1 when DS = 0 stays the default. */
    static int dominantDs(WSEvidence ev) {
        Map<Integer, Integer> n = new HashMap<>();
        int single = 0;
        for (Set<Integer> s : ev.ds.values()) {
            if (s.size() != 1) continue;
            single++;
            n.merge(s.iterator().next(), 1, Integer::sum);
        }
        if (single == 0) return -1;
        Map.Entry<Integer, Integer> top = Collections.max(n.entrySet(), Map.Entry.comparingByValue());
        return top.getKey() != 0 && (double) top.getValue() / single >= DS_DOMINANT_MIN ? top.getKey() : -1;
    }

    static double share(WSEvidence ev, int v) {
        int single = 0, hit = 0;
        for (Set<Integer> s : ev.ds.values()) if (s.size() == 1) { single++; if (s.contains(v)) hit++; }
        return single == 0 ? 0 : (double) hit / single;
    }

    /** D0: set DS = v over every initialized ROM block (linear window and bank overlays). Data overlays stay untouched. */
    static int applyDsDefault(Program p, int v) throws Exception {
        ProgramContext ctx = p.getProgramContext();
        Register ds = ctx.getRegister("DS");
        int blocks = 0;
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isExecute() || b.getName().equals("RAM")) continue;
            if (WonderSwanLoader.isDataOverlay(b)) continue;
            Address s = b.getStart(), e = b.getEnd();
            ctx.setValue(ds, s, e, BigInteger.valueOf(v));
            blocks++;
        }
        return blocks;
    }

    /** D3: set CS to each span's own display segment over every initialized block. Code always runs with
     *  CS = the segment Ghidra shows, so MOV reg,CS / PUSH CS fold to constants instead of surfacing as
     *  unaffected CS inputs; bank windows are uninitialized and excluded, RAM included (CS = 0 there).
     *  Loader data overlays (ROM_xx) are pure data and left untouched.
     *  Returns {spans, blocks}. */
    static int[] applyCsDefault(Program p) throws Exception {
        ProgramContext ctx = p.getProgramContext();
        Register cs = ctx.getRegister("CS");
        int spans = 0, blocks = 0;
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            if (WonderSwanLoader.isDataOverlay(b)) continue;
            Address a = b.getStart(), end = b.getEnd();
            if (!(a instanceof SegmentedAddress) || !(end instanceof SegmentedAddress)) continue;
            blocks++;
            while (a != null && a.compareTo(end) <= 0) {
                int sg = ((SegmentedAddress) a).getSegment();
                long offPart = a.getOffset() - ((long) sg << 4);
                long chunk = (offPart >= 0 && offPart <= 0xFFFF) ? 0x10000 - offPart : 1;
                long remaining = end.getOffset() - a.getOffset() + 1;
                if (chunk > remaining) chunk = remaining;
                Address spanEnd = a.add(chunk - 1);
                if (spanEnd == null || spanEnd.compareTo(end) > 0) spanEnd = end;
                ctx.setValue(cs, a, spanEnd, BigInteger.valueOf(sg));
                spans++;
                if (spanEnd.equals(end)) break;
                a = spanEnd.next();
            }
        }
        return new int[] { spans, blocks };
    }
}
