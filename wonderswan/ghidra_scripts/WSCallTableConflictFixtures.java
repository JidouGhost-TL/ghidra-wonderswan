// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.lang.reflect.*;
import java.math.BigInteger;
import java.util.*;
import java.util.function.Consumer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import jidoughost.wonderswan.WSEvidence;

/**
 * Rule J1z: a proven CS-relative CALL table whose one slot lands one byte inside an existing (preserved)
 * instruction publishes its other slots as call entries; the conflicted slot stays unresolved, the existing
 * instruction is untouched. The same table read by a JMP keeps the whole-site rule J1s (nothing published).
 * Synthetic program; run as a headless post script.
 */
public class WSCallTableConflictFixtures extends GhidraScript {
    private int checks;
    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
        println("CHECK PASS " + message);
    }
    private static void put(byte[] raw, int at, String hex) {
        byte[] b = HexFormat.of().parseHex(hex); System.arraycopy(b, 0, raw, at, b.length);
    }

    void fixture(String name, String dispatchOp) throws Exception {
        ProgramDB p = new ProgramDB(name, currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx = p.startTransaction(name);
        try {
            SegmentedAddressSpace sp = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
            byte[] rom = new byte[0x10000]; Arrays.fill(rom, (byte) 0xff);
            // MOV BL,AH; XOR BH,BH; SHL BX,1; ADD BX,0x0100; CALL/JMP word ptr CS:[BX]; RET
            put(rom, 0x40, "8adc32ffd1e381c30001" + dispatchOp + "c3");
            put(rom, 0x100, "0801410160018001");                // four slots: 0108 0141 0160 0180 (table ends at 0108)
            put(rom, 0x108, "b80100c3");
            put(rom, 0x140, "21521e1f5ac3");                    // 0140 AND [BP+SI+1e],DX; slot 0141 = PUSH DX ...
            put(rom, 0x160, "b80300c3");
            put(rom, 0x180, "b80400c3");
            MemoryBlock b = p.getMemory().createInitializedBlock("fixture", sp.getAddress(0x4000, 0),
                new ByteArrayInputStream(rom), rom.length, monitor, false);
            b.setPermissions(true, false, true);
            p.getProgramContext().setValue(p.getRegister("csval"), b.getStart(), b.getEnd(), BigInteger.valueOf(0x4000));
            Address site = b.getStart().add(0x4a), conflictAt = b.getStart().add(0x140), slot = b.getStart().add(0x141);
            new DisassembleCommand(b.getStart().add(0x40), null, true).applyTo(p, monitor);
            // the competing interpretation: one instruction at 0140 that the table's slot 0141 lands inside
            var kept = new ghidra.app.util.PseudoDisassembler(p).disassemble(conflictAt);
            p.getListing().createInstruction(kept.getAddress(), kept.getPrototype(), kept, kept.getProcessorContext(), 0);
            Instruction si = p.getListing().getInstructionAt(site);
            check(si != null && si.getFlowType().isComputed(), name + ": dispatch decoded: " + si);
            String before = p.getListing().getInstructionAt(conflictAt).toString();

            List<String> log = new ArrayList<>();
            Class<?> cls = Class.forName("jidoughost.wonderswan.WSJumpTables");
            Constructor<?> ctor = cls.getDeclaredConstructor(Program.class, WSEvidence.class, Consumer.class);
            ctor.setAccessible(true);
            Consumer<String> emit = log::add;
            Object jt = ctor.newInstance(p, new WSEvidence(), emit);
            Method apply = cls.getDeclaredMethod("apply", TaskMonitor.class); apply.setAccessible(true);
            apply.invoke(jt, monitor);
            for (String l : log) if (l.contains(site.toString()) || l.contains("J1z")) println("EVIDENCE " + l);

            int[] good = { 0x108, 0x160, 0x180 };
            Set<Address> refs = new HashSet<>();
            for (Reference r : p.getReferenceManager().getReferencesFrom(site)) refs.add(r.getToAddress());
            check(p.getListing().getInstructionAt(slot) == null, name + ": conflicted slot not decoded");
            check(p.getListing().getInstructionAt(conflictAt) != null
                && p.getListing().getInstructionAt(conflictAt).toString().equals(before), name + ": existing interpretation untouched");
            check(log.stream().anyMatch(l -> l.contains("UNRESOLVED_CONFLICT") && l.contains(slot.toString())), name + ": conflict reported");
            if (name.startsWith("call")) {
                for (int g : good) {
                    Address t = b.getStart().add(g);
                    check(p.getListing().getInstructionAt(t) != null, name + ": slot " + t + " decoded");
                    check(p.getFunctionManager().getFunctionAt(t) != null, name + ": slot " + t + " is a call entry");
                    check(refs.contains(t), name + ": site references " + t);
                }
                check(log.stream().anyMatch(l -> l.contains("\"rule\":\"J1z\"") && l.contains("\"published\":3") && l.contains(slot.toString())),
                    name + ": partial call table reported");
                check(log.stream().anyMatch(l -> l.contains("\"outcome\":\"RECOVERED\"") && l.contains(site.toString())), name + ": site recovered");
            } else {
                for (int g : good) check(p.getFunctionManager().getFunctionAt(b.getStart().add(g)) == null,
                    name + ": no entry published at " + b.getStart().add(g));
                check(log.stream().noneMatch(l -> l.contains("\"outcome\":\"RECOVERED\"") && l.contains(site.toString())), name + ": site stays unresolved");
                check(log.stream().noneMatch(l -> l.contains("\"rule\":\"J1z\"")), name + ": no partial publication");
            }
            byte[] after = new byte[rom.length]; p.getMemory().getBytes(b.getStart(), after);
            check(Arrays.equals(rom, after), name + ": bytes preserved");
        } finally { p.endTransaction(tx, false); p.release(this); }
    }

    @Override public void run() throws Exception {
        fixture("call-table", "2eff17");
        fixture("jump-table", "2eff27");
        println("WSCallTableConflictFixtures: PASS checks=" + checks);
    }
}
