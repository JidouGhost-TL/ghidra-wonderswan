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
 * Rule J1y: a bank-overlay table site resolves its observed targets and table slots in its own overlay even when
 * another site, in a different address space, was recovered after it in the same pass (recover() runs for every
 * site of a pass before any table is applied). Synthetic program; run as a headless post script.
 */
public class WSOverlayTableFixtures extends GhidraScript {
    private int checks;
    private void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
        checks++;
        println("CHECK PASS " + message);
    }
    private static void put(byte[] raw, int at, String hex) {
        byte[] b = HexFormat.of().parseHex(hex); System.arraycopy(b, 0, raw, at, b.length);
    }
    private static final String DISPATCH = "8b1e100033ff03db2effa70001";  // MOV BX,[0010]; XOR DI,DI; ADD BX,BX; JMP CS:[BX+0100]

    @Override public void run() throws Exception {
        ProgramDB p = new ProgramDB("overlay-table", currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx = p.startTransaction("overlay-table");
        try {
            SegmentedAddressSpace sp = (SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace();
            Memory mem = p.getMemory();
            var csval = p.getRegister("csval");
            // the empty ROM0 bank window and one bank's overlay over it (the loader's B2 shape)
            mem.createUninitializedBlock("ROM0_WINDOW", sp.getAddress(0x2000, 0), 0x10000, false);
            byte[] bank = new byte[0x10000]; Arrays.fill(bank, (byte) 0xff);
            put(bank, 0x40, DISPATCH); put(bank, 0x100, "0601"); put(bank, 0x106, "b80100c3"); put(bank, 0x190, "b80200c3");
            MemoryBlock ov = mem.createInitializedBlock("ROM0_BANK_00F2", sp.getAddress(0x2000, 0),
                new ByteArrayInputStream(bank), bank.length, monitor, true);
            ov.setPermissions(true, false, true);
            p.getProgramContext().setValue(csval, ov.getStart(), ov.getEnd(), BigInteger.valueOf(0x2000));
            // a second table site in the default space, recovered after the overlay site
            byte[] rom = new byte[0x10000]; Arrays.fill(rom, (byte) 0xff);
            put(rom, 0x40, DISPATCH); put(rom, 0x100, "0601"); put(rom, 0x106, "b80300c3");
            MemoryBlock fixed = mem.createInitializedBlock("fixture", sp.getAddress(0x4000, 0),
                new ByteArrayInputStream(rom), rom.length, monitor, false);
            fixed.setPermissions(true, false, true);
            p.getProgramContext().setValue(csval, fixed.getStart(), fixed.getEnd(), BigInteger.valueOf(0x4000));
            Address ovSite = ov.getStart().add(0x48), defSite = fixed.getStart().add(0x48);
            new DisassembleCommand(ov.getStart().add(0x40), null, true).applyTo(p, monitor);
            new DisassembleCommand(fixed.getStart().add(0x40), null, true).applyTo(p, monitor);
            Instruction oi = p.getListing().getInstructionAt(ovSite), di = p.getListing().getInstructionAt(defSite);
            check(oi != null && oi.getFlowType().isComputed(), "overlay dispatch decoded: " + oi);
            check(di != null && di.getFlowType().isComputed(), "default dispatch decoded: " + di);

            // evidence: the overlay site was observed jumping to 2000:0190, which the table does not list
            WSEvidence ev = new WSEvidence();
            ev.cs.put(0x20040L, 0x2000); ev.cs.put(0x20048L, 0x2000); ev.cs.put(0x20190L, 0x2000);
            ev.edges.add(new WSEvidence.Edge(0x20048L, 0x20190L, 0x2000, "jump", 1));

            List<String> log = new ArrayList<>();
            Class<?> cls = Class.forName("jidoughost.wonderswan.WSJumpTables");
            Constructor<?> ctor = cls.getDeclaredConstructor(Program.class, WSEvidence.class, Consumer.class);
            ctor.setAccessible(true);
            Consumer<String> emit = log::add;
            Object jt = ctor.newInstance(p, ev, emit);
            Method recover = cls.getDeclaredMethod("recover", Instruction.class); recover.setAccessible(true);
            Class<?> rec = Class.forName("jidoughost.wonderswan.WSJumpTables$Rec");
            Method apply = cls.getDeclaredMethod("applySite", Instruction.class, rec, TaskMonitor.class); apply.setAccessible(true);
            Field targets = rec.getDeclaredField("targets"); targets.setAccessible(true);

            // the pass order of applyPass: every site is recovered first, then each one is applied
            Object ro = recover.invoke(jt, oi);
            Object rd = recover.invoke(jt, di);
            println("overlay rec targets " + targets.get(ro) + "; default rec targets " + targets.get(rd));
            check(!((List<?>) targets.get(ro)).isEmpty(), "overlay table recovered");
            boolean applied = (Boolean) apply.invoke(jt, oi, ro, monitor);
            for (String l : log) println("EVIDENCE " + l);
            check(applied, "overlay site applied (observed target resolved in the overlay)");

            Address ovTarget = ov.getStart().add(0x190), windowTarget = sp.getAddress(0x2000, 0x190);
            check(p.getListing().getInstructionAt(ovTarget) != null, "observed target decoded in the overlay");
            boolean refOverlay = false, refWindow = false;
            for (Reference r : p.getReferenceManager().getReferencesFrom(ovSite)) {
                if (r.getToAddress().equals(ovTarget)) refOverlay = true;
                if (r.getToAddress().getAddressSpace().equals(sp)) refWindow = true;
            }
            check(refOverlay, "site references the overlay target");
            check(!refWindow, "site has no reference into the empty bank window");
            check(log.stream().noneMatch(l -> l.contains(windowTarget.toString())), "no evidence line names the window address " + windowTarget);
            check(p.getListing().getDefinedDataContaining(ov.getStart().add(0x100)) != null, "table slot defined as data in the overlay");
            byte[] after = new byte[bank.length]; mem.getBytes(ov.getStart(), after);
            check(Arrays.equals(bank, after), "overlay bytes preserved");
            println("WSOverlayTableFixtures: PASS checks=" + checks);
        } finally { p.endTransaction(tx, false); p.release(this); }
    }
}
