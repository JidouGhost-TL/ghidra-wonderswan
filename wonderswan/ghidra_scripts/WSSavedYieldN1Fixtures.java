// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import jidoughost.wonderswan.*;

/**
 * Rule N1 keeps a J4 saved-yield helper's "does not return": the CALL's next instruction executes later through the
 * saved continuation. Clearing it on every repair pass undoes J4 and the call-site repair Ghidra's call-fixup
 * analyzer makes for a non-returning callee, which re-schedules the byte analyzers without end.
 */
public class WSSavedYieldN1Fixtures extends GhidraScript {
    int checks, failures;
    void check(boolean ok, String message) { checks++; if (!ok) { failures++; printerr("FAIL: " + message); } }
    void put(byte[] b, int off, String hex) { byte[] v = HexFormat.of().parseHex(hex); System.arraycopy(v, 0, b, off, v.length); }
    Address at(Program p, int off) {
        return ((SegmentedAddressSpace) p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000, off);
    }

    static boolean yieldFixup(Function f) { return f.getCallFixup() != null && f.getCallFixup().startsWith("ws_saved_yield_"); }

    @SuppressWarnings("unchecked")
    void evidence(Program p, WSEvidence ev) throws Exception {
        Field f = WSEvidenceAnalyzer.class.getDeclaredField("EVIDENCE");
        f.setAccessible(true);
        ((Map<Program, WSEvidence>) f.get(null)).put(p, ev);
    }

    @Override
    public void run() throws Exception {
        byte[] bytes = new byte[0x400];
        Arrays.fill(bytes, (byte) 0xcc);
        put(bytes, 0x40, "e8bd01c744023412c3"); // CALL 0200; MOV [SI+2],1234h; RET (function)
        put(bytes, 0x80, "e87d01c3");           // CALL 0200; RET (no containing function: J4 leaves it)
        put(bytes, 0xc0, "e83d02c3");           // CALL 0300; RET (function)
        put(bytes, 0x200, "588904c3");          // J4 yield helper: POP AX; MOV [SI],AX; RET
        put(bytes, 0x300, "c3");                // plain callee, marked non-returning below
        ProgramDB p = new ProgramDB("saved-yield-n1", currentProgram.getLanguage(),
            currentProgram.getLanguage().getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID()), this);
        int tx = p.startTransaction("fixture");
        try {
            var file = p.getMemory().createFileBytes("fixture", 0, bytes.length, new ByteArrayInputStream(bytes), monitor);
            var block = p.getMemory().createInitializedBlock("fixture", at(p, 0), file, 0, bytes.length, false);
            block.setPermissions(true, false, true);
            p.getProgramContext().setValue(p.getRegister("csval"), at(p, 0), at(p, bytes.length - 1), BigInteger.valueOf(0x4000));
            for (int off : new int[] {0x200, 0x300, 0x40, 0xc0}) {
                new DisassembleCommand(at(p, off), null, true).applyTo(p, monitor);
                new CreateFunctionCmd(at(p, off)).applyTo(p, monitor);
            }
            new DisassembleCommand(at(p, 0x80), null, true).applyTo(p, monitor);
            // Every call and each CALL's next instruction executed (the yield continuations run on a later entry).
            WSEvidence ev = new WSEvidence();
            for (int off : new int[] {0x40, 0x43, 0x48, 0x80, 0x83, 0xc0, 0xc3, 0x200, 0x201, 0x203, 0x300})
                ev.cs.put(0x40000L + off, 0x4000);
            WSEvidenceAnalyzer.repairEvidence(p, ev, "", monitor);
            Function helper = p.getFunctionManager().getFunctionAt(at(p, 0x200));
            Function plain = p.getFunctionManager().getFunctionAt(at(p, 0x300));
            check(yieldFixup(helper) && helper.hasNoReturn(), "J4 models the yield helper");
            check(!yieldFixup(plain), "plain callee is no saved-yield helper");
            plain.setNoReturn(true);
            evidence(p, ev);
            Instruction outside = p.getListing().getInstructionAt(at(p, 0x80));
            for (int round = 0; round < 2; round++) {
                // What Ghidra's call-fixup analyzer does for a non-returning callee: call sites that still fall
                // through get a CALL_RETURN override (and the analyzer re-schedules byte analysis when it changes one).
                for (Address site : new Address[] {at(p, 0x80)}) {
                    Instruction call = p.getListing().getInstructionAt(site);
                    if (call.getFallThrough() != null && call.getFlowOverride() != FlowOverride.CALL_RETURN)
                        call.setFlowOverride(FlowOverride.CALL_RETURN);
                }
                MessageLog log = new MessageLog();
                new WSEvidenceRepairAnalyzer().added(p, p.getMemory(), monitor, log);
                outside = p.getListing().getInstructionAt(at(p, 0x80));
                check(helper.hasNoReturn(), "round " + round + ": N1 keeps the J4 yield helper non-returning");
                check(outside != null && outside.getFlowOverride() == FlowOverride.CALL_RETURN,
                    "round " + round + ": the call-fixup repair of a yield call site stays (no re-schedule cycle)");
                check(!plain.hasNoReturn(), "round " + round + ": N1 still clears an ordinary non-returning callee");
                plain.setNoReturn(true);
            }
            check(p.getListing().getInstructionAt(at(p, 0x43)) != null && p.getListing().getInstructionAt(at(p, 0x83)) != null,
                "continuation code preserved");
        } finally { p.endTransaction(tx, false); p.release(this); }
        println("WSSavedYieldN1Fixtures: checks=" + checks + " failures=" + failures);
        if (failures != 0) throw new AssertionError("WSSavedYieldN1Fixtures failures=" + failures);
        println("WSSavedYieldN1Fixtures: PASS checks=" + checks);
    }
}
