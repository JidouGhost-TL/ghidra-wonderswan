// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import java.util.function.Consumer;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** B3t: a proved constant-bank far jump is a tail transfer into its decoded bank view. */
public final class WSBankTransfers {
    public static final String CATEGORY = "WSBankTransfer";
    private WSBankTransfers() { }
    public static String apply(Program p, Consumer<String> emit, TaskMonitor monitor) throws Exception {
        List<Instruction> code = new ArrayList<>();
        for (Instruction i : p.getListing().getInstructions(true)) code.add(i);
        int tails = 0;
        for (Instruction i : code) {
            monitor.checkCancelled();
            if (!i.getMnemonicString().equals("JMPF") || !i.getFlowType().isJump()
                || i.getFlowType().isComputed() || i.getFlowType().isConditional()
                || i.getFlowOverride() != FlowOverride.NONE || i.getFlows().length != 1) continue;
            Address raw = i.getFlows()[0]; long lin = raw.getOffset();
            if (raw.getAddressSpace().isOverlaySpace() || lin < 0x20000 || lin >= 0x40000) continue;
            Function owner = p.getFunctionManager().getFunctionContaining(i.getAddress());
            if (owner == null || owner.getSymbol().getSource() == SourceType.USER_DEFINED
                || owner.getSignatureSource() == SourceType.USER_DEFINED || owner.getSignatureSource() == SourceType.IMPORTED) continue;
            if (Arrays.stream(i.getReferencesFrom()).anyMatch(r -> r.getReferenceType().isFlow()
                && (r.getSource() == SourceType.USER_DEFINED || r.getSource() == SourceType.IMPORTED))) continue;
            Integer bank = WSRomEvidence.staticBank(p, i, lin);
            if (bank == null) continue;
            String name = String.format("ROM%d_BANK_%04X", lin < 0x30000 ? 0 : 1, bank);
            var block = p.getMemory().getBlock(name);
            if (block == null || !block.isInitialized()) continue;
            Address target = block.getStart().add(lin & 0xffff);
            if (p.getListing().getInstructionAt(target) == null) continue;
            Function into = p.getFunctionManager().getFunctionAt(target);
            if (into == null) {
                new CreateFunctionCmd(target).applyTo(p, monitor);
                into = p.getFunctionManager().getFunctionAt(target);
            }
            if (into == null) continue;
            i.setFlowOverride(FlowOverride.CALL_RETURN);
            Reference ref = p.getReferenceManager().addMemoryReference(i.getAddress(), target,
                RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, Reference.MNEMONIC);
            p.getReferenceManager().setPrimary(ref, true);
            p.getBookmarkManager().setBookmark(i.getAddress(), BookmarkType.ANALYSIS, CATEGORY,
                String.format("B3t constant-bank tail transfer: bank %04X, encoded %s, target %s", bank, raw, target));
            tails++;
            emit.accept(String.format("{\"rule\":\"B3t\",\"site\":\"%s\",\"encoded_target\":\"%s\",\"target\":\"%s\",\"bank\":%d,\"outcome\":\"TAIL_TRANSFER\"}",
                i.getAddress(), raw, target, bank));
        }
        return "B3t constant-bank tail transfers " + tails;
    }
}
