// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.List;
import java.util.ArrayList;

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.SleighInstructionDecoder;
import ghidra.pcode.emu.DefaultPcodeThread;
import ghidra.app.plugin.processors.sleigh.SleighParserContext;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.DisassemblerContextAdapter;
import ghidra.program.model.lang.ParserContext;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;

/** Decoded instructions and p-code, validated against the live memory and full context on every hit. */
final class WSInstructionDecoder extends SleighInstructionDecoder {
    // Bound retained parser contexts even when code repeatedly changes banks or modifies itself.
    private static final int MAX_ENTRIES = 16384;
    private final PcodeExecutorState<byte[]> memory;
    private final Map<Address, MemoInstruction> cache = new HashMap<>();
    private PseudoInstruction last;
    private int lastLength;

    WSInstructionDecoder(Language language, PcodeExecutorState<byte[]> memory) {
        super(language, memory);
        this.memory = memory;
    }

    @Override
    public PseudoInstruction decodeInstruction(Address address, RegisterValue context) {
        MemoInstruction hit = cache.get(address);
        if (hit != null && Objects.equals(hit.inputContext, context)
                && bytesMatch(address, hit.parsedBytes)) {
            last = hit;
            lastLength = hit.getLength();
            return hit;
        }
        // The framework's last-block reuse does not validate context or bytes.
        block = null;
        PseudoInstruction decoded = super.decodeInstruction(address, context);
        lastLength = super.getLastLengthWithDelays();
        try {
            if (decoded.getDelaySlotDepth() == 0) {
                ProcessorContextImpl parsedContext = new ProcessorContextImpl(language);
                parsedContext.setRegisterValue(decoded.getRegisterValue(language.getContextBaseRegister()));
                MemoInstruction memo = new MemoInstruction(language, decoded, parsedContext, context);
                if (cache.size() >= MAX_ENTRIES) cache.clear();
                cache.put(address, memo);
                decoded = memo;
            }
        } catch (AddressOverflowException | MemoryAccessException e) {
            throw new IllegalStateException("Cannot retain decoded instruction", e);
        }
        last = decoded;
        return decoded;
    }

    private boolean bytesMatch(Address address, byte[] bytes) {
        if (memory instanceof WSArrayState flat) return flat.matches(address, bytes);
        return Arrays.equals(bytes, memory.getVar(address, bytes.length, false, Reason.EXECUTE_DECODE));
    }

    @Override
    public Instruction getLastInstruction() {
        return last;
    }

    @Override
    public int getLastLengthWithDelays() {
        return lastLength;
    }

    static final class MemoInstruction extends PseudoInstruction {
        final RegisterValue inputContext;
        final byte[] parsedBytes;
        final String mnemonic;
        final boolean repeat, changesCS, loadsSS;
        final int inCycles;
        final FlowType flow;
        Varnode[] ioReads, ioWrites;
        private PcodeOp[] pcode;
        private PcodeOp[] pcodeWithOverrides;
        RegisterValue finishInput, finishOutput;
        Address finishCounter;
        byte[] finishBytes;
        private final Language language;
        private final List<Map.Entry<Address, RegisterValue>> commits;

        MemoInstruction(Language language, PseudoInstruction original, ProcessorContextImpl context,
                RegisterValue inputContext) throws AddressOverflowException, MemoryAccessException {
            super(language.getAddressFactory(), original.getAddress(), original.getPrototype(), original, context);
            this.inputContext = inputContext;
            this.parsedBytes = original.getParsedBytes();
            mnemonic = original.getMnemonicString();
            repeat = mnemonic.contains(".REP");
            changesCS = WSMachine.isCsWriter(mnemonic);
            flow = original.getFlowType();
            int q = 0;
            while (q < parsedBytes.length - 1 && WSCpuTiming.isPrefix(parsedBytes[q] & 0xFF)) q++;
            int opcode = parsedBytes[q] & 0xFF;
            inCycles = opcode == 0xE4 || opcode == 0xE5 ? 6 : opcode == 0xEC || opcode == 0xED ? 5 : 0;
            loadsSS = ("MOV".equals(mnemonic) || "POP".equals(mnemonic)) &&
                (opcode == 0x17 || (opcode == 0x8E && q + 1 < parsedBytes.length && ((parsedBytes[q + 1] >> 3) & 3) == 2));
            this.language = language;
            List<Map.Entry<Address, RegisterValue>> captured = new ArrayList<>();
            // applyCommits consumes the parser's list. Keep every masked write in its original order.
            ((SleighParserContext) getParserContext()).applyCommits(new DisassemblerContextAdapter() {
                @Override
                public void setFutureRegisterValue(Address address, RegisterValue value) {
                    if (value.getRegister().isProcessorContext()) captured.add(Map.entry(address, value));
                }
            });
            commits = List.copyOf(captured);
        }

        void prepareIo(PcodeProgram program, AddressSpace io) {
            if (ioReads != null) return;
            List<Varnode> reads = new ArrayList<>(), writes = new ArrayList<>();
            for (PcodeOp op : program.getCode()) {
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode input = op.getInput(i);
                    if (input.getAddress().getAddressSpace() == io) reads.add(input);
                }
                Varnode output = op.getOutput();
                if (output != null && output.getAddress().getAddressSpace() == io) writes.add(output);
            }
            ioReads = reads.toArray(Varnode[]::new);
            ioWrites = writes.toArray(Varnode[]::new);
        }

        RegisterValue committedContext(long counter) {
            RegisterValue result = new RegisterValue(language.getContextBaseRegister());
            for (var commit : commits) {
                if (commit.getKey().getOffset() == counter || commit.getKey().equals(getAddress())) {
                    result = result.assign(commit.getValue().getRegister(), commit.getValue());
                }
            }
            return result;
        }

        RegisterValue freshCommittedContext(long counter) {
            return DefaultPcodeThread.getContextAfterCommits(this, counter);
        }

        @Override
        public ParserContext getParserContext() throws MemoryAccessException {
            // Context commits are consumed by Ghidra; every framework application needs a fresh list.
            if (commits != null && !commits.isEmpty()) return getPrototype().getParserContext(this, this);
            return super.getParserContext();
        }

        @Override
        public PcodeOp[] getPcode() {
            return getPcode(false);
        }

        @Override
        public PcodeOp[] getPcode(boolean includeOverrides) {
            if (includeOverrides) {
                if (pcodeWithOverrides == null) pcodeWithOverrides = super.getPcode(true);
                return pcodeWithOverrides;
            }
            if (pcode == null) pcode = super.getPcode(false);
            return pcode;
        }
    }
}
