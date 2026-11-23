// SPDX-License-Identifier: MIT OR Apache-2.0
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import jidoughost.wonderswan.WSEvidence;
import jidoughost.wonderswan.WSMesenTrace;
import jidoughost.wonderswan.WSRom;
import jidoughost.wonderswan.WSRomWindows;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Exercise the real D0 and D1 pipeline using a saved synthetic listing. */
public class WSSegmentEntryFixtures extends GhidraScript {
    private static final byte[] STORE = {(byte) 0xa2, 0x34, 0x01, (byte) 0xc3};
    private static final int DEFAULT = 0x1000;
    private static final int ROM_SIZE = 4 * 1024 * 1024;
    private static final String BANK_FE = WSRomWindows.name(0x2000, 0xfe);
    private static final String BANK_FF = WSRomWindows.name(0x2000, 0xff);

    private record Fixture(String name, int linear, String block, int expected) {}

    private static final List<Fixture> CASES = List.of(
        new Fixture("observed_zero", 0x81020, "LIN_8000", 0),
        new Fixture("observed_nonzero", 0x81030, "LIN_8000", 0x220),
        new Fixture("ambiguous_register", 0x81040, "LIN_8000", DEFAULT),
        new Fixture("unobserved", 0x81050, "LIN_8000", DEFAULT),
        new Fixture("wrong_fixed_image", 0x81060, "LIN_8000", DEFAULT),
        new Fixture("mixed_fixed_images", 0x81070, "LIN_8000", DEFAULT),
        new Fixture("unknown_fixed_image", 0x81080, "LIN_8000", DEFAULT),
        new Fixture("observed_bank", 0x20020, BANK_FE, 0),
        new Fixture("other_bank", 0x20020, BANK_FF, DEFAULT),
        new Fixture("default_window", 0x20020, "DEFAULT_WINDOW", DEFAULT),
        new Fixture("observed_bank_mixed", 0x20030, BANK_FE, DEFAULT),
        new Fixture("other_bank_mixed", 0x20030, BANK_FF, DEFAULT),
        new Fixture("patched_entry", 0x81090, "LIN_8000", DEFAULT),
        new Fixture("mixed_evidence_sources", 0x810a0, "LIN_8000", DEFAULT)
    );

    private Address at(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Address at(Fixture fixture) {
        var block = currentProgram.getMemory().getBlock(fixture.block());
        return block.getStart().add(fixture.linear() - block.getStart().getOffset());
    }

    private void setup() throws Exception {
        var memory = currentProgram.getMemory();
        var rom = WSRom.fileBytes(currentProgram);
        if (rom == null || rom.getSize() != ROM_SIZE) throw new IllegalStateException("Fixture ROM must have 4 MiB");
        for (var block : memory.getBlocks()) memory.removeBlock(block, monitor);
        var code = memory.createInitializedBlock("LIN_8000", at(0x81000), rom, 0x381000, 0x100, false);
        code.setPermissions(true, false, true);
        var window = memory.createInitializedBlock("DEFAULT_WINDOW", at(0x20000), rom, 0x3f0000, 0x100, false);
        window.setPermissions(true, false, true);
        WSRomWindows.view(currentProgram, 0x2000, 0xfe, true, monitor);
        WSRomWindows.view(currentProgram, 0x2000, 0xff, true, monitor);
        for (int linear : new int[] {0x100, 0x2300, 0x10100}) {
            var data = memory.createUninitializedBlock("DATA_" + linear, at(linear), 0x100, false);
            data.setPermissions(true, true, false);
        }
        // MOV [0134],AL -> MOV [0134],AX at one otherwise correctly placed entry.
        memory.setByte(at(0x81090), (byte) 0xa3);
        for (var fixture : CASES) {
            var entry = at(fixture);
            var body = new AddressSet(entry, entry.add(STORE.length - 1));
            if (!new DisassembleCommand(entry, body, true).applyTo(currentProgram, monitor))
                throw new IllegalStateException("Could not disassemble " + fixture.name());
            currentProgram.getFunctionManager().createFunction(fixture.name(), entry, body, SourceType.ANALYSIS);
        }
    }

    private static void observe(WSMesenTrace.TraceData trace, long linear, Set<Integer> values,
            Set<Integer> c0, Set<Integer> windowBanks) {
        trace.firstCs.put(linear, (int) (linear >>> 16) << 12);
        trace.ds.put(linear, values);
        trace.ss.put(linear, values);
        if (!c0.isEmpty()) trace.c0.put(linear, c0);
        if (!windowBanks.isEmpty()) trace.windowBanks.put(linear, windowBanks);
    }

    private void applyRules(Path report) throws Exception {
        var trace = new WSMesenTrace.TraceData();
        for (long i = 0; i < 32; i++)
            observe(trace, 0x81800 + i, Set.of(DEFAULT), Set.of(0xff), Set.of());
        observe(trace, 0x81020, Set.of(0), Set.of(0xff), Set.of());
        observe(trace, 0x81030, Set.of(0x220), Set.of(0xff), Set.of());
        observe(trace, 0x81040, Set.of(0, 0x220), Set.of(0xff), Set.of());
        observe(trace, 0x81060, Set.of(0), Set.of(0xfe), Set.of());
        observe(trace, 0x81070, Set.of(0), Set.of(0xfe, 0xff), Set.of());
        observe(trace, 0x81080, Set.of(0), Set.of(), Set.of());
        observe(trace, 0x81090, Set.of(0), Set.of(0xff), Set.of());
        observe(trace, 0x810a0, Set.of(0), Set.of(0xff), Set.of());
        observe(trace, 0x20020, Set.of(0), Set.of(), Set.of(0xfe));
        observe(trace, 0x20030, Set.of(0), Set.of(), Set.of(0xfe, 0xff));
        var primary = WSEvidence.fromMesen(trace, null, null, "synthetic", ROM_SIZE, null, -1);
        if (primary.cs.containsKey(0x81060L) || !Set.of(0).equals(primary.ds.get(0x81060L)))
            throw new IllegalStateException("Mismatched C0 must retain title samples without qualifying execution");
        var otherTrace = new WSMesenTrace.TraceData();
        observe(otherTrace, 0x810a0, Set.of(0), Set.of(0xfe), Set.of());
        var secondary = WSEvidence.fromMesen(otherTrace, null, null, "opposing", ROM_SIZE, null, -1);
        var ev = WSEvidence.merge(primary, secondary);

        var seeder = Class.forName("jidoughost.wonderswan.WSEvidenceAnalyzer$Seeder", true, WSEvidence.class.getClassLoader());
        var constructor = seeder.getDeclaredConstructor(Program.class, WSEvidence.class, String.class,
            boolean.class, TaskMonitor.class, MessageLog.class);
        constructor.setAccessible(true);
        try (var rules = (AutoCloseable) constructor.newInstance(currentProgram, ev, report.toString(),
                false, monitor, new MessageLog())) {
            var repair = Class.forName("jidoughost.wonderswan.WSEvidenceRepairAnalyzer", true, WSEvidence.class.getClassLoader());
            var d0 = repair.getDeclaredMethod("applyDsDefault", Program.class, WSEvidence.class, seeder);
            d0.setAccessible(true);
            d0.invoke(null, currentProgram, ev, rules);
            for (var fixture : CASES) {
                if (segment("DS", at(fixture)) != DEFAULT || segment("SS", at(fixture)) != DEFAULT)
                    throw new IllegalStateException("Fixture did not receive the nonzero D0 default");
            }
            var d1 = seeder.getDeclaredMethod("seedDs");
            d1.setAccessible(true);
            d1.invoke(rules);
        }
    }

    private int segment(String register, Address address) {
        BigInteger value = currentProgram.getProgramContext().getValue(currentProgram.getRegister(register), address, false);
        return value == null ? -1 : value.intValueExact();
    }

    private long decompiledStore(DecompInterface decompiler, Address entry, int width) {
        var result = decompiler.decompileFunction(currentProgram.getFunctionManager().getFunctionAt(entry), 20, monitor);
        if (!result.decompileCompleted()) throw new IllegalStateException(result.getErrorMessage());
        for (var ops = result.getHighFunction().getPcodeOps(); ops.hasNext();) {
            var op = ops.next();
            var output = op.getOutput();
            if (op.getSeqnum().getTarget().getOffset() == entry.getOffset() && op.getOpcode() == PcodeOp.COPY
                && output != null && output.isAddress() && output.getSize() == width
                && op.getInput(0).isRegister()) {
                return output.getOffset();
            }
        }
        throw new IllegalStateException("Missing folded one-byte store at " + entry);
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args[0].equals("setup")) {
            setup();
            return;
        }

        Path output = Path.of(args[1]);
        if (args[0].equals("apply")) {
            applyRules(output);
            return;
        }

        var rows = new ArrayList<String>();
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot open decompiler");
            for (var fixture : CASES) {
                var entry = at(fixture);
                int data = segment("DS", entry);
                int stack = segment("SS", entry);
                long store = decompiledStore(decompiler, entry, fixture.name().equals("patched_entry") ? 2 : 1);
                long expectedStore = (fixture.expected() << 4) + 0x134;
                boolean pass = data == fixture.expected() && stack == fixture.expected() && store == expectedStore;
                rows.add("%s\t%s\tDS=%04x\tSS=%04x\tstore=%05x\texpected=%05x".formatted(
                    fixture.name(), pass ? "PASS" : "FAIL", data, stack, store, expectedStore));
            }
        } finally {
            decompiler.dispose();
        }
        Files.write(output, rows);
        if (rows.stream().anyMatch(row -> row.contains("\tFAIL\t")))
            throw new IllegalStateException("Segment entry fixtures failed. See the result report.");
    }
}
