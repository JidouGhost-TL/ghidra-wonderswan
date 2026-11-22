// SPDX-License-Identifier: MIT OR Apache-2.0
// Inspect the saved synthetic bank exercise without reanalysis.
//@category WonderSwan.Examples

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.symbol.RefType;
import jidoughost.wonderswan.WSRom;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

public class VerifyBankedCall extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || (!args[2].equals("observed") && !args[2].equals("static"))) {
            throw new IllegalArgumentException("Usage: original.ws receipt.txt observed|static");
        }
        Path cartridge = Path.of(args[0]);
        byte[] rom = Files.readAllBytes(cartridge);
        HexFormat hex = HexFormat.of();
        String sha256 = hex.formatHex(MessageDigest.getInstance("SHA-256").digest(rom));
        if (!sha256.equals(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("Reopened program hash differs from the cartridge hash");
        }

        long expectedOffset = switch (cartridge.getFileName().toString()) {
            case "bank-fe.ws", "bank-unknown.ws" -> 0x69;
            case "bank-ff.ws" -> 0x10069;
            default -> throw new IllegalArgumentException("Use a cartridge generated for this exercise");
        };
        var cpu = (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        var call = currentProgram.getListing().getInstructionAt(cpu.getAddress(0xf000, 0x010d));
        if (call == null || !hex.formatHex(call.getBytes()).equals("9a69000020")) {
            throw new IllegalStateException("Expected the fixture's far call at F000:010D");
        }

        var report = new StringBuilder("sha256\t").append(sha256).append("\n");
        report.append("call\t").append(call.getAddress()).append("\t9a69000020\n");
        String decompiled = null;
        boolean rawWindow = false;
        int qualified = 0;
        for (var reference : call.getReferencesFrom()) {
            var target = reference.getToAddress();
            var block = currentProgram.getMemory().getBlock(target);
            var offset = WSRom.offsetOf(currentProgram, target);
            if (reference.getReferenceType().isCall()) {
                report.append("reference\t").append(reference.getReferenceType()).append("\t")
                    .append(target).append("\t").append(block == null ? "-" : block.getName()).append("\n");
            }
            if (block != null && block.getName().equals("ROM0_WINDOW")
                    && reference.getReferenceType().isCall() && offset.isEmpty()) {
                rawWindow = true;
            }
            if (reference.getReferenceType() != RefType.CALL_OVERRIDE_UNCONDITIONAL) {
                continue;
            }
            qualified++;
            if (block == null || !block.isInitialized() || !block.isExecute()
                    || offset.orElse(-1) != expectedOffset) {
                throw new IllegalStateException("Unexpected physical call target: " + target);
            }
            byte[] body = new byte[6];
            currentProgram.getMemory().getBytes(target, body);
            int start = Math.toIntExact(expectedOffset);
            if (!Arrays.equals(body, Arrays.copyOfRange(rom, start, start + body.length))) {
                throw new IllegalStateException("Overlay bytes differ from the cartridge");
            }
            report.append("rom-offset\t0x").append(Long.toHexString(expectedOffset)).append("\n");
            report.append("target-bytes\t").append(hex.formatHex(body)).append("\n");

            var function = currentProgram.getFunctionManager().getFunctionAt(target);
            if (function == null) {
                throw new IllegalStateException("Missing saved function at " + target);
            }
            var decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    throw new IllegalStateException("Could not open the decompiler");
                }
                var result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted()) {
                    throw new IllegalStateException(result.getErrorMessage());
                }
                decompiled = result.getDecompiledFunction().getC();
                String marker = expectedOffset == 0x69 ? "42" : "99";
                if (!decompiled.replaceAll("\\s+", "").contains("uRam00000200=0x" + marker + ";")) {
                    throw new IllegalStateException("Missing the expected marker store at RAM 0x0200");
                }
            } finally {
                decompiler.dispose();
            }
        }

        int expectedCalls = args[2].equals("observed") ? 1 : 0;
        if (!rawWindow || qualified != expectedCalls) {
            throw new IllegalStateException("Expected raw window call and " + expectedCalls
                + " physical call override, found raw=" + rawWindow + " physical=" + qualified);
        }
        report.append("physical-overrides\t").append(qualified).append("\n");
        if (decompiled != null) {
            report.append("\n").append(decompiled);
        }
        Files.writeString(Path.of(args[1]), report, StandardOpenOption.CREATE_NEW);
    }
}
