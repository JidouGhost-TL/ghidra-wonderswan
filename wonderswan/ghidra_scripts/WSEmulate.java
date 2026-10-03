// SPDX-License-Identifier: MIT OR Apache-2.0
// Run the current WonderSwan program in WSMachine and write emulation evidence.
// Args: <out dir> [frames=1500] [slice=40000] [stopAt linear hex, or - for none] [shotEvery=100]
//       [saves dir to load, or -] [input script file, or -]
// Writes coverage.json (executed instruction linear addresses with ROM offset, CS and DS/ES sets), edges.tsv,
// banks.json (bank writes + DMA log), ram.bin, vram_writers.json, saves/ (internal.eeprom, cart.eeprom,
// cart.sram as present after the run) and eeprom.log (every EEPROM operation and refused request).
// Default input: Start on frames f>=100 with f%40<3, A on 20<=f%40<23. An input script replaces it: one
// "from to buttons" line per span (frames, inclusive; buttons hex: bit1 Start, 2 A, 3 B, 4-7 X, 8-11 Y).
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.WSHardware;
import jidoughost.wonderswan.WSMachine;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class WSEmulate extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        Path out = Paths.get(a[0]); Files.createDirectories(out);
        int frames = a.length > 1 ? Integer.parseInt(a[1]) : 1500;
        int slice = a.length > 2 ? Integer.parseInt(a[2]) : 40000;
        int shotEvery = a.length > 4 ? Integer.parseInt(a[4]) : 100;
        boolean color = currentProgram.getOptions("WonderSwan").getBoolean("Color", true);
        WSMachine m = new WSMachine(currentProgram, color);
        if (a.length > 3 && !a[3].equals("-")) m.stopAt = Long.parseLong(a[3], 16);
        if (a.length > 5 && !a[5].equals("-")) println("WSEmulate: loaded saves " + m.loadSaves(Paths.get(a[5])));
        List<int[]> script = new ArrayList<>();
        if (a.length > 6 && !a[6].equals("-")) {
            for (String l : Files.readAllLines(Paths.get(a[6]))) {
                l = l.replaceAll("#.*", "").trim();
                if (l.isEmpty()) continue;
                String[] t = l.split("\\s+");
                if (t.length != 3) throw new IllegalArgumentException("input script line needs 'from to buttons': " + l);
                script.add(new int[] { Integer.parseInt(t[0]), Integer.parseInt(t[1]), Integer.parseInt(t[2], 16) });
            }
        }
        long t0 = System.currentTimeMillis();
        String error = null;
        try {
            m.run(frames, slice, f -> {
                if (script.isEmpty()) {
                    int ph = f % 40;
                    m.buttons = (f >= 100 && ph < 3) ? 0x02 : (f >= 100 && ph >= 20 && ph < 23) ? 0x04 : 0;
                } else {
                    int b = 0;
                    for (int[] sp : script) if (f >= sp[0] && f <= sp[1]) b |= sp[2];
                    m.buttons = b;
                }
                if (shotEvery > 0 && f % shotEvery == 0) {
                    try {
                        javax.imageio.ImageIO.write(jidoughost.wonderswan.WSRender.render(m), "png", out.resolve(String.format("shot_%05d.png", f)).toFile());
                        byte[] pb = new byte[256];
                        for (int i = 0; i < 256; i++) pb[i] = (byte) m.ports[i];
                        Files.write(out.resolve(String.format("ports_%05d.bin", f)), pb);
                        Files.write(out.resolve(String.format("ram_%05d.bin", f)), m.read(0, 0x10000));
                    }
                    catch (Exception e) { println("render failed at frame " + f + ": " + e); }
                }
                if (f % 100 == 0) println(String.format("frame %d insns %d pc %05x irq %s B2=%02x access %s", f, m.instructions, m.linearPC(), m.irqStats, m.ports[0xB2], m.accessStats));
            });
        } catch (Exception e) {
            error = e.toString();
            println("WSEmulate: stopped at " + String.format("%05x", m.linearPC()) + ": " + e);
            for (String t : m.trace) println("TRACE " + t);
        }
        long ms = System.currentTimeMillis() - t0;
        try (PrintWriter w = new PrintWriter(out.resolve("coverage.json").toFile())) {
            w.print("[");
            boolean first = true;
            for (Map.Entry<Long, Set<Integer>> e : m.executed.entrySet()) {
                long lin = e.getKey();
                StringBuilder ds = new StringBuilder(), es = new StringBuilder();
                TreeSet<Integer> d = new TreeSet<>(), x = new TreeSet<>();
                for (int v : e.getValue()) { d.add(v >>> 16); x.add(v & 0xFFFF); }
                Set<Integer> wb = m.windowBanks.get(lin);   // bank-window code: ROM offset per bank it ran under
                long romOff = wb != null ? WSHardware.bankToRom(wb.iterator().next(), m.rom.length) | (lin & 0xFFFF)
                    : lin >= 0x40000 ? m.romOffset(lin) : -1;
                w.print((first ? "" : ",") + String.format("{\"linear\":%d,\"rom_off\":%d,\"cs\":%d,\"ds\":%s,\"es\":%s%s}",
                    lin, romOff, m.csAt.getOrDefault(lin, -1), d, x, wb == null ? "" : ",\"banks\":" + wb));
                first = false;
            }
            w.print("]");
        }
        try (PrintWriter w = new PrintWriter(out.resolve("banks.json").toFile())) {
            w.print("{\"error\":" + (error == null ? "null" : "\"" + error.replace("\"", "'") + "\"") + ",\"instructions\":" + m.instructions
                + ",\"ms\":" + ms + ",\"bank_writes\":" + mapJson(m.bankWrites) + ",\"dma\":[" + String.join(",", m.dmaLog) + "]}");
        }
        Files.write(out.resolve("ram.bin"), m.read(0, 0x10000));
        m.writeSaves(out.resolve("saves"));
        try (PrintWriter w = new PrintWriter(out.resolve("eeprom.log").toFile())) {
            w.printf("# internal: %d operations, %d refused%n", m.internalEeprom.operations, m.internalEeprom.refused);
            for (String l : m.internalEeprom.log) w.println("I " + l);
            if (m.cartEeprom != null) {
                w.printf("# cartridge: %d operations, %d refused%n", m.cartEeprom.operations, m.cartEeprom.refused);
                for (String l : m.cartEeprom.log) w.println("C " + l);
            }
            if (m.sram != null) w.printf("# SRAM: %d bytes, %d stores%n", m.sram.length, m.sramWrites);
        }
        try (PrintWriter w = new PrintWriter(out.resolve("edges.tsv").toFile())) {
            w.println("from\tto\ttarget_cs\tkind\tcount");   // linear hex; from=fffff for injected irq
            for (Map.Entry<String, Integer> e : m.edges.entrySet()) w.println(e.getKey().replace(',', '\t') + "\t" + e.getValue());
        }
        try (PrintWriter w = new PrintWriter(out.resolve("trace.tsv").toFile())) {
            w.println("n\tcs\tip\tax\tbx\tcx\tdx\tsi\tdi\tbp\tsp\tds\tes\tss\tflags");
            for (String line : m.firstTrace) w.println(line);
        }
        println("ACCESS " + m.accessStats + " IRQ " + m.irqStats + " ports B2=" + m.ports[0xB2] + " B0=" + m.ports[0xB0]);
        println(String.format("WSEmulate: frames=%d instructions=%d unique_insn=%d dma=%d ms=%d (%.0f insn/s) error=%s",
            frames, m.instructions, m.executed.size(), m.dmaLog.size(), ms, m.instructions * 1000.0 / Math.max(1, ms), error));
    }

    static String mapJson(Map<String, Integer> m) {
        StringBuilder b = new StringBuilder("{");
        for (Map.Entry<String, Integer> e : m.entrySet()) b.append(b.length() > 1 ? "," : "").append("\"").append(e.getKey()).append("\":").append(e.getValue());
        return b.append("}").toString();
    }
}
