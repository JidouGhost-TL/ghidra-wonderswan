// SPDX-License-Identifier: MIT OR Apache-2.0
// Boot current cartridge as A and a second cartridge as B, linked in one process.
// Args: <ROM B> <out dir> [frames=1500] [shotEvery=100] [input A|-] [input B|-]
//       [saves A|-] [saves B|-] [model A=auto|mono|color] [model B=auto|mono|color]
// Input: "from to buttons" (inclusive shared frame numbers, hexadecimal WSMachine button mask).
// Missing input means no buttons. Saves are read-only inputs in WSMachine's save-image naming scheme.
// Output: A/ and B/ screenshots, final.png, ram.bin, ports.bin, saves/, coverage.tsv; serial.tsv and summary.txt.
// Coverage: ROM file byte ranges [rom_start, rom_end), hexadecimal offsets, decimal first shared frame.
// Shared frames are 159 * 256 clocks; each console retains its own post-boot display phase.
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;
import jidoughost.wonderswan.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.ImageIO;

public class WSLinkEmulate extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("need ROM B and output directory");
        Path out = Path.of(args[1]);
        Files.createDirectories(out.resolve("A"));
        Files.createDirectories(out.resolve("B"));
        int frames = args.length > 2 ? Integer.parseInt(args[2]) : 1500;
        int shotEvery = args.length > 3 ? Integer.parseInt(args[3]) : 100;
        List<int[]> inputsA = input(arg(args, 4, "-")), inputsB = input(arg(args, 5, "-"));
        Program other;
        try (var loaded = ProgramLoader.builder().source(new File(args[0]))
                .loaders(WonderSwanLoader.class).language(currentProgram.getLanguage())
                .compiler(currentProgram.getCompilerSpec()).monitor(monitor).load()) {
            other = loaded.getPrimaryDomainObject(this);
        }
        try {
            WSMachine a = new WSMachine(currentProgram, color(currentProgram, arg(args, 8, "auto")));
            WSMachine b = new WSMachine(other, color(other, arg(args, 9, "auto")));
            a.traceLimit = b.traceLimit = 0;
            Coverage coverageA = new Coverage(a), coverageB = new Coverage(b);
            a.beforeStep = coverageA::beforeStep;
            b.beforeStep = coverageB::beforeStep;
            if (!arg(args, 6, "-").equals("-")) a.loadSaves(Path.of(args[6]));
            if (!arg(args, 7, "-").equals("-")) b.loadSaves(Path.of(args[7]));
            long start = System.currentTimeMillis();
            int[] completed = { 0 };
            long[] bytes = { 0, 0, 0 };
            Exception failure = null;
            try (PrintWriter log = new PrintWriter(out.resolve("serial.tsv").toFile())) {
                log.println("direction\tframe\tclock\tvalue\tbaud\tresult");
                WSLink link = new WSLink(a, b, e -> {
                    log.printf("%s\t%d\t%d\t%02X\t%d\t%s%n", e.direction(), e.frame(), e.clock(), e.value(), e.baud(), e.result());
                    bytes[e.direction().equals("A>B") ? 0 : 1]++;
                    if (!e.result().equals("RECEIVED")) bytes[2]++;
                });
                try {
                    link.run(frames, f -> {
                        coverageA.frame = coverageB.frame = f;
                        if (monitor.isCancelled()) throw new IllegalStateException("link run cancelled");
                        a.buttons = buttons(inputsA, f);
                        b.buttons = buttons(inputsB, f);
                        if (shotEvery > 0 && f % shotEvery == 0) {
                            try { shot(a, out.resolve("A"), f); shot(b, out.resolve("B"), f); }
                            catch (IOException ex) { throw new UncheckedIOException(ex); }
                        }
                        completed[0] = f;
                        if (f % 100 == 0) {
                            log.flush();
                            println(String.format("WSLinkEmulate: frame=%d clock=%d A=%05X B=%05X bytes=%d/%d dropped=%d",
                                f, link.clock(), a.linearPC(), b.linearPC(), bytes[0], bytes[1], bytes[2]));
                        }
                    });
                    completed[0] = frames;
                } catch (Exception ex) { failure = ex; }
            } finally {
                coverageA.write(out.resolve("A/coverage.tsv"));
                coverageB.write(out.resolve("B/coverage.tsv"));
                finish(a, out.resolve("A"));
                finish(b, out.resolve("B"));
            }
            String summary = String.format("frames=%d/%d clocks=%d/%d instructions=%d/%d bytes=%d/%d dropped=%d ms=%d error=%s%n",
                completed[0], frames, a.cycles, b.cycles, a.instructions, b.instructions, bytes[0], bytes[1], bytes[2],
                System.currentTimeMillis() - start, failure);
            Files.writeString(out.resolve("summary.txt"), summary);
            println("WSLinkEmulate: " + summary);
            if (failure != null) throw failure;
        } finally { other.release(this); }
    }

    private static String arg(String[] args, int index, String fallback) { return args.length > index ? args[index] : fallback; }

    /** Sample new instruction starts before bank-changing OUTs, then confirm against the executed map.
     * Decode only a ROM start's first visit; include operand bytes, exclude RAM and cartridge padding.
     * Adjacent bytes merge only when their first frames agree, preserving each byte's first observation.
     */
    static final class Coverage {
        final WSMachine machine;
        final int[] firstFrame;
        final BitSet starts = new BitSet();
        int frame, pendingFrame;
        long pendingLinear = -1;
        int[] pendingOffsets;

        Coverage(WSMachine machine) {
            this.machine = machine;
            firstFrame = new int[Math.toIntExact(machine.cartridge.fileSize)];
            Arrays.fill(firstFrame, -1);
        }

        void confirm() {
            if (pendingOffsets != null && machine.executed.containsKey(pendingLinear)) {
                for (int offset : pendingOffsets)
                    if (offset >= 0 && firstFrame[offset] < 0) firstFrame[offset] = pendingFrame;
                if (pendingOffsets[0] >= 0) starts.set(pendingOffsets[0]);
            }
            pendingOffsets = null;
        }

        void beforeStep(WSMachine m) {
            confirm();
            long linear = m.linearPC();
            long effective = m.romOffset(linear);
            if (effective < 0) return;
            int offset = (int) WSHardware.fileOffset(effective, m.cartridge.fileSize);
            if (offset < 0 || offset >= firstFrame.length || starts.get(offset)) return;
            try {
                ProcessorContextImpl context = new ProcessorContextImpl(m.lang);
                context.setRegisterValue(m.thread.getContext());
                int length = m.lang.parse(new ByteMemBufferImpl(m.addr(linear), m.read(linear, 16), false),
                    context, false).getLength();
                pendingOffsets = new int[length];
                for (int i = 0; i < length; i++) {
                    long rom = m.romOffset((linear + i) & 0xFFFFF);
                    long file = rom < 0 ? -1 : WSHardware.fileOffset(rom, m.cartridge.fileSize);
                    pendingOffsets[i] = file >= 0 && file < firstFrame.length ? (int) file : -1;
                }
                pendingLinear = linear;
                pendingFrame = frame;
            } catch (ghidra.program.model.lang.InsufficientBytesException |
                     ghidra.program.model.lang.UnknownInstructionException ex) {
                // Let the CPU report its own decode failure; never invent instruction lengths.
            }
        }

        void write(Path file) throws IOException {
            confirm();
            try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(file))) {
                w.println("rom_start\trom_end\tfirst_frame");
                for (int start = 0; start < firstFrame.length;) {
                    if (firstFrame[start] < 0) { start++; continue; }
                    int end = start + 1;
                    while (end < firstFrame.length && firstFrame[end] == firstFrame[start]) end++;
                    w.printf("%x\t%x\t%d%n", start, end, firstFrame[start]);
                    start = end;
                }
            }
        }
    }

    private static boolean color(Program program, String model) {
        return switch (model) {
            case "auto" -> program.getOptions("WonderSwan").getBoolean("Color", true);
            case "color" -> true;
            case "mono" -> false;
            default -> throw new IllegalArgumentException("model must be auto, mono or color");
        };
    }

    private static List<int[]> input(String file) throws IOException {
        List<int[]> spans = new ArrayList<>();
        if (file.equals("-")) return spans;
        for (String line : Files.readAllLines(Path.of(file))) {
            line = line.replaceAll("#.*", "").trim();
            if (line.isEmpty()) continue;
            String[] words = line.split("\\s+");
            if (words.length != 3) throw new IllegalArgumentException("need 'from to buttons': " + line);
            int from = Integer.parseInt(words[0]), to = Integer.parseInt(words[1]), value = Integer.parseInt(words[2], 16);
            if (from < 0 || to < from || (value & ~0xFFE) != 0) throw new IllegalArgumentException("invalid input span: " + line);
            spans.add(new int[] { from, to, value });
        }
        return spans;
    }

    private static int buttons(List<int[]> spans, int frame) {
        int value = 0;
        for (int[] span : spans) if (frame >= span[0] && frame <= span[1]) value |= span[2];
        return value;
    }

    private static void shot(WSMachine machine, Path out, int frame) throws IOException {
        ImageIO.write(WSRender.render(machine), "png", out.resolve(String.format("shot_%05d.png", frame)).toFile());
    }

    private static void finish(WSMachine machine, Path out) throws IOException {
        ImageIO.write(WSRender.render(machine), "png", out.resolve("final.png").toFile());
        Files.write(out.resolve("ram.bin"), machine.read(0, 0x10000));
        byte[] ports = new byte[256];
        for (int p = 0; p < ports.length; p++) ports[p] = (byte) machine.ports[p];
        Files.write(out.resolve("ports.bin"), ports);
        machine.writeSaves(out.resolve("saves"));
    }
}
