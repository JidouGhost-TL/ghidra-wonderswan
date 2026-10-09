// SPDX-License-Identifier: MIT OR Apache-2.0
// Boot current cartridge as A and a second cartridge as B, linked in one process.
// Args: <ROM B> <out dir> [frames=1500] [shotEvery=100] [input A|-] [input B|-]
//       [saves A|-] [saves B|-] [model A=auto|mono|color] [model B=auto|mono|color]
// Input: "from to buttons" (inclusive shared frame numbers, hexadecimal WSMachine button mask).
// Missing input means no buttons. Saves are read-only inputs in WSMachine's save-image naming scheme.
// Output: A/ and B/ screenshots, final.png, ram.bin, ports.bin, saves/; serial.tsv and summary.txt.
// Shared frames are 159 * 256 clocks; each console retains its own post-boot display phase.
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.program.model.listing.Program;
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
