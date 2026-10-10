// SPDX-License-Identifier: MIT OR Apache-2.0
// Run the current cartridge as one console whose serial port is a raw byte stream over TCP. The partner can be another
// console in a separate process, a relay, or a bridge to a serial device or another program (for example socat).
// Args: <endpoint> <out dir> [frames=1500] [shotEvery=100] [input|-] [saves|-] [model=auto|mono|color]
//       [pacing=pull|wire] [timing=realtime|fast]
// Endpoint: tcp:<host>:<port> (connect, retried for 60 s) or listen:[<host>:]<port> (wait 60 s for one peer).
// Input: "from to buttons" (inclusive frame numbers, hexadecimal WSMachine button mask); missing input = no buttons.
// Saves: read-only input directory in WSMachine's save-image naming scheme.
// Output: shot_NNNNN.png, final.png, ram.bin, saves/, serial.tsv (direction frame clock value baud result), summary.txt.
// Pacing (receive): pull holds an incoming byte while the previous one is unread; wire delivers at line rate.
// Timing: realtime paces frames to wall-clock time (for partners that run in real time); fast runs unthrottled.
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import javax.imageio.ImageIO;

public class WSSerialEndpointRun extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("need endpoint and output directory");
        Path out = Path.of(args[1]);
        Files.createDirectories(out);
        int frames = args.length > 2 ? Integer.parseInt(args[2]) : 1500;
        int shotEvery = args.length > 3 ? Integer.parseInt(args[3]) : 100;
        List<int[]> inputs = input(arg(args, 4, "-"));
        WSSerialEndpoint.Pacing pacing = WSSerialEndpoint.Pacing.valueOf(arg(args, 7, "pull").toUpperCase(Locale.ROOT));
        boolean realTime = switch (arg(args, 8, "realtime")) {
            case "realtime" -> true;
            case "fast" -> false;
            default -> throw new IllegalArgumentException("timing must be realtime or fast");
        };
        WSMachine machine = new WSMachine(currentProgram, color(arg(args, 6, "auto")));
        if (!arg(args, 5, "-").equals("-")) machine.loadSaves(Path.of(args[5]));
        long[] counts = { 0, 0, 0 };
        long start = System.currentTimeMillis();
        int[] completed = { 0 };
        Exception failure = null;
        try (Socket socket = open(args[0]);
             PrintWriter log = new PrintWriter(out.resolve("serial.tsv").toFile())) {
            socket.setTcpNoDelay(true);
            log.println("direction\tframe\tclock\tvalue\tbaud\tresult");
            try (WSSerialEndpoint link = new WSSerialEndpoint(machine, socket.getInputStream(), socket.getOutputStream(), pacing, e -> {
                    log.printf("%s\t%d\t%d\t%02X\t%d\t%s%n", e.direction(), e.frame(), e.clock(), e.value(), e.baud(), e.result());
                    counts[e.direction().equals("TX") ? 0 : 1]++;
                    if (!e.result().equals("SENT") && !e.result().equals("RECEIVED")) counts[2]++;
                })) {
                link.run(frames, realTime, f -> {
                    if (monitor.isCancelled()) throw new IllegalStateException("serial endpoint run cancelled");
                    machine.buttons = buttons(inputs, f);
                    if (shotEvery > 0 && f % shotEvery == 0) {
                        try { ImageIO.write(WSRender.render(machine), "png", out.resolve(String.format("shot_%05d.png", f)).toFile()); }
                        catch (IOException ex) { throw new UncheckedIOException(ex); }
                    }
                    completed[0] = f;
                    if (f % 500 == 0) {
                        log.flush();
                        println(String.format("WSSerialEndpointRun: frame=%d pc=%05X tx=%d rx=%d other=%d", f, machine.linearPC(), counts[0], counts[1], counts[2]));
                    }
                });
                completed[0] = frames;
                if (link.readFailure() != null) println("WSSerialEndpointRun: peer read failed: " + link.readFailure());
            }
        } catch (Exception ex) { failure = ex; }
        finally {
            ImageIO.write(WSRender.render(machine), "png", out.resolve("final.png").toFile());
            Files.write(out.resolve("ram.bin"), machine.read(0, 0x10000));
            machine.writeSaves(out.resolve("saves"));
        }
        String summary = String.format("endpoint=%s pacing=%s timing=%s frames=%d/%d clocks=%d instructions=%d tx=%d rx=%d not_delivered=%d ms=%d error=%s%n",
            args[0], pacing, realTime ? "realtime" : "fast", completed[0], frames, machine.cycles, machine.instructions,
            counts[0], counts[1], counts[2], System.currentTimeMillis() - start, failure);
        Files.writeString(out.resolve("summary.txt"), summary);
        println("WSSerialEndpointRun: " + summary);
        if (failure != null) throw failure;
    }

    /** tcp:<host>:<port> connects (retrying for 60 s); listen:[<host>:]<port> accepts one peer within 60 s. */
    private Socket open(String endpoint) throws IOException, InterruptedException {
        int colon = endpoint.lastIndexOf(':');
        if (endpoint.startsWith("tcp:") && colon > 4) {
            String host = endpoint.substring(4, colon);
            int port = Integer.parseInt(endpoint.substring(colon + 1));
            long deadline = System.currentTimeMillis() + 60_000;
            while (true) {
                try { return new Socket(host, port); }
                catch (ConnectException e) {
                    if (System.currentTimeMillis() > deadline) throw e;
                    Thread.sleep(250);
                }
            }
        }
        if (endpoint.startsWith("listen:")) {
            String rest = endpoint.substring(7);
            int c = rest.lastIndexOf(':');
            String host = c < 0 ? "0.0.0.0" : rest.substring(0, c);
            int port = Integer.parseInt(c < 0 ? rest : rest.substring(c + 1));
            try (ServerSocket server = new ServerSocket()) {
                server.setReuseAddress(true);
                server.bind(new InetSocketAddress(host, port));
                server.setSoTimeout(60_000);
                return server.accept();
            }
        }
        throw new IllegalArgumentException("endpoint must be tcp:<host>:<port> or listen:[<host>:]<port>");
    }

    private static String arg(String[] args, int index, String fallback) { return args.length > index ? args[index] : fallback; }

    private boolean color(String model) {
        return switch (model) {
            case "auto" -> currentProgram.getOptions("WonderSwan").getBoolean("Color", true);
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
}
