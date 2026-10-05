// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Immutable display-state snapshot: work RAM, I/O ports, per-line port state
 * and the hardware colour flag. Headless-friendly: it carries no emulator or
 * GUI references, so asset code can render from a live machine, a saved state
 * or a pair of WSEmulate output files ({@code ram_N.bin}, {@code ports_N.bin}).
 *
 * <p>Layout follows the WSdev Display pages: 2bpp tiles at 0x2000, 4bpp tiles
 * at 0x4000, screen maps at {@code nibble * 0x800}, sprite table at
 * {@code (port04 & 0x3F) * 0x200}, colour palettes at 0xFE00 (RGB444), mono
 * shade pool at ports 1C-1F with per-palette LUTs at ports 20-3F.
 */
public final class WSSnapshot {
    /** Work RAM size (colour); mono hardware exposes the low 16 KiB. */
    public static final int RAM_SIZE = 0x10000;
    public static final int PORTS = 256;
    public static final int VISIBLE_LINES = 144;

    public final byte[] ram;
    public final int[] ports;
    /** Per-visible-line port snapshots for raster effects; entries may be null. */
    public final int[][] linePorts;
    /** True on colour hardware (the MUL ZF / palette-RAM model). */
    public final boolean colorHardware;

    public WSSnapshot(byte[] ram, int[] ports, int[][] linePorts, boolean colorHardware) {
        if (ram == null || ram.length != RAM_SIZE) throw new IllegalArgumentException("ram must be 64 KiB");
        if (ports == null || ports.length != PORTS) throw new IllegalArgumentException("ports must hold 256 entries");
        if (linePorts != null && linePorts.length != VISIBLE_LINES)
            throw new IllegalArgumentException("linePorts must hold 144 entries");
        this.ram = ram.clone();
        this.ports = ports.clone();
        if (linePorts == null) {
            this.linePorts = new int[VISIBLE_LINES][];
        } else {
            this.linePorts = new int[VISIBLE_LINES][];
            for (int i = 0; i < VISIBLE_LINES; i++) {
                this.linePorts[i] = linePorts[i] == null ? null : linePorts[i].clone();
            }
        }
        this.colorHardware = colorHardware;
    }

    /** Capture the display state of a live emulator machine. */
    public static WSSnapshot fromMachine(WSMachine m) {
        return new WSSnapshot(m.read(0, RAM_SIZE), m.ports, m.linePorts, m.color);
    }

    /**
     * Load a snapshot from WSEmulate outputs: a 64 KiB RAM dump and a 256-byte
     * port dump. No per-line state is available, so every line renders with the
     * same ports.
     */
    public static WSSnapshot fromFiles(Path ramBin, Path portsBin, boolean colorHardware) throws IOException {
        byte[] ram = Files.readAllBytes(ramBin);
        byte[] pb = Files.readAllBytes(portsBin);
        if (ram.length != RAM_SIZE) throw new IllegalArgumentException(ramBin + ": " + ram.length + " bytes, need 65536");
        if (pb.length != PORTS) throw new IllegalArgumentException(portsBin + ": " + pb.length + " bytes, need 256");
        int[] ports = new int[PORTS];
        for (int i = 0; i < PORTS; i++) ports[i] = pb[i] & 0xFF;
        return new WSSnapshot(ram, ports, null, colorHardware);
    }

    /** Colour mode active on the given port row (port 60 bit 7, colour hardware). */
    public boolean colorMode(int[] p) {
        return colorHardware && (p[0x60] & 0x80) != 0;
    }

    /** Ports in force at the start of a visible line (raster snapshot, else current). */
    public int[] portsForLine(int y) {
        return linePorts[y] != null ? linePorts[y] : ports;
    }
}
