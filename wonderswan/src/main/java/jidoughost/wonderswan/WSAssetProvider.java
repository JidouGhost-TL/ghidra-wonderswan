// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.image.BufferedImage;
import java.nio.file.Path;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

import docking.ComponentProvider;
import docking.WindowPosition;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

/**
 * Asset viewer panel: listing tiles/tilemaps plus emulator VRAM, palettes and
 * sprites. All decoding uses the headless {@link WSAssets} core.
 */
public class WSAssetProvider extends ComponentProvider {
    private static final int MAX_TILE_BYTES = 64 * 1024;
    private static final int MAX_MAP_ENTRIES = 32 * 32;

    private final WSAssetPlugin plugin;
    private Program program;
    private Address address;
    private int selectionLength;

    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel(" ");

    // Tiles tab
    private final JComboBox<WSTileFormat> tileFormat = new JComboBox<>(WSTileFormat.values());
    private final JComboBox<String> tileSource =
        new JComboBox<>(new String[] { "Listing", "ROM offset", "Decoded" });
    private final JTextField romOffset = new JTextField("0x000000", 8);
    private final JSpinner romStep = new JSpinner(new SpinnerNumberModel(256, 1, 65536, 256));
    private final JButton romPrev = new JButton("<");
    private final JButton romNext = new JButton(">");
    private final JButton romPagePrev = new JButton("<<");
    private final JButton romPageNext = new JButton(">>");
    private final JLabel romHere = new JLabel(" ");
    private final JButton romViewHere = new JButton("View cursor in ROM mode");
    private int lastWindowBytes = 4096;
    private final JComboBox<WSTileArrangement> tileArrange =
        new JComboBox<>(WSTileArrangement.presets());
    private final JSpinner arrangeW = new JSpinner(new SpinnerNumberModel(2, 1, 8, 1));
    private final JSpinner arrangeH = new JSpinner(new SpinnerNumberModel(2, 1, 8, 1));
    private final JComboBox<WSTileArrangement.Order> arrangeOrder =
        new JComboBox<>(WSTileArrangement.Order.values());
    private final JCheckBox arrangeCustom = new JCheckBox("Custom W/H", false);
    private final JSpinner tilePalette = new JSpinner(new SpinnerNumberModel(0, 0, 15, 1));
    private final JCheckBox tileColor = new JCheckBox("Colour", true);
    private final JSpinner tileWidth = new JSpinner(new SpinnerNumberModel(16, 1, 32, 1));
    private final JSpinner tileZoom = new JSpinner(new SpinnerNumberModel(2, 1, 8, 1));
    private final JLabel tileInfo = new JLabel(" ");
    private final JLabel tileImage = new JLabel();
    private byte[] decodedBytes;

    // Tilemap tab
    private final JSpinner mapCols = new JSpinner(new SpinnerNumberModel(32, 1, 64, 1));
    private final JComboBox<WSTileFormat> mapFormat = new JComboBox<>(WSTileFormat.values());
    private final JCheckBox mapColor = new JCheckBox("Colour", true);
    private final JComboBox<String> mapTileSource =
        new JComboBox<>(new String[] { "VRAM", "Listing", "ROM offset", "Decoded" });
    private final JTextField mapTileBase = new JTextField(12);
    private final JLabel mapInfo = new JLabel(" ");
    private final JLabel mapImage = new JLabel();

    // Emulator tab
    private final JLabel emuInfo = new JLabel(" ");
    private final JSpinner emuFrames = new JSpinner(new SpinnerNumberModel(300, 1, 100000, 100));
    private final JSpinner emuSlice = new JSpinner(new SpinnerNumberModel(15000, 100, 1000000, 1000));
    private final JButton emuRun = new JButton("Run emulator");
    private final JButton emuLoad = new JButton("Load ram/ports…");
    private final JButton emuClear = new JButton("Clear");
    private final JLabel screenImage = new JLabel();
    private final JLabel paletteImage = new JLabel();
    private final JLabel vramImage = new JLabel();
    private final JTable spriteTable;
    private WSSnapshot snapshot;

    private BufferedImage currentTiles, currentMap, currentScreen;

    public WSAssetProvider(WSAssetPlugin plugin) {
        super(plugin.getTool(), "WS Asset Viewer", plugin.getName());
        this.plugin = plugin;
        setTitle("WS Asset Viewer");
        setDefaultWindowPosition(WindowPosition.RIGHT);

        DefaultTableModel sm = new DefaultTableModel(
            new String[] { "#", "X", "Y", "Tile", "Pal", "Flip", "Pri", "Win" }, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        spriteTable = new JTable(sm);
        spriteTable.setPreferredScrollableViewportSize(new Dimension(420, 120));

        tileFormat.setSelectedItem(WSTileFormat.BPP2);
        mapFormat.setSelectedItem(WSTileFormat.BPP2);
        romStep.setToolTipText("Byte step for the ROM < > buttons");
        romPrev.setToolTipText("Back one step");
        romNext.setToolTipText("Forward one step");
        romPagePrev.setToolTipText("Back one window");
        romPageNext.setToolTipText("Forward one window");
        mapTileBase.setToolTipText(
            "Listing: address (empty = tiles follow the map). ROM offset: hex file offset (required).");

        tabs.addTab("Tiles", buildTilesTab());
        tabs.addTab("Tilemap", buildMapTab());
        tabs.addTab("Emulator", buildEmuTab());

        tileSource.addActionListener(e -> { updateRomEnabled(); refreshTiles(); });
        for (var c : new JComponent[] { tileFormat, tilePalette, tileColor, tileWidth, tileZoom,
                tileArrange, arrangeW, arrangeH, arrangeOrder, arrangeCustom }) {
            if (c instanceof JComboBox) ((JComboBox<?>) c).addActionListener(e -> refreshTiles());
            else if (c instanceof JSpinner) ((JSpinner) c).addChangeListener(e -> refreshTiles());
            else ((JCheckBox) c).addActionListener(e -> { updateRomEnabled(); refreshTiles(); });
        }
        romOffset.addActionListener(e -> refreshTiles());
        romPrev.addActionListener(e -> stepRom(-((Integer) romStep.getValue())));
        romNext.addActionListener(e -> stepRom((Integer) romStep.getValue()));
        romPagePrev.addActionListener(e -> stepRom(-lastWindowBytes));
        romPageNext.addActionListener(e -> stepRom(lastWindowBytes));
        romViewHere.addActionListener(e -> viewCursorInRom());
        for (var c : new JComponent[] { mapCols, mapFormat, mapColor, mapTileSource }) {
            if (c instanceof JComboBox) ((JComboBox<?>) c).addActionListener(e -> refreshMap());
            else if (c instanceof JSpinner) ((JSpinner) c).addChangeListener(e -> refreshMap());
            else ((JCheckBox) c).addActionListener(e -> refreshMap());
        }
        mapTileBase.addActionListener(e -> refreshMap());
        updateRomEnabled();
        emuRun.addActionListener(e -> runEmulator());
        emuLoad.addActionListener(e -> loadSnapshot());
        emuClear.addActionListener(e -> { snapshot = null; refreshEmu(); refreshMap(); });

        addToTool();
    }

    public Program getProgram() { return program; }

    private JPanel root;

    /** The docking framework may ask more than once; the component must be the same instance. */
    @Override public JComponent getComponent() {
        if (root == null) {
            root = new JPanel(new BorderLayout());
            root.add(tabs, BorderLayout.CENTER);
            root.add(status, BorderLayout.SOUTH);
        }
        return root;
    }

    /** Update the viewed program and cursor; refreshes listing tabs. */
    public void setProgram(Program p, ProgramLocation loc, ProgramSelection sel) {
        this.program = p;
        this.address = loc == null ? null : loc.getAddress();
        this.selectionLength = 0;
        if (sel != null && !sel.isEmpty()) {
            long n = sel.getNumAddresses();
            this.selectionLength = (int) Math.min(n, MAX_TILE_BYTES);
        }
        refreshRomHere();
        refreshTiles();
        refreshMap();
        refreshEmuInfo();
    }

    // ------------------------------------------------------------------ tabs

    private JComponent buildTilesTab() {
        JPanel row1 = new JPanel();
        row1.add(new JLabel("Source:"));
        row1.add(tileSource);
        row1.add(new JLabel("ROM:"));
        row1.add(romOffset);
        row1.add(new JLabel("Step:"));
        row1.add(romStep);
        row1.add(romPagePrev);
        row1.add(romPrev);
        row1.add(romNext);
        row1.add(romPageNext);
        row1.add(romHere);
        row1.add(romViewHere);
        row1.add(new JLabel("Format:"));
        row1.add(tileFormat);
        row1.add(new JLabel("Palette:"));
        row1.add(tilePalette);
        row1.add(tileColor);

        JPanel row2 = new JPanel();
        row2.add(new JLabel("Arrange:"));
        row2.add(tileArrange);
        row2.add(arrangeCustom);
        row2.add(arrangeW);
        row2.add(new JLabel("x"));
        row2.add(arrangeH);
        row2.add(arrangeOrder);
        row2.add(new JLabel("Width:"));
        row2.add(tileWidth);
        row2.add(new JLabel("Zoom:"));
        row2.add(tileZoom);
        JButton exp = new JButton("Export PNG…");
        exp.addActionListener(e -> exportImage(currentTiles, "tiles.png"));
        row2.add(exp);
        JButton dec = new JButton("Decompress here…");
        dec.addActionListener(e -> decompressHere());
        row2.add(dec);

        JPanel opts = new JPanel(new java.awt.GridLayout(2, 1));
        opts.add(row1);
        opts.add(row2);

        JPanel root = new JPanel(new BorderLayout());
        root.add(opts, BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(tileImage);
        sp.setPreferredSize(new Dimension(500, 400));
        root.add(sp, BorderLayout.CENTER);
        root.add(tileInfo, BorderLayout.SOUTH);
        return root;
    }

    private JComponent buildMapTab() {
        JPanel opts = new JPanel();
        opts.add(new JLabel("Columns:"));
        opts.add(mapCols);
        opts.add(new JLabel("Tile format:"));
        opts.add(mapFormat);
        opts.add(mapColor);
        opts.add(new JLabel("Tiles:"));
        opts.add(mapTileSource);
        opts.add(new JLabel("Tile base:"));
        opts.add(mapTileBase);
        JButton exp = new JButton("Export PNG…");
        exp.addActionListener(e -> exportImage(currentMap, "tilemap.png"));
        opts.add(exp);

        JPanel root = new JPanel(new BorderLayout());
        root.add(opts, BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(mapImage);
        sp.setPreferredSize(new Dimension(500, 400));
        root.add(sp, BorderLayout.CENTER);
        root.add(mapInfo, BorderLayout.SOUTH);
        return root;
    }

    private JComponent buildEmuTab() {
        JPanel opts = new JPanel();
        opts.add(new JLabel("Frames:"));
        opts.add(emuFrames);
        opts.add(new JLabel("Insns/frame:"));
        opts.add(emuSlice);
        opts.add(emuRun);
        opts.add(emuLoad);
        opts.add(emuClear);
        JButton expS = new JButton("Screen PNG…");
        expS.addActionListener(e -> exportImage(currentScreen, "screen.png"));
        opts.add(expS);
        JButton expL = new JButton("Layers PNG…");
        expL.addActionListener(e -> exportLayers());
        opts.add(expL);

        JPanel grid = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 4, 4, 4);
        g.anchor = GridBagConstraints.NORTHWEST;
        g.gridx = 0; g.gridy = 0;
        grid.add(new JLabel("Screen:"), g);
        g.gridx = 1;
        grid.add(new JScrollPane(screenImage), g);
        g.gridx = 0; g.gridy = 1;
        grid.add(new JLabel("Palettes:"), g);
        g.gridx = 1;
        grid.add(new JScrollPane(paletteImage), g);
        g.gridx = 0; g.gridy = 2;
        grid.add(new JLabel("VRAM tiles:"), g);
        g.gridx = 1;
        grid.add(new JScrollPane(vramImage), g);
        g.gridx = 0; g.gridy = 3;
        grid.add(new JLabel("Sprites:"), g);
        g.gridx = 1;
        grid.add(new JScrollPane(spriteTable), g);

        JPanel root = new JPanel(new BorderLayout());
        root.add(opts, BorderLayout.NORTH);
        root.add(new JScrollPane(grid), BorderLayout.CENTER);
        root.add(emuInfo, BorderLayout.SOUTH);
        return root;
    }

    // ------------------------------------------------------------------ tiles

    private void refreshTiles() {
        if (tileImage == null) return;
        byte[] src;
        String origin;
        String sel = (String) tileSource.getSelectedItem();
        if ("Decoded".equals(sel)) {
            if (decodedBytes == null) {
                tileInfo.setText("No decoded bytes yet: use Decompress here first.");
                tileImage.setIcon(null);
                currentTiles = null;
                return;
            }
            src = decodedBytes;
            origin = "decoded (" + src.length + " bytes)";
        } else if ("ROM offset".equals(sel)) {
            if (program == null) {
                tileInfo.setText("No program.");
                tileImage.setIcon(null);
                currentTiles = null;
                return;
            }
            long off = WSRom.parseOffset(romOffset.getText());
            if (off < 0) {
                tileInfo.setText("Bad ROM offset: " + romOffset.getText().trim());
                tileImage.setIcon(null);
                currentTiles = null;
                return;
            }
            int want = selectionLength > 0 ? selectionLength : 4096;
            want = Math.min(want, MAX_TILE_BYTES);
            src = WSRom.read(program, off, want);
            lastWindowBytes = Math.max(1, want);
            long size = WSRom.size(program);
            origin = "ROM " + WSRom.formatOffset(off) + " (" + src.length + " bytes"
                + (size >= 0 ? " of " + size : "") + ")";
        } else {
            if (program == null || address == null) {
                tileInfo.setText("No location.");
                tileImage.setIcon(null);
                currentTiles = null;
                return;
            }
            int want = selectionLength > 0 ? selectionLength : 4096;
            src = readBytes(program, address, Math.min(want, MAX_TILE_BYTES));
            var romOff = WSRom.offsetOf(program, address);
            origin = address + (romOff.isPresent() ? " (this is ROM " + WSRom.formatOffset(romOff.getAsLong()) + ", " : " (")
                + src.length + " bytes"
                + (selectionLength > 0 ? ", selection" : ", 4 KiB default") + ")";
        }
        WSTileFormat fmt = (WSTileFormat) tileFormat.getSelectedItem();
        int count = WSAssets.tileCount(src.length, fmt);
        if (count == 0) {
            tileInfo.setText(origin + ": no whole " + fmt + " tiles.");
            tileImage.setIcon(null);
            currentTiles = null;
            return;
        }
        int pal = (Integer) tilePalette.getValue();
        boolean color = tileColor.isSelected();
        int[] rgb = paletteForTiles(pal, color, fmt);
        WSTileArrangement arr = currentArrangement();
        int cols = (Integer) tileWidth.getValue();
        int zoom = (Integer) tileZoom.getValue();
        BufferedImage img = WSAssets.renderArrangedAtlas(src, 0, count, fmt, rgb, arr, cols, zoom);
        currentTiles = img;
        tileImage.setIcon(new ImageIcon(img));
        int cells = (count + arr.tilesPerCell() - 1) / arr.tilesPerCell();
        tileInfo.setText(origin + ": " + count + " " + fmt + " tiles (" + cells + " " + arr.label
            + "), palette " + pal + (color ? " (colour)" : " (mono)"));
        status.setText("Tiles: " + count + " from " + origin);
    }

    /** Arrangement from the preset combo, or the custom W/H/order when checked. */
    private WSTileArrangement currentArrangement() {
        if (arrangeCustom.isSelected()) {
            return WSTileArrangement.custom((Integer) arrangeW.getValue(), (Integer) arrangeH.getValue(),
                (WSTileArrangement.Order) arrangeOrder.getSelectedItem());
        }
        return (WSTileArrangement) tileArrange.getSelectedItem();
    }

    /** Enable ROM controls only in ROM-offset mode, custom W/H only when checked. */
    private void updateRomEnabled() {
        boolean rom = "ROM offset".equals(tileSource.getSelectedItem());
        romOffset.setEnabled(rom);
        romStep.setEnabled(rom);
        romPrev.setEnabled(rom);
        romNext.setEnabled(rom);
        romPagePrev.setEnabled(rom);
        romPageNext.setEnabled(rom);
        tileArrange.setEnabled(!arrangeCustom.isSelected());
        arrangeW.setEnabled(arrangeCustom.isSelected());
        arrangeH.setEnabled(arrangeCustom.isSelected());
        arrangeOrder.setEnabled(arrangeCustom.isSelected());
    }

    /** Move the ROM offset by a signed byte delta, clamped at 0. */
    private void stepRom(int delta) {
        long off = WSRom.parseOffset(romOffset.getText());
        if (off < 0) off = 0;
        romOffset.setText(WSRom.formatOffset(Math.max(0, off + delta)));
        refreshTiles();
    }

    /** Switch to ROM-offset mode at the listing cursor's ROM offset. */
    private void viewCursorInRom() {
        if (program == null || address == null) return;
        var off = WSRom.offsetOf(program, address);
        if (off.isEmpty()) return;
        romOffset.setText(WSRom.formatOffset(off.getAsLong()));
        tileSource.setSelectedItem("ROM offset");
        updateRomEnabled();
        refreshTiles();
    }

    /** Show the listing cursor's ROM offset when it sits in mapped ROM (LIN, B2 or ROM_xx data overlay). */
    private void refreshRomHere() {
        if (program != null && address != null) {
            var off = WSRom.offsetOf(program, address);
            if (off.isPresent()) {
                romHere.setText("cursor: this is ROM " + WSRom.formatOffset(off.getAsLong()));
                romViewHere.setEnabled(true);
                return;
            }
        }
        romHere.setText("cursor: not in mapped ROM");
        romViewHere.setEnabled(false);
    }

    /** Palette for listing bytes: VRAM palette when a snapshot exists, else greyscale. */
    private int[] paletteForTiles(int pal, boolean color, WSTileFormat fmt) {
        int n = fmt.bitsPerPixel == 2 ? 4 : 16;
        if (snapshot != null) {
            if (color && snapshot.colorHardware) {
                int[] full = WSAssets.colorPalette(snapshot.ram, pal);
                if (n == 4) return new int[] { full[0], full[1], full[2], full[3] };
                return full;
            }
            if (!color) return WSAssets.monoPalette(snapshot.ports, pal);
            int[] full = WSAssets.colorPalette(snapshot.ram, pal);
            if (n == 4) return new int[] { full[0], full[1], full[2], full[3] };
            return full;
        }
        int[] grey = new int[n];
        for (int i = 0; i < n; i++) {
            int g = 255 - i * 255 / (n - 1);
            grey[i] = g << 16 | g << 8 | g;
        }
        return grey;
    }

    // ------------------------------------------------------------------ tilemap

    private void refreshMap() {
        if (mapImage == null) return;
        if (program == null || address == null) {
            mapInfo.setText("No location.");
            mapImage.setIcon(null);
            currentMap = null;
            return;
        }
        int wantEntries = selectionLength > 0 ? selectionLength / 2 : 1024;
        wantEntries = Math.max(1, Math.min(wantEntries, MAX_MAP_ENTRIES));
        byte[] src = readBytes(program, address, wantEntries * 2);
        int entries = src.length / 2;
        if (entries == 0) {
            mapInfo.setText(address + ": no map entries.");
            mapImage.setIcon(null);
            currentMap = null;
            return;
        }
        boolean color = mapColor.isSelected();
        WSTileFormat fmt = (WSTileFormat) mapFormat.getSelectedItem();
        List<WSAssets.MapEntry> list = WSAssets.decodeMap(src, 0, entries, color);
        int cols = (Integer) mapCols.getValue();
        boolean bpp4 = fmt.bitsPerPixel == 4;
        String tileSel = (String) mapTileSource.getSelectedItem();
        boolean vram = "VRAM".equals(tileSel) && snapshot != null;
        try {
            BufferedImage img;
            String tileOrigin;
            if (vram) {
                tileOrigin = "VRAM tiles";
                byte[] ram = snapshot.ram;
                int[] p = snapshot.ports;
                boolean snapColor = snapshot.colorMode(p);
                img = WSAssets.renderMap(list, cols,
                    tile -> {
                        boolean use4 = snapshot.colorMode(p) && (p[0x60] & 0x40) != 0;
                        boolean pk = use4 && (p[0x60] & 0x20) != 0;
                        int[] px = new int[64];
                        for (int y = 0; y < 8; y++) {
                            for (int x = 0; x < 8; x++) {
                                px[y * 8 + x] = use4 ? WSAssets.tilePixel4bpp(ram, tile, x, y, pk)
                                    : WSAssets.tilePixel2bpp(ram, tile, x, y);
                            }
                        }
                        return px;
                    },
                    pal -> snapColor ? WSAssets.colorPalette(ram, pal) : WSAssets.monoPalette(p, pal),
                    snapshot.colorMode(p) && (p[0x60] & 0x40) != 0);
            } else {
                byte[] tiles;
                if ("ROM offset".equals(tileSel)) {
                    long off = WSRom.parseOffset(mapTileBase.getText());
                    if (off < 0) {
                        mapInfo.setText("Bad ROM offset: " + mapTileBase.getText().trim());
                        return;
                    }
                    tiles = WSRom.read(program, off, MAX_TILE_BYTES);
                    tileOrigin = "ROM " + WSRom.formatOffset(off) + " tiles";
                } else if ("Decoded".equals(tileSel)) {
                    if (decodedBytes == null) {
                        mapInfo.setText("No decoded bytes yet: use Decompress here first.");
                        return;
                    }
                    tiles = decodedBytes;
                    tileOrigin = "decoded tiles";
                } else {
                    // Listing (also the fallback when VRAM is selected but no snapshot exists).
                    String baseText = mapTileBase.getText().trim();
                    if (baseText.isEmpty()) {
                        // Tiles follow the map in the listing.
                        Address after = address.add(entries * 2);
                        tiles = readBytes(program, after, MAX_TILE_BYTES);
                    } else {
                        Address base = parseAddress(program, baseText);
                        if (base == null) {
                            mapInfo.setText("Bad tile base: " + baseText);
                            return;
                        }
                        tiles = readBytes(program, base, MAX_TILE_BYTES);
                    }
                    tileOrigin = "listing tiles";
                }
                final byte[] tb = tiles;
                int[] grey = paletteForTiles(0, color, fmt);
                img = WSAssets.renderMap(list, cols,
                    tile -> {
                        int off = tile * fmt.bytesPerTile;
                        if (off + fmt.bytesPerTile > tb.length) throw new IllegalArgumentException("tile out of range");
                        return WSAssets.decodeTile(tb, off, fmt);
                    },
                    pal -> grey, bpp4);
            }
            currentMap = img;
            mapImage.setIcon(new ImageIcon(img));
            mapInfo.setText(address + ": " + entries + " entries (" + cols + " cols), " + tileOrigin);
        } catch (RuntimeException e) {
            mapInfo.setText("Map render failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ emulator

    private void refreshEmuInfo() {
        if (emuInfo == null) return;
        if (program == null) {
            emuInfo.setText("No program.");
            return;
        }
        boolean color = true;
        try {
            color = program.getOptions("WonderSwan").getBoolean("Color", true);
        } catch (Exception e) {
            // Not a WonderSwan program; emulator state unavailable.
        }
        emuInfo.setText("Program: " + program.getName() + (snapshot == null ? " (no emulator state)" : " (state captured)")
            + ", model " + (color ? "colour" : "mono"));
    }

    private void refreshEmu() {
        refreshEmuInfo();
        if (snapshot == null) {
            screenImage.setIcon(null);
            paletteImage.setIcon(null);
            vramImage.setIcon(null);
            ((DefaultTableModel) spriteTable.getModel()).setRowCount(0);
            currentScreen = null;
            return;
        }
        try {
            BufferedImage scr = WSAssets.renderScreen(snapshot);
            currentScreen = scr;
            screenImage.setIcon(new ImageIcon(scr.getScaledInstance(448, 288, BufferedImage.SCALE_FAST)));
            paletteImage.setIcon(new ImageIcon(renderPaletteSwatches(snapshot)));
            vramImage.setIcon(new ImageIcon(renderVramAtlas(snapshot)));
            DefaultTableModel m = (DefaultTableModel) spriteTable.getModel();
            m.setRowCount(0);
            for (WSAssets.Sprite s : WSAssets.decodeSprites(snapshot.ram, snapshot.ports)) {
                m.addRow(new Object[] { s.index(), s.x(), s.y(), s.tile(), s.palette(),
                    (s.hFlip() ? "H" : "") + (s.vFlip() ? "V" : ""), s.highPriority() ? "hi" : "lo",
                    s.insideWindow() ? "in" : "out" });
            }
            status.setText("Emulator state: screen + palettes + sprites refreshed.");
        } catch (RuntimeException e) {
            Msg.showError(this, null, "Asset viewer", "Render failed: " + e.getMessage());
        }
    }

    private static BufferedImage renderPaletteSwatches(WSSnapshot s) {
        boolean color = s.colorMode(s.ports);
        int cols = color ? 16 : 4, rows = 16, cell = 12;
        BufferedImage img = new BufferedImage(cols * cell, rows * cell, BufferedImage.TYPE_INT_RGB);
        for (int pal = 0; pal < 16; pal++) {
            int[] rgb = color ? WSAssets.colorPalette(s.ram, pal) : WSAssets.monoPalette(s.ports, pal);
            for (int i = 0; i < rgb.length; i++) {
                for (int y = 0; y < cell; y++) {
                    for (int x = 0; x < cell; x++) {
                        img.setRGB(i * cell + x, pal * cell + y, rgb[i]);
                    }
                }
            }
        }
        return img;
    }

    private static BufferedImage renderVramAtlas(WSSnapshot s) {
        boolean color = s.colorMode(s.ports);
        boolean bpp4 = color && (s.ports[0x60] & 0x40) != 0;
        boolean packed = bpp4 && (s.ports[0x60] & 0x20) != 0;
        // First 256 tiles of the active tile area with palette 0.
        int[] pal = color ? WSAssets.colorPalette(s.ram, 0) : WSAssets.monoPalette(s.ports, 0);
        int base = bpp4 ? 0x4000 : 0x2000;
        int bytes = bpp4 ? 32 : 16;
        int count = 256;
        byte[] slice = new byte[count * bytes];
        System.arraycopy(s.ram, base, slice, 0, Math.min(slice.length, s.ram.length - base));
        WSTileFormat fmt = !bpp4 ? WSTileFormat.BPP2 : packed ? WSTileFormat.BPP4_PACKED : WSTileFormat.BPP4_PLANAR;
        return WSAssets.renderAtlas(slice, 0, count, fmt, pal, 16, 1);
    }

    private void runEmulator() {
        if (program == null) return;
        emuRun.setEnabled(false);
        status.setText("Running emulator…");
        int frames = (Integer) emuFrames.getValue();
        int slice = (Integer) emuSlice.getValue();
        Program p = program;
        new SwingWorker<WSSnapshot, Void>() {
            @Override protected WSSnapshot doInBackground() throws Exception {
                boolean color = p.getOptions("WonderSwan").getBoolean("Color", true);
                WSMachine m = new WSMachine(p, color);
                m.run(frames, slice, null);
                return WSSnapshot.fromMachine(m);
            }

            @Override protected void done() {
                emuRun.setEnabled(true);
                try {
                    snapshot = get();
                    refreshEmu();
                    refreshMap();
                    refreshTiles();
                } catch (Exception e) {
                    Msg.showError(this, null, "Asset viewer", "Emulator run failed: " + e.getMessage());
                    status.setText("Emulator run failed.");
                }
            }
        }.execute();
    }

    private void loadSnapshot() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Select ram_N.bin (ports_N.bin beside it)");
        if (fc.showOpenDialog(getComponent()) != JFileChooser.APPROVE_OPTION) return;
        Path ram = fc.getSelectedFile().toPath();
        String name = ram.getFileName().toString();
        Path ports;
        if (name.startsWith("ram_")) {
            ports = ram.resolveSibling(name.replace("ram_", "ports_"));
        } else {
            JOptionPane.showMessageDialog(getComponent(), "Pick a ram_N.bin file; ports_N.bin must sit beside it.");
            return;
        }
        try {
            boolean color = program != null && program.getOptions("WonderSwan").getBoolean("Color", true);
            snapshot = WSSnapshot.fromFiles(ram, ports, color);
            refreshEmu();
            refreshMap();
            refreshTiles();
        } catch (Exception e) {
            Msg.showError(this, null, "Asset viewer", "Load failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ export

    private void exportImage(BufferedImage img, String suggested) {
        if (img == null) {
            JOptionPane.showMessageDialog(getComponent(), "Nothing to export.");
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(suggested));
        fc.setFileFilter(new FileNameExtensionFilter("PNG", "png"));
        if (fc.showSaveDialog(getComponent()) != JFileChooser.APPROVE_OPTION) return;
        try {
            WSAssets.writePng(img, fc.getSelectedFile().toPath());
            status.setText("Wrote " + fc.getSelectedFile());
        } catch (Exception e) {
            Msg.showError(this, null, "Asset viewer", "Export failed: " + e.getMessage());
        }
    }

    private void exportLayers() {
        if (snapshot == null) {
            JOptionPane.showMessageDialog(getComponent(), "No emulator state.");
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (fc.showSaveDialog(getComponent()) != JFileChooser.APPROVE_OPTION) return;
        try {
            Path out = fc.getSelectedFile().toPath();
            int[] p = snapshot.ports;
            WSAssets.writePng(WSAssets.renderLayer(snapshot, p[0x07] & 0x0F), out.resolve("layer_scr1.png"));
            WSAssets.writePng(WSAssets.renderLayer(snapshot, p[0x07] >> 4), out.resolve("layer_scr2.png"));
            WSAssets.writePng(renderPaletteSwatches(snapshot), out.resolve("palettes.png"));
            status.setText("Wrote layers to " + out);
        } catch (Exception e) {
            Msg.showError(this, null, "Asset viewer", "Export failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ decompress

    /**
     * Decompress the bytes at the cursor (listing, ROM offset, or the current
     * decoded bytes, following the Tiles source) through a registered codec.
     * The output feeds the Tiles and Tilemap views' Decoded source.
     */
    public void decompressHere() {
        if (program == null) {
            JOptionPane.showMessageDialog(getComponent(), "No program.");
            return;
        }
        var codecs = WSCodecRegistry.all();
        if (codecs.isEmpty()) {
            JOptionPane.showMessageDialog(getComponent(),
                "No codecs registered. Private codecs plug in via WSCodecRegistry.");
            return;
        }
        String sel = (String) tileSource.getSelectedItem();
        byte[] src;
        String origin;
        if ("ROM offset".equals(sel)) {
            long off = WSRom.parseOffset(romOffset.getText());
            if (off < 0) {
                JOptionPane.showMessageDialog(getComponent(), "Bad ROM offset: " + romOffset.getText().trim());
                return;
            }
            int want = selectionLength > 0 ? selectionLength : MAX_TILE_BYTES;
            src = WSRom.read(program, off, want);
            origin = "ROM " + WSRom.formatOffset(off);
        } else if ("Decoded".equals(sel) && decodedBytes != null) {
            src = decodedBytes;
            origin = "decoded bytes";
        } else {
            if (address == null) {
                JOptionPane.showMessageDialog(getComponent(), "No location.");
                return;
            }
            int want = selectionLength > 0 ? selectionLength : MAX_TILE_BYTES;
            src = readBytes(program, address, want);
            origin = address.toString();
        }
        String[] ids = codecs.stream().map(WSCodec::id).toArray(String[]::new);
        String id = (String) JOptionPane.showInputDialog(getComponent(), "Codec:", "Decompress here",
            JOptionPane.PLAIN_MESSAGE, null, ids, ids[0]);
        if (id == null) return;
        WSCodec codec = WSCodecRegistry.get(id);
        try {
            WSCodec.Result r = codec.decode(src, 0, src.length);
            decodedBytes = r.data();
            tileSource.setSelectedItem("Decoded");
            refreshTiles();
            refreshMap();
            tabs.setSelectedIndex(0);
            int save = JOptionPane.showConfirmDialog(getComponent(),
                String.format("%s from %s: %d input bytes -> %d output bytes (consumed %d). Save to file?",
                    id, origin, src.length, r.data().length, r.consumed()),
                "Decompressed", JOptionPane.YES_NO_OPTION);
            if (save == JOptionPane.YES_OPTION) {
                JFileChooser fc = new JFileChooser();
                if (fc.showSaveDialog(getComponent()) == JFileChooser.APPROVE_OPTION) {
                    java.nio.file.Files.write(fc.getSelectedFile().toPath(), r.data());
                }
            }
        } catch (Exception e) {
            Msg.showError(this, null, "Asset viewer", "Decode failed: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Read up to {@code max} bytes from a program address; stops at unreadable memory. */
    static byte[] readBytes(Program p, Address a, int max) {
        Memory mem = p.getMemory();
        byte[] out = new byte[Math.max(0, max)];
        int got = 0;
        Address cur = a;
        while (got < out.length) {
            int chunk = Math.min(4096, out.length - got);
            byte[] buf = new byte[chunk];
            int n;
            try {
                n = mem.getBytes(cur, buf);
            } catch (Exception e) {
                break;
            }
            if (n <= 0) break;
            System.arraycopy(buf, 0, out, got, n);
            got += n;
            if (n < chunk) break;
            try {
                cur = cur.add(n);
            } catch (Exception e) {
                break;
            }
        }
        if (got == out.length) return out;
        byte[] trim = new byte[got];
        System.arraycopy(out, 0, trim, 0, got);
        return trim;
    }

    /** Parse "seg:off" or linear hex into a program address; null when invalid. */
    static Address parseAddress(Program p, String text) {
        try {
            Address a = p.getAddressFactory().getAddress(text);
            if (a != null) return a;
        } catch (Exception e) {
            // Fall through to hex parse.
        }
        try {
            String t = text.trim().toLowerCase().replaceFirst("^0x", "");
            if (t.contains(":")) {
                String[] s = t.split(":");
                long linear = (Long.parseLong(s[0], 16) << 4) + Long.parseLong(s[1], 16);
                return p.getAddressFactory().getDefaultAddressSpace().getAddress(linear & 0xFFFFF);
            }
            return p.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseLong(t, 16) & 0xFFFFF);
        } catch (Exception e) {
            return null;
        }
    }

    /** True when the program looks like a WonderSwan cartridge the emulator supports. */
    static boolean supportsEmulator(Program p) {
        try {
            return p.getLanguage().getProcessor().toString().equals("V30MZ")
                && !p.getMemory().getAllFileBytes().isEmpty()
                && p.getOptions("WonderSwan").contains("Color");
        } catch (Exception e) {
            return false;
        }
    }
}
