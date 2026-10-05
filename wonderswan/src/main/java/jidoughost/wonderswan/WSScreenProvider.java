// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.image.BufferedImage;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import docking.ComponentProvider;

/**
 * WonderSwan screen view: the current frame rendered from the live emulated state, refreshed
 * whenever emulation stops (step, run, breakpoint, frame step) and on demand. Navigating the
 * trace history without emulating keeps the last live frame: the trace records RAM but not the
 * display ports, so earlier frames cannot be re-rendered from history.
 */
public class WSScreenProvider extends ComponentProvider {
    private static final int SCALE = 2;
    private final WSDebuggerPlugin plugin;
    private final JPanel main;
    private final ScreenPanel panel;
    private BufferedImage image;

    private class ScreenPanel extends JComponent {
        ScreenPanel() {
            setPreferredSize(new Dimension(224 * SCALE, 144 * SCALE));
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            BufferedImage img = image;
            if (img == null) {
                g.drawString("No WonderSwan emulation running.", 20, 20);
                return;
            }
            g.drawImage(img, 0, 0, 224 * SCALE, 144 * SCALE, null);
        }
    }

    public WSScreenProvider(WSDebuggerPlugin plugin) {
        super(plugin.getTool(), "WonderSwan Screen", plugin.getName());
        this.plugin = plugin;
        this.main = new JPanel(new BorderLayout());
        this.panel = new ScreenPanel();
        main.add(panel, BorderLayout.CENTER);
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refresh());
        main.add(refresh, BorderLayout.SOUTH);
        setVisible(false);
    }

    @Override
    public JComponent getComponent() {
        return main;
    }

    /** Re-render from the live emulator on the Swing thread. */
    public void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }
        WSDebuggerEmulator emu = plugin.getCurrentEmulator();
        if (emu == null || emu.ws == null) {
            image = null;
        }
        else {
            try {
                image = WSRender.render(emu.ws);
            }
            catch (RuntimeException e) {
                image = null;
            }
        }
        panel.repaint();
    }
}
