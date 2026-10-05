// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import docking.ComponentProvider;

/**
 * WonderSwan controller panel: press-and-hold buttons feeding the emulated key port
 * ({@link WSMachine#buttons}) of the live emulation. Buttons disable when nothing is emulating.
 */
public class WSInputProvider extends ComponentProvider {
    private final WSDebuggerPlugin plugin;
    private final JPanel main;
    private final List<JButton> buttons = new ArrayList<>();

    /** Label, WSMachine.buttons bit. */
    private static final Object[][] PAD = {
        { "Y1", 0x100 }, { "Y2", 0x200 }, { "Y3", 0x400 }, { "Y4", 0x800 },
        { "X1", 0x10 }, { "X2", 0x20 }, { "X3", 0x40 }, { "X4", 0x80 },
        { "START", 0x02 }, { "A", 0x04 }, { "B", 0x08 },
    };

    public WSInputProvider(WSDebuggerPlugin plugin) {
        super(plugin.getTool(), "WonderSwan Input", plugin.getName());
        this.plugin = plugin;
        this.main = new JPanel(new GridLayout(3, 4));
        for (Object[] def : PAD) {
            String label = (String) def[0];
            int bit = (Integer) def[1];
            JButton b = new JButton(label);
            b.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    setBit(bit, true);
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    setBit(bit, false);
                }
            });
            buttons.add(b);
            main.add(b);
        }
        main.add(new JPanel());
        setVisible(false);
    }

    private void setBit(int bit, boolean down) {
        WSDebuggerEmulator emu = plugin.getCurrentEmulator();
        if (emu == null || emu.ws == null) return;
        if (down) emu.ws.buttons |= bit;
        else emu.ws.buttons &= ~bit;
    }

    @Override
    public JComponent getComponent() {
        return main;
    }

    /** Enable the pad only while an emulation is live. */
    public void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }
        boolean live = plugin.getCurrentEmulator() != null;
        for (JButton b : buttons) b.setEnabled(live);
    }
}
