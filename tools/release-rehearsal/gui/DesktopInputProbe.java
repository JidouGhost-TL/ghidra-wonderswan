// SPDX-License-Identifier: MIT OR Apache-2.0
import java.awt.Color;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Robot;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

class DesktopInputProbe {
    public static void main(String[] args) throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("PUBLIC_GHIDRA_GUI_DESKTOP_REFUSED");
            System.exit(2);
        }
        var window = new JFrame("Foreground GUI input");
        var panel = new JPanel();
        var entry = new JTextField(10);
        var color = new Color(13, 201, 139);
        var pixel = new Point();
        var click = new Point();
        var report = new String[1];
        var clicked = new boolean[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                entry.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent event) {
                        clicked[0] = true;
                    }
                });
                panel.setBackground(color);
                panel.add(entry);
                window.setContentPane(panel);
                window.setSize(300, 160);
                window.setLocationRelativeTo(null);
                window.setAlwaysOnTop(true);
                window.setVisible(true);
                var origin = panel.getLocationOnScreen();
                pixel.setLocation(origin.x + 15, origin.y + panel.getHeight() - 20);
                var location = entry.getLocationOnScreen();
                click.setLocation(location.x + entry.getWidth() / 2, location.y + entry.getHeight() / 2);
            });
            var robot = new Robot();
            robot.waitForIdle();
            for (int attempt = 0; attempt < 20; attempt++) {
                var got = robot.getPixelColor(pixel.x, pixel.y);
                int difference = Math.abs(got.getRed() - color.getRed()) +
                    Math.abs(got.getGreen() - color.getGreen()) + Math.abs(got.getBlue() - color.getBlue());
                if (difference < 15) {
                    robot.mouseMove(click.x, click.y);
                    robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);
                    robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
                    robot.waitForIdle();
                    robot.keyPress(KeyEvent.VK_A);
                    robot.keyRelease(KeyEvent.VK_A);
                    robot.waitForIdle();
                    SwingUtilities.invokeAndWait(() -> report[0] = clicked[0] ? entry.getText() : null);
                    if ("a".equalsIgnoreCase(report[0])) {
                        System.out.println("PUBLIC_GHIDRA_GUI_DESKTOP_INPUT_PASS");
                        return;
                    }
                    throw new IllegalStateException("Foreground keyboard input did not reach probe");
                }
                robot.delay(200);
            }
            throw new IllegalStateException("Foreground probe pixels were not rendered");
        } finally {
            SwingUtilities.invokeAndWait(window::dispose);
        }
    }
}
