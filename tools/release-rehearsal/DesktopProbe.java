// SPDX-License-Identifier: MIT OR Apache-2.0
import java.awt.Color;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Robot;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

class DesktopProbe {
    public static void main(String[] args) throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            throw new IllegalStateException("No desktop graphics session");
        }
        var window = new JFrame("Release rehearsal desktop probe");
        var panel = new JPanel();
        var color = new Color(13, 201, 139);
        var point = new Point();
        try {
            SwingUtilities.invokeAndWait(() -> {
                panel.setBackground(color);
                window.setContentPane(panel);
                window.setSize(300, 130);
                window.setLocationRelativeTo(null);
                window.setAlwaysOnTop(true);
                window.setVisible(true);
                var upperLeft = panel.getLocationOnScreen();
                point.setLocation(upperLeft.x + panel.getWidth() / 2, upperLeft.y + panel.getHeight() / 2);
            });
            var robot = new Robot();
            robot.waitForIdle();
            for (int retry = 0; retry < 10; retry++) {
                var pixel = robot.getPixelColor(point.x, point.y);
                int difference = Math.abs(pixel.getRed() - color.getRed()) +
                    Math.abs(pixel.getGreen() - color.getGreen()) + Math.abs(pixel.getBlue() - color.getBlue());
                if (difference < 15) {
                    System.out.println("DESKTOP_PROBE_PASS");
                    return;
                }
                robot.delay(250);
            }
            throw new IllegalStateException("Cannot observe the probe window's interior");
        } finally {
            SwingUtilities.invokeAndWait(window::dispose);
        }
    }
}
