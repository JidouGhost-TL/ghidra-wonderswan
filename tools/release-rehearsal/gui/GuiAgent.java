// SPDX-License-Identifier: MIT OR Apache-2.0
import java.awt.Component;
import java.awt.Container;
import java.awt.GraphicsEnvironment;
import java.awt.Frame;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JComponent;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JProgressBar;
import javax.swing.JTable;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;

public class GuiAgent {
    private static Window preferredWindow;
    public static void premain(String argument) {
        Thread worker = new Thread(() -> work(Path.of(argument)), "gui-rehearsal");
        worker.setDaemon(true);
        worker.start();
    }

    private static void work(Path directory) {
        Path result = directory.resolve("result.txt");
        try {
            Files.createDirectories(directory);
            if (GraphicsEnvironment.isHeadless()) {
                throw new IllegalStateException("No active graphical desktop");
            }
            Robot robot = new Robot();
            reply(directory.resolve("ready.txt"), Long.toString(ProcessHandle.current().pid()));
            for (int sequence = 1; ; sequence++) {
                Path request = directory.resolve("request-" + sequence + ".txt");
                while (!Files.isRegularFile(request)) {
                    Thread.sleep(75);
                }
                result = directory.resolve("result-" + sequence + ".txt");
                try {
                    reply(result, "OK\n" + command(robot, Files.readString(request).stripTrailing()));
                } catch (Exception error) {
                    reply(result, "ERROR\n" + error);
                }
            }
        } catch (Exception error) {
            try {
                reply(result, "ERROR\n" + error);
            } catch (Exception suppressed) {
                error.addSuppressed(suppressed);
                error.printStackTrace();
            }
        }
    }

    private static void reply(Path result, String value) throws Exception {
        Path temporary = result.resolveSibling(result.getFileName() + ".part");
        Files.writeString(temporary, value);
        Files.move(temporary, result, StandardCopyOption.ATOMIC_MOVE);
    }

    private static <T> T edt(Callable<T> query) throws Exception {
        var job = new FutureTask<>(query);
        SwingUtilities.invokeAndWait(job);
        return job.get();
    }

    record Control(String role, String name, Point point, Rectangle bounds, Window owner) {
        String describe() {
            return role + "\t" + name.replace("\n", "\\n").replace("\t", " ") + "\t"
                + (point == null ? "" : point.x + "," + point.y);
        }
    }

    private static List<Control> visible() {
        var controls = new ArrayList<Control>();
        for (Window window : Window.getWindows()) {
            if (!window.isShowing()) {
                continue;
            }
            String label = window.getAccessibleContext().getAccessibleName();
            Rectangle bounds = window.getBounds();
            controls.add(new Control(window.isActive() ? "ACTIVE" : "WINDOW",
                label == null ? window.getClass().getSimpleName() : label, null, bounds, window));
            collect(window, controls, window);
        }
        return controls;
    }

    private static void collect(Component component, List<Control> rows, Window owner) {
        if (!component.isShowing()) {
            return;
        }
        String type = component.getClass().getSimpleName();
        String label = null;
        if (component instanceof AbstractButton button && button.isEnabled()) {
            label = button.getText();
            if (label == null || label.isBlank()) {
                label = button.getToolTipText();
            }
            if (button instanceof javax.swing.JToggleButton || button instanceof javax.swing.JCheckBoxMenuItem) {
                rows.add(new Control(type + ":checked", label + "=" + button.isSelected(),
                    center(button, new Rectangle(0, 0, button.getWidth(), button.getHeight())),
                    button.getBounds(), owner));
            }
        } else if (component instanceof JLabel text) {
            label = text.getText();
        } else if (component instanceof JComboBox<?> combo) {
            label = String.valueOf(combo.getSelectedItem());
        } else if (component instanceof JTextComponent text) {
            label = text.getText();
            if (label.isBlank()) {
                label = "(empty)";
            }
        } else if (component instanceof JTable table) {
            for (int i = 0; i < Math.min(30, table.getRowCount()); i++) {
                for (int j = 0; j < table.getColumnCount(); j++) {
                    Rectangle cell = table.getCellRect(i, j, true);
                    Object value = table.getValueAt(i, j);
                    if (value != null && table.getVisibleRect().intersects(cell)) {
                        rows.add(new Control("table:" + table.getColumnName(j), value.toString(),
                            center(table, cell), cell, owner));
                    }
                }
            }
        } else if (component instanceof JTree tree) {
            for (int i = 0; i < Math.min(100, tree.getRowCount()); i++) {
                Rectangle cell = tree.getRowBounds(i);
                if (cell != null && tree.getVisibleRect().intersects(cell)) {
                    rows.add(new Control("tree", tree.getPathForRow(i).getLastPathComponent().toString(),
                        center(tree, cell), cell, owner));
                }
            }
        } else if (component instanceof JList<?> list) {
            for (int i = 0; i < Math.min(100, list.getModel().getSize()); i++) {
                Rectangle cell = list.getCellBounds(i, i);
                if (cell != null && list.getVisibleRect().intersects(cell)) {
                    rows.add(new Control("list", list.getModel().getElementAt(i).toString(),
                        center(list, cell), cell, owner));
                }
            }
        } else if (component instanceof JProgressBar progress) {
            label = progress.getString();
        } else if (type.endsWith("FieldPanel")) {
            collectFields(component, rows, owner);
        } else if (component.getAccessibleContext() != null) {
            label = component.getAccessibleContext().getAccessibleName();
        }
        if (label != null && !label.isBlank() && component.getWidth() > 0 && component.getHeight() > 0) {
            Rectangle bounds = new Rectangle(0, 0, component.getWidth(), component.getHeight());
            if (!(component instanceof JComponent widget) || widget.getVisibleRect().intersects(bounds)) {
                rows.add(new Control(type, label, center(component, bounds), bounds, owner));
            }
        }
        if (component instanceof Container parent) {
            Component optionLabel = null;
            Component optionEditor = null;
            for (Component child : parent.getComponents()) {
                if (child instanceof JLabel text && child.isShowing() && text.getText() != null) {
                    optionLabel = child;
                } else if (child.isShowing() && child.getClass().getSimpleName().startsWith("Property")) {
                    optionEditor = child;
                }
            }
            if (optionLabel instanceof JLabel text && optionEditor != null) {
                Rectangle area = new Rectangle(0, 0, optionEditor.getWidth(), optionEditor.getHeight());
                rows.add(new Control(optionEditor.getClass().getSimpleName() + ":option", text.getText(),
                    center(optionEditor, area), area, owner));
            }
            for (Component child : parent.getComponents()) {
                collect(child, rows, owner);
            }
        }
    }

    private static void collectFields(Component panel, List<Control> controls, Window owner) {
        try {
            ClassLoader loader = panel.getClass().getClassLoader();
            Class<?> panelType = Class.forName("docking.widgets.fieldpanel.FieldPanel", false, loader);
            Class<?> layoutType = Class.forName("docking.widgets.fieldpanel.support.AnchoredLayout", false, loader);
            Class<?> fieldType = Class.forName("docking.widgets.fieldpanel.field.Field", false, loader);
            var layouts = (List<?>) panelType.getMethod("getVisibleLayouts").invoke(panel);
            for (Object layout : layouts) {
                int count = (int) layoutType.getMethod("getNumFields").invoke(layout);
                for (int field = 0; field < count; field++) {
                    Object displayed = layoutType.getMethod("getField", int.class).invoke(layout, field);
                    if (displayed == null) {
                        continue;
                    }
                    Rectangle bounds = new Rectangle((Rectangle) layoutType
                        .getMethod("getFieldBounds", int.class).invoke(layout, field));
                    bounds = bounds.intersection(((JComponent) panel).getVisibleRect());
                    if (bounds.isEmpty()) {
                        continue;
                    }
                    String text = (String) fieldType.getMethod("getText").invoke(displayed);
                    if (text != null && !text.isBlank()) {
                        String role = panel.getClass().getSimpleName().equals("FieldPanel") ? "field" : "decompiled";
                        controls.add(new Control(role, text, center(panel, bounds), bounds, owner));
                    }
                }
            }
        } catch (ReflectiveOperationException error) {
            throw new IllegalStateException("Cannot inspect rendered listing fields", error);
        }
    }

    private static Window window(String name) throws Exception {
        Pattern pattern = Pattern.compile(name);
        List<Window> matches = List.of(Window.getWindows()).stream()
            .filter(Window::isShowing).filter(w -> pattern.matcher(
                String.valueOf(w.getAccessibleContext().getAccessibleName())).matches()).toList();
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Expected one window, found " + matches.size() + ": " + name);
        }
        return matches.getFirst();
    }

    private static Point center(Component component, Rectangle rectangle) {
        Point origin = component.getLocationOnScreen();
        origin.translate(rectangle.x + rectangle.width / 2, rectangle.y + rectangle.height / 2);
        return origin;
    }

    private static Control find(String rolePattern, String names) throws Exception {
        Pattern role = Pattern.compile(rolePattern);
        Pattern name = Pattern.compile(names, Pattern.DOTALL);
        List<Control> matches = edt(GuiAgent::visible).stream()
            .filter(row -> role.matcher(row.role).matches() && name.matcher(row.name).matches()).toList();
        if (matches.size() > 1) {
            List<Control> foreground = edt(() -> matches.stream().filter(row -> row.owner.isActive()).toList());
            if (foreground.size() == 1) {
                return foreground.getFirst();
            }
            List<Control> preferred = matches.stream().filter(row -> row.owner == preferredWindow).toList();
            if (preferred.size() == 1) {
                return preferred.getFirst();
            }
        }
        if (matches.size() != 1) {
            throw new IllegalArgumentException("Expected one shown control, found " + matches.size()
                + ": " + rolePattern + " " + names);
        }
        return matches.getFirst();
    }

    private static void click(Robot robot, Point point, int times, int button) {
        Rectangle screen = GraphicsEnvironment.getLocalGraphicsEnvironment()
            .getDefaultScreenDevice().getDefaultConfiguration().getBounds();
        if (!screen.contains(point)) {
            throw new IllegalArgumentException("Requested control is off the active desktop");
        }
        robot.mouseMove(point.x, point.y);
        for (int i = 0; i < times; i++) {
            robot.mousePress(button);
            robot.mouseRelease(button);
            robot.delay(70);
        }
    }

    private static void chord(Robot robot, String text) throws Exception {
        String[] names = text.split("\\+");
        var keys = new ArrayList<Integer>();
        for (String name : names) {
            Field value = KeyEvent.class.getField("VK_" + name);
            int key = value.getInt(null);
            keys.add(key);
            robot.keyPress(key);
        }
        for (int key : keys.reversed()) {
            robot.keyRelease(key);
        }
    }

    private static String command(Robot robot, String request) throws Exception {
        String[] parts = request.split("\t", 3);
        return switch (parts[0]) {
            case "snapshot" -> String.join("\n", edt(GuiAgent::visible).stream().map(Control::describe).toList());
            case "click", "double", "right" -> {
                Control control = find(parts[1], parts[2]);
                if (control.point == null) {
                    throw new IllegalArgumentException("Control has no interactive point");
                }
                click(robot, control.point, parts[0].equals("double") ? 2 : 1,
                    parts[0].equals("right") ? InputEvent.BUTTON3_DOWN_MASK : InputEvent.BUTTON1_DOWN_MASK);
                yield control.describe();
            }
            case "exit-click" -> {
                Control control = find(parts[1], parts[2]);
                Thread.ofPlatform().daemon().start(() -> {
                    robot.delay(250);
                    click(robot, control.point, 1, InputEvent.BUTTON1_DOWN_MASK);
                });
                yield control.describe();
            }
            case "point" -> {
                click(robot, new Point(Integer.parseInt(parts[1]), Integer.parseInt(parts[2])), 1, InputEvent.BUTTON1_DOWN_MASK);
                yield "";
            }
            case "focus", "fit", "front" -> edt(() -> {
                Window target = window(parts[1]);
                if (!parts[0].equals("focus")) {
                    Rectangle desktop = target.getGraphicsConfiguration().getBounds();
                    int width = Math.min(target.getWidth(), desktop.width - 50);
                    int height = Math.min(target.getHeight(), desktop.height - 100);
                    if (parts[0].equals("fit") && target instanceof Frame && parts[1].startsWith("CodeBrowser")) {
                        width = desktop.width - 50;
                        height = desktop.height - 100;
                    }
                    target.setBounds(desktop.x + 20, desktop.y + 35, width, height);
                }
                preferredWindow = target;
                target.toFront();
                target.requestFocus();
                return target.getAccessibleContext().getAccessibleName();
            });
            case "key" -> {
                chord(robot, parts[1]);
                yield "";
            }
            case "paste" -> {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(parts[1]), null);
                chord(robot, System.getProperty("os.name").startsWith("Mac") ? "META+V" : "CONTROL+V");
                yield "";
            }
            case "capture" -> {
                Control active = find("ACTIVE", parts[1]);
                robot.waitForIdle();
                Rectangle desktop = GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice().getDefaultConfiguration().getBounds();
                if (!desktop.contains(active.bounds)) {
                    throw new IllegalStateException("Active GUI is clipped by the desktop");
                }
                var image = robot.createScreenCapture(active.bounds);
                var colors = new java.util.HashSet<Integer>();
                for (int y = 3; y < image.getHeight(); y += 7) {
                    for (int x = 3; x < image.getWidth(); x += 7) {
                        colors.add(image.getRGB(x, y));
                    }
                }
                if (colors.size() < 8) {
                    throw new IllegalStateException("Active GUI capture lacks rendered pixel detail");
                }
                var png = new ByteArrayOutputStream();
                ImageIO.write(image, "png", png);
                yield image.getWidth() + "x" + image.getHeight() + " "
                    + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(png.toByteArray()));
            }
            default -> throw new IllegalArgumentException("Unexpected GUI action");
        };
    }
}
