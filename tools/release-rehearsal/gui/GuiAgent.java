// SPDX-License-Identifier: MIT OR Apache-2.0
import java.awt.Component;
import java.awt.Container;
import java.awt.Dialog;
import java.awt.GraphicsEnvironment;
import java.awt.Frame;
import java.awt.KeyboardFocusManager;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.ByteArrayOutputStream;
import java.io.File;
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
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import javax.swing.tree.TreePath;

public class GuiAgent {
    private static final String IMPORT_CHOOSER = "Select File to Import";
    private static final String IMPORT_SUMMARY = "Import Results Summary";
    private static final String ANALYSIS_OPTIONS = "Analysis Options";
    private static Window preferredWindow;
    private static JButton watchedButton;
    private static Window watchedWindow;
    private static int buttonActions;
    private static ActionListener watchedListener;
    private static String watchedAnalyzeFixture;
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

    record Control(String role, String name, Point point, Rectangle bounds, Window owner, Component component) {
        Control(String role, String name, Point point, Rectangle bounds, Window owner) {
            this(role, name, point, bounds, owner, null);
        }

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
        if (watchedButton != null) {
            String name = watchedButton.getText();
            Rectangle bounds = watchedWindow.getBounds();
            controls.add(new Control("button-focus", name + "=" + watchedButtonFocused(), null, bounds, watchedWindow));
            controls.add(new Control("button-action", name + "=" + buttonActions, null, bounds, watchedWindow));
        }
        return controls;
    }

    private static void collect(Component component, List<Control> rows, Window owner) {
        if (!component.isShowing()) {
            return;
        }
        String type = component.getClass().getSimpleName();
        boolean importChooser = owner instanceof Dialog dialog && IMPORT_CHOOSER.equals(dialog.getTitle());
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
            if (importChooser && "Path".equals(text.getName())) {
                type = "chooser-path";
            }
            label = text.getText();
            if (label.isBlank()) {
                label = "(empty)";
            }
        } else if (component instanceof JTable table) {
            collectAnalyzerRows(table, owner, rows);
            for (int i = 0; i < Math.min(30, table.getRowCount()); i++) {
                for (int j = 0; j < table.getColumnCount(); j++) {
                    Rectangle cell = table.getCellRect(i, j, true);
                    Object value = table.getValueAt(i, j);
                    if (value != null && table.getVisibleRect().intersects(cell)) {
                        String role = importChooser && "TABLE".equals(table.getName()) && value instanceof File
                            ? "chooser-file" : "table:" + table.getColumnName(j);
                        rows.add(new Control(role, value.toString(), center(table, cell), cell, owner));
                    }
                }
            }
        } else if (component instanceof JTree tree) {
            boolean projectTree = isProjectDataTree(tree);
            for (int i = 0; i < Math.min(100, tree.getRowCount()); i++) {
                Rectangle cell = tree.getRowBounds(i);
                if (cell != null && tree.getVisibleRect().intersects(cell)) {
                    TreePath path = tree.getPathForRow(i);
                    Object node = path.getLastPathComponent();
                    Point point = center(tree, cell);
                    rows.add(new Control("tree", node.toString(), point, cell, owner));
                    if (projectTree && isRootProjectFile(path)) {
                        rows.add(new Control("project-file-row", node.toString(), point, cell, owner, tree));
                    }
                }
            }
        } else if (component instanceof JList<?> list) {
            for (int i = 0; i < Math.min(100, list.getModel().getSize()); i++) {
                Rectangle cell = list.getCellBounds(i, i);
                if (cell != null && list.getVisibleRect().intersects(cell)) {
                    Object value = list.getModel().getElementAt(i);
                    String role = importChooser && "LIST".equals(list.getName()) && value instanceof File
                        ? "chooser-file" : "list";
                    rows.add(new Control(role, value.toString(), center(list, cell), cell, owner));
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
                Point point = center(component, bounds);
                rows.add(new Control(type, label, point, bounds, owner));
                if (component instanceof JTextComponent text && text.getName() != null) {
                    rows.add(new Control(type + ":name", text.getName(), point, bounds, owner));
                    rows.add(new Control(type + ":value:" + text.getName(), label, point, bounds, owner));
                }
                if (component instanceof AbstractButton button && button.isEnabled()) {
                    rows.add(new Control(type + ":enabled", label, point, bounds, owner, component));
                }
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
                        controls.add(new Control(role, text, center(panel, bounds), bounds, owner, panel));
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

    private static Window activeWindow(String title) throws Exception {
        Window owner = window(Pattern.quote(title));
        if (!owner.isActive()) {
            throw new IllegalStateException("Expected the exact window to own the desktop");
        }
        return owner;
    }

    private static boolean ownedBy(Window child, Window owner) {
        for (Window current = child.getOwner(); current != null; current = current.getOwner()) {
            if (current == owner) {
                return true;
            }
        }
        return false;
    }

    private static JTextComponent focusedGoEditor(String browser) throws Exception {
        Window dialog = activeWindow("Go To ...");
        Window owner = window(Pattern.quote(browser));
        Component focus = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        if (!ownedBy(dialog, owner) || !(focus instanceof JTextComponent editor) ||
                !editor.isShowing() || !editor.isEnabled() || !editor.isEditable() ||
                SwingUtilities.getWindowAncestor(editor) != dialog) {
            throw new IllegalStateException("Expected the focused editor in the owned Go To dialog");
        }
        return editor;
    }

    private static List<Control> listingFields(Window owner, String address) {
        var rows = new ArrayList<Control>();
        collect(owner, rows, owner);
        return rows.stream().filter(control -> "field".equals(control.role) &&
            control.name.equalsIgnoreCase(address) && control.point != null &&
            owner.getBounds().contains(control.point)).toList();
    }

    private static Control listingField(String browser, String address) throws Exception {
        var matches = listingFields(activeWindow(browser), address);
        if (matches.size() != 1) {
            throw new IllegalStateException("Expected one exact visible listing address in the active program");
        }
        return matches.getFirst();
    }

    private static String listingReferenceReadiness(String browser, String address) throws Exception {
        Window owner;
        try {
            owner = window(Pattern.quote(browser));
        }
        catch (IllegalArgumentException error) {
            return "reference_browser_lookup";
        }
        if (!owner.isActive()) {
            return "reference_browser_inactive";
        }
        List<Control> matches = listingFields(owner, address);
        if (matches.size() != 1) {
            return matches.isEmpty() ? "reference_listing_address_absent" : "reference_listing_address_ambiguous";
        }
        Component panel = matches.getFirst().component;
        Component focus = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        if (focus == null) {
            return "reference_listing_focus_absent";
        }
        if (focus != panel || SwingUtilities.getWindowAncestor(panel) != owner) {
            return "reference_listing_focus_other";
        }
        try {
            Object current = panel.getClass().getMethod("getCurrentField").invoke(panel);
            Class<?> type = Class.forName("docking.widgets.fieldpanel.field.Field", false,
                panel.getClass().getClassLoader());
            if (current == null) {
                return "reference_cursor_unavailable";
            }
            return address.equalsIgnoreCase((String) type.getMethod("getText").invoke(current))
                ? "reference_ready" : "reference_cursor_mismatch";
        }
        catch (ReflectiveOperationException error) {
            return "reference_cursor_readback";
        }
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

    private static boolean watchedButtonFocused() {
        return watchedButton != null && watchedWindow.isActive() && watchedButton.isShowing()
            && watchedButton.isEnabled()
            && KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner() == watchedButton;
    }

    private static boolean analyzePromptMatches(Window owner, String fixture) {
        if (!(owner instanceof Dialog dialog) || !"Analyze?".equals(dialog.getTitle()) || !dialog.isActive()) {
            return false;
        }
        String expected = fixture + " has not been analyzed. Would you like to analyze it now?";
        var rows = new ArrayList<Control>();
        collect(owner, rows, owner);
        return rows.stream().filter(row -> row.point != null && expected.equals(row.name)).count() == 1;
    }

    private static void watchButton(Control control, String title, String fixture) {
        if (!(control.component instanceof JButton button) || !(control.owner instanceof Dialog dialog)
                || !title.equals(dialog.getTitle()) || !dialog.isActive() || !button.isEnabled()
                || !button.isShowing() || (watchedWindow != null && watchedWindow.isShowing())) {
            throw new IllegalStateException("Expected the active wizard's enabled button");
        }
        if (fixture != null && !analyzePromptMatches(dialog, fixture)) {
            throw new IllegalStateException("Active Analyze? prompt does not match the expected fixture");
        }
        var inputs = button.getInputMap(JComponent.WHEN_FOCUSED);
        for (boolean release : new boolean[] {false, true}) {
            Object binding = inputs.get(KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0, release));
            if (binding == null || button.getActionMap().get(binding) == null) {
                throw new IllegalStateException("The wizard button has no focused Space binding");
            }
        }
        if (watchedButton != null) {
            watchedButton.removeActionListener(watchedListener);
        }
        watchedButton = button;
        watchedWindow = dialog;
        watchedAnalyzeFixture = fixture;
        buttonActions = 0;
        watchedListener = event -> buttonActions++;
        button.addActionListener(watchedListener);
        button.requestFocusInWindow();
    }

    private static int column(JTable table, String name) {
        for (int i = 0; i < table.getColumnCount(); i++) {
            if (name.equals(table.getColumnName(i))) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isAnalyzerTable(JTable table, Window owner) {
        if (!(owner instanceof Dialog dialog) || !ANALYSIS_OPTIONS.equals(dialog.getTitle())
                || SwingUtilities.getWindowAncestor(table) != owner
                || column(table, "Analyzer") < 0 || column(table, "Enabled") < 0) {
            return false;
        }
        for (Component parent = table.getParent(); parent != null && parent != owner; parent = parent.getParent()) {
            if ("ghidra.app.plugin.core.analysis.AnalysisPanel".equals(parent.getClass().getName())) {
                return true;
            }
        }
        return false;
    }

    private static void collectAnalyzerRows(JTable table, Window owner, List<Control> rows) {
        if (!owner.isActive() || !isAnalyzerTable(table, owner)) {
            return;
        }
        Rectangle view = table.getVisibleRect();
        int analyzer = column(table, "Analyzer");
        int enabled = column(table, "Enabled");
        if (!view.isEmpty()) {
            rows.add(new Control("analysis-table", "Analyzer", center(table, view), view, owner, table));
        }
        for (int row = 0; row < table.getRowCount(); row++) {
            Rectangle bounds = table.getCellRect(row, analyzer, false);
            if (!view.contains(bounds)) {
                continue;
            }
            String name = String.valueOf(table.getValueAt(row, analyzer));
            if (table.getFontMetrics(table.getFont()).stringWidth(name) + 8 > bounds.width) {
                continue;
            }
            Point point = center(table, bounds);
            rows.add(new Control("analysis-analyzer", name, point, bounds, owner, table));
            if (table.isRowSelected(row)) {
                rows.add(new Control("analysis-selected", name, point, bounds, owner, table));
                Rectangle enablement = table.getCellRect(row, enabled, false);
                if (view.contains(enablement)) {
                    rows.add(new Control("analysis-selected-enabled", name + "=" + table.getValueAt(row, enabled),
                        center(table, enablement), enablement, owner, table));
                }
            }
        }
    }

    private static boolean isForegroundAnalyzer(Control control, String name) {
        if (!(control.component instanceof JTable table) || !control.owner.isActive()
                || !table.isShowing() || !isAnalyzerTable(table, control.owner)) {
            return false;
        }
        Point point = new Point(control.point);
        SwingUtilities.convertPointFromScreen(point, table);
        int row = table.rowAtPoint(point);
        int analyzer = column(table, "Analyzer");
        return row >= 0 && table.columnAtPoint(point) == analyzer
            && table.getVisibleRect().contains(table.getCellRect(row, analyzer, false))
            && name.equals(table.getValueAt(row, analyzer));
    }

    private record AnalyzerViewport(Rectangle visible, Rectangle target, Point wheelPoint) {}

    private static AnalyzerViewport analyzerViewport(Control control, String name) {
        if (!(control.component instanceof JTable table) || !control.owner.isActive()
                || !table.isShowing() || !isAnalyzerTable(table, control.owner)) {
            throw new IllegalStateException("Expected an active analysis-options analyzer table");
        }
        int analyzer = column(table, "Analyzer");
        Rectangle target = null;
        for (int row = 0; row < table.getRowCount(); row++) {
            if (name.equals(table.getValueAt(row, analyzer))) {
                if (target != null) {
                    throw new IllegalStateException("Analyzer name is ambiguous");
                }
                target = table.getCellRect(row, analyzer, false);
            }
        }
        if (target == null) {
            throw new IllegalStateException("Expected analyzer is absent");
        }
        Rectangle visible = table.getVisibleRect();
        if (visible.isEmpty() || target.x < visible.x || target.x + target.width > visible.x + visible.width) {
            throw new IllegalStateException("Analyzer column is outside the visible table");
        }
        return new AnalyzerViewport(visible, target, center(table, visible));
    }

    private static int analyzerPageDistance(AnalyzerViewport view) {
        int above = view.visible.y - view.target.y;
        int below = view.target.y + view.target.height - view.visible.y - view.visible.height;
        return Math.max(0, Math.max(above, below));
    }

    private static Point analyzerFocusPoint(Control control, String name) {
        AnalyzerViewport view = analyzerViewport(control, name);
        JTable table = (JTable) control.component;
        int analyzer = column(table, "Analyzer");
        int direction = view.target.y < view.visible.y ? -1 : 1;
        Rectangle screen = control.owner.getGraphicsConfiguration().getBounds();
        for (int offset = 0; offset < table.getRowCount(); offset++) {
            int row = direction > 0 ? table.getRowCount() - 1 - offset : offset;
            Rectangle cell = table.getCellRect(row, analyzer, false);
            if (view.visible.contains(cell)) {
                Point point = center(table, cell);
                if (screen.contains(point) && control.owner.getBounds().contains(point)) {
                    return point;
                }
            }
        }
        throw new IllegalStateException("No visible analyzer cell to focus within the active desktop");
    }

    private static void requireAnalyzerPageKey(Control control, int key, int direction) {
        JTable table = (JTable) control.component;
        if (!control.owner.isActive() || KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner() != table
                || table.isEditing()) {
            throw new IllegalStateException("The active analyzer table lacks keyboard focus");
        }
        KeyStroke stroke = KeyStroke.getKeyStroke(key, 0);
        Object binding = table.getInputMap(JComponent.WHEN_FOCUSED).get(stroke);
        if (binding == null) {
            binding = table.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(stroke);
        }
        String expected = direction > 0 ? "scrollDownChangeSelection" : "scrollUpChangeSelection";
        var action = table.getActionMap().get(expected);
        if (!expected.equals(binding) || action == null || !action.isEnabled()) {
            throw new IllegalStateException("The analyzer table lacks the expected focused page binding");
        }
    }

    private static String revealAnalyzer(Robot robot, Control control, String name, boolean pageKeys) throws Exception {
        AnalyzerViewport current = edt(() -> analyzerViewport(control, name));
        Rectangle initial = current.visible;
        if (pageKeys && !current.visible.contains(current.target)) {
            Point focus = edt(() -> analyzerFocusPoint(control, name));
            click(robot, focus, 1, InputEvent.BUTTON1_DOWN_MASK);
            robot.waitForIdle();
            current = edt(() -> analyzerViewport(control, name));
            if (!initial.equals(current.visible)) {
                throw new IllegalStateException("The analyzer viewport changed while acquiring keyboard focus");
            }
        }
        for (int steps = 0; steps <= 18; steps++) {
            if (current.visible.contains(current.target)) {
                return initial.equals(current.visible) ? "viewport-unchanged" : "viewport-moved";
            }
            if (steps == 18) {
                break;
            }
            int direction = current.target.y < current.visible.y ? -1 : 1;
            if (pageKeys) {
                int key = direction > 0 ? KeyEvent.VK_PAGE_DOWN : KeyEvent.VK_PAGE_UP;
                edt(() -> {
                    requireAnalyzerPageKey(control, key, direction);
                    return null;
                });
                robot.keyPress(key);
                robot.keyRelease(key);
            }
            else {
                robot.mouseMove(current.wheelPoint.x, current.wheelPoint.y);
                robot.mouseWheel(direction);
            }
            robot.waitForIdle();
            robot.delay(100);
            AnalyzerViewport next = edt(() -> analyzerViewport(control, name));
            int movement = Integer.signum(next.visible.y - current.visible.y);
            if (movement != direction) {
                if (pageKeys) {
                    throw new IllegalStateException(movement == 0
                        ? "Analyzer page key did not move the active table"
                        : "Analyzer page key moved the active table away from the target");
                }
                throw new IllegalStateException(movement == 0
                    ? "Analyzer wheel did not move the active table"
                    : "Analyzer wheel moved the active table away from the target");
            }
            if (pageKeys && analyzerPageDistance(next) >= analyzerPageDistance(current)) {
                throw new IllegalStateException("Analyzer page key moved the active table away from the target");
            }
            current = next;
        }
        throw new IllegalStateException("Analyzer row stayed outside the bounded viewport reveal");
    }

    private static boolean matchingImportSummary(Control active, String digest) {
        if (!(active.owner instanceof Dialog dialog) || !IMPORT_SUMMARY.equals(dialog.getTitle()) ||
            !dialog.isShowing() || !dialog.isActive() || !active.bounds.equals(dialog.getBounds())) {
            return false;
        }
        ImportMetadata fields = importMetadata(dialog);
        return fields != null && digest.equals(fields.sha.getText()) &&
            "WonderSwan Cartridge".equals(fields.format.getText()) && fields.fullyVisible();
    }

    private record ImportMetadata(JScrollPane pane, JTextField shaLabel, JTextField sha,
                                  JTextField formatLabel, JTextField format) {
        List<JTextField> fields() {
            return List.of(shaLabel, sha, formatLabel, format);
        }

        private static Rectangle glyphBounds(JTextField field) {
            var insets = field.getInsets();
            int width = field.getFontMetrics(field.getFont()).stringWidth(field.getText());
            return new Rectangle(insets.left, 0, width + 1, field.getHeight());
        }

        Rectangle textBounds() {
            Rectangle bounds = null;
            for (JTextField field : fields()) {
                var rendered = SwingUtilities.convertRectangle(field, glyphBounds(field), pane.getViewport().getView());
                bounds = bounds == null ? rendered : bounds.union(rendered);
            }
            return bounds;
        }

        boolean fullyVisible() {
            return pane.getViewport().getViewRect().contains(textBounds()) && fields().stream()
                .allMatch(field -> field.isShowing() && field.getVisibleRect().contains(glyphBounds(field)));
        }
    }

    private static ImportMetadata importMetadata(Dialog dialog) {
        var matches = new ArrayList<ImportMetadata>();
        findImportMetadata(dialog, matches);
        return matches.size() == 1 ? matches.getFirst() : null;
    }

    private static void findImportMetadata(Component component, List<ImportMetadata> matches) {
        if (component instanceof JScrollPane pane && pane.isShowing() &&
            pane.getViewport() != null &&
            pane.getViewport().getView() instanceof Container rows) {
            // The stock metadata pane contains alternating label and value text fields.
            JTextField shaLabel = null, sha = null, formatLabel = null, format = null;
            Component[] fields = rows.getComponents();
            for (int i = 0; i + 1 < fields.length; i += 2) {
                if (fields[i] instanceof JTextField label && fields[i + 1] instanceof JTextField value) {
                    switch (label.getText()) {
                        case "Executable SHA256:" -> {
                            if (sha != null) {
                                return;
                            }
                            shaLabel = label;
                            sha = value;
                        }
                        case "Executable Format:" -> {
                            if (format != null) {
                                return;
                            }
                            formatLabel = label;
                            format = value;
                        }
                    }
                }
            }
            if (sha != null && format != null) {
                matches.add(new ImportMetadata(pane, shaLabel, sha, formatLabel, format));
            }
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                findImportMetadata(child, matches);
            }
        }
    }

    private static String prepareImportSummary(Robot robot, String expected, String otherFixture) throws Exception {
        Control active = find("ACTIVE", IMPORT_SUMMARY);
        record ScrollState(String outcome, Point point, int rotations, int position) {}
        int previous = Integer.MIN_VALUE;
        for (int attempt = 0; attempt <= 48; attempt++) {
            ScrollState state = edt(() -> {
                if (!(active.owner instanceof Dialog dialog) || !dialog.isActive() ||
                    !dialog.isShowing() || !IMPORT_SUMMARY.equals(dialog.getTitle())) {
                    return new ScrollState("summary_changed", null, 0, 0);
                }
                ImportMetadata fields = importMetadata(dialog);
                if (fields == null) {
                    return new ScrollState("summary_rows_missing", null, 0, 0);
                }
                String digest = fields.sha.getText();
                if (!expected.equals(digest)) {
                    String outcome = otherFixture.equals(digest) ? "summary_other_fixture" :
                        digest.matches("[0-9a-fA-F]{64}") ? "summary_other_digest" : "summary_digest_missing";
                    return new ScrollState(outcome, null, 0, 0);
                }
                if (!"WonderSwan Cartridge".equals(fields.format.getText())) {
                    return new ScrollState("summary_wrong_format", null, 0, 0);
                }
                if (fields.fullyVisible()) {
                    return new ScrollState("summary_ready", null, 0, 0);
                }
                var viewport = fields.pane.getViewport();
                Rectangle visible = viewport.getViewRect();
                Rectangle wanted = fields.textBounds();
                if (wanted.height > visible.height || wanted.x < visible.x ||
                    wanted.x + wanted.width > visible.x + visible.width) {
                    return new ScrollState("summary_viewport_limited", null, 0, 0);
                }
                int delta = wanted.y < visible.y ? wanted.y - visible.y :
                    wanted.y + wanted.height - visible.y - visible.height;
                int direction = Integer.signum(delta);
                int increment = Math.max(1, fields.pane.getVerticalScrollBar().getUnitIncrement(direction));
                int turns = Math.min(8, Math.max(1, Math.abs(delta) / increment / 3));
                Point point = center(viewport, new Rectangle(0, 0, viewport.getWidth(), viewport.getHeight()));
                Rectangle screen = dialog.getGraphicsConfiguration().getBounds();
                if (direction == 0 || !dialog.getBounds().contains(point) || !screen.contains(point)) {
                    return new ScrollState("summary_viewport_limited", null, 0, 0);
                }
                return new ScrollState(null, point, direction * turns, visible.y);
            });
            if (state.outcome != null) {
                return state.outcome;
            }
            if (state.position == previous) {
                return "summary_scroll_ignored";
            }
            if (attempt == 48) {
                break;
            }
            previous = state.position;
            robot.mouseMove(state.point.x, state.point.y);
            robot.mouseWheel(state.rotations);
            robot.waitForIdle();
        }
        return "summary_viewport_limited";
    }

    private static boolean isProjectDataTree(Component component) {
        for (Component current = component; current != null; current = current.getParent()) {
            if ("ghidra.framework.main.datatree.DataTree".equals(current.getClass().getName())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRootProjectFile(TreePath path) {
        return path.getPathCount() == 2
            && "ghidra.framework.main.datatree.DomainFolderRootNode".equals(path.getPathComponent(0).getClass().getName())
            && "ghidra.framework.main.datatree.DomainFileNode".equals(path.getLastPathComponent().getClass().getName());
    }

    private static boolean isForegroundProjectFile(Control row, String title, String name) {
        if (!row.owner.isActive() || !title.equals(row.owner.getAccessibleContext().getAccessibleName())
                || !(row.component instanceof JTree tree) || !tree.isShowing()) {
            return false;
        }
        Point point = new Point(row.point);
        SwingUtilities.convertPointFromScreen(point, tree);
        var path = tree.getPathForLocation(point.x, point.y);
        if (path == null || !tree.getVisibleRect().contains(point)) {
            return false;
        }
        return isRootProjectFile(path) && title.equals("Ghidra: " + path.getPathComponent(0))
            && name.equals(path.getLastPathComponent().toString());
    }

    private static String command(Robot robot, String request) throws Exception {
        String[] parts = request.split("\t", 3);
        String editModifier = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx() == InputEvent.META_DOWN_MASK
            ? "META" : "CONTROL";
        return switch (parts[0]) {
            case "snapshot" -> String.join("\n", edt(GuiAgent::visible).stream().map(Control::describe).toList());
            case "snapshot-active-window" -> edt(() -> {
                Window owner = window(parts[1]);
                if (!owner.isActive()) {
                    throw new IllegalStateException("Expected an active window");
                }
                var rows = new ArrayList<Control>();
                collect(owner, rows, owner);
                return String.join("\n", rows.stream().map(Control::describe).toList());
            });
            case "start-listing-go" -> {
                edt(() -> activeWindow(parts[1]));
                chord(robot, "G");
                yield "";
            }
            case "verify-go-editor" -> {
                edt(() -> focusedGoEditor(parts[1]));
                yield "";
            }
            case "submit-go-address" -> {
                edt(() -> {
                    if (!parts[2].equals(focusedGoEditor(parts[1]).getText())) {
                        throw new IllegalStateException("The focused Go To editor lacks the exact requested address");
                    }
                    return null;
                });
                chord(robot, "ENTER");
                yield "";
            }
            case "focus-listing-address" -> {
                Control field = edt(() -> listingField(parts[1], parts[2]));
                click(robot, field.point, 1, InputEvent.BUTTON1_DOWN_MASK);
                robot.waitForIdle();
                yield field.describe();
            }
            case "read-listing-reference-state" ->
                edt(() -> listingReferenceReadiness(parts[1], parts[2]));
            case "open-listing-references" -> {
                String readiness = edt(() -> listingReferenceReadiness(parts[1], parts[2]));
                if (!readiness.equals("reference_ready")) {
                    yield readiness;
                }
                try {
                    robot.keyPress(KeyEvent.VK_R);
                    robot.keyRelease(KeyEvent.VK_R);
                }
                catch (IllegalArgumentException | SecurityException error) {
                    yield "reference_key_input_refused";
                }
                yield "reference_key_sent";
            }
            case "click-analysis-button" -> {
                Control button = find("JButton:enabled", Pattern.quote(parts[1]));
                if (!edt(() -> button.component instanceof JButton control && control.isShowing()
                        && control.isEnabled() && button.owner instanceof Dialog dialog
                        && ANALYSIS_OPTIONS.equals(dialog.getTitle()) && dialog.isActive())) {
                    throw new IllegalStateException("Expected enabled button in the active Analysis Options");
                }
                click(robot, button.point, 1, InputEvent.BUTTON1_DOWN_MASK);
                yield button.describe();
            }
            case "select-analyzer" -> {
                Control row = find("analysis-analyzer", Pattern.quote(parts[1]));
                if (!edt(() -> isForegroundAnalyzer(row, parts[1]))) {
                    throw new IllegalStateException("Expected the exact row in active Analysis Options");
                }
                click(robot, row.point, 1, InputEvent.BUTTON1_DOWN_MASK);
                yield row.describe();
            }
            case "reveal-analyzer", "reveal-analyzer-page" -> {
                Control table = find("analysis-table", "Analyzer");
                yield revealAnalyzer(robot, table, parts[1], parts[0].equals("reveal-analyzer-page"));
            }
            case "open-project-file" -> {
                Control row = find("project-file-row", Pattern.quote(parts[2]));
                if (!edt(() -> isForegroundProjectFile(row, parts[1], parts[2]))) {
                    throw new IllegalStateException("Expected the exact file row in the active project manager");
                }
                click(robot, row.point, 2, InputEvent.BUTTON1_DOWN_MASK);
                yield row.describe();
            }
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
            case "chooser-path-enter" -> {
                boolean focused = edt(() -> {
                    Window chooser = window(IMPORT_CHOOSER);
                    Component field = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
                    return chooser.isActive() && field instanceof JTextComponent &&
                        "Path".equals(field.getName()) && SwingUtilities.getWindowAncestor(field) == chooser;
                });
                if (!focused) {
                    throw new IllegalStateException("Import chooser path field lacks foreground focus");
                }
                chord(robot, "ENTER");
                yield "";
            }
            case "chooser-open-file" -> {
                Control file = find("chooser-file", parts[1]);
                if (!edt(file.owner::isActive)) {
                    throw new IllegalStateException("Import chooser lost foreground focus before selection");
                }
                click(robot, file.point, 2, InputEvent.BUTTON1_DOWN_MASK);
                yield "";
            }
            case "watch-button" -> {
                Control button = find("JButton:enabled", Pattern.quote(parts[2]));
                edt(() -> {
                    watchButton(button, parts[1], null);
                    return null;
                });
                yield "";
            }
            case "watch-analysis-yes" -> {
                Control button = find("JButton:enabled", "Yes");
                edt(() -> {
                    watchButton(button, "Analyze?", parts[1]);
                    return null;
                });
                yield "";
            }
            case "press-watched-space" -> {
                edt(() -> {
                    if (!watchedButtonFocused()) {
                        throw new IllegalStateException("The watched button lacks active keyboard focus");
                    }
                    if (watchedAnalyzeFixture != null && !analyzePromptMatches(watchedWindow, watchedAnalyzeFixture)) {
                        throw new IllegalStateException("Watched Analyze? prompt does not match the expected fixture");
                    }
                    return null;
                });
                chord(robot, "SPACE");
                yield "";
            }
            case "select-all" -> {
                chord(robot, editModifier + "+A");
                yield "";
            }
            case "paste" -> {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(parts[1]), null);
                chord(robot, editModifier + "+V");
                yield "";
            }
            case "prepare-import-summary" -> {
                if (!parts[1].matches("[0-9a-f]{64}") || !parts[2].matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Expected pinned import fixture digests");
                }
                yield prepareImportSummary(robot, parts[1], parts[2]);
            }
            case "capture", "capture-import-summary" -> {
                boolean importSummary = parts[0].equals("capture-import-summary");
                if (importSummary && !parts[1].matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Expected a pinned summary digest");
                }
                Control active = find("ACTIVE", importSummary ? IMPORT_SUMMARY : parts[1]);
                robot.waitForIdle();
                if (importSummary && !edt(() -> matchingImportSummary(active, parts[1]))) {
                    throw new IllegalStateException("Expected active import summary fields before capture");
                }
                Rectangle desktop = GraphicsEnvironment.getLocalGraphicsEnvironment()
                    .getDefaultScreenDevice().getDefaultConfiguration().getBounds();
                if (!desktop.contains(active.bounds)) {
                    throw new IllegalStateException("Active GUI is clipped by the desktop");
                }
                var image = robot.createScreenCapture(active.bounds);
                if (importSummary && !edt(() -> matchingImportSummary(active, parts[1]))) {
                    throw new IllegalStateException("Active import summary changed during capture");
                }
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
