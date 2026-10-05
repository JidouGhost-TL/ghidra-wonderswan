// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * WonderSwan asset viewer: tiles, tilemaps, palettes and sprites.
 *
 * <p>Shows the bytes at the listing cursor or selection as tiles or tilemaps,
 * and — when the current program is a WonderSwan cartridge the emulator
 * supports — VRAM, palette RAM and the sprite table from a {@link WSMachine}
 * run. All rendering reuses the headless {@link WSAssets} core; export writes
 * PNG files.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "WonderSwan",
    category = PluginCategoryNames.CODE_VIEWER,
    shortDescription = "WonderSwan asset viewer",
    description = "View WonderSwan tiles, tilemaps, palettes and sprites from the listing or emulator state, and export them to PNG."
)
public class WSAssetPlugin extends ProgramPlugin {
    private WSAssetProvider provider;

    public WSAssetPlugin(PluginTool tool) {
        super(tool);
        provider = new WSAssetProvider(this);
    }

    @Override
    public void init() {
        super.init();      // the provider registers itself (addToTool in its constructor)
        createActions();
    }

    private void createActions() {
        DockingAction show = new DockingAction("Show Asset Viewer", getName()) {
            @Override public void actionPerformed(ActionContext context) {
                tool.showComponentProvider(provider, true);
            }
        };
        show.setDescription("Show the WonderSwan asset viewer");
        show.setMenuBarData(new MenuData(new String[] { "Window", "WonderSwan Asset Viewer" }));
        show.markHelpUnnecessary();
        tool.addAction(show);

        DockingAction decomp = new DockingAction("WS Decompress Here", getName()) {
            @Override public void actionPerformed(ActionContext context) {
                provider.decompressHere();
            }

            @Override public boolean isEnabledForContext(ActionContext context) {
                return currentProgram != null && currentLocation != null;
            }
        };
        decomp.setDescription("Decompress the bytes at the cursor with a registered codec");
        decomp.setPopupMenuData(new MenuData(new String[] { "WonderSwan", "Decompress Here" }));
        decomp.markHelpUnnecessary();
        tool.addAction(decomp);
    }

    @Override
    protected void programActivated(Program program) {
        provider.setProgram(program, currentLocation, currentSelection);
    }

    @Override
    protected void programClosed(Program program) {
        if (program == provider.getProgram()) {
            provider.setProgram(null, null, null);
        }
    }

    @Override
    protected void locationChanged(ProgramLocation loc) {
        provider.setProgram(currentProgram, loc, currentSelection);
    }

    @Override
    protected void selectionChanged(ProgramSelection sel) {
        provider.setProgram(currentProgram, currentLocation, sel);
    }

    /** Current listing address, or null. */
    public Address currentAddress() {
        return currentLocation == null ? null : currentLocation.getAddress();
    }
}
