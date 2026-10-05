// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.List;
import java.util.Set;

/**
 * Unit tests for the loader's ROM-bank data overlays (naming, bank selection),
 * on synthetic sizes (no ROM data, no framework beyond the loader class).
 */
public final class WSRomBanksTest {
    private WSRomBanksTest() { }

    public static void run() {
        naming();
        linearCoverage4M();
        linearCoverage8M();
        smallRomMirror();
        paddedBanks();
        System.out.println("WSRomBanksTest: PASS");
    }

    private static void naming() {
        Check.eq("ROM_00", WonderSwanLoader.dataOverlayName(0x00), "bank 0 name");
        Check.eq("ROM_3A", WonderSwanLoader.dataOverlayName(0x3A), "bank 3A name");
        Check.eq("ROM_100", WonderSwanLoader.dataOverlayName(0x100), "bank 100 name");
        Check.isTrue(WonderSwanLoader.isDataOverlayName("ROM_3A"), "ROM_3A matches");
        Check.isTrue(WonderSwanLoader.isDataOverlayName("ROM_00"), "ROM_00 matches");
        Check.isFalse(WonderSwanLoader.isDataOverlayName("ROM0_BANK_00FF"), "B2 ROM0 excluded");
        Check.isFalse(WonderSwanLoader.isDataOverlayName("ROM1_BANK_0001"), "B2 ROM1 excluded");
        Check.isFalse(WonderSwanLoader.isDataOverlayName("LIN_4000"), "LIN excluded");
        Check.isFalse(WonderSwanLoader.isDataOverlayName("RAM"), "RAM excluded");
        Check.isFalse(WonderSwanLoader.isDataOverlayName("ROM_"), "empty bank excluded");
        Check.isFalse(WonderSwanLoader.isDataOverlayName("ROM_3a"), "lowercase excluded");
        Check.eq(0x3A, WonderSwanLoader.dataOverlayBankName("ROM_3A"), "ROM_3A bank");
        Check.eq(0x00, WonderSwanLoader.dataOverlayBankName("ROM_00"), "ROM_00 bank");
        Check.eq(-1, WonderSwanLoader.dataOverlayBankName("ROM0_BANK_00FF"), "B2 has no data bank");
    }

    private static void linearCoverage4M() {
        // 4 MiB: 64 banks, linear window shows the top 12 (0x34-0x3F).
        Set<Integer> lin = WonderSwanLoader.linearBanks(0x400000L);
        Check.eq(12, lin.size(), "4M linear count");
        for (int b = 0x34; b <= 0x3F; b++) Check.isTrue(lin.contains(b), "4M linear has " + b);
        List<Integer> data = WonderSwanLoader.dataOverlayBanks(0x400000L);
        Check.eq(52, data.size(), "4M data count");
        Check.eq(0, (int) data.get(0), "4M data first");
        Check.eq(0x33, (int) data.get(data.size() - 1), "4M data last");
        for (int b : data) Check.isFalse(lin.contains(b), "4M data not in linear: " + b);
    }

    private static void linearCoverage8M() {
        // 8 MiB: 128 banks, linear window shows the top 12 (0x74-0x7F).
        Set<Integer> lin = WonderSwanLoader.linearBanks(0x800000L);
        Check.eq(12, lin.size(), "8M linear count");
        for (int b = 0x74; b <= 0x7F; b++) Check.isTrue(lin.contains(b), "8M linear has " + b);
        List<Integer> data = WonderSwanLoader.dataOverlayBanks(0x800000L);
        Check.eq(116, data.size(), "8M data count");
        Check.eq(0, (int) data.get(0), "8M data first");
        Check.eq(0x73, (int) data.get(data.size() - 1), "8M data last");
    }

    private static void smallRomMirror() {
        // 512 KiB: 8 banks mirrored across the 12 linear slots, all visible, no data overlays.
        Set<Integer> lin = WonderSwanLoader.linearBanks(0x80000L);
        Check.isTrue(lin.size() <= 8, "small linear distinct <= banks, got " + lin.size());
        List<Integer> data = WonderSwanLoader.dataOverlayBanks(0x80000L);
        for (int b : data) Check.isFalse(lin.contains(b), "small data not in linear: " + b);
        Check.eq(8 - lin.size(), data.size(), "small data fills the gap");
    }

    private static void paddedBanks() {
        // 768 KiB file reads as 1 MiB effective: 16 banks, linear shows top 12, 4 data overlays.
        long eff = WSHardware.effectiveSize(0xC0000L);
        Check.eq(0x100000L, eff, "768K effective");
        List<Integer> data = WonderSwanLoader.dataOverlayBanks(eff);
        Check.eq(4, data.size(), "768K data count");
        // Padding banks have no file bytes; file banks do.
        Check.eq(-1L, WSHardware.fileOffset(((long) data.get(0)) << 16, 0xC0000L), "first data bank padded");
    }

    public static void main(String[] args) {
        run();
    }
}
