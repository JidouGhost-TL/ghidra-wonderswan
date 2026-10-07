// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/** Unit tests for static-evidence bank-view naming and coverage checks (pure; no framework). */
public final class WSStaticBankViewTest {
    private WSStaticBankViewTest() { }

    public static void run() {
        Check.eq("ROM0_BANK_0022", WSStaticCode.staticBankViewName(0x2000, 0x22), "ROM0 view name");
        Check.eq("ROM1_BANK_0023", WSStaticCode.staticBankViewName(0x3000, 0x23), "ROM1 view name");
        Check.eq("ROM1_BANK_00F3", WSStaticCode.staticBankViewName(0x3000, 0xF3), "ROM1 high bank name");
        // Static views are executable views, never data overlays.
        Check.isFalse(WonderSwanLoader.isDataOverlayName(WSStaticCode.staticBankViewName(0x2000, 0x22)), "ROM0 view not data");
        Check.isFalse(WonderSwanLoader.isDataOverlayName(WSStaticCode.staticBankViewName(0x3000, 0x23)), "ROM1 view not data");
        // Coverage overlap: same and partial ranges overlap, adjacent banks do not.
        Check.isTrue(WSStaticCode.fileRangesOverlap(0x220000, 0x10000, 0x220000, 0x10000), "same bank overlaps");
        Check.isTrue(WSStaticCode.fileRangesOverlap(0x220000, 0x10000, 0x228000, 0x10000), "partial overlaps");
        Check.isFalse(WSStaticCode.fileRangesOverlap(0x210000, 0x10000, 0x220000, 0x10000), "adjacent banks disjoint");
        Check.isFalse(WSStaticCode.fileRangesOverlap(0x220000, 0x10000, 0x230000, 0x10000), "next bank disjoint");
        Check.isTrue(WSStaticCode.fileRangesOverlap(0x220000, 0x8001, 0x228000, 0x10000), "short view overlaps");
        Check.isFalse(WSStaticCode.fileRangesOverlap(0x220000, 0x8000, 0x228000, 0x10000), "touching ranges disjoint");
        System.out.println("WSStaticBankViewTest: PASS");
    }
}
