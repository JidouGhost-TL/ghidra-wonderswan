// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/** Runs every plain-Java unit test in this package (no framework; any failure throws). */
public final class MapperTestAll {
    private MapperTestAll() { }

    public static void main(String[] args) {
        WSCartridgeTest.run();
        WSFlashTest.run();
        WSRtcTest.run();
        WSKarnakTest.run();
        WSRomBanksTest.run();
        WSStaticBankViewTest.run();
        WSComputedEdgesTest.run();
        WSNoiseTest.run();
        WSSerialTest.run();
        WSSerialEndpointTest.run();
        System.out.println("MapperTestAll: PASS (" + Check.count + " checks)");
    }
}
