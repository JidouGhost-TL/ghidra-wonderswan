// SPDX-License-Identifier: MIT OR Apache-2.0
// Integration fixture: two consoles running the same frame-locked link handshake on a default WSLink.
// Run as a postScript on a synthetic cartridge imported with the WonderSwan loader. Args: <report file>
//
// Both CPUs run one program. Once per frame (after line 144) it reads the UART: a received CE while its
// own CE is outstanding means a collision, so it backs off and sends nothing this frame; a CE received
// without its own outstanding makes it the responder (sends B7); a received B7 makes it the initiator.
// With nothing received it sends CE. Real software uses this pattern and relies on the two consoles'
// frame phases differing, because two consoles are never switched on at the same instant.
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.*;
import java.nio.file.*;
import java.util.*;

public class WSLinkPowerOnTest extends GhidraScript {
    /** RAM 1000: frame-locked beacon handshake; result byte at 1200 (1 = responder, 2 = initiator). */
    static final byte[] HANDSHAKE = bytes(
        0xB0, 0xC0, 0xE6, 0xB3,                         // UART on, 38,400 baud
        0xE4, 0x02, 0x3C, 0x90, 0x75, 0xFA,             // wait for line 144
        0xE4, 0x02, 0x3C, 0x90, 0x74, 0xFA,             // wait until line 144 ends
        0xE4, 0xB3, 0xA8, 0x01, 0x74, 0x28,             // nothing received -> send
        0xE4, 0xB1, 0x3C, 0xCE, 0x75, 0x18,             // received byte other than CE -> check B7
        0xF6, 0x06, 0x00, 0x11, 0x01, 0x74, 0x07,       // CE and no own CE outstanding -> respond
        0xC6, 0x06, 0x00, 0x11, 0x00, 0xEB, 0xDA,       // collision: forget own CE, send nothing this frame
        0xB0, 0xB7, 0xE6, 0xB1, 0xC6, 0x06, 0x00, 0x12, 0x01, 0xF4,   // respond B7, result 1, halt
        0x3C, 0xB7, 0x75, 0xCC, 0xC6, 0x06, 0x00, 0x12, 0x02, 0xF4,   // B7: result 2, halt
        0xE4, 0xB3, 0xA8, 0x04, 0x74, 0xC0,             // send: wait for TX empty
        0xB0, 0xCE, 0xE6, 0xB1, 0xC6, 0x06, 0x00, 0x11, 0x01, 0xEB, 0xB5);   // CE, own CE outstanding

    static byte[] bytes(int... values) {
        byte[] b = new byte[values.length];
        for (int i = 0; i < b.length; i++) b[i] = (byte) values[i];
        return b;
    }

    private WSMachine machine() {
        WSMachine m = new WSMachine(currentProgram, false);
        m.traceLimit = 0;
        m.setReg(m.lang.getRegister("CS"), 0);
        m.setReg(m.lang.getRegister("DS"), 0);
        m.syncCsval();
        m.write(0x1000, HANDSHAKE);
        m.thread.overrideCounter(m.addr(0x1000));
        return m;
    }

    @Override public void run() throws Exception {
        WSMachine a = machine(), b = machine();
        List<WSLink.ByteEvent> bytes = new ArrayList<>();
        WSLink link = new WSLink(a, b, bytes::add);
        link.run(20, null);
        int ra = a.read(0x1200, 1)[0] & 0xFF, rb = b.read(0x1200, 1)[0] & 0xFF;
        long ce = bytes.stream().filter(e -> e.value() == 0xCE).count();
        String report = String.format("A result %d, B result %d, CE bytes %d, bytes %d", ra, rb, ce, bytes.size());
        println(report);
        if (!((ra == 1 && rb == 2) || (ra == 2 && rb == 1)))
            throw new AssertionError("symmetric handshake did not resolve on a default link: " + report);
        List<String> results = List.of("PASS default link resolves a symmetric frame-locked handshake: " + report,
            "WSLinkPowerOnTest: PASS");
        Path file = Path.of(getScriptArgs()[0]);
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, results);
        for (String r : results) println(r);
    }
}
