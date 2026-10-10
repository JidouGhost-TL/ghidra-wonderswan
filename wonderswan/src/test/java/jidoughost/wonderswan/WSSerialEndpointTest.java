// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/** Receive pacing of the external serial stream, on a bare UART (no CPU or ROM). */
public final class WSSerialEndpointTest {
    public static void run() {
        for (WSSerialEndpoint.Pacing pacing : WSSerialEndpoint.Pacing.values()) {
            List<String> log = new ArrayList<>();
            WSSerialEndpoint.Reporter reporter = (d, clock, value, baud, result) -> log.add(String.format("%d %02X %s", clock, value, result));
            WSSerial rx = new WSSerial((v, b, s, e, t) -> { });
            WSSerialEndpoint.Receiver receiver = new WSSerialEndpoint.Receiver(pacing);

            receiver.arrived.add(0x11);
            receiver.deliver(rx, 0, reporter);
            Check.eq("0 11 DISABLED", log.get(0), pacing + ": disabled port drops");

            rx.writeControl(0x80);                  // 9600 baud: 3200 clocks per byte
            receiver.arrived.add(0x5A);
            receiver.arrived.add(0xA5);
            receiver.deliver(rx, 100, reporter);
            Check.eq("100 5A RECEIVED", log.get(1), pacing + ": first byte at once");
            Check.eq(2, log.size(), pacing + ": second byte waits one byte time");
            receiver.deliver(rx, 100 + 3199, reporter);
            Check.eq(2, log.size(), pacing + ": not before the byte time");
            receiver.deliver(rx, 100 + 3200, reporter);
            if (pacing == WSSerialEndpoint.Pacing.PULL) {
                Check.eq(2, log.size(), "pull: held while the first byte is unread");
                Check.eq(0x5A, rx.readData(), "pull: first byte read");
                receiver.deliver(rx, 100 + 3300, reporter);
                Check.eq("3400 A5 RECEIVED", log.get(2), "pull: second byte after the read");
                Check.eq(0xA5, rx.readData(), "pull: second byte value");
                Check.eq(0, rx.readStatus() & 2, "pull: no overrun");
            } else {
                Check.eq("3300 A5 OVERRUN", log.get(2), "wire: second byte overruns");
                Check.eq(3, rx.readStatus() & 3, "wire: full and sticky overrun");
                Check.eq(0x5A, rx.readData(), "wire: unread byte survives");
            }

            rx.writeControl(0xC0);                  // 38400 baud: 800 clocks per byte
            int before = log.size();
            receiver.arrived.add(0x01);
            receiver.arrived.add(0x02);
            receiver.deliver(rx, 10_000, reporter);
            Check.eq(before + 1, log.size(), pacing + ": 38400 first byte");
            if (pacing == WSSerialEndpoint.Pacing.PULL) rx.readData();
            receiver.deliver(rx, 10_800, reporter);
            Check.eq(before + 2, log.size(), pacing + ": 38400 byte time is 800 clocks");

            receiver.arrived.add(0x03);
            rx.readData();
            receiver.deliver(rx, 5, reporter);       // master clock restarted (new run)
            Check.eq(before + 3, log.size(), pacing + ": restarted clock does not stall delivery");
        }
    }
}
