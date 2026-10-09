// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.ArrayList;
import java.util.List;

/** UART timing and buffer semantics without a CPU or external ROM. */
public final class WSSerialTest {
    private record Sent(int value, int baud, long start, long end, long token) { }

    public static void run() {
        for (int control : new int[] { 0x80, 0xA0, 0xC0, 0xE0 }) {
            List<Sent> sent = new ArrayList<>();
            WSSerial tx = new WSSerial((v, b, s, e, t) -> sent.add(new Sent(v, b, s, e, t)));
            WSSerial rx = new WSSerial((v, b, s, e, t) -> { });
            Check.eq(0, tx.readStatus(), "UART disabled at reset");
            Check.isFalse(tx.writeData(0x12), "disabled write ignored");
            tx.writeControl(control);
            rx.writeControl(control);
            int clocks = (control & 0x40) != 0 ? 800 : 3200;
            Check.eq(clocks, tx.byteClocks(), "8N1 byte time");
            Check.eq((control & 0xC0) | 4, tx.readStatus(), "control/status mask");
            Check.eq(1, tx.interruptLevels(), "send ready level");
            Check.isTrue(tx.writeData(0x15A), "first transmit accepted");
            Check.isFalse(tx.writeData(0xEE), "busy transmit ignored");
            Check.eq(1, sent.size(), "one transmit buffer");
            Check.eq(0x5A, sent.get(0).value, "byte masking");
            Check.eq(clocks, sent.get(0).end, "delivery deadline");
            Check.eq(0, tx.interruptLevels(), "send ready off while busy");
            tx.advanceTo(clocks - 1);
            Check.eq(control & 0xC0, tx.readStatus(), "TX busy before last clock");
            Check.eq(0, rx.readStatus() & 1, "RX empty before delivery");
            tx.advanceTo(clocks);
            Check.eq(4, tx.readStatus() & 4, "TX empty at byte time");
            Check.isTrue(tx.validTransmission(sent.get(0).token), "completed byte valid");
            Check.eq("RECEIVED", rx.receive(0x5A, tx.baud()).name(), "matching receiver");
            Check.eq(5, rx.readStatus() & 7, "RX full and TX empty");
            Check.eq(9, rx.interruptLevels(), "RX ready level 3");
            Check.eq("OVERRUN", rx.receive(0xA5, tx.baud()).name(), "unread byte overrun");
            Check.eq(7, rx.readStatus() & 7, "overrun sticky");
            rx.writeControl(control & 0xC0);
            Check.eq(2, rx.readStatus() & 2, "zero does not clear overrun");
            rx.writeControl(control | 0x20);
            Check.eq(5, rx.readStatus() & 7, "bit 5 clears overrun only");
            Check.eq(0x5A, rx.readData(), "overrun preserves unread byte");
            Check.eq(4, rx.readStatus() & 7, "B1 consumes buffer");
            Check.eq(1, rx.interruptLevels(), "read clears RX level");
            rx.writeControl(0);
            Check.eq("DISABLED", rx.receive(0x99, tx.baud()).name(), "disabled receiver drops");
            rx.writeControl((control ^ 0x40) & 0xC0);
            Check.eq("SPEED_MISMATCH", rx.receive(0x99, tx.baud()).name(), "baud mismatch drops");
            Check.eq(0, rx.readStatus() & 1, "dropped bytes do not fill buffer");
            tx.writeData(0x33);
            long activeToken = sent.get(1).token;
            tx.writeControl(0);
            tx.writeControl(control);
            Check.isFalse(tx.validTransmission(activeToken), "disable cancels in-flight byte");
            Check.eq(4, tx.readStatus() & 7, "reenable empty");
        }
    }

    public static void main(String[] args) {
        run();
        System.out.println("WSSerialTest: PASS (" + Check.count + " checks)");
    }
}
