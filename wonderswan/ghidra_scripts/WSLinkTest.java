// SPDX-License-Identifier: MIT OR Apache-2.0
// Integration fixture: two WSMachine instances, timed UARTs and CPU interrupt delivery.
// Run as a postScript on a synthetic cartridge imported with the WonderSwan loader. Args: <report file>
// @category WonderSwan
import ghidra.app.script.GhidraScript;
import jidoughost.wonderswan.*;
import java.nio.file.*;
import java.util.*;

public class WSLinkTest extends GhidraScript {
    private int checks;

    private void eq(long want, long got, String message) {
        checks++;
        if (want != got) throw new AssertionError(message + ": expected " + want + ", got " + got);
    }

    private WSMachine machine() {
        WSMachine m = new WSMachine(currentProgram, false);
        m.traceLimit = 0;
        m.halted = true;
        return m;
    }

    @Override public void run() throws Exception {
        List<String> results = new ArrayList<>();
        for (int control : new int[] { 0x80, 0xC0 }) {
            WSMachine a = machine(), b = machine();
            List<WSLink.ByteEvent> bytes = new ArrayList<>();
            WSLink link = new WSLink(a, b, bytes::add);
            a.setPort(0xB3, 1, control);
            b.setPort(0xB3, 1, control);
            a.setPort(0xB1, 1, 0x5A);
            int clocks = control == 0xC0 ? 800 : 3200;
            link.runUntil(clocks - 1);
            eq(clocks - 1, link.clock(), "both halted clocks stepped together");
            eq(0, b.getPort(0xB3, 1) & 1, "not received one clock early");
            eq(0, a.getPort(0xB3, 1) & 4, "transmitter still busy");
            link.runUntil(clocks);
            eq(1, b.getPort(0xB3, 1) & 1, "receive full at stop bit");
            eq(4, a.getPort(0xB3, 1) & 4, "transmit empty at stop bit");
            eq(1, bytes.size(), "one cable byte");
            eq(clocks, bytes.get(0).clock(), "byte timestamp");
            eq(0, b.getPort(0xB4, 1) & 8, "B2 masks RX interrupt");
            b.setPort(0xB2, 1, 8);
            eq(8, b.getPort(0xB4, 1) & 8, "enable with full buffer requests RX");
            b.setPort(0xB6, 1, 8);
            eq(8, b.getPort(0xB4, 1) & 8, "RX acknowledge reasserts while full");
            eq(0x5A, b.getPort(0xB1, 1), "peer B1 data");
            eq(0, b.getPort(0xB3, 1) & 1, "B1 read consumes");
            eq(8, b.getPort(0xB4, 1) & 8, "B1 read leaves IRQ latch");
            b.setPort(0xB6, 1, 8);
            eq(0, b.getPort(0xB4, 1) & 8, "RX acknowledge after read clears");
            a.setPort(0xB2, 1, 1);
            eq(1, a.getPort(0xB4, 1) & 1, "TX level at empty");
            a.setPort(0xB6, 1, 1);
            eq(1, a.getPort(0xB4, 1) & 1, "TX acknowledge reasserts");
            a.setPort(0xB1, 1, 0xA5);
            a.setPort(0xB6, 1, 1);
            eq(0, a.getPort(0xB4, 1) & 1, "busy TX can be acknowledged");
            results.add("PASS baud=" + a.serial().baud() + " byteClocks=" + clocks + " receive=5A; status and IRQ latch checked");
        }

        // Execute real IN/OUT instructions in RAM on each CPU, with opposite data directions.
        WSMachine a = machine(), b = machine();
        for (WSMachine m : new WSMachine[] { a, b }) {
            m.halted = false;
            m.setReg(m.lang.getRegister("CS"), 0);
            m.setReg(m.lang.getRegister("DS"), 0);
            m.syncCsval();
            // MOV AL,C0; OUT B3,AL; MOV AL,value; OUT B1,AL;
            // IN AL,B3; TEST AL,1; JZ back; IN AL,B1; MOV [1200],AL; HLT.
            m.write(0x1000, new byte[] { (byte)0xB0, (byte)0xC0, (byte)0xE6, (byte)0xB3,
                (byte)0xB0, (byte)(m == a ? 0x69 : 0x96), (byte)0xE6, (byte)0xB1,
                (byte)0xE4, (byte)0xB3, (byte)0xA8, 1, (byte)0x74, (byte)0xFA,
                (byte)0xE4, (byte)0xB1, (byte)0xA2, 0, 0x12, (byte)0xF4 });
            m.thread.overrideCounter(m.addr(0x1000));
        }
        WSLink codeLink = new WSLink(a, b, null);
        codeLink.runUntil(2000);
        eq(0x96, a.read(0x1200, 1)[0] & 0xFF, "CPU A IN received B OUT");
        eq(0x69, b.read(0x1200, 1)[0] & 0xFF, "CPU B IN received A OUT");
        eq(1, a.halted ? 1 : 0, "CPU A completes fixture");
        eq(1, b.halted ? 1 : 0, "CPU B completes fixture");
        results.add("PASS two CPU programs OUT/IN full duplex: A received 96, B received 69");

        // A receive interrupt wakes the halted CPU, vectors through B0+3, reads B1 and acknowledges B6.
        a = machine(); b = machine();
        b.setReg(b.lang.getRegister("CS"), 0);
        b.setReg(b.lang.getRegister("DS"), 0);
        b.setReg(b.lang.getRegister("SS"), 0);
        b.setReg(b.lang.getRegister("SP"), 0x2000);
        b.setReg(b.lang.getRegister("IF"), 1);
        b.syncCsval();
        b.thread.overrideCounter(b.addr(0x1000));
        b.write(0x8C, new byte[] { 0, 0x12, 0, 0 });
        b.write(0x1200, new byte[] { (byte)0xE4, (byte)0xB1, (byte)0xA2, 0, 0x13,
            (byte)0xB0, 8, (byte)0xE6, (byte)0xB6, (byte)0xF4 });
        WSLink interruptLink = new WSLink(a, b, null);
        a.setPort(0xB3, 1, 0xC0); b.setPort(0xB3, 1, 0xC0);
        b.setPort(0xB0, 1, 0x20); b.setPort(0xB2, 1, 8);
        a.setPort(0xB1, 1, 0xD7);
        interruptLink.runUntil(1200);
        eq(0xD7, b.read(0x1300, 1)[0] & 0xFF, "RX ISR consumes linked byte");
        eq(1, b.irqStats.getOrDefault("taken", 0), "RX IRQ entered once");
        eq(0, b.getPort(0xB4, 1) & 8, "ISR acknowledges after consuming");
        eq(1, b.halted ? 1 : 0, "ISR fixture completes");
        results.add("PASS RX interrupt wakes HLT, executes vector 23 handler and acknowledges B6");

        // Both CPUs stall in a DMA longer than one byte. The wire still completes on clock 800.
        final WSMachine dmaA = machine(), dmaB = machine();
        for (WSMachine m : new WSMachine[] { dmaA, dmaB }) {
            m.halted = false;
            m.setReg(m.lang.getRegister("CS"), 0);
            m.setReg(m.lang.getRegister("AL"), 0x80);
            m.syncCsval();
            m.write(0x1000, new byte[] { (byte)0xE6, 0x48, (byte)0xF4 });
            m.thread.overrideCounter(m.addr(0x1000));
            m.setPort(0x40, 2, 0x1200);
            m.setPort(0x44, 2, 0x2000);
            m.setPort(0x46, 2, 0x800);
        }
        List<Long> observedClocks = new ArrayList<>();
        WSLink dmaLink = new WSLink(dmaA, dmaB, e -> observedClocks.add(Math.min(dmaA.cycles, dmaB.cycles)));
        dmaA.setPort(0xB3, 1, 0xC0); dmaB.setPort(0xB3, 1, 0xC0);
        dmaA.setPort(0xB1, 1, 0xAB);
        dmaLink.runUntil(900);
        eq(1, observedClocks.size(), "DMA fixture byte delivered");
        eq(800, observedClocks.get(0), "wire clock exact inside DMA stall");
        eq(0xAB, dmaB.getPort(0xB1, 1), "DMA fixture received byte");
        eq(0, dmaA.ports[0x46] | dmaA.ports[0x47], "DMA completed on A");
        eq(0, dmaB.ports[0x46] | dmaB.ports[0x47], "DMA completed on B");
        results.add("PASS wire clock 800 inside two 2053-clock DMA stalls");

        // UART bytes are also visible in word-sized IN/OUT accesses to adjacent ports.
        a = machine(); b = machine();
        WSLink wordLink = new WSLink(a, b, null);
        a.setPort(0xB3, 1, 0xC0);
        b.setPort(0xB0, 1, 0x20);
        b.setPort(0xB2, 2, 0xC008);          // IRQ mask in AL, UART control in AH
        a.setPort(0xB0, 2, 0x5A20);          // vector base in AL, transmit data in AH
        wordLink.runUntil(800);
        eq(0xC508, b.getPort(0xB2, 2), "word IN includes live UART status in AH");
        eq(0x5A23, b.getPort(0xB0, 2), "word IN consumes B1 in AH");
        eq(0x08C4, b.getPort(0xB3, 2), "unaligned word IN includes IRQ latch in AH");
        b.setPort(0xB6, 1, 8);
        eq(0x00C4, b.getPort(0xB3, 2), "word IN after RX consumed and acknowledged");
        b.setPort(0xB2, 1, 0x49);
        eq(0x495A, b.getPort(0xB1, 2), "unaligned data word IN includes B2 in AH");
        results.add("PASS word IN/OUT UART byte lanes, buffer consumption and live status");

        // Detached compatibility: every write is instant, even disabled; never receives.
        WSMachine detached = machine();
        detached.setPort(0xB1, 1, 0x77);
        eq(1, detached.serialOut.size(), "detached disabled output unchanged");
        detached.setPort(0xB3, 1, 0xE0);
        eq(0xC4, detached.getPort(0xB3, 1), "detached TX always empty");
        eq(0, detached.getPort(0xB1, 1), "detached never receives");
        results.add("PASS detached compatibility");
        results.add("WSLinkTest: PASS (" + checks + " checks)");
        Path file = Path.of(getScriptArgs()[0]);
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, results);
        for (String result : results) println(result);
    }
}
