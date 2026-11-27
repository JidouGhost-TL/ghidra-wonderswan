// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import static org.junit.Assert.*;

import java.lang.reflect.Proxy;
import java.util.*;

import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/** Focused unit tests for WSJumpTables rules CT1a-ES/DS, J1-STACKSAVE, and J1-NULLGUARD. */
public class WSJumpTablesTest {

    static final class FakeProg {
        final SegmentedAddressSpace space = new SegmentedAddressSpace("ram", 0);
        final Map<Address, Instruction> insns = new HashMap<>();
        final Map<Address, List<Reference>> refsTo = new HashMap<>();
        final Map<Address, Function> funcs = new HashMap<>();
        final Program program;
        final WSJumpTables jt;

        FakeProg() {
            AddressFactory af = (AddressFactory) Proxy.newProxyInstance(
                AddressFactory.class.getClassLoader(), new Class<?>[] { AddressFactory.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getDefaultAddressSpace" -> space;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            Listing listing = (Listing) Proxy.newProxyInstance(
                Listing.class.getClassLoader(), new Class<?>[] { Listing.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getInstructionAt" -> insns.get(a[0]);
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            ReferenceManager rm = (ReferenceManager) Proxy.newProxyInstance(
                ReferenceManager.class.getClassLoader(), new Class<?>[] { ReferenceManager.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getReferencesTo" -> new ReferenceIterator() {
                        final Iterator<Reference> it = refsTo.getOrDefault(a[0], List.of()).iterator();
                        @Override public boolean hasNext() { return it.hasNext(); }
                        @Override public Reference next() { return it.next(); }
                        @Override public Iterator<Reference> iterator() { return this; }
                    };
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            FunctionManager fm = (FunctionManager) Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(), new Class<?>[] { FunctionManager.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getFunctionAt" -> funcs.get(a[0]);
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            ProgramContext ctx = (ProgramContext) Proxy.newProxyInstance(
                ProgramContext.class.getClassLoader(), new Class<?>[] { ProgramContext.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getRegister", "getValue" -> null;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            program = (Program) Proxy.newProxyInstance(
                Program.class.getClassLoader(), new Class<?>[] { Program.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getAddressFactory" -> af;
                    case "getListing" -> listing;
                    case "getMemory" -> null;
                    case "getReferenceManager" -> rm;
                    case "getFunctionManager" -> fm;
                    case "getProgramContext" -> ctx;
                    case "getRegister" -> null;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            jt = new WSJumpTables(program, new WSEvidence(), s -> { });
        }

        Address at(int seg, int off) { return space.getAddress(seg, off); }

        void addFunc(int seg, int off, int stackPurgeSize) {
            Address addr = at(seg, off);
            Function fn = (Function) Proxy.newProxyInstance(
                Function.class.getClassLoader(), new Class<?>[] { Function.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getStackPurgeSize" -> stackPurgeSize;
                    case "getEntryPoint" -> addr;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            funcs.put(addr, fn);
        }

        Instruction addInsn(int seg, int off, String text, byte[] bytes, Address fallFrom) {
            return addInsn(seg, off, text, bytes, fallFrom, null, null);
        }

        Instruction addInsn(int seg, int off, String text, byte[] bytes, Address fallFrom, Address fallThrough, Address[] explicitFlows) {
            Address addr = at(seg, off);
            String mn = text.contains(" ") ? text.substring(0, text.indexOf(' ')) : text;
            String mnUp = mn.toUpperCase();
            String ops = text.contains(" ") ? text.substring(text.indexOf(' ') + 1).trim() : "";
            int numOps = ops.isEmpty() ? 0 : ops.split(",").length;
            FlowType flowType;
            Address[] flows;
            if (mnUp.equals("CALL") || mnUp.equals("CALLF")) {
                if (ops.startsWith("0x") || ops.startsWith("0X")) {
                    flowType = RefType.UNCONDITIONAL_CALL;
                    flows = explicitFlows != null ? explicitFlows : new Address[] { at(seg, Integer.parseInt(ops.substring(2), 16)) };
                } else {
                    flowType = RefType.COMPUTED_CALL;
                    flows = explicitFlows != null ? explicitFlows : new Address[0];
                }
            } else if (mnUp.equals("RET") || mnUp.equals("RETF") || mnUp.equals("IRET")) {
                flowType = RefType.TERMINATOR;
                flows = new Address[0];
            } else if (mnUp.equals("JMP") || mnUp.equals("JMPF")) {
                flowType = ops.startsWith("0x") ? RefType.UNCONDITIONAL_JUMP : RefType.COMPUTED_JUMP;
                flows = explicitFlows != null ? explicitFlows : new Address[0];
            } else if (mnUp.startsWith("J")) {
                flowType = RefType.CONDITIONAL_JUMP;
                flows = explicitFlows != null ? explicitFlows : new Address[0];
            } else {
                flowType = RefType.FALL_THROUGH;
                flows = explicitFlows != null ? explicitFlows : new Address[0];
            }
            Instruction ins = (Instruction) Proxy.newProxyInstance(
                Instruction.class.getClassLoader(), new Class<?>[] { Instruction.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getAddress" -> addr;
                    case "getMnemonicString" -> mn;
                    case "toString" -> text;
                    case "getBytes" -> bytes == null ? new byte[0] : bytes;
                    case "getFallFrom" -> fallFrom;
                    case "getFallThrough" -> fallThrough;
                    case "getFlowType" -> flowType;
                    case "getFlows" -> flows;
                    case "getNumOperands" -> numOps;
                    case "getResultObjects" -> new Object[0];
                    case "equals" -> p == a[0];
                    case "hashCode" -> System.identityHashCode(p);
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            insns.put(addr, ins);
            return ins;
        }

        /** Build a straight fall-through chain of instructions starting at {@code seg:startOff}. */
        List<Instruction> chain(int seg, int startOff, String[] texts, byte[][] bytes) {
            List<Instruction> out = new ArrayList<>();
            Address prev = null;
            int off = startOff;
            for (int i = 0; i < texts.length; i++) {
                byte[] b = bytes != null && i < bytes.length ? bytes[i] : null;
                Address next = i + 1 < texts.length ? at(seg, off + 2) : null;
                Instruction ins = addInsn(seg, off, texts[i], b, prev, next, null);
                out.add(ins);
                prev = ins.getAddress();
                off += 2;
            }
            return out;
        }

        void addFlowRef(Address from, Address to, RefType type) {
            Reference ref = (Reference) Proxy.newProxyInstance(
                Reference.class.getClassLoader(), new Class<?>[] { Reference.class },
                (p, m, a) -> switch (m.getName()) {
                    case "getFromAddress" -> from;
                    case "getToAddress" -> to;
                    case "getReferenceType" -> type;
                    default -> throw new UnsupportedOperationException(m.getName());
                });
            refsTo.computeIfAbsent(to, k -> new ArrayList<>()).add(ref);
        }
    }

    // --- CT1a-ES/DS tests ---

    @Test
    public void segmentPrefixDecodesAllPrefixesAndLastWins() {
        FakeProg f = new FakeProg();
        assertEquals("ES", WSJumpTables.segmentPrefix(f.addInsn(0x4000, 0x10, "CALLF [BX + 0x20]", new byte[] { 0x26, (byte) 0xFF, (byte) 0x9F, 0x20, 0x00 }, null)));
        assertEquals("CS", WSJumpTables.segmentPrefix(f.addInsn(0x4000, 0x20, "CALLF [BX + 0x20]", new byte[] { 0x2E, (byte) 0xFF, (byte) 0x9F, 0x20, 0x00 }, null)));
        assertEquals("SS", WSJumpTables.segmentPrefix(f.addInsn(0x4000, 0x30, "CALLF [BP + 0x4]", new byte[] { 0x36, (byte) 0xFF, 0x5E, 0x04 }, null)));
        assertEquals("DS", WSJumpTables.segmentPrefix(f.addInsn(0x4000, 0x40, "CALLF [SI + 0x10]", new byte[] { 0x3E, (byte) 0xFF, 0x5C, 0x10 }, null)));
        assertNull(WSJumpTables.segmentPrefix(f.addInsn(0x4000, 0x50, "CALLF [BX + 0x10]", new byte[] { (byte) 0xFF, 0x5F, 0x10 }, null)));
        // Last segment prefix wins, and repeat/lock prefixes before it are skipped
        assertEquals("ES", WSJumpTables.segmentPrefix(f.addInsn(0x4000, 0x60, "CALLF [BX]", new byte[] { (byte) 0xF3, 0x2E, 0x26, (byte) 0xFF, 0x1F }, null)));
    }

    @Test
    public void farmemMatchesCallfAndJmpfForms() {
        assertTrue(WSJumpTables.FARMEM.matcher("CALLF [BX + 0x20]").matches());
        assertTrue(WSJumpTables.FARMEM.matcher("CALLF [SI + 0x100]").matches());
        assertTrue(WSJumpTables.FARMEM.matcher("JMPF ES:[BX + 0x20]").matches());
        assertTrue(WSJumpTables.FARMEM.matcher("JMPF DS:[DI - 0x10]").matches());
        assertTrue(WSJumpTables.FARMEM.matcher("JMPF [SI + 0x8]").matches());
        assertFalse(WSJumpTables.FARMEM.matcher("JMPF SS:[BP + 0x4]").matches());
    }

    @Test
    public void ct1aEsAndDsConstantRomPositive() {
        FakeProg f = new FakeProg();
        // ES = 0x4200 -> CALLF ES:[SI + 0x100]
        List<Instruction> esChain = f.chain(0x4000, 0x100,
            new String[] { "MOV CX,0x4200", "MOV ES,CX", "SHL SI,1", "SHL SI,1", "CALLF [SI + 0x100]" },
            new byte[][] { null, null, null, null, new byte[] { 0x26, (byte) 0xFF, (byte) 0x9C, 0x00, 0x01 } });
        Instruction esSite = esChain.get(esChain.size() - 1);
        assertTrue(f.jt.farTableSite(esSite));
        assertEquals(0x4200, f.jt.resolveTableSeg(esSite, f.jt.predecessors(esSite, 16), "ES", "SI", 0x4000));

        // DS = 0x5000 -> JMPF DS:[BX + 0x100]
        List<Instruction> dsChain = f.chain(0x4000, 0x200,
            new String[] { "MOV AX,0x5000", "MOV DS,AX", "SHL BX,1", "SHL BX,1", "JMPF DS:[BX + 0x100]" },
            new byte[][] { null, null, null, null, new byte[] { 0x3E, (byte) 0xFF, (byte) 0xAF, 0x00, 0x01 } });
        Instruction dsSite = dsChain.get(dsChain.size() - 1);
        assertTrue(f.jt.farTableSite(dsSite));
        assertEquals(0x5000, f.jt.resolveTableSeg(dsSite, f.jt.predecessors(dsSite, 16), "DS", "BX", 0x4000));

        // Unprefixed CALLF [BX + 0x100] with proven DS = 0x4000
        List<Instruction> unprefChain = f.chain(0x4000, 0x300,
            new String[] { "MOV AX,0x4000", "MOV DS,AX", "CALLF [BX + 0x100]" },
            new byte[][] { null, null, new byte[] { (byte) 0xFF, (byte) 0x9F, 0x00, 0x01 } });
        Instruction unprefSite = unprefChain.get(unprefChain.size() - 1);
        assertTrue(f.jt.farTableSite(unprefSite));
        assertEquals(0x4000, f.jt.resolveTableSeg(unprefSite, f.jt.predecessors(unprefSite, 16), null, "BX", 0x4000));
    }

    @Test
    public void ct1aEsDsNegativeSoundnessGuards() {
        FakeProg f = new FakeProg();
        // 1. WRAM segment (0x0000)
        List<Instruction> wram = f.chain(0x4000, 0x100,
            new String[] { "MOV AX,0x0", "MOV ES,AX", "CALLF [BX + 0x100]" },
            new byte[][] { null, null, new byte[] { 0x26, (byte) 0xFF, (byte) 0x9F, 0x00, 0x01 } });
        assertFalse(f.jt.farTableSite(wram.get(2)));

        // 2. Bank window segment != CS (0x2000 when CS=0x4000)
        List<Instruction> win = f.chain(0x4000, 0x200,
            new String[] { "MOV AX,0x2000", "MOV ES,AX", "CALLF [BX + 0x100]" },
            new byte[][] { null, null, new byte[] { 0x26, (byte) 0xFF, (byte) 0x9F, 0x00, 0x01 } });
        assertFalse(f.jt.farTableSite(win.get(2)));

        // 3. Clobbered ES before site
        List<Instruction> clob = f.chain(0x4000, 0x300,
            new String[] { "MOV AX,0x4000", "MOV ES,AX", "MOV ES,BX", "CALLF [BX + 0x100]" },
            new byte[][] { null, null, null, new byte[] { 0x26, (byte) 0xFF, (byte) 0x9F, 0x00, 0x01 } });
        assertFalse(f.jt.farTableSite(clob.get(3)));

        // 4. Intervening CALL between MOV ES and CALLF
        List<Instruction> call = f.chain(0x4000, 0x400,
            new String[] { "MOV AX,0x4000", "MOV ES,AX", "CALL 0x0900", "CALLF [BX + 0x100]" },
            new byte[][] { null, null, null, new byte[] { 0x26, (byte) 0xFF, (byte) 0x9F, 0x00, 0x01 } });
        assertFalse(f.jt.farTableSite(call.get(3)));

        // 5. Flow join between MOV ES and CALLF
        List<Instruction> join = f.chain(0x4000, 0x500,
            new String[] { "MOV AX,0x4000", "MOV ES,AX", "CALLF [BX + 0x100]" },
            new byte[][] { null, null, new byte[] { 0x26, (byte) 0xFF, (byte) 0x9F, 0x00, 0x01 } });
        f.addFlowRef(f.at(0x4000, 0x050), join.get(2).getAddress(), RefType.UNCONDITIONAL_JUMP);
        assertFalse(f.jt.farTableSite(join.get(2)));

        // 6. Unprefixed BP defaults to SS, not DS
        List<Instruction> bp = f.chain(0x4000, 0x600,
            new String[] { "MOV AX,0x4000", "MOV DS,AX", "CALLF [BP + 0x10]" },
            new byte[][] { null, null, new byte[] { (byte) 0xFF, 0x5E, 0x10 } });
        assertFalse(f.jt.farTableSite(bp.get(2)));
    }

    // --- J1-STACKSAVE tests ---

    @Test
    public void stackSaveRecoversByteBoundAcrossCallAndBranch() {
        FakeProg f = new FakeProg();
        f.chain(0x4000, 0x0500, new String[] { "CLC", "RET" }, null);
        List<Instruction> c = f.chain(0x4000, 0x100, new String[] {
            "MOV AL,byte ptr [0x10]",
            "MOV AH,0x0",
            "PUSH AX",
            "CALL 0x0500",
            "POP AX",
            "JC 0x0140",
            "SHL AX,1",
            "JMP word ptr CS:[BX + 0x200]"
        }, null);
        Instruction site = c.get(c.size() - 1);
        WSJumpTables.Rec r = new WSJumpTables.Rec();
        r.idx = "AX";
        f.jt.byteBound(f.jt.predecessors(site, 16), "AX", r);
        assertTrue("byteBound should succeed across balanced PUSH/CALL/POP", r.byteBound);
        assertEquals(256, r.cap);
        assertNotNull(r.ct1);
        assertTrue(r.ct1.contains("J1-STACKSAVE"));
    }

    @Test
    public void stackSaveRecoversByteBoundWithNestedPushAndCdeclAddSp() {
        FakeProg f = new FakeProg();
        f.addFunc(0x4000, 0x0500, 0);
        List<Instruction> c = f.chain(0x4000, 0x200, new String[] {
            "XOR BH,BH",
            "MOV BL,byte ptr [0x10]",
            "PUSH BX",
            "PUSH CX",
            "PUSH DX",
            "CALL 0x0500",
            "ADD SP,0x4",
            "POP BX",
            "SHL BX,1",
            "CALL word ptr CS:[BX + 0x200]"
        }, null);
        Instruction site = c.get(c.size() - 1);
        WSJumpTables.Rec r = new WSJumpTables.Rec();
        r.idx = "BX";
        f.jt.byteBound(f.jt.predecessors(site, 16), "BX", r);
        assertTrue("byteBound should balance nested PUSH + ADD SP,0x4", r.byteBound);
        assertEquals(256, r.cap);
        assertTrue(r.ct1.contains("J1-STACKSAVE"));
    }

    @Test
    public void stackSaveRecoversMaskBoundAcrossCall() {
        FakeProg f = new FakeProg();
        f.chain(0x4000, 0x0500, new String[] { "NOP", "RETF" }, null);
        List<Instruction> c = f.chain(0x4000, 0x300, new String[] {
            "AND AX,0x7",
            "PUSH AX",
            "CALL 0x0500",
            "POP AX",
            "SHL AX,1",
            "JMP word ptr CS:[BX + 0x200]"
        }, null);
        Instruction site = c.get(c.size() - 1);
        WSJumpTables.Rec r = new WSJumpTables.Rec();
        r.idx = "AX";
        TreeSet<Integer> offs = f.jt.maskValues(f.jt.predecessors(site, 16), "AX", r);
        assertNotNull("maskValues should trace across balanced PUSH/CALL/POP", offs);
        assertEquals(Set.of(0, 2, 4, 6, 8, 10, 12, 14), offs);
        assertTrue(r.ct1.contains("J1-STACKSAVE"));
    }

    @Test
    public void stackSaveNegativeSoundnessGuards() {
        FakeProg f = new FakeProg();
        f.addFunc(0x4000, 0x0500, 0);
        // 1. Unbalanced extra PUSH before POP
        List<Instruction> unbal = f.chain(0x4000, 0x100, new String[] {
            "MOV AH,0x0", "PUSH AX", "PUSH BX", "CALL 0x0500", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r1 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(unbal.get(6), 16), "AX", r1);
        assertFalse("unbalanced extra PUSH must not prove byteBound", r1.byteBound);

        // 2. Wrong register pushed
        List<Instruction> wrongReg = f.chain(0x4000, 0x200, new String[] {
            "MOV AH,0x0", "PUSH BX", "CALL 0x0500", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r2 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(wrongReg.get(5), 16), "AX", r2);
        assertFalse("mismatched PUSH BX / POP AX must not prove byteBound", r2.byteBound);

        // 3. Flow join between PUSH and POP
        List<Instruction> join = f.chain(0x4000, 0x300, new String[] {
            "MOV AH,0x0", "PUSH AX", "CALL 0x0500", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        f.addFlowRef(f.at(0x4000, 0x050), join.get(3).getAddress(), RefType.CONDITIONAL_JUMP);
        WSJumpTables.Rec r3 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(join.get(5), 16), "AX", r3);
        assertFalse("flow join into POP must not prove byteBound", r3.byteBound);

        // 4. SP clobbered between PUSH and POP
        List<Instruction> spClob = f.chain(0x4000, 0x400, new String[] {
            "MOV AH,0x0", "PUSH AX", "MOV SP,BP", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r4 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(spClob.get(5), 16), "AX", r4);
        assertFalse("SP write between PUSH and POP must not prove byteBound", r4.byteBound);

        // 5. Direct [SP] stack-slot write between PUSH and POP
        List<Instruction> spSlot = f.chain(0x4000, 0x500, new String[] {
            "MOV AH,0x0", "PUSH AX", "MOV word ptr [SP],BX", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r5 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(spSlot.get(5), 16), "AX", r5);
        assertFalse("direct [SP] access must not prove byteBound", r5.byteBound);

        // 6. Indirect / computed CALL between PUSH and POP
        List<Instruction> indirectCall = f.chain(0x4000, 0x600, new String[] {
            "MOV AH,0x0", "PUSH AX", "CALL AX", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r6 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(indirectCall.get(5), 16), "AX", r6);
        assertFalse("computed/indirect CALL must not prove byteBound", r6.byteBound);

        // 7. Callee with RET 0x2 (pops stack arguments) via Function.getStackPurgeSize() > 0
        f.addFunc(0x4000, 0x0520, 2);
        List<Instruction> retPurgeFn = f.chain(0x4000, 0x700, new String[] {
            "MOV AH,0x0", "PUSH AX", "CALL 0x0520", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r7 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(retPurgeFn.get(5), 16), "AX", r7);
        assertFalse("callee with positive stack purge must not prove byteBound", r7.byteBound);

        // 8. Callee with RET 0x2 (decoded body, no Function object)
        f.chain(0x4000, 0x0540, new String[] { "NOP", "RET 0x2" }, null);
        List<Instruction> retPurgeScan = f.chain(0x4000, 0x800, new String[] {
            "MOV AH,0x0", "PUSH AX", "CALL 0x0540", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r8 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(retPurgeScan.get(5), 16), "AX", r8);
        assertFalse("callee ending in RET 0x2 must not prove byteBound", r8.byteBound);

        // 9. Undecoded callee with unknown stack purge
        f.addFunc(0x4000, 0x0560, Function.UNKNOWN_STACK_DEPTH_CHANGE);
        List<Instruction> unknownPurge = f.chain(0x4000, 0x900, new String[] {
            "MOV AH,0x0", "PUSH AX", "CALL 0x0560", "POP AX", "SHL AX,1", "JMP word ptr CS:[BX + 0x200]"
        }, null);
        WSJumpTables.Rec r9 = new WSJumpTables.Rec();
        f.jt.byteBound(f.jt.predecessors(unknownPurge.get(5), 16), "AX", r9);
        assertFalse("undecoded callee with unknown stack purge must not prove byteBound", r9.byteBound);
    }

    // --- J1-NULLGUARD tests ---

    @Test
    public void isZeroTestAcceptsPureZeroTestsAndRejectsMutations() {
        assertTrue(WSJumpTables.isZeroTest("TESTAX,AX", "AX"));
        assertTrue(WSJumpTables.isZeroTest("ORAX,AX", "AX"));
        assertTrue(WSJumpTables.isZeroTest("ANDAX,AX", "AX"));
        assertTrue(WSJumpTables.isZeroTest("CMPAX,0X0", "AX"));
        assertTrue(WSJumpTables.isZeroTest("CMPAX,0", "AX"));

        assertFalse(WSJumpTables.isZeroTest("ORAX,0X1", "AX"));
        assertFalse(WSJumpTables.isZeroTest("ORAX,BX", "AX"));
        assertFalse(WSJumpTables.isZeroTest("ANDAX,0XFF", "AX"));
        assertFalse(WSJumpTables.isZeroTest("CMPAX,0X1", "AX"));
        assertFalse(WSJumpTables.isZeroTest("XORAX,AX", "AX"));
        assertFalse(WSJumpTables.isZeroTest("TESTAX,BX", "AX"));
    }

    @Test
    public void invertedNullGuardTestPositiveAndNegative() {
        FakeProg f = new FakeProg();
        // Positive: TEST AX,AX; JNE site; RET; site: CALL AX
        Instruction test = f.addInsn(0x4000, 0x100, "TEST AX,AX", null, null);
        Instruction jne = f.addInsn(0x4000, 0x102, "JNE 0x0106", null, test.getAddress());
        Instruction site = f.addInsn(0x4000, 0x106, "CALL AX", null, null);
        f.addFlowRef(jne.getAddress(), site.getAddress(), RefType.CONDITIONAL_JUMP);
        assertSame(test, f.jt.invertedNullGuardTest(site, "AX"));

        // Positive with OR AX,AX + JNZ
        Instruction orTest = f.addInsn(0x4000, 0x200, "OR AX,AX", null, null);
        Instruction jnz = f.addInsn(0x4000, 0x202, "JNZ 0x0206", null, orTest.getAddress());
        Instruction site2 = f.addInsn(0x4000, 0x206, "JMP AX", null, null);
        f.addFlowRef(jnz.getAddress(), site2.getAddress(), RefType.CONDITIONAL_JUMP);
        assertSame(orTest, f.jt.invertedNullGuardTest(site2, "AX"));

        // Negative: multiple incoming branches (join at site)
        f.addFlowRef(f.at(0x4000, 0x090), site.getAddress(), RefType.UNCONDITIONAL_JUMP);
        assertNull(f.jt.invertedNullGuardTest(site, "AX"));

        // Negative: incoming CALL reference to site alongside JNE
        Instruction testCall = f.addInsn(0x4000, 0x240, "TEST AX,AX", null, null);
        Instruction jneCall = f.addInsn(0x4000, 0x242, "JNE 0x0246", null, testCall.getAddress());
        Instruction siteCall = f.addInsn(0x4000, 0x246, "CALL AX", null, null);
        f.addFlowRef(jneCall.getAddress(), siteCall.getAddress(), RefType.CONDITIONAL_JUMP);
        f.addFlowRef(f.at(0x4000, 0x080), siteCall.getAddress(), RefType.UNCONDITIONAL_CALL);
        assertNull("incoming CALL to site must reject invertedNullGuardTest", f.jt.invertedNullGuardTest(siteCall, "AX"));

        // Negative: incoming flow join at JNE branch (bypasses zero test)
        Instruction testJoin = f.addInsn(0x4000, 0x280, "TEST AX,AX", null, null);
        Instruction jneJoin = f.addInsn(0x4000, 0x282, "JNE 0x0286", null, testJoin.getAddress());
        Instruction siteJoin = f.addInsn(0x4000, 0x286, "CALL AX", null, null);
        f.addFlowRef(jneJoin.getAddress(), siteJoin.getAddress(), RefType.CONDITIONAL_JUMP);
        f.addFlowRef(f.at(0x4000, 0x070), jneJoin.getAddress(), RefType.UNCONDITIONAL_JUMP);
        assertNull("flow join at JNE must reject invertedNullGuardTest", f.jt.invertedNullGuardTest(siteJoin, "AX"));

        // Negative: JE instead of JNE
        Instruction test3 = f.addInsn(0x4000, 0x300, "TEST AX,AX", null, null);
        Instruction je = f.addInsn(0x4000, 0x302, "JE 0x0306", null, test3.getAddress());
        Instruction site3 = f.addInsn(0x4000, 0x306, "CALL AX", null, null);
        f.addFlowRef(je.getAddress(), site3.getAddress(), RefType.CONDITIONAL_JUMP);
        assertNull(f.jt.invertedNullGuardTest(site3, "AX"));

        // Negative: mutating OR AX,0x1 before JNE
        Instruction badOr = f.addInsn(0x4000, 0x400, "OR AX,0x1", null, null);
        Instruction jne4 = f.addInsn(0x4000, 0x402, "JNE 0x0406", null, badOr.getAddress());
        Instruction site4 = f.addInsn(0x4000, 0x406, "CALL AX", null, null);
        f.addFlowRef(jne4.getAddress(), site4.getAddress(), RefType.CONDITIONAL_JUMP);
        assertNull(f.jt.invertedNullGuardTest(site4, "AX"));
    }
}
