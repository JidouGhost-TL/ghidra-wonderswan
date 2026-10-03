// SPDX-License-Identifier: MIT OR Apache-2.0
// Differential decode test: decode the same byte sequences under two languages and
// report every difference in length / mnemonic / operand text, classified by cause.
//
// Args: <langA id> <langB id> <corpus> <out jsonl> [options...]
//   corpus = "sweep"            all opcode bytes x all ModRM bytes, trailing 12 34 56 78 9a bc,
//                               bare and behind each prefix 26 2e 36 3e f0 f2 f3 64 65 66 67 0f
//          | path to a file of hex lines (one instruction stream per line; first instruction compared)
//          | "dump:<dir>[,<dir>...]"  executed-code corpus: each dir holds linear.bin (CPU linear
//                               0x40000-0xFFFFF image) and coverage.json (list of executed blocks
//                               {"linear":int,"size":int,"cs":int,...}). Every instruction of every
//                               block is decoded sequentially at its real linear address. Blocks whose
//                               cs is the 64K-aligned segment of their address are compared A vs B;
//                               for every block, B's near-branch targets and CS-relative operands are
//                               checked against linear = cs*16 + ((ip + disp) & 0xFFFF).
//          | "csflow"           self-test of the B language's csval context flow (far CALL/JMP
//                               globalset, near targets inside a non-64K-aligned CS)
//          | "lengths"          targeted test of the formerly unresolved undefined encodings
//                               (docs/V30MZ-UNDEFINED-ENCODINGS.md): with hwundef=1 each case must
//                               decode with its verified length and mnemonic; with hwundef=0 each
//                               must be BAD (strict mode). langA is not used.
//   options: "hwundef"  decode B with context hwundef=1 (hardware-faithful undefined forms)
//            "all"      write every decoded case to the jsonl, not only differences
//
// If language B (or A) has a "csval" context field it is set to the code segment of each decoded
// address (sweep / hex file: the 64K-aligned segment of the buffer, i.e. what x86 real mode assumes;
// dump: the per-block "cs").
// Every difference gets a category; categories are justified by docs/V30MZ-SPEC-NOTES.md.
// UNEXPLAINED must be 0. A summary is printed and written to <out jsonl>.summary.json.
// A run of A vs A must report zero differences (harness self-check).
// Backward compatible with the original 4-argument form.
// @category V30MZ
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

public class V30MZDecodeDiff extends GhidraScript {
    static class Dec {
        Program p; PseudoDisassembler d; Address base; Register csval, hwundef; boolean hw;
    }

    static final long SWEEP_BASE = 0x10000;

    Dec open(String langId, long blockStart, byte[] init, int len, boolean hw) throws Exception {
        LanguageService ls = DefaultLanguageService.getLanguageService();
        Language lang = ls.getLanguage(new LanguageID(langId));
        CompilerSpec cs = lang.getDefaultCompilerSpec();
        Dec d = new Dec();
        d.p = new ProgramDB("diff-" + langId, lang, cs, this);
        int tx = d.p.startTransaction("mem");
        d.base = d.p.getAddressFactory().getDefaultAddressSpace().getAddress(blockStart);
        if (init != null)
            d.p.getMemory().createInitializedBlock("buf", d.base, new ByteArrayInputStream(init), init.length, TaskMonitor.DUMMY, false);
        else
            d.p.getMemory().createInitializedBlock("buf", d.base, len, (byte) 0, TaskMonitor.DUMMY, false);
        d.p.endTransaction(tx, true);
        d.d = new PseudoDisassembler(d.p);
        d.csval = d.p.getRegister("csval");
        d.hwundef = d.p.getRegister("hwundef");
        d.hw = hw;
        if (hw && d.hwundef == null) throw new IllegalArgumentException(langId + " has no hwundef context");
        return d;
    }

    PseudoInstruction decodeAt(Dec d, Address a, long cs) {
        try {
            PseudoDisassemblerContext ctx = new PseudoDisassemblerContext(d.p.getProgramContext());
            if (d.csval != null) ctx.setFutureRegisterValue(a, new RegisterValue(d.csval, BigInteger.valueOf(cs)));
            if (d.hw) ctx.setFutureRegisterValue(a, new RegisterValue(d.hwundef, BigInteger.ONE));
            return d.d.disassemble(a, ctx, false);
        } catch (Exception e) {
            return null;
        }
    }

    static String text(PseudoInstruction i) { return i == null ? "BAD" : i.getLength() + " " + i.toString(); }

    String decode(Dec d, byte[] bytes) throws Exception {
        int tx = d.p.startTransaction("w");
        byte[] buf = Arrays.copyOf(bytes, 64);
        d.p.getMemory().setBytes(d.base, buf);
        d.p.endTransaction(tx, true);
        return text(decodeAt(d, d.base, (d.base.getOffset() >> 4) & 0xf000));
    }

    // ---------------------------------------------------------------- classification
    static final Set<Integer> V30MZ_PREFIX = Set.of(0x26, 0x2e, 0x36, 0x3e, 0xf0, 0xf2, 0xf3);

    static boolean strict = true;   // B decoded with hwundef=0

    /** Categories for forms that are undefined on the V30MZ: B must be BAD in strict mode. */
    static final String[] UNDEF_CATS = { "FS_GS_PREFIX", "OPSIZE_ADDRSIZE_PREFIX", "TWO_BYTE_0F_MAP", "ARPL_63", "INT1_F1",
        "X87_D8_DF", "VEX_C4_C5", "EVEX_62", "TSX_XABORT_XBEGIN", "GRP3_F6F7_1", "GRP4_FE_2_7", "GRP5_FF_7", "GRP2_6",
        "SREG_FS_GS", "MOV_CS", "SREG_BIT5_ALIAS", "LEA_MOD3_ALT_EA", "FAR_MOD3_ALT_EA", "GRP1A_8F_1_7", "MOV_C6C7_1_7" };

    /** Category of a difference between A (x86 real mode) and B (V30MZ); see README. */
    static String classify(byte[] b, String ra, String rb, long addr, long cs) {
        String c = classify0(b, ra, rb, addr, cs);
        if (strict) for (String u : UNDEF_CATS) if (c.startsWith(u + "(") && !rb.equals("BAD")) return "UNEXPLAINED(strict decode of " + u + ")";
        if (c.startsWith("PAUSE_F3_90") && !rb.endsWith(" NOP")) return "UNEXPLAINED(F3 90)";
        return c;
    }

    static String classify0(byte[] b, String ra, String rb, long addr, long cs) {
        int i = 0;
        boolean lock = false;
        while (i < b.length && V30MZ_PREFIX.contains(b[i] & 0xff)) { if ((b[i] & 0xff) == 0xf0) lock = true; i++; }
        if (i >= b.length) return "UNEXPLAINED";
        int op = b[i] & 0xff;
        int modrm = i + 1 < b.length ? b[i + 1] & 0xff : -1;
        int mod = modrm >> 6, reg = (modrm >> 3) & 7;
        String am = ra.equals("BAD") ? "" : ra.substring(ra.indexOf(' ') + 1);
        if (op == 0x64 || op == 0x65) return "FS_GS_PREFIX(64/65 are 1-byte undefined, not prefixes)";
        if (op == 0x66 || op == 0x67) return "OPSIZE_ADDRSIZE_PREFIX(66/67 are 1-byte undefined, not prefixes)";
        if (op == 0x0f) return "TWO_BYTE_0F_MAP(0F is 1-byte undefined)";
        if (op == 0x63) return "ARPL_63(undefined on V30MZ)";
        if (op == 0xf1) return "INT1_F1(undefined/unresolved on V30MZ)";
        if (op >= 0xd8 && op <= 0xdf) return "X87_D8_DF(no FPU; ESC NOP only under hwundef)";
        if (op == 0x9b && rb.equals("1 WAIT") && am.startsWith("F")) return "X87_WAIT_FUSION(9B is a 1-byte WAIT)";
        if ((op == 0xc4 || op == 0xc5) && mod == 3) return "VEX_C4_C5(no VEX; mod=11 LES/LDS alt-EA, hwundef only)";
        if (op == 0x62 && mod == 3) return "EVEX_62(no EVEX; mod=11 BOUND, hwundef only)";
        if (op == 0x8d && mod == 3) return "LEA_MOD3_ALT_EA(mod=11 LEA uses base+index modes; hwundef only)";
        if (op == 0x90 && am.startsWith("PAUSE")) return "PAUSE_F3_90(REP NOP on V30MZ)";
        if ((op == 0xc6 || op == 0xc7) && modrm == 0xf8) return "TSX_XABORT_XBEGIN(C6/C7 /7 undefined)";
        if ((op == 0xc6 || op == 0xc7) && reg != 0) return "MOV_C6C7_1_7(reg field ignored, MOV r/m,imm; hwundef only)";
        if (op == 0x8f && reg != 0) return "GRP1A_8F_1_7(reg field ignored, POP r/m; hwundef only)";
        if ((ra.contains(".XACQUIRE") || ra.contains(".XRELEASE"))
                && rb.equals(ra.replace(".XACQUIRE", "").replace(".XRELEASE", ""))) return "TSX_HLE_HINT(F2/F3 are REP on V30MZ)";
        if (lock && op == 0xff && reg >= 2 && reg <= 6 && am.startsWith("INC.")) return "LOCK_FF_x86_INC_QUIRK(x86 decodes F0 FF /2-/6 as INC.LOCK)";
        if (lock && ra.equals("BAD") && !rb.equals("BAD")) return "LOCK_ACCEPTED(V30MZ accepts F0 on any instruction)";
        if (op == 0x8e && mod == 3 && reg != 1 && reg < 4 && !ra.equals("BAD") && !rb.equals("BAD")) {
            String[] pa = am.split("[ ,]"), pb = rb.substring(rb.indexOf(' ') + 1).split("[ ,]");
            if (pa.length == 3 && pb.length == 3 && pa[1].equals(pb[2]) && pa[2].equals(pb[1]))
                return "X86_DISPLAY_BUG_8E_REG(Ghidra x86 prints MOV Sreg,r16 operands reversed)";
        }
        if (op >= 0xe4 && op <= 0xe7 && !ra.equals("BAD") && i + 1 < b.length) {
            String p8 = String.format("0x%x", b[i + 1] & 0xff), p16 = String.format("0x%04x", b[i + 1] & 0xff);
            if (rb.equals(ra.replace(p8, p16))) return "IO_PORT_OPERAND(imm8 port is an io-space address operand)";
        }
        if ((op == 0xf6 || op == 0xf7) && reg == 1) return "GRP3_F6F7_1(undefined NOP, no immediate; hwundef only)";
        if (op == 0xfe && reg >= 2) return "GRP4_FE_2_7(x86 INC quirk; V30MZ FF alias/undefined, hwundef only)";
        if (op == 0xff && (reg == 3 || reg == 5) && mod == 3) return "FAR_MOD3_ALT_EA(mod=11 CALLF/JMPF use base+index modes; hwundef only)";
        if (op == 0xff && reg == 7) return "GRP5_FF_7(undefined; hwundef only)";
        if ((op == 0xc0 || op == 0xc1 || (op >= 0xd0 && op <= 0xd3)) && reg == 6) return "GRP2_6(undefined, writes 0; hwundef only)";
        if ((op == 0x8c || op == 0x8e) && (reg == 4 || reg == 5)) return "SREG_FS_GS(2-bit sreg field; bit5 alias hwundef only)";
        if (op == 0x8e && reg == 1) return "MOV_CS(no-op on V30MZ; hwundef only)";
        if ((op == 0x8c || op == 0x8e) && (reg == 6 || reg == 7)) return "SREG_BIT5_ALIAS(hwundef only)";
        if (!ra.equals("BAD") && !rb.equals("BAD")) {
            // Near relative branch whose target wraps: x86 adds without wrapping (rel8) or wraps in
            // the linear 64K block (rel16); the V30MZ wraps IP inside CS [ST:3012-3013].
            String[] wa = ra.split(" "), wb = rb.split(" ");
            Long ta = segTarget(ra), tb = segTarget(rb);
            Long disp = null;
            if ((op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3) || op == 0xeb) disp = (long) b[i + 1];
            else if (op == 0xe8 || op == 0xe9) disp = (long) (short) ((b[i + 1] & 0xff) | ((b[i + 2] & 0xff) << 8));
            if (disp != null && ta != null && tb != null && wa[0].equals(wb[0]) && wa[1].equals(wb[1])) {
                long next = addr + Long.parseLong(wb[0]);
                long expect = (cs * 16 + (((next - cs * 16) + disp) & 0xffff)) & 0xfffff;
                if (tb == expect && ta != expect) return "IP_WRAP(near target wraps inside CS on the V30MZ)";
            }
        }
        return "UNEXPLAINED";
    }

    /** Linear value of the first "0xSSSS:OOOO" address in a decoded text, or null. */
    static Long segTarget(String t) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("0x([0-9a-f]{4}):([0-9a-f]{4})").matcher(t);
        if (!m.find()) return null;
        return Long.parseLong(m.group(1), 16) * 16 + Long.parseLong(m.group(2), 16);
    }

    // ---------------------------------------------------------------- run
    Map<String, Integer> cats = new TreeMap<>();
    Map<String, Integer> counts = new LinkedHashMap<>();
    List<String> notes = new ArrayList<>();

    void count(String k, int n) { counts.merge(k, n, Integer::sum); }

    static String hex(byte[] b) {
        StringBuilder hx = new StringBuilder();
        for (byte x : b) hx.append(String.format("%02x", x & 0xff));
        return hx.toString();
    }

    static String js(String s) { return s.replace("\\", "\\\\").replace("\"", "'"); }

    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        Set<String> opts = new HashSet<>(Arrays.asList(a).subList(4, a.length));
        boolean hw = opts.contains("hwundef"), all = opts.contains("all");
        strict = !hw;
        try (PrintWriter out = new PrintWriter(new FileWriter(a[3]))) {
            if (a[2].startsWith("dump:")) runDump(a[0], a[1], a[2].substring(5).split(","), out, hw, all);
            else if (a[2].equals("csflow")) runCsFlow(a[1]);
            else if (a[2].equals("lengths")) runLengths(a[1], out);
            else runBytes(a[0], a[1], a[2], out, hw, all);
        }
        int unexplained = 0;
        for (var e : cats.entrySet()) if (e.getKey().startsWith("UNEXPLAINED") || e.getKey().startsWith("CS_MODEL_MISMATCH")
                || e.getKey().startsWith("B_BAD_IN_EXECUTED_CODE")) unexplained += e.getValue();
        StringBuilder sb = new StringBuilder("{\"counts\":{");
        boolean f = true;
        for (var e : counts.entrySet()) { sb.append(f ? "" : ",").append('"').append(e.getKey()).append("\":").append(e.getValue()); f = false; }
        sb.append("},\"categories\":{");
        f = true;
        for (var e : cats.entrySet()) { sb.append(f ? "" : ",").append('"').append(js(e.getKey())).append("\":").append(e.getValue()); f = false; }
        sb.append("},\"notes\":[");
        f = true;
        for (String n : notes) { sb.append(f ? "" : ",").append('"').append(js(n)).append('"'); f = false; }
        sb.append("],\"unexplained\":").append(unexplained).append("}");
        Files.writeString(Paths.get(a[3] + ".summary.json"), sb.toString());
        println("V30MZDecodeDiff: " + counts);
        for (var e : cats.entrySet()) println(String.format("  %8d  %s", e.getValue(), e.getKey()));
        for (String n : notes) println("  NOTE " + n);
        println("V30MZDecodeDiff: UNEXPLAINED=" + unexplained + (unexplained == 0 ? " PASS" : " FAIL"));
    }

    void runBytes(String la, String lb, String corpusArg, PrintWriter out, boolean hw, boolean all) throws Exception {
        Dec A = open(la, SWEEP_BASE, null, 64, false), B = open(lb, SWEEP_BASE, null, 64, hw);
        List<byte[]> corpus = new ArrayList<>();
        if (corpusArg.equals("sweep")) {
            int[] prefixes = { -1, 0x26, 0x2e, 0x36, 0x3e, 0xf0, 0xf2, 0xf3, 0x64, 0x65, 0x66, 0x67, 0x0f };
            byte[] tail = { 0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc };
            for (int p : prefixes)
                for (int op = 0; op < 256; op++)
                    for (int modrm = 0; modrm < 256; modrm++) {
                        ByteArrayOutputStream o = new ByteArrayOutputStream();
                        if (p >= 0) o.write(p);
                        o.write(op); o.write(modrm); o.write(tail);
                        corpus.add(o.toByteArray());
                    }
        } else {
            for (String line : Files.readAllLines(Paths.get(corpusArg))) {
                line = line.trim();
                if (line.isEmpty()) continue;
                byte[] b = new byte[line.length() / 2];
                for (int k = 0; k < b.length; k++) b[k] = (byte) Integer.parseInt(line.substring(2 * k, 2 * k + 2), 16);
                corpus.add(b);
            }
        }
        int same = 0, diff = 0, aBad = 0, bBad = 0;
        Map<String, Integer> byFirst = new TreeMap<>();
        for (byte[] b : corpus) {
            String ra = decode(A, b), rb = decode(B, b);
            if (ra.equals("BAD")) aBad++;
            if (rb.equals("BAD")) bBad++;
            boolean eq = ra.equals(rb);
            String cat = eq ? null : classify(b, ra, rb, SWEEP_BASE, (SWEEP_BASE >> 4) & 0xf000);
            if (cat != null && cat.startsWith("LOCK_ACCEPTED")) cat = checkLock(A, b, rb, cat);
            if (eq) same++;
            else {
                diff++;
                byFirst.merge(String.format("%02x", b[0] & 0xff), 1, Integer::sum);
                cats.merge(cat, 1, Integer::sum);
            }
            if (!eq || all)
                out.println("{\"bytes\":\"" + hex(b) + "\",\"a\":\"" + js(ra) + "\",\"b\":\"" + js(rb) + "\""
                        + (cat == null ? "" : ",\"cat\":\"" + js(cat) + "\"") + "}");
        }
        count("cases", corpus.size()); count("same", same); count("diff", diff); count("A_bad", aBad); count("B_bad", bBad);
        notes.add("diff_by_first_byte=" + byFirst);
        A.p.release(this); B.p.release(this);
    }

    /**
     * LOCK_ACCEPTED check: B's decode of F0+insn must equal x86's decode of the insn without that
     * F0 (length + 1), up to another justified category.
     */
    String checkLock(Dec A, byte[] b, String rb, String cat) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int k = 0, n = 0;
        while (k < b.length && V30MZ_PREFIX.contains(b[k] & 0xff)) { if ((b[k] & 0xff) == 0xf0) n++; else o.write(b[k]); k++; }
        o.write(b, k, b.length - k);
        byte[] s = o.toByteArray();
        String ra2 = decode(A, s);
        if (ra2.equals("BAD")) {
            if (rb.equals("BAD")) return cat;
            String c2 = classify(s, ra2, rb, SWEEP_BASE, (SWEEP_BASE >> 4) & 0xf000);
            return c2.startsWith("UNEXPLAINED") ? "UNEXPLAINED(lock: x86 BAD without F0)" : cat;
        }
        int sp = ra2.indexOf(' ');
        String adj = (Integer.parseInt(ra2.substring(0, sp)) + n) + ra2.substring(sp);
        if (adj.equals(rb)) return cat;
        String c2 = classify(s, adj, rb, SWEEP_BASE, (SWEEP_BASE >> 4) & 0xf000);
        return c2.startsWith("UNEXPLAINED") ? "UNEXPLAINED(lock: " + adj + " vs " + rb + ")" : cat;
    }

    // ---------------------------------------------------------------- executed-code corpus
    static final long LIN_BASE = 0x40000;

    void runDump(String la, String lb, String[] dirs, PrintWriter out, boolean hw, boolean all) throws Exception {
        for (String dir : dirs) {
            Path dp = Paths.get(dir);
            String game = dp.getParent() != null && dp.getFileName().toString().equals("dump") ? dp.getParent().getFileName().toString() : dp.getFileName().toString();
            byte[] img = Files.readAllBytes(dp.resolve("linear.bin"));
            JsonArray blocks = JsonParser.parseString(Files.readString(dp.resolve("coverage.json"))).getAsJsonArray();
            Dec A = open(la, LIN_BASE, img, img.length, false), B = open(lb, LIN_BASE, img, img.length, hw);
            int insns = 0, cmp = 0, same = 0, diff = 0, bBad = 0, nBlk = 0, nAligned = 0, skipped = 0;
            int brChk = 0, brOk = 0, csChk = 0, csOk = 0;
            Set<String> seen = new HashSet<>();
            for (JsonElement je : blocks) {
                JsonObject bo = je.getAsJsonObject();
                long lin = bo.get("linear").getAsLong(), size = bo.get("size").getAsLong(), cs = bo.get("cs").getAsLong();
                nBlk++;
                if (lin < LIN_BASE || lin + size > LIN_BASE + img.length) { skipped++; continue; }
                boolean aligned = cs == ((lin >> 4) & 0xf000);
                if (aligned) nAligned++;
                long addr = lin;
                while (addr < lin + size) {
                    Address ad = B.base.getNewAddress(addr);
                    PseudoInstruction ib = decodeAt(B, ad, cs);
                    String rb = text(ib);
                    int len = ib == null ? 1 : ib.getLength();
                    byte[] bytes = Arrays.copyOfRange(img, (int) (addr - LIN_BASE), (int) Math.min(addr - LIN_BASE + Math.max(len, 6), img.length));
                    String key = addr + ":" + cs;
                    boolean fresh = seen.add(key);
                    if (fresh) insns++;
                    if (ib == null) {
                        if (fresh) {
                            bBad++;
                            cats.merge("B_BAD_IN_EXECUTED_CODE", 1, Integer::sum);
                            out.println("{\"game\":\"" + game + "\",\"linear\":" + addr + ",\"cs\":" + cs + ",\"bytes\":\"" + hex(bytes) + "\",\"b\":\"BAD\",\"cat\":\"B_BAD_IN_EXECUTED_CODE\"}");
                        }
                        break;
                    }
                    if (fresh) {
                        // ---- A vs B text, only where x86's 64K-aligned CS model is the true CS
                        if (aligned) {
                            String ra = text(decodeAt(A, A.base.getNewAddress(addr), cs));
                            cmp++;
                            boolean eq = ra.equals(rb);
                            String cat = eq ? null : classify(bytes, ra, rb, addr, cs);
                            if (eq) same++; else { diff++; cats.merge(cat, 1, Integer::sum); }
                            if (!eq || all)
                                out.println("{\"game\":\"" + game + "\",\"linear\":" + addr + ",\"cs\":" + cs + ",\"bytes\":\"" + hex(bytes)
                                        + "\",\"a\":\"" + js(ra) + "\",\"b\":\"" + js(rb) + "\"" + (cat == null ? "" : ",\"cat\":\"" + js(cat) + "\"") + "}");
                        }
                        else if (all)
                            out.println("{\"game\":\"" + game + "\",\"linear\":" + addr + ",\"cs\":" + cs + ",\"bytes\":\"" + hex(bytes)
                                    + "\",\"b\":\"" + js(rb) + "\"}");
                        // ---- B's CS model against the true CS
                        String bad = checkCs(B, ib, bytes, addr, cs);
                        if (bad != null) {
                            if (bad.startsWith("BR")) brChk++; else csChk++;
                            if (bad.endsWith("OK")) { if (bad.startsWith("BR")) brOk++; else csOk++; }
                            else {
                                cats.merge("CS_MODEL_MISMATCH", 1, Integer::sum);
                                out.println("{\"game\":\"" + game + "\",\"linear\":" + addr + ",\"cs\":" + cs + ",\"bytes\":\"" + hex(bytes)
                                        + "\",\"b\":\"" + js(rb) + "\",\"cat\":\"CS_MODEL_MISMATCH\",\"detail\":\"" + js(bad) + "\"}");
                            }
                        }
                    }
                    addr += len;
                }
            }
            String g = game + ".";
            count(g + "blocks", nBlk); count(g + "blocks_cs_64k_aligned", nAligned); count(g + "blocks_outside_image", skipped);
            count(g + "insns", insns); count(g + "B_bad", bBad);
            count(g + "x86_compared", cmp); count(g + "x86_same", same); count(g + "x86_diff", diff);
            count(g + "near_branch_checked", brChk); count(g + "near_branch_ok", brOk);
            count(g + "cs_relative_checked", csChk); count(g + "cs_relative_ok", csOk);
            A.p.release(this); B.p.release(this);
        }
    }

    /**
     * Check B's near branch target / CS-relative operand against the true CS.
     * Returns null when the instruction has neither, else "BR OK", "CS OK" or a mismatch description.
     */
    String checkCs(Dec B, PseudoInstruction ib, byte[] b, long addr, long cs) {
        int i = 0;
        boolean csOver = false;
        while (i < b.length && V30MZ_PREFIX.contains(b[i] & 0xff)) { if ((b[i] & 0xff) == 0x2e) csOver = true; i++; }
        int op = b[i] & 0xff;
        long next = addr + ib.getLength();
        long ipNext = (next - cs * 16) & 0xffff;
        Long disp = null;
        if ((op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3) || op == 0xeb) disp = (long) b[i + 1];
        else if (op == 0xe8 || op == 0xe9) disp = (long) (short) ((b[i + 1] & 0xff) | ((b[i + 2] & 0xff) << 8));
        if (disp != null) {
            long expect = (cs * 16 + ((ipNext + disp) & 0xffff)) & 0xfffff;
            Address[] fl = ib.getFlows();
            if (fl.length != 1 || fl[0].getOffset() != expect)
                return "BR expected " + Long.toHexString(expect) + " got " + Arrays.toString(fl);
            return "BR OK";
        }
        int reg = i + 1 < b.length ? (b[i + 1] >> 3) & 7 : -1;
        boolean nearInd = op == 0xff && (reg == 2 || reg == 4);
        if (!(csOver || nearInd || op == 0x0e)) return null;
        PcodeOp[] pc = ib.getPcode();
        boolean found = false, any = false;
        Map<Varnode, Long> constOf = new HashMap<>();   // registers/uniques set from a constant
        for (PcodeOp p : pc) {
            if (p.getOpcode() == PcodeOp.COPY && p.getInput(0).isConstant() && p.getOutput() != null)
                constOf.put(p.getOutput(), p.getInput(0).getOffset());
            if (p.getOpcode() == PcodeOp.CALLOTHER && "segment".equals(B.p.getLanguage().getUserDefinedOpName((int) p.getInput(0).getOffset()))) {
                Varnode base = p.getInput(1);
                Long v = base.isConstant() ? Long.valueOf(base.getOffset()) : constOf.get(base);
                if ((csOver || nearInd) && v != null) { any = true; if (v == cs) found = true; }
            }
            if (op == 0x0e && p.getOpcode() == PcodeOp.COPY && p.getInput(0).isConstant()) { any = true; if (p.getInput(0).getOffset() == cs) found = true; }
        }
        if (!any) return null;  // e.g. CS: prefix on an instruction without a memory operand
        if (found) return "CS OK";
        return "CS expected segment " + Long.toHexString(cs) + " pcode " + Arrays.toString(pc);
    }

    // ---------------------------------------------------------------- targeted length test
    /**
     * { hex bytes (the sweep tail 12 34 56 78 9a bc is appended), expected length under hwundef=1
     * (0 = must stay BAD in both modes), expected hwundef=1 text without the length ("" = only the
     * mnemonic is not checked) }. D = displacement length of the ModRM: mod=00 r/m=110 -> 2,
     * mod=01 -> 1, mod=10 -> 2, otherwise 0. Verdicts: docs/V30MZ-UNDEFINED-ENCODINGS.md.
     */
    static final String[][] LENGTH_CASES = {
        // F1: CONFLICT -> never decoded
        { "f1", "0", "" },
        // F6 /1, F7 /1: 2+D, no immediate
        { "f6c8", "2", "UNDEF AL" }, { "f608", "2", "UNDEF byte ptr [BX + SI]" }, { "f60e", "4", "UNDEF byte ptr [0x3412]" },
        { "f64f", "3", "UNDEF byte ptr [BX + 0x12]" }, { "f68e", "4", "UNDEF byte ptr [BP + 0x3412]" },
        { "f7c8", "2", "UNDEF AX" }, { "f708", "2", "UNDEF word ptr [BX + SI]" }, { "f70e", "4", "UNDEF word ptr [0x3412]" },
        { "f74f", "3", "UNDEF word ptr [BX + 0x12]" }, { "f78e", "4", "UNDEF word ptr [BP + 0x3412]" },
        // 8F /1-/7: 2+D, POP r/m16
        { "8fc8", "2", "POP AX" }, { "8ff9", "2", "POP CX" }, { "8fcc", "2", "POP SP" }, { "8f08", "2", "POP word ptr [BX + SI]" },
        { "8f0e", "4", "POP word ptr [0x3412]" }, { "8f7f", "3", "POP word ptr [BX + 0x12]" }, { "8fb6", "4", "POP word ptr [BP + 0x3412]" },
        // C6 /1-/7: 3+D, C7 /1-/7: 4+D, MOV r/m,imm
        { "c6c8", "3", "MOV AL,0x12" }, { "c6f8", "3", "MOV AL,0x12" }, { "c608", "3", "MOV byte ptr [BX + SI],0x12" },
        { "c60e", "5", "MOV byte ptr [0x3412],0x56" }, { "c67f", "4", "MOV byte ptr [BX + 0x12],0x34" },
        { "c6b6", "5", "MOV byte ptr [BP + 0x3412],0x56" },
        { "c7c8", "4", "MOV AX,0x3412" }, { "c7f8", "4", "MOV AX,0x3412" }, { "c708", "4", "MOV word ptr [BX + SI],0x3412" },
        { "c70e", "6", "MOV word ptr [0x3412],0x7856" }, { "c77f", "5", "MOV word ptr [BX + 0x12],0x5634" },
        { "c7b6", "6", "MOV word ptr [BP + 0x3412],0x7856" },
        // mod=11 LEA / LES / LDS / BOUND / CALLF / JMPF: 2 bytes, no displacement
        { "8dc0", "2", "LEA AX,[BX + AX]" }, { "8dc8", "2", "LEA CX,[BX + AX]" }, { "8dc9", "2", "LEA CX,[BX + CX]" },
        { "8dca", "2", "LEA CX,[BP + DX]" }, { "8dcb", "2", "LEA CX,[BP + BX]" }, { "8dcc", "2", "LEA CX,[SI + SP]" },
        { "8dcd", "2", "LEA CX,[DI + BP]" }, { "8dce", "2", "LEA CX,[BP + SI]" }, { "8dcf", "2", "LEA CX,[BX + DI]" },
        { "c4d8", "2", "LES BX,[BX + AX]" }, { "c4da", "2", "LES BX,[BP + DX]" }, { "c4df", "2", "LES BX,[BX + DI]" },
        { "c5d8", "2", "LDS BX,[BX + AX]" }, { "c5de", "2", "LDS BX,[BP + SI]" }, { "26c5da", "3", "LDS BX,ES:[BP + DX]" },
        { "2ec4d8", "3", "" },
        { "62c0", "2", "BOUND AX,AX" }, { "62df", "2", "BOUND BX,DI" },
        { "ffd8", "2", "CALLF [BX + AX]" }, { "ffdc", "2", "CALLF [SI + SP]" }, { "ffda", "2", "CALLF [BP + DX]" },
        { "ffe8", "2", "JMPF [BX + AX]" }, { "ffef", "2", "JMPF [BX + DI]" },
        { "fed8", "2", "CALLF [BX + AX]" }, { "fee8", "2", "JMPF [BX + AX]" },
    };

    void runLengths(String lb, PrintWriter out) throws Exception {
        Dec hw = open(lb, SWEEP_BASE, null, 64, true), st = open(lb, SWEEP_BASE, null, 64, false);
        byte[] tail = { 0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc };
        int ok = 0;
        for (String[] c : LENGTH_CASES) {
            byte[] h = new byte[c[0].length() / 2];
            for (int k = 0; k < h.length; k++) h[k] = (byte) Integer.parseInt(c[0].substring(2 * k, 2 * k + 2), 16);
            byte[] b = Arrays.copyOf(h, h.length + tail.length);
            System.arraycopy(tail, 0, b, h.length, tail.length);
            String rh = decode(hw, b), rs = decode(st, b);
            int want = Integer.parseInt(c[1]);
            String wantText = want == 0 ? "BAD" : want + (c[2].isEmpty() ? "" : " " + c[2]);
            boolean good = rs.equals("BAD")
                    && (want == 0 ? rh.equals("BAD") : (c[2].isEmpty() ? rh.startsWith(want + " ") : rh.equals(wantText)));
            String pc = "";
            if (want != 0 && !rh.equals("BAD")) {
                int tx = hw.p.startTransaction("w");
                hw.p.getMemory().setBytes(hw.base, Arrays.copyOf(b, 64));
                hw.p.endTransaction(tx, true);
                PseudoInstruction pi = decodeAt(hw, hw.base, (hw.base.getOffset() >> 4) & 0xf000);
                if (pi != null) pc = Arrays.toString(pi.getPcode());
            }
            out.println("{\"bytes\":\"" + c[0] + "\",\"want\":\"" + js(wantText) + "\",\"hwundef\":\"" + js(rh) + "\",\"strict\":\"" + js(rs)
                    + "\",\"ok\":" + good + ",\"pcode\":\"" + js(pc) + "\"}");
            if (good) ok++;
            else {
                cats.merge("UNEXPLAINED(length test)", 1, Integer::sum);
                notes.add("FAIL " + c[0] + " want " + wantText + " / strict BAD; got hwundef=" + rh + " strict=" + rs);
            }
        }
        count("length_cases", LENGTH_CASES.length); count("length_ok", ok);
        hw.p.release(this); st.p.release(this);
    }

    // ---------------------------------------------------------------- csval flow self-test
    void runCsFlow(String lb) throws Exception {
        // 4000:0000  9A 10 00 00 44   CALLF 4400:0010   (-> linear 0x44010, pushes IP 0005)
        // 4000:0005  EB FE            JMP $
        // 4400:0010  E9 DD FF         JMP rel16 -> IP 0xFFF0 in CS 4400 = linear 0x53FF0
        //                             (x86's 64K-aligned model would give 0x43FF0)
        // 4400:FFF0  EA 00 00 00 50   JMPF 5000:0000   (linear 0x53FF0)
        // 5000:0000  2E FF 27         JMP word ptr CS:[BX]  (segment(0x5000, BX))
        byte[] img = new byte[0x20000];
        byte[][] code = { { (byte) 0x9a, 0x10, 0x00, 0x00, 0x44, (byte) 0xeb, (byte) 0xfe } };
        System.arraycopy(code[0], 0, img, 0, code[0].length);
        byte[] c2 = { (byte) 0xe9, (byte) 0xdd, (byte) 0xff };
        System.arraycopy(c2, 0, img, 0x4010, c2.length);
        byte[] c4 = { (byte) 0xea, 0x00, 0x00, 0x00, 0x50 };
        System.arraycopy(c4, 0, img, 0x13ff0, c4.length);
        byte[] c3 = { 0x2e, (byte) 0xff, 0x27 };
        System.arraycopy(c3, 0, img, 0x10000, c3.length);
        Dec B = open(lb, 0x40000, img, img.length, false);
        if (B.csval == null) throw new IllegalArgumentException(lb + " has no csval context");
        AddressSpace sp = B.p.getAddressFactory().getDefaultAddressSpace();
        int tx = B.p.startTransaction("dis");
        B.p.getProgramContext().setValue(B.csval, sp.getAddress(0x40000), sp.getAddress(0x40000), BigInteger.valueOf(0x4000));
        Disassembler dis = Disassembler.getDisassembler(B.p, TaskMonitor.DUMMY, null);
        AddressSetView done = dis.disassemble(sp.getAddress(0x40000), null, true);
        B.p.endTransaction(tx, true);
        Listing l = B.p.getListing();
        String[][] expect = {
            { "40000", "4000" }, { "40005", "4000" }, { "44010", "4400" }, { "53ff0", "4400" }, { "50000", "5000" } };
        int ok = 0;
        for (String[] e : expect) {
            Address ad = sp.getAddress(Long.parseLong(e[0], 16));
            Instruction ins = l.getInstructionAt(ad);
            BigInteger v = B.p.getProgramContext().getValue(B.csval, ad, false);
            String got = ins == null ? "none" : ins.toString() + " flows=" + Arrays.toString(ins.getFlows()) + " csval=" + (v == null ? "null" : v.toString(16));
            boolean good = ins != null && v != null && v.toString(16).equals(e[1]);
            if (e[0].equals("44010")) good &= ins != null && ins.getFlows().length == 1 && ins.getFlows()[0].getOffset() == 0x53ff0;
            if (e[0].equals("40000")) {
                // return IP pushed by CALLF must be 0x0005 (relative to the caller's CS 4000) ...
                // ... and the pushed CS must be the caller's 0x4000
                boolean pushOk = false, csOk = false;
                if (ins != null) for (PcodeOp p : ins.getPcode()) if (p.getOpcode() == PcodeOp.COPY && p.getInput(0).isConstant()) {
                    if (p.getInput(0).getOffset() == 5) pushOk = true;
                    if (p.getInput(0).getOffset() == 0x4000) csOk = true;
                }
                good &= pushOk && csOk;
                got += " pcode=" + (ins == null ? "" : Arrays.toString(ins.getPcode()));
            }
            if (e[0].equals("50000") && ins != null) {
                boolean segOk = false;
                for (PcodeOp p : ins.getPcode()) if (p.getOpcode() == PcodeOp.CALLOTHER && p.getInput(1).isConstant() && p.getInput(1).getOffset() == 0x5000) segOk = true;
                good &= segOk;
            }
            println((good ? "OK   " : "FAIL ") + e[0] + " " + got);
            notes.add((good ? "OK " : "FAIL ") + e[0] + " " + got);
            if (good) ok++; else cats.merge("UNEXPLAINED", 1, Integer::sum);
        }
        count("csflow_checks", expect.length); count("csflow_ok", ok);
        count("disassembled_bytes", (int) done.getNumAddresses());
        B.p.release(this);
    }
}
