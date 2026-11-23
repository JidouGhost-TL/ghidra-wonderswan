// SPDX-License-Identifier: MIT OR Apache-2.0
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import jidoughost.wonderswan.WSReturns;

/** Read-only BX live-through and opposing eligibility controls. */
public class WSBxLiveThroughFixtures extends GhidraScript {
    private static final String SPECIALIZED = "__wsasm_near_bx_preserved";
    private static final String LEAF = "89c6b800208ec0";
    private static final String READ_BX = "891e0021";
    private static final String STORE_RESULTS = "893602218c060421c3";
    private int checks;

    private void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
        checks++;
    }

    private Address at(ProgramDB p, int n) {
        return ((SegmentedAddressSpace)p.getAddressFactory().getDefaultAddressSpace()).getAddress(0x4000,n);
    }

    private void put(byte[] bytes, int n, String encoding) {
        var data=HexFormat.of().parseHex(encoding);
        System.arraycopy(data,0,bytes,n,data.length);
    }

    private void signature(ProgramDB p, Function f, SourceType source) throws Exception {
        var word = WordDataType.dataType;
        var shape = new StructureDataType(new CategoryPath("/WonderSwan/Registers"),"result_SI_ES",0);
        shape.add(word,"out_SI",null);
        shape.add(word,"out_ES",null);
        var input = new ParameterImpl("in_AX",word,new VariableStorage(p,p.getRegister("AX")),p,source);
        var output = new ReturnParameterImpl(shape,new VariableStorage(p,p.getRegister("SI"),p.getRegister("ES")),p);
        f.updateFunction("__wsasm",output,List.of(input),Function.FunctionUpdateType.CUSTOM_STORAGE,false,source);
    }

    private void test(String name, String leaf, String continuation, SourceType source, boolean accepted) throws Exception {
        byte[] bytes = new byte[0x180];
        Arrays.fill(bytes,(byte)0xcc);
        put(bytes,0x40,"bb3412b80900e8b700"+continuation+STORE_RESULTS);
        put(bytes,0x100,leaf+"c3");
        var language = currentProgram.getLanguage();
        var spec = language.getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID());
        var p = new ProgramDB(name,language,spec,this);
        int transaction=p.startTransaction(name);
        try {
            var file=p.getMemory().createFileBytes(name,0,bytes.length,new ByteArrayInputStream(bytes),monitor);
            p.getMemory().createInitializedBlock("code",at(p,0),file,0,bytes.length,false).setPermissions(true,false,true);
            var ctx=p.getProgramContext();
            for (String register : List.of("csval","DS","SS")) {
                ctx.setValue(p.getRegister(register),at(p,0),at(p,bytes.length-1),
                    register.equals("csval") ? BigInteger.valueOf(0x4000) : BigInteger.ZERO);
            }
            for (int start : new int[] {0x100,0x40}) {
                check(new DisassembleCommand(at(p,start),null,true).applyTo(p,monitor),name+" disassembly");
                check(new CreateFunctionCmd(at(p,start)).applyTo(p,monitor),name+" function creation");
            }
            var f=p.getFunctionManager().getFunctionAt(at(p,0x100));
            signature(p,f,source);
            var events=new ArrayList<String>();
            WSReturns.apply(p,events::add,monitor);
            check(f.getCallingConventionName().equals(accepted ? SPECIALIZED : "__wsasm"),name+" convention "+events);
            if (source!=SourceType.ANALYSIS)
                check(f.getSignatureSource()==source && f.hasCustomVariableStorage(),name+" explicit signature kept");
            if (accepted) {
                var decomp=new DecompInterface();
                try {
                    check(decomp.openProgram(p),name+" decompiler");
                    var result=decomp.decompileFunction(p.getFunctionManager().getFunctionAt(at(p,0x40)),30,monitor);
                    check(result.decompileCompleted(),name+" caller decompilation");
                    boolean exactCall=false, exactStore=false;
                    for (var ops=result.getHighFunction().getPcodeOps();ops.hasNext();) {
                        var op=ops.next();
                        if (op.getOpcode()==PcodeOp.CALL && op.getSeqnum().getTarget().equals(at(p,0x46))) {
                            exactCall=op.getNumInputs()==2 && op.getInput(1).isConstant()
                                && op.getInput(1).getOffset()==9 && op.getOutput()!=null && op.getOutput().getSize()==4;
                        }
                        if (op.getSeqnum().getTarget().equals(at(p,0x49))) {
                            Varnode value=op.getOpcode()==PcodeOp.STORE ? op.getInput(2)
                                : op.getOpcode()==PcodeOp.COPY && op.getOutput().getAddress().isMemoryAddress()
                                ? op.getInput(0) : null;
                            if (value!=null && value.isConstant() && value.getOffset()==0x1234) exactStore=true;
                        }
                    }
                    check(exactCall && exactStore,name+" exact input, joined result and caller BX store");
                } finally {
                    decomp.dispose();
                }
                events.clear();
                WSReturns.apply(p,events::add,monitor);
                check(events.stream().noneMatch(line->line.contains("\"rule\":\"R1d\"")),name+" stable replay");
                var call=p.getListing().getInstructionAt(at(p,0x46));
                var resume=p.getListing().getInstructionAt(call.getFallThrough());
                var oldBody=f.getBody();
                f.setBody(new ghidra.program.model.address.AddressSet(f.getEntryPoint(),oldBody.getMaxAddress().subtract(1)));
                WSReturns.apply(p,events::add,monitor);
                check(f.getCallingConventionName().equals("__wsasm")
                    && f.getReturn().getVariableStorage().toString().equals("SI:2,ES:2")
                    && f.getParameterCount()==1 && f.hasCustomVariableStorage(),name+" unprove preserves prior signature");
                check(resume.getAddress().equals(at(p,0x49)),name+" caller continuation unchanged");
            }
            var after=new byte[bytes.length];
            p.getMemory().getBytes(at(p,0),after);
            check(Arrays.equals(after,bytes),name+" code bytes intact");
        } finally {
            p.endTransaction(transaction,false);
            p.release(this);
        }
    }

    @Override public void run() throws Exception {
        test("pure read-through",LEAF,READ_BX,SourceType.ANALYSIS,true);
        test("ordinary memory writer",LEAF+"a30022",READ_BX,SourceType.ANALYSIS,false);
        test("conditional body", "85c07402"+LEAF,READ_BX,SourceType.ANALYSIS,false);
        test("overlapping byte write",LEAF+"b37f",READ_BX,SourceType.ANALYSIS,false);
        test("caller replaces BX first",LEAF,"bb7856"+READ_BX,SourceType.ANALYSIS,false);
        test("explicit user signature",LEAF,READ_BX,SourceType.USER_DEFINED,false);
        test("imported signature",LEAF,READ_BX,SourceType.IMPORTED,false);
        println("WSBxLiveThroughFixtures: PASS checks="+checks);
    }
}
