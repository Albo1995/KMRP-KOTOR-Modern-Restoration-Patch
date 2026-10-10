// Decompile functions and dump vtables. Args: <outfile> <item>...
// item: 0xADDR (function containing ADDR is decompiled, with its disassembly)
//       vt:ClassName (vftable entries of that RTTI class, with each target's name)
//       xref:0xADDR (functions referencing ADDR)
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class Decomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        try (PrintWriter w = new PrintWriter(new FileWriter(args[0]))) {
            for (int i = 1; i < args.length; i++) {
                String a = args[i];
                if (a.startsWith("vt:")) {
                    String cls = a.substring(3);
                    for (Symbol s : currentProgram.getSymbolTable().getSymbols("vftable")) {
                        if (!s.getParentNamespace().getName(true).equals(cls)) continue;
                        w.println("== vftable " + cls + " @ " + s.getAddress());
                        Address p = s.getAddress();
                        for (int slot = 0; slot < 200; slot++) {
                            Address e = p.add(slot * 4L);
                            if (slot > 0 && currentProgram.getSymbolTable().getPrimarySymbol(e) != null
                                    && currentProgram.getSymbolTable().getPrimarySymbol(e).getSource() != SourceType.DEFAULT) break;
                            int v = getInt(e);
                            Address t = toAddr(v & 0xffffffffL);
                            Function f = fm.getFunctionAt(t);
                            if (f == null && getMemoryBlock(t) == null) break;
                            if (getMemoryBlock(t) == null || !getMemoryBlock(t).isExecute()) break;
                            w.printf("slot %3d (+0x%03X): %s %s%n", slot, slot * 4, t, f == null ? "?" : f.getName(true));
                        }
                    }
                } else if (a.startsWith("xref:")) {
                    Address t = toAddr(a.substring(5));
                    w.println("== xrefs to " + t);
                    for (Reference r : getReferencesTo(t)) {
                        Function f = fm.getFunctionContaining(r.getFromAddress());
                        w.println(r.getFromAddress() + " " + r.getReferenceType() + " in " + (f == null ? "?" : f.getEntryPoint() + " " + f.getName(true)));
                    }
                } else {
                    Address t = toAddr(a);
                    Function f = fm.getFunctionContaining(t);
                    if (f == null) { w.println("== no function at " + t); continue; }
                    w.println("== " + f.getName(true) + " @ " + f.getEntryPoint() + " size " + f.getBody().getNumAddresses());
                    DecompileResults r = di.decompileFunction(f, 120, monitor);
                    w.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "decompile failed: " + r.getErrorMessage());
                    w.println("-- disassembly");
                    for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                        StringBuilder hex = new StringBuilder();
                        for (byte b : ins.getBytes()) hex.append(String.format("%02X", b));
                        w.printf("%s  %-16s %s%n", ins.getAddress(), hex, ins);
                    }
                }
            }
        }
        di.dispose();
    }
}
