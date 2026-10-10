// Print N instructions (with bytes) starting at ADDR, plus containing function. Args: <outfile> <0xADDR:N>...
// 0xADDR-:N prints N instructions BEFORE addr as well.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ScreenDis extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                String[] p = a[i].split(":");
                boolean back = p[0].endsWith("-");
                Address t = toAddr(back ? p[0].substring(0, p[0].length() - 1) : p[0]);
                int n = Integer.parseInt(p[1]);
                Function f = fm.getFunctionContaining(t);
                Instruction ins = l.getInstructionAt(t);
                w.println("== " + t + " in " + (f == null ? "?" : f.getEntryPoint()) + (ins == null ? "  (NOT AN INSTRUCTION START)" : ""));
                if (ins == null) ins = l.getInstructionAfter(t);
                if (back) { for (int k = 0; k < n && ins.getPrevious() != null; k++) ins = ins.getPrevious(); n = 2 * n; }
                for (int k = 0; k < n && ins != null; k++, ins = ins.getNext()) {
                    StringBuilder hex = new StringBuilder();
                    for (byte b : ins.getBytes()) hex.append(String.format("%02X", b));
                    boolean tgt = getReferencesTo(ins.getAddress()).length > 0;
                    w.printf("%s %s %-20s %s%n", ins.getAddress(), tgt ? "*" : " ", hex, ins);
                }
            }
        }
    }
}
