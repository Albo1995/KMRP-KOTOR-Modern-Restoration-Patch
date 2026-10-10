// Verify bytes and instruction boundaries. Args: <outfile> <va:hex>...
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ListsBytes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Listing L = currentProgram.getListing();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                String[] p = a[i].split(":");
                Address t = toAddr(p[0]);
                int n = p[1].length() / 2;
                byte[] b = new byte[n];
                currentProgram.getMemory().getBytes(t, b);
                StringBuilder h = new StringBuilder();
                for (byte x : b) h.append(String.format("%02X", x));
                boolean ok = h.toString().equalsIgnoreCase(p[1]);
                Instruction s = L.getInstructionAt(t);
                Instruction c = L.getInstructionContaining(t);
                Address end = t.add(n);
                Instruction e = L.getInstructionContaining(end.subtract(1));
                String bound = (s != null ? "starts-insn" : "mid-insn(" + (c == null ? "data" : c.getAddress() + " " + c) + ")")
                    + " / " + (e == null ? "data" : (e.getMaxAddress().equals(end.subtract(1)) ? "ends-insn" : "splits " + e.getAddress() + " " + e));
                w.printf("%s %s %s %s%n", ok ? "OK " : "BAD", t, h, bound);
            }
        }
    }
}
