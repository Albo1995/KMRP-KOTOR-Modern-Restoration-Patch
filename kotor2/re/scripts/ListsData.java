// Print raw bytes + int/float/double at addresses. Args: <outfile> <addr>...
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import java.io.*;

public class ListsData extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int i = 1; i < a.length; i++) {
                Address t = toAddr(a[i]);
                byte[] b = new byte[8];
                try { currentProgram.getMemory().getBytes(t, b); } catch (Exception e) { w.println(t + " unreadable"); continue; }
                StringBuilder h = new StringBuilder();
                for (byte x : b) h.append(String.format("%02X", x));
                java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN);
                int iv = bb.getInt(0); float fv = bb.getFloat(0); double dv = bb.getDouble(0);
                w.printf("%s %s int=%d float=%g double=%g block=%s init=%s%n", t, h, iv, fv, dv,
                    currentProgram.getMemory().getBlock(t).getName(), currentProgram.getMemory().getBlock(t).isInitialized());
            }
        }
    }
}
