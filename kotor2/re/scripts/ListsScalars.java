// Find instructions with given scalar operands. Args: <outfile> <start> <end> <hexval>...
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.scalar.*;
import java.io.*;
import java.util.*;

public class ListsScalars extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Set<Long> vals = new HashSet<>();
        for (int i = 3; i < a.length; i++) vals.add(Long.parseLong(a[i].replace("0x",""), 16));
        FunctionManager fm = currentProgram.getFunctionManager();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (Instruction ins : currentProgram.getListing().getInstructions(new AddressSet(toAddr(a[1]), toAddr(a[2])), true)) {
                for (int op = 0; op < ins.getNumOperands(); op++) {
                    for (Object o : ins.getOpObjects(op)) {
                        if (o instanceof Scalar) {
                            long v = ((Scalar) o).getUnsignedValue() & 0xffffffffL;
                            long sv = ((Scalar) o).getSignedValue();
                            if (vals.contains(v) || vals.contains(sv & 0xffffffffL) || vals.contains(-sv)) {
                                Function f = fm.getFunctionContaining(ins.getAddress());
                                StringBuilder hex = new StringBuilder();
                                for (byte b : ins.getBytes()) hex.append(String.format("%02X", b));
                                w.printf("%s\t%s\t%s\t%s%n", ins.getAddress(), hex, ins, f == null ? "?" : f.getEntryPoint().toString());
                            }
                        }
                    }
                }
            }
        }
    }
}
