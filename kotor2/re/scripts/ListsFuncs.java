// List functions in [start,end): entry size nrefs calls strings. Args: <outfile> <start> <end> [...more ranges]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

public class ListsFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing L = currentProgram.getListing();
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (int k = 1; k + 1 < a.length; k += 2) {
                Address s = toAddr(a[k]), e = toAddr(a[k+1]);
                for (Function f : fm.getFunctions(new AddressSet(s, e), true)) {
                    int nref = 0;
                    for (Reference r : getReferencesTo(f.getEntryPoint())) nref++;
                    StringBuilder calls = new StringBuilder();
                    StringBuilder strs = new StringBuilder();
                    for (Instruction ins : L.getInstructions(f.getBody(), true)) {
                        for (Reference r : ins.getReferencesFrom()) {
                            if (r.getReferenceType().isCall()) {
                                calls.append(r.getToAddress()).append(' ');
                            } else if (r.getReferenceType().isData()) {
                                Data d = L.getDataAt(r.getToAddress());
                                if (d != null && d.hasStringValue()) {
                                    String v = d.getDefaultValueRepresentation();
                                    if (v.length() > 40) v = v.substring(0, 40);
                                    strs.append(v).append(' ');
                                }
                            }
                        }
                    }
                    w.printf("%s\t%d\t%d\t%s\t%s\t%s%n", f.getEntryPoint(), f.getBody().getNumAddresses(), nref, f.getName(), calls.toString().trim(), strs.toString().trim());
                }
            }
        }
    }
}
