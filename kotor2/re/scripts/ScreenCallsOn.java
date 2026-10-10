// For each read of a global pointer, find the next CALL within N instructions; tally targets.
// Args: <outfile> <globalAddr> [window]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ScreenCallsOn extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        Address g = toAddr(a[1]);
        int win = a.length > 2 ? Integer.parseInt(a[2]) : 6;
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        Map<Address, List<String>> hits = new TreeMap<>();
        for (Reference r : getReferencesTo(g)) {
            Instruction ins = l.getInstructionAt(r.getFromAddress());
            if (ins == null) continue;
            Instruction cur = ins;
            for (int k = 0; k < win && cur != null; k++) {
                cur = cur.getNext();
                if (cur == null) break;
                if (cur.getFlowType().isCall()) {
                    Address[] fl = cur.getFlows();
                    if (fl.length > 0) {
                        Function caller = fm.getFunctionContaining(cur.getAddress());
                        hits.computeIfAbsent(fl[0], x -> new ArrayList<>()).add(cur.getAddress() + "@" + (caller == null ? "?" : caller.getEntryPoint().toString()));
                    }
                    break;
                }
            }
        }
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            for (Map.Entry<Address, List<String>> e : hits.entrySet()) {
                Function f = fm.getFunctionAt(e.getKey());
                w.println(e.getKey() + " n=" + e.getValue().size() + " size=" + (f == null ? "?" : f.getBody().getNumAddresses()) + " " + e.getValue().subList(0, Math.min(5, e.getValue().size())));
            }
        }
    }
}
