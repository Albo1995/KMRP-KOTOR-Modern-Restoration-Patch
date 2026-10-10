// Survey: function count, RTTI class names with vftables, and GUI/font strings with referencing functions.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.StringDataInstance;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class Survey extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp";
        Listing listing = currentProgram.getListing();
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();

        try (PrintWriter w = new PrintWriter(new FileWriter(outDir + "/classes.txt"))) {
            int n = 0;
            for (Symbol s : st.getAllSymbols(true)) {
                if (s.getName().equals("vftable")) {
                    w.println(s.getAddress() + "\t" + s.getParentNamespace().getName(true));
                    n++;
                }
            }
            println("functions=" + fm.getFunctionCount() + " vftables=" + n);
        }

        Pattern p = Pattern.compile("(?i)gui|font|listbox|resolution|screen|\\.tga|txi|aspect|width|height|scrollbar|map");
        ReferenceManager rm = currentProgram.getReferenceManager();
        try (PrintWriter w = new PrintWriter(new FileWriter(outDir + "/strings.txt"))) {
            DataIterator it = listing.getDefinedData(true);
            int n = 0;
            while (it.hasNext() && !monitor.isCancelled()) {
                Data d = it.next();
                if (!d.hasStringValue()) continue;
                String v = String.valueOf(d.getValue());
                if (v.length() < 3 || !p.matcher(v).find()) continue;
                StringBuilder fns = new StringBuilder();
                for (Reference r : rm.getReferencesTo(d.getAddress())) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    fns.append(f == null ? r.getFromAddress().toString() : f.getEntryPoint() + ":" + f.getName()).append(' ');
                }
                w.println(d.getAddress() + "\t" + v.replace("\n", "\\n") + "\t" + fns);
                n++;
            }
            println("strings=" + n);
        }
    }
}
