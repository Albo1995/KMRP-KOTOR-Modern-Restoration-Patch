// Searches. Args: <outfile> <item>...
// str:TEXT     defined strings containing TEXT (case-sensitive) + referencing functions
// imp:NAME     symbols named NAME (externals/thunks) + references
// scalar:0xV   instructions having scalar operand V (optionally scalar:0xV@0xLO-0xHI to limit range)
// bytes:HEX    memory occurrences of byte pattern (?? wildcard allowed as "..")
// fn:0xADDR    function info: entry, size, callers, callees
// rd:0xADDR:N  dump N dwords at ADDR (with symbol / function names)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.*;
import java.io.*;
import java.util.*;

public class ScreenFind extends GhidraScript {
    FunctionManager fm;
    String fn(Address a) {
        Function f = fm.getFunctionContaining(a);
        return f == null ? "?" : f.getEntryPoint() + ":" + f.getName(true);
    }
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        try (PrintWriter w = new PrintWriter(new FileWriter(args[0]))) {
            for (int i = 1; i < args.length; i++) {
                String a = args[i];
                w.println("== " + a);
                if (a.startsWith("str:") || a.startsWith("streq:")) {
                    boolean eq = a.startsWith("streq:");
                    String t = a.substring(eq ? 6 : 4);
                    DataIterator it = listing.getDefinedData(true);
                    while (it.hasNext()) {
                        Data d = it.next();
                        if (!d.hasStringValue()) continue;
                        String v = String.valueOf(d.getValue());
                        if (eq ? !v.equals(t) : !v.contains(t)) continue;
                        w.print(d.getAddress() + " \"" + v.replace("\n", "\\n") + "\" <-");
                        for (Reference r : getReferencesTo(d.getAddress())) w.print(" " + r.getFromAddress() + "(" + fn(r.getFromAddress()) + ")");
                        w.println();
                    }
                } else if (a.startsWith("imp:")) {
                    String t = a.substring(4);
                    for (Symbol s : currentProgram.getSymbolTable().getSymbols(t)) {
                        w.println("sym " + s.getAddress() + " " + s.getName(true));
                        for (Reference r : getReferencesTo(s.getAddress())) w.println("  " + r.getFromAddress() + " " + r.getReferenceType() + " " + fn(r.getFromAddress()));
                    }
                    // also look for pointer thunks
                    SymbolIterator si = currentProgram.getSymbolTable().getExternalSymbols();
                    while (si.hasNext()) {
                        Symbol s = si.next();
                        if (!s.getName().contains(t)) continue;
                        w.println("ext " + s.getName(true) + " @" + s.getAddress());
                        for (Reference r : getReferencesTo(s.getAddress())) {
                            w.println("  ref " + r.getFromAddress() + " " + fn(r.getFromAddress()));
                            for (Reference r2 : getReferencesTo(r.getFromAddress())) w.println("    " + r2.getFromAddress() + " " + fn(r2.getFromAddress()));
                        }
                    }
                } else if (a.startsWith("scalar:")) {
                    String spec = a.substring(7);
                    long lo = 0, hi = Long.MAX_VALUE;
                    if (spec.contains("@")) {
                        String[] p = spec.split("@");
                        spec = p[0];
                        String[] r = p[1].split("-");
                        lo = Long.decode(r[0]); hi = Long.decode(r[1]);
                    }
                    boolean allowDisp = spec.startsWith("d");
                    if (allowDisp) spec = spec.substring(1);
                    long v = Long.decode(spec);
                    InstructionIterator it = listing.getInstructions(true);
                    int n = 0;
                    while (it.hasNext() && n < 400) {
                        Instruction ins = it.next();
                        long off = ins.getAddress().getOffset();
                        if (off < lo || off > hi) continue;
                        boolean hit = false;
                        for (int op = 0; op < ins.getNumOperands() && !hit; op++) {
                            int ot = ins.getOperandType(op);
                        boolean imm = (ot & ghidra.program.model.lang.OperandType.DYNAMIC) == 0 && (ot & ghidra.program.model.lang.OperandType.ADDRESS) == 0;
                        if (!imm && !allowDisp) continue;
                        for (Object o : ins.getOpObjects(op)) {
                                if (o instanceof Scalar) {
                                    Scalar s = (Scalar) o;
                                    if (s.getUnsignedValue() == (v & 0xffffffffL) || s.getSignedValue() == v) hit = true;
                                }
                            }
                        }
                        if (hit) { w.println(ins.getAddress() + " " + ins + "  in " + fn(ins.getAddress())); n++; }
                    }
                } else if (a.startsWith("bytes:")) {
                    String hex = a.substring(6);
                    int len = hex.length() / 2;
                    byte[] pat = new byte[len], mask = new byte[len];
                    for (int k = 0; k < len; k++) {
                        String b = hex.substring(2 * k, 2 * k + 2);
                        if (b.equals("..")) { pat[k] = 0; mask[k] = 0; } else { pat[k] = (byte) Integer.parseInt(b, 16); mask[k] = (byte) 0xff; }
                    }
                    Memory mem = currentProgram.getMemory();
                    Address start = mem.getMinAddress();
                    int n = 0;
                    while (n < 200) {
                        Address f = mem.findBytes(start, pat, mask, true, monitor);
                        if (f == null) break;
                        w.println(f + " in " + fn(f));
                        start = f.add(1); n++;
                    }
                } else if (a.startsWith("fn:")) {
                    Address t = toAddr(a.substring(3));
                    Function f = fm.getFunctionContaining(t);
                    if (f == null) { w.println("none"); continue; }
                    w.println(f.getEntryPoint() + " " + f.getName(true) + " size " + f.getBody().getNumAddresses());
                    for (Reference r : getReferencesTo(f.getEntryPoint())) w.println("  caller " + r.getFromAddress() + " " + r.getReferenceType() + " " + fn(r.getFromAddress()));
                    for (Function c : f.getCalledFunctions(monitor)) w.println("  callee " + c.getEntryPoint() + " " + c.getName(true));
                } else if (a.startsWith("list:")) {
                    String[] r = a.substring(5).split("-");
                    Address lo = toAddr(r[0]), hi = toAddr(r[1]);
                    for (Function f : fm.getFunctions(new AddressSet(lo, hi), true)) {
                        StringBuilder sb = new StringBuilder();
                        int nref = 0;
                        for (Reference x : getReferencesTo(f.getEntryPoint())) { nref++; if (nref <= 4) sb.append(" <").append(fn(x.getFromAddress())).append(">"); }
                        StringBuilder strs = new StringBuilder();
                        for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                            for (Reference x : ins.getReferencesFrom()) {
                                Data d = listing.getDataAt(x.getToAddress());
                                if (d != null && d.hasStringValue()) strs.append(" \"").append(String.valueOf(d.getValue())).append("\"");
                            }
                        }
                        w.println(f.getEntryPoint() + " size " + f.getBody().getNumAddresses() + " refs " + nref + sb + (strs.length() > 0 ? " STR" + (strs.length() > 300 ? strs.substring(0, 300) : strs) : ""));
                    }
                } else if (a.startsWith("rd:")) {
                    String[] p = a.split(":");
                    Address t = toAddr(p[1]);
                    int n = Integer.parseInt(p[2]);
                    for (int k = 0; k < n; k++) {
                        Address e = t.add(4L * k);
                        int v = getInt(e);
                        Address va = toAddr(v & 0xffffffffL);
                        String extra = "";
                        Function f = fm.getFunctionAt(va);
                        if (f != null) extra = f.getName(true);
                        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(e);
                        w.printf("%s %08X %s %s float=%g%n", e, v, s == null ? "" : s.getName(true), extra, Float.intBitsToFloat(v));
                    }
                }
            }
        }
    }
}
