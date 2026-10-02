import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.listing.Function;

public class FindCallers extends GhidraScript {
    static final long[] TARGETS = { 0x00034290L };

    @Override
    public void run() throws Exception {
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (long addr : TARGETS) {
            Address a = toAddr(addr);
            println("== callers of " + a + " ==");
            ReferenceIterator it = rm.getReferencesTo(a);
            int n = 0;
            while (it.hasNext()) {
                Reference ref = it.next();
                Function f = getFunctionContaining(ref.getFromAddress());
                println("  from " + ref.getFromAddress() + " in " +
                        (f != null ? f.getName() + "@" + f.getEntryPoint() : "?"));
                n++;
            }
            println("  (" + n + " refs)");
        }
    }
}
