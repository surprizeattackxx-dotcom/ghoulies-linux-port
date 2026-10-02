// Quick sanity report after RemapGhoulies.java has run: function count, entry point
// decompile, and the largest discovered functions (likely top-level game systems).
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class ReportGhoulies extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionIterator fit = listing.getFunctions(true);
        List<Function> funcs = new ArrayList<>();
        while (fit.hasNext()) funcs.add(fit.next());
        println("total functions: " + funcs.size());

        Function entry = getFunctionAt(toAddr(0x14FAE9L));
        if (entry == null) {
            println("no function at entry 0x14FAE9");
        } else {
            println("== decompiling entry() ==");
            DecompInterface ifc = new DecompInterface();
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(entry, 30, new ConsoleTaskMonitor());
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("decompile failed: " + (res != null ? res.getErrorMessage() : "null result"));
            }
        }

        Collections.sort(funcs, new Comparator<Function>() {
            public int compare(Function a, Function b) {
                return Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses());
            }
        });
        println("== 15 largest functions ==");
        for (int i = 0; i < Math.min(15, funcs.size()); i++) {
            Function f = funcs.get(i);
            println(String.format("  %-12s size=0x%-8x params=%d name=%s",
                    f.getEntryPoint(), f.getBody().getNumAddresses(),
                    f.getParameterCount(), f.getName()));
        }
    }
}
