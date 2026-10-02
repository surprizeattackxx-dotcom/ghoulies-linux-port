//Recon pass over an extracted original-Xbox XEX (Grabbed by the Ghoulies, default.xbe).
//Loaded as raw binary at base 0x00010000; file offset == RVA - 0x10000.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.data.StringDataInstance;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class XbeRecon extends GhidraScript {

    private static final long TEXT_RVA = 0x162000L;
    private static final long TEXT_SIZE = 0x135D8L;
    private static final long IMPRTAB_RVA = 0x10A70L;
    private static final long IMPRTAB_SIZE = 0x400L;

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        Address base = currentProgram.getImageBase();

        println("== XbeRecon ==");
        println("language    : " + currentProgram.getLanguageID());
        println("compiler    : " + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("image base  : " + base);
        println("min addr    : " + mem.getMinAddress());
        println("max addr    : " + mem.getMaxAddress());

        labelBlock(mem, base, "xbe_header", 0x10000L);

        // XEX section table gave us .text; name the region so analysis/readers have a handle.
        try {
            mem.createUninitializedBlock(".text", base.add(TEXT_RVA - 0x10000L),
                    TEXT_SIZE, false);
            mem.getBlock(base.add(TEXT_RVA - 0x10000L)).setRead(true);
            mem.getBlock(base.add(TEXT_RVA - 0x10000L)).setExecute(true);
            mem.getBlock(base.add(TEXT_RVA - 0x10000L)).setWrite(false);
            println("named .text at 0x" + Long.toHexString(TEXT_RVA)
                    + " size 0x" + Long.toHexString(TEXT_SIZE));
        }
        catch (Exception e) {
            println("could not name .text: " + e.getMessage());
        }

        // --- function inventory -------------------------------------------------
        FunctionIterator fit = listing.getFunctions(true);
        List<Function> funcs = new ArrayList<>();
        while (fit.hasNext()) {
            funcs.add(fit.next());
        }
        long totalBytes = 0;
        for (Function f : funcs) {
            totalBytes += f.getBody().getNumAddresses();
        }
        println("functions   : " + funcs.size());
        println("code bytes  : " + totalBytes + " (0x" + Long.toHexString(totalBytes) + ")");

        final Listing ls = listing;
        Collections.sort(funcs, new Comparator<Function>() {
            public int compare(Function a, Function b) {
                return Long.compare(
                        b.getBody().getNumAddresses(), a.getBody().getNumAddresses());
            }
        });
        println("-- 15 largest functions (likely top-level systems) --");
        for (int i = 0; i < Math.min(15, funcs.size()); i++) {
            Function f = funcs.get(i);
            println(String.format("  %-12s size=0x%-8x  params=%d",
                    f.getEntryPoint(), f.getBody().getNumAddresses(),
                    f.getParameterCount()));
        }

        // --- what does it import / call -----------------------------------------
        ReferenceManager rm = currentProgram.getReferenceManager();
        println("-- external (thunk/imported) call targets --");
        int shown = 0;
        AddressSetView ext = null;
        for (Function f : funcs) {
            for (var r : f.getCalledFunctions(null)) {
                if (r.isExternal() || r.isThunk()) {
                    if (shown < 60) {
                        println("  " + r.getName() + "  <- " + r.getEntryPoint());
                        shown++;
                    }
                }
            }
        }
        println("  (external call targets shown: " + shown + ")");

        // --- strings ------------------------------------------------------------
        println("-- notable strings (game/subsystem names) --");
        int n = 0;
        var it = listing.getDefinedData(true);
        while (it.hasNext() && n < 80) {
            var d = it.next();
            if (d.getDataType().getName().toLowerCase().indexOf("string") < 0) {
                continue;
            }
            String s = d.getDefaultValueRepresentation();
            if (s == null || s.length() < 6) {
                continue;
            }
            println("  0x" + d.getAddress().getOffset() + "  " + s);
            n++;
        }
        println("  (strings shown: " + n + ")");
    }

    private void labelBlock(Memory mem, Address base, String name, long size) {
        try {
            MemoryBlock b = mem.getBlock(base);
            if (b != null) {
                b.setName(name);
            }
        }
        catch (Exception e) {
            println("labelBlock " + name + ": " + e.getMessage());
        }
    }
}
