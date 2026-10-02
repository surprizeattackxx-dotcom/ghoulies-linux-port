// Decompile a single named/addressed function. Usage: pass the hex address via
// the FUNC_ADDR system property, e.g. -scriptArgs 0014bbe5 isn't supported in
// all headless modes cleanly, so this just hardcodes a small worklist instead.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileOne extends GhidraScript {
    static final long[] TARGETS = { 0x000341e0L };

    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        for (long addr : TARGETS) {
            Function f = getFunctionContaining(toAddr(addr));
            println("== " + String.format("%08x", addr) + " (" + (f != null ? f.getName() + " @ " + f.getEntryPoint() : "no function") + ") ==");
            if (f == null) continue;
            DecompileResults res = ifc.decompileFunction(f, 30, new ConsoleTaskMonitor());
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("decompile failed: " + (res != null ? res.getErrorMessage() : "null"));
            }
        }
    }
}
