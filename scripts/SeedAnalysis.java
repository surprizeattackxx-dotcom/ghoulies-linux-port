// Seeds analysis for a raw, entry-point-less original-Xbox XEX.
// The XEX container gives Ghidra no PE entry point, so nothing gets disassembled by
// default. Enable pattern-based function discovery and anchor on the known .text range.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class SeedAnalysis extends GhidraScript {

    private static final long TEXT_START = 0x162000L;
    private static final long TEXT_SIZE = 0x135D8L;

    @Override
    public void run() throws Exception {
        Map<String, String> cur = getCurrentAnalysisOptionsAndValues(currentProgram);
        println("=== analysis options currently: " + cur.size() + " ===");
        for (String k : new TreeMap<>(cur).keySet()) {
            if (k.toLowerCase().contains("aggressive")
                    || k.toLowerCase().contains("decompiler parameter")
                    || k.toLowerCase().contains("function start")
                    || k.toLowerCase().contains("non-returning")
                    || k.toLowerCase().contains("nonreturning")) {
                println("  BEFORE " + k + " = " + cur.get(k));
            }
        }

        Map<String, String> want = new HashMap<>();
        String[] exactOn = {
            "Aggressive Instruction Finder",
            "Decompiler Parameter ID",
            "Function Start Search",
            "Non-Returning Functions - Discovered",
        };
        for (String k : exactOn) {
            if (cur.containsKey(k)) {
                want.put(k, "true");
            }
            else {
                println("  NOTE: option not present: " + k);
            }
        }
        println("=== flipping to true ===");
        for (String k : new TreeMap<>(want).keySet()) {
            println("  " + k + " : " + cur.get(k) + " -> true");
        }
        if (!want.isEmpty()) {
            // clear the bad values a previous run may have written, then apply only
            // the exact keys we want.
            resetAllAnalysisOptions(currentProgram);
            Map<String, String> after = getCurrentAnalysisOptionsAndValues(currentProgram);
            Map<String, String> apply = new HashMap<>();
            for (String k : want.keySet()) {
                apply.put(k, "true");
            }
            setAnalysisOptions(currentProgram, apply);
            println("reset + applied " + apply.size() + " options");
        }

        Address textStart = toAddr(TEXT_START);
        Address textEnd = toAddr(TEXT_START + TEXT_SIZE);
        Memory mem = currentProgram.getMemory();
        MemoryBlock b = mem.getBlock(textStart);
        if (b != null) {
            println("block for .text: " + b.getName()
                    + " r=" + b.isRead() + " x=" + b.isExecute() + " w=" + b.isWrite());
            b.setExecute(true);
            b.setRead(true);
        }
        println("seed range: " + new AddressSet(textStart, textEnd));
        println("SEED_OK");
    }
}
