// Derives the true image load base from the code's own absolute data references.
//
// With the payload imported flat (file offset F -> address F + IMAGE_BASE), any absolute
// address baked into the code is loaded verbatim. If IMAGE_BASE were correct, data
// references would cluster inside the loaded range. They do not, so we histogram every
// absolute reference target and look for the cluster: its floor is the true base.
//
// A reference landing at address X means the code believed X was a valid address. Under a
// flat import, address X in our space holds file byte (X - IMAGE_BASE). If the cluster
// starts at address C, then the code's own base is (C + IMAGE_BASE - IMAGE_BASE) = C.
// In practice: base = cluster_floor, and file_offset = addr - base.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.Map;
import java.util.TreeMap;

public class X86BaseProbe extends GhidraScript {

    private static final long IMAGE_BASE = 0x1000L;
    private static final long FILE_SIZE  = 0x458000L;

    @Override
    public void run() throws Exception {
        println("=== X86BaseProbe ===");
        println("functions : " + currentProgram.getFunctionManager().getFunctionCount());

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        long insnCount = 0;
        long inRange = 0;
        long outRange = 0;
        long minAddr = Long.MAX_VALUE;
        long maxAddr = 0;
        TreeMap<Long, Long> buckets = new TreeMap<>();

        while (it.hasNext()) {
            Instruction ins = it.next();
            insnCount++;
            if (!ins.getFlowType().isFlow()) {
                // still may carry data refs
            }
            ReferenceIterator rit = ins.getReferencesFrom();
            while (rit.hasNext()) {
                Reference r = rit.next();
                Address to = r.getToAddress();
                if (to == null || to.isMemoryAddress()) {
                    if (to == null) {
                        continue;
                    }
                }
                long v = to.getOffset();
                if (v >= IMAGE_BASE && v < IMAGE_BASE + FILE_SIZE) {
                    inRange++;
                }
                else {
                    outRange++;
                    if (v < minAddr) {
                        minAddr = v;
                    }
                    if (v > maxAddr) {
                        maxAddr = v;
                    }
                    buckets.merge(v & ~0xFFFFL, 1L, Long::sum);
                }
            }
        }

        println("instructions       : " + insnCount);
        println("refs inside  image : " + inRange);
        println("refs outside image : " + outRange);
        println("outside min / max  : 0x" + Long.toHexString(minAddr)
                + " / 0x" + Long.toHexString(maxAddr));

        println("--- top 32 outside clusters (64KB buckets) ---");
        buckets.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(32)
                .forEach(e -> println("  0x" + Long.toHexString(e.getKey())
                        + " : " + e.getValue()));

        println("X86PROBE_OK");
    }
}