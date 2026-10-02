// Seeds x86 function entry points in a flat-loaded XBE payload.
//
// The payload is imported flat (file offset F -> address F + IMAGE_BASE) as x86:LE:32.
// There is no container-provided entry point we trust, so we scan the code region for
// MSVC-style prologue byte patterns and create functions at each hit. Aggressive
// Instruction Finder + Function Start Search then extend the graph from those anchors.
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;

public class X86Seed extends GhidraScript {

    /** Flat import base: file offset 0 lands here. */
    public static final long IMAGE_BASE = 0x1000L;

    /** Region empirically identified as x86 code (density scan). */
    private static final long CODE_START = 0x1000L;
    private static final long CODE_END   = 0x200000L;

    private static final byte[] PROLOGUES = {
        (byte) 0x55, (byte) 0x8B, (byte) 0xEC,   // push ebp; mov ebp, esp
        (byte) 0x8B, (byte) 0xFF,                  // mov edi, edi (hotpatch)
        (byte) 0x6A, (byte) 0xFF,                  // push -1  (SEH prolog)
        (byte) 0xCC,                               // int3 (padding => block end)
    };

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address base = toAddr(IMAGE_BASE);

        println("=== X86Seed ===");
        println("language : " + currentProgram.getLanguageID());
        println("compiler : " + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("imagebase: 0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
        println("code rgn : 0x" + Long.toHexString(CODE_START) + " - 0x" + Long.toHexString(CODE_END));
        println("memory   : " + mem.getLoadedAndInitializedAddressSet().toString());

        long fileStart = CODE_START;
        long fileEnd   = CODE_END;
        long scanned = 0;
        int created = 0;
        int existed = 0;

        for (long off = fileStart; off < fileEnd - 8; off++) {
            Address a = base.add(off);
            if (mem.getByte(a) == null) {
                continue;
            }
            scanned++;
            if (!looksLikeEntry(off)) {
                continue;
            }
            Function f = getFunctionAt(a);
            if (f != null) {
                existed++;
                continue;
            }
            Address entry = base.add(off);
            if (isInFunction(entry, true)) {
                // already interior to a discovered function; skip
                existed++;
                continue;
            }
            CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
            if (cmd.applyTo(currentProgram, monitor)) {
                created++;
            }
        }

        println("scanned bytes      : " + scanned);
        println("functions created  : " + created);
        println("entries skipped    : " + existed);
        println("total functions now: " + currentProgram.getFunctionManager().getFunctionCount());
        println("X86SEED_OK");
    }

    /** Cheap, alignment-aware prologue sniff on the flat file bytes. */
    private boolean looksLikeEntry(long off) {
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            Byte v = currentProgram.getMemory().getByte(toAddr(IMAGE_BASE + off + i));
            if (v == null) {
                return false;
            }
            b[i] = v;
        }
        boolean msVC = b[0] == (byte) 0x55 && b[1] == (byte) 0x8B && b[2] == (byte) 0xEC;
        boolean hotpatch = b[0] == (byte) 0x8B && b[1] == (byte) 0xFF;
        boolean sehProlog = b[0] == (byte) 0x6A && b[1] == (byte) 0xFF;
        boolean padInt3 = b[0] == (byte) 0xCC;
        if (msVC || hotpatch || sehProlog || padInt3) {
            return true;
        }
        for (byte[] p : PROLOGUES) {
            if (p[0] == b[0] && p.length == 2 && p[1] == b[1]) {
                return true;
            }
        }
        return false;
    }
}