// Scans the whole .text-equivalent instruction stream for any instruction
// that references a specific displacement (e.g. +0x160) as a memory
// operand, and reports the containing function + address. Used to find
// where a struct field is written when there's no symbol/xref to search by.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class FindOffsetWrites extends GhidraScript {
    static final long TARGET_DISP = 0x160L;
    static final int MAX_HITS = 1000;
    static final long RANGE_START = 0x001b0000L;
    static final long RANGE_END = 0x001f0000L;

    @Override
    public void run() throws Exception {
        int hits = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(toAddr(RANGE_START), true);
        while (it.hasNext() && hits < MAX_HITS) {
            Instruction ins = it.next();
            if (ins.getAddress().getOffset() > RANGE_END) break;
            String mnem = ins.getMnemonicString();
            if (!(mnem.equals("MOV") || mnem.equals("LEA") || mnem.equals("CMP") || mnem.equals("ADD"))) continue;
            int numOps = ins.getNumOperands();
            for (int i = 0; i < numOps; i++) {
                Object[] objs = ins.getOpObjects(i);
                for (Object o : objs) {
                    if (o instanceof Scalar) {
                        long val = ((Scalar) o).getSignedValue();
                        if (val == TARGET_DISP || val == -TARGET_DISP) {
                            Address a = ins.getAddress();
                            Function f = getFunctionContaining(a);
                            println(a + "  [" + (f != null ? f.getName() : "?") + "]  " + ins.toString());
                            hits++;
                            break;
                        }
                    }
                }
            }
        }
        println("total hits: " + hits);
    }
}
