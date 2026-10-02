// Disassemble a range around a given address and report containing function.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;

public class DisasmAt extends GhidraScript {
    static final long AROUND = 0x000342f0L;
    static final long LEN = 0x90L;

    @Override
    public void run() throws Exception {
        Function f = getFunctionContaining(toAddr(AROUND));
        println("containing function: " + (f != null ? f.getName() + "@" + f.getEntryPoint() : "none"));
        Address start = toAddr(AROUND);
        Address end = toAddr(AROUND + LEN);
        Memory mem = currentProgram.getMemory();
        InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) > 0) break;
            int len = ins.getLength();
            byte[] bytes = new byte[len];
            mem.getBytes(ins.getAddress(), bytes);
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) hex.append(String.format("%02x ", b));
            println(ins.getAddress() + "  " + hex + " " + ins.toString());
        }
    }
}
