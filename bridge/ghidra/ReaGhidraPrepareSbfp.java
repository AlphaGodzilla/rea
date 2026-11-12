import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Resolve SBPF call relocations before default auto-analysis.
 *
 * <p>A Solana program links its system calls through {@code .rel.dyn} entries of
 * type {@code R_BPF_64_32} whose symbol is undefined. The toolchain leaves the
 * {@code imm} field of each call site at {@code -1}, so Ghidra would decode every
 * syscall as a call to itself and build a wrong call graph. This script rewrites
 * each such site as {@code call <syscall address>}, where the address is the hash
 * the loaded language declares in its {@code syscall} address space.
 *
 * <p>{@code R_BPF_64_RELATIVE} entries need no work: their addends already hold
 * section-relative virtual addresses, which is exactly what a Ghidra import at
 * the ELF virtual addresses uses.
 */
public final class ReaGhidraPrepareSbfp extends GhidraScript {
    private static final long R_BPF_64_32 = 10;
    private static final int CALL_OPCODE = 0x85;
    private static final int RELATIVE_CALL_NIBBLES = 0x10;
    private static final int SYSCALL_CALL_NIBBLES = 0x00;
    private static final long UNRELOCATED_IMMEDIATE = 0xFFFFFFFFL;
    private static final int SYMBOL_ENTRY_BYTES = 24;
    private static final int RELOCATION_ENTRY_BYTES = 16;
    private static final String PREPARED_FLAG = "REA sbpf prepared";
    private static final String SYSCALL_SPACE = "syscall";

    @Override
    public void run() throws Exception {
        String languageId = currentProgram.getLanguageID().getIdAsString();
        if (!languageId.startsWith("sBPF:")) {
            throw new IllegalArgumentException(
                "SBPF preparation requires an sBPF language: " + languageId
            );
        }
        Memory memory = currentProgram.getMemory();
        MemoryBlock dynsym = memory.getBlock(".dynsym");
        MemoryBlock dynstr = memory.getBlock(".dynstr");
        MemoryBlock relDyn = memory.getBlock(".rel.dyn");
        if (dynsym == null || dynstr == null || relDyn == null) {
            // Statically linked images carry no dynamic calls to resolve.
            println("REA sbpf: no dynamic relocation blocks");
            return;
        }

        Map<String, Long> syscallByName = syscallAddresses();
        byte[] strtab = readBlock(dynstr);
        byte[] symbols = readBlock(dynsym);
        byte[] relocations = readBlock(relDyn);
        Disassembler disassembler = Disassembler.getDisassembler(currentProgram, monitor, null);

        int syscalls = 0;
        int internal = 0;
        for (int offset = 0; offset + RELOCATION_ENTRY_BYTES <= relocations.length;
             offset += RELOCATION_ENTRY_BYTES) {
            long target = readU64(relocations, offset);
            long info = readU64(relocations, offset + 8);
            long type = info & 0xFFFFFFFFL;
            if (type != R_BPF_64_32) {
                continue;
            }
            int symbolIndex = (int) (info >>> 32);
            int symbolOffset = symbolIndex * SYMBOL_ENTRY_BYTES;
            if (symbolOffset + SYMBOL_ENTRY_BYTES > symbols.length) {
                throw new IllegalArgumentException(
                    "SBPF relocation at 0x" + Long.toHexString(target) +
                    " names symbol " + symbolIndex + ", which .dynsym does not hold"
                );
            }
            String name = cString(strtab, (int) readU32(symbols, symbolOffset));
            int sectionIndex = readU16(symbols, symbolOffset + 6);
            long symbolValue = readU64(symbols, symbolOffset + 8);
            Address site = toAddress(target);
            if (!memory.contains(site)) {
                throw new IllegalArgumentException(
                    "SBPF relocation at 0x" + Long.toHexString(target) + " is outside the program"
                );
            }
            if (memory.getByte(site) != (byte) CALL_OPCODE) {
                throw new IllegalArgumentException(
                    "SBPF R_BPF_64_32 relocation at 0x" + Long.toHexString(target) +
                    " does not name a call instruction"
                );
            }
            if (Integer.toUnsignedLong(memory.getInt(site.add(4))) != UNRELOCATED_IMMEDIATE) {
                // Already resolved, either by the producer or a previous run.
                continue;
            }
            byte[] instruction = new byte[8];
            instruction[0] = (byte) CALL_OPCODE;
            long immediate;
            if (sectionIndex == 0) {
                Long hash = syscallByName.get(name);
                if (hash == null) {
                    throw new IllegalArgumentException(
                        "System call " + name + " at 0x" + Long.toHexString(target) +
                        " is not declared by language " + languageId +
                        "; add it to the processor module's processor specification"
                    );
                }
                instruction[1] = (byte) SYSCALL_CALL_NIBBLES;
                immediate = hash;
                syscalls++;
            } else {
                // Internal calls keep the relative encoding the producer emits:
                // target = site + (imm + 1) * instruction size.
                long delta = symbolValue - target;
                if (delta % 8 != 0) {
                    throw new IllegalArgumentException(
                        "Internal call relocation at 0x" + Long.toHexString(target) +
                        " is not aligned to the instruction size"
                    );
                }
                instruction[1] = (byte) RELATIVE_CALL_NIBBLES;
                immediate = delta / 8 - 1;
                internal++;
            }
            writeImmediate32(instruction, immediate);
            // A memory write that overlaps decoded code is refused, so clear the
            // eight site bytes before writing the resolved instruction.
            currentProgram.getListing().clearCodeUnits(site, site.add(7), false);
            memory.setBytes(site, instruction);
            disassembler.disassemble(site, null);
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean(PREPARED_FLAG, true);
        currentProgram.getOptions(Program.PROGRAM_INFO).setInt("REA sbpf syscalls", syscalls);
        currentProgram.getOptions(Program.PROGRAM_INFO).setInt("REA sbpf internal calls", internal);
        println("REA sbpf: resolved " + syscalls + " system calls and " + internal +
            " internal calls");
    }

    private Map<String, Long> syscallAddresses() {
        Map<String, Long> byName = new HashMap<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getAddress().getAddressSpace().getName().equals(SYSCALL_SPACE)) {
                byName.put(symbol.getName(), symbol.getAddress().getOffset());
            }
        }
        return byName;
    }

    private Address toAddress(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private byte[] readBlock(MemoryBlock block) throws Exception {
        byte[] bytes = new byte[(int) block.getSize()];
        currentProgram.getMemory().getBytes(block.getStart(), bytes);
        return bytes;
    }

    private static void writeImmediate32(byte[] instruction, long immediate) {
        instruction[4] = (byte) (immediate & 0xFF);
        instruction[5] = (byte) ((immediate >>> 8) & 0xFF);
        instruction[6] = (byte) ((immediate >>> 16) & 0xFF);
        instruction[7] = (byte) ((immediate >>> 24) & 0xFF);
    }

    private static long readU64(byte[] bytes, int offset) {
        long value = 0;
        for (int index = 7; index >= 0; index--) {
            value = (value << 8) | (bytes[offset + index] & 0xFFL);
        }
        return value;
    }

    private static long readU32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL) | ((bytes[offset + 1] & 0xFFL) << 8) |
            ((bytes[offset + 2] & 0xFFL) << 16) | ((bytes[offset + 3] & 0xFFL) << 24);
    }

    private static int readU16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8);
    }

    private static String cString(byte[] bytes, int offset) {
        int end = offset;
        while (end < bytes.length && bytes[end] != 0) {
            end++;
        }
        return new String(bytes, offset, end - offset, StandardCharsets.UTF_8);
    }
}
