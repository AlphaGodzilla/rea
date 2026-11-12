import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
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
        int namedByHash = 0;
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
                Long declared = syscallByName.get(name);
                if (declared == null) {
                    // The loader names a syscall by the same murmur3 hash of its
                    // symbol name, so an undeclared one is still exact: name the
                    // address it targets so the call graph and pseudocode keep it.
                    long computed = murmur3_32(name);
                    nameSyscall(computed, name);
                    instruction[1] = (byte) SYSCALL_CALL_NIBBLES;
                    immediate = computed;
                    namedByHash++;
                    syscalls++;
                    writeImmediate32(instruction, immediate);
                    currentProgram.getListing().clearCodeUnits(site, site.add(7), false);
                    memory.setBytes(site, instruction);
                    disassembler.disassemble(site, null);
                    continue;
                }
                instruction[1] = (byte) SYSCALL_CALL_NIBBLES;
                immediate = declared;
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
        currentProgram.getOptions(Program.PROGRAM_INFO).setInt(
            "REA sbpf syscalls named by hash", namedByHash);
        println("REA sbpf: resolved " + syscalls + " system calls (" + namedByHash +
            " not declared by the language) and " + internal + " internal calls");
    }

    /**
     * Name a syscall address the loaded language does not declare, so the call
     * renders as the symbol the ELF imports rather than a bare hash.
     */
    private void nameSyscall(long offset, String name) throws InvalidInputException {
        AddressSpace space =
            currentProgram.getAddressFactory().getAddressSpace(SYSCALL_SPACE);
        if (space == null) {
            return;
        }
        Address address = space.getAddress(offset);
        if (currentProgram.getSymbolTable().getPrimarySymbol(address) != null) {
            return;
        }
        currentProgram.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
    }

    /** The 32-bit murmur3 hash the SBPF loader uses to identify a system call. */
    private static long murmur3_32(String name) {
        byte[] data = name.getBytes(StandardCharsets.UTF_8);
        final long c1 = 0xcc9e2d51L;
        final long c2 = 0x1b873593L;
        long hash = 0;
        int blocks = data.length / 4;
        for (int index = 0; index < blocks; index++) {
            int base = index * 4;
            long k = (data[base] & 0xffL) | ((data[base + 1] & 0xffL) << 8) |
                ((data[base + 2] & 0xffL) << 16) | ((data[base + 3] & 0xffL) << 24);
            k = (k * c1) & 0xffffffffL;
            k = ((k << 15) | (k >>> 17)) & 0xffffffffL;
            k = (k * c2) & 0xffffffffL;
            hash ^= k;
            hash = ((hash << 13) | (hash >>> 19)) & 0xffffffffL;
            hash = (hash * 5 + 0xe6546b64L) & 0xffffffffL;
        }
        int tailStart = blocks * 4;
        int remaining = data.length - tailStart;
        long tail = 0;
        if (remaining >= 3) {
            tail ^= (data[tailStart + 2] & 0xffL) << 16;
        }
        if (remaining >= 2) {
            tail ^= (data[tailStart + 1] & 0xffL) << 8;
        }
        if (remaining >= 1) {
            tail ^= data[tailStart] & 0xffL;
            tail = (tail * c1) & 0xffffffffL;
            tail = ((tail << 15) | (tail >>> 17)) & 0xffffffffL;
            tail = (tail * c2) & 0xffffffffL;
            hash ^= tail;
        }
        hash ^= data.length;
        hash ^= hash >>> 16;
        hash = (hash * 0x85ebca6bL) & 0xffffffffL;
        hash ^= hash >>> 13;
        hash = (hash * 0xc2b2ae35L) & 0xffffffffL;
        hash ^= hash >>> 16;
        return hash;
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
