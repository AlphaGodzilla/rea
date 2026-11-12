# SBPF ELF analysis through Ghidra

This lane extends native ELF analysis to Solana programs compiled to SBPF
(Solana BPF). It disassembles and decompiles a deployed program image; it does
not emulate the Solana VM, resolve Anchor instruction discriminators to source
names, or reconstruct Rust source.

## Admission boundary

ELF `EM_BPF` (247) and `EM_SBF` (263) are retained as the provider-neutral
`sbpf` family. Current SBPF toolchains emit 263; older deployed programs carry 247. The header's `e_flags` is the declared instruction-set version, and it is
part of the admitted facts:

| `e_flags` | Declared version | Ghidra language REA pins            |
| --------- | ---------------- | ----------------------------------- |
| 0         | V0               | `sBPF:v1`                           |
| 1         | V1               | `sBPF:v1`                           |
| 2         | V2               | `sBPF:v2`                           |
| 3         | V3               | `sBPF:v3`                           |
| 4         | V4               | refused: no verified language       |
| other     | reserved         | refused: the version is not guessed |

The module's language variants are cumulative, and it defines no V0-only
language, so V0 and V1 share `sBPF:v1`. Decoding a program with the wrong
variant does not fail loudly — it silently stops at the first encoding it does
not know — which is why the version selects the language instead of the
loader's default.

The lane admits little-endian ELF64 images of type `ET_EXEC` or `ET_DYN`.
Relocatable objects, ELF32 and big-endian images are refused with the
declaration that failed. Hopper, IDA and Kuna decline the family and route the
caller to Ghidra.

## Installation requirement

Ghidra does not ship an SBPF processor. The lane needs a processor module under
`Ghidra/Processors/sBPF` that defines the languages `sBPF:v1`, `sBPF:v2` and
`sBPF:v3` and declares the Solana system calls in its processor specification.
[NWMonster/Ghidra_sBPF](https://github.com/NWMonster/Ghidra_sBPF) is the module
this lane was verified with; it extends Ghidra's bundled eBPF processor with the
SIMD-0173 and SIMD-0174 encodings. The repository's installer copies that module
into the selected installation, verifies the archive against a pinned commit and
SHA-256, and compiles its SLEIGH sources:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra node scripts/install-sbpf-module.mjs --check
GHIDRA_INSTALL_DIR=/path/to/ghidra node scripts/install-sbpf-module.mjs
```

`--check` only reports whether the three languages are declared and compiled.
`--dry-run` fetches and verifies the pinned archive without installing, and
`--force` replaces an installed module. Installing by hand means copying the
module's `sBPF` directory and running:

```sh
support/sleigh -a Ghidra/Processors/sBPF/data/languages
```

An installation without those languages is refused before analysis starts, with
`GHIDRA_INSTALL_DIR` reported as defining no such language under `Ghidra/Processors/sBPF`.

## Call relocation preparation

A Solana program links its system calls through `.rel.dyn` entries of type
`R_BPF_64_32` whose symbols are undefined; the producer leaves each call site's
`imm` field at `-1`. Imported as-is, every system call decodes as a call to
itself, so the call graph is wrong and the pseudocode shows recursive self-calls.

`ReaGhidraPrepareSbfp.java` runs as loader preparation, before default
auto-analysis, and rewrites each such site as `call <syscall address>` using the
hash the language declares in its `syscall` address space. Internal calls keep
the producer's relative encoding.

A system call the module does not declare is resolved anyway: the loader
identifies a system call by the 32-bit murmur3 hash of its symbol name, so the
script computes that hash and labels the target address with the name the ELF
imports. A program that calls a system call newer than the module's table still
gets a named call instead of an unnamed one.

`R_BPF_64_RELATIVE` entries need no work: their addends already hold
section-relative virtual addresses, which is what an import at the ELF virtual
addresses uses.

## Inspect and decompile

```sh
rea inspect ./program.so --provider ghidra --json
rea decompile ./program.so 0x2f08 --provider ghidra --json
rea decompile-all ./program.so --output ./pseudocode --provider ghidra
```

The analysis profile records the declared facts under `sbpf_elf` together with
`sbpf_syscall_relocations` and `sbpf_support_lane`, so a session states which
version and language produced its results.

## Limitations

- Decompiled output is Ghidra's C-like pseudocode. Rust constructs such as
  `Result`, `Option` and iterator pipelines appear as their lowered form.
- Deployed programs are normally stripped. Exported `entrypoint` and
  `custom_panic`, dynamic system-call imports and `.rodata` strings are the
  available anchors; internal function names are not.
- Anchor dispatch is recovered as 8-byte discriminator comparisons. REA does not
  map a discriminator to an instruction name from IDL metadata.
- A system call's name comes from the ELF's `.dynstr` and its target from that
  name's murmur3 hash. Preparation therefore cannot detect a program whose call
  site disagrees with its symbol table; both files are shipped together.
- SBPF V4 images are refused: the module has no verified V4 language, and
  decoding them with V3 would mis-decode their encodings.
- `REA_GHIDRA_PROJECT_PATH` (existing-project mode) and
  `REA_GHIDRA_CHECKPOINT_DIR` do not apply: both are limited to stock imports
  without a pinned language or loader preparation.
