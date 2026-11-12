# Admit SBPF as a provider-neutral ELF family in the Ghidra lane

- Status: accepted
- Date: 2026-11-12

## Context

Solana programs deploy as ELF images for SBPF, a Solana-specific eBPF variant.
Two machine ids appear in practice: `EM_BPF` (247) from earlier toolchains and
`EM_SBF` (263) from current ones. The instruction-set version is the header's
`e_flags`, and the encodings differ enough between versions that a wrong
language does not fail loudly: decoding stops at the first unknown encoding.

Three facts shaped the decision:

- Ghidra ships an eBPF processor but no SBPF processor and no Solana system
  call table, so the languages arrive with a third-party processor module.
- A program links its system calls through `.rel.dyn` entries of type
  `R_BPF_64_32` whose `imm` field is left at `-1`. Ghidra's ELF loader applies
  neither those entries nor a Ghidra-side equivalent, so an unprepared import
  decodes every system call as a self-call.
- REA's admission layer refused the family outright, so no provider lane could
  be reached even with the module installed.

## Decision

Admit `sbpf` as a provider-neutral architecture family, detected from
`e_machine` 247 and 263, carrying the declared `e_flags` version as target
metadata.

The Ghidra lane pins its language from that version rather than letting the
loader choose: V0 and V1 use `sBPF:v1`, V2 uses `sBPF:v2`, V3 uses `sBPF:v3`.
V4 and any value the sbpf loader reserves are refused, because no verified
language exists for them.

Call relocations are resolved by a loader-preparation script
(`ReaGhidraPrepareSbfp.java`) that runs before default auto-analysis. It reads
`.rel.dyn` from the imported program, resolves undefined symbols against the
`syscall` address space the language declares, and fails the import when a
system call is not declared. `R_BPF_64_RELATIVE` entries are left untouched:
their addends already hold section-relative virtual addresses.

An installation without the required languages is refused during profile
resolution with `REA_GHIDRA_SBPF_MODULE` as the offending setting.

## Consequences

Good:

- `inspect`, `decompile`, `decompile-all` and the MCP tools work on a deployed
  program with no manual Ghidra session: names such as `sol_log_`,
  `sol_invoke_signed_c` and `abort` appear in pseudocode.
- A version/language mismatch is caught at admission instead of producing a
  plausible-looking but truncated listing.
- An unknown system call fails preparation loudly rather than leaving an
  unnamed call in the call graph.
- Provider ownership stays explicit: Hopper, IDA and Kuna decline the family
  and route the caller to Ghidra.

Bad:

- The lane depends on a Ghidra processor module REA does not ship, and the
  module's language ids (`sBPF:v1`…) are not Ghidra's usual
  `processor:endian:size:variant` spelling, so they must be selected by id.
- SBPF V4 and newer system calls need the module to grow first; REA cannot
  fall back to another version without mis-decoding.
- Existing-project mode and checkpoint mode stay unavailable for this family,
  because both are limited to stock imports without a pinned language or loader
  preparation.
- Decompiled output is C-like pseudocode, which does not recover Rust source
  constructs.
