import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { SbpfVersion } from "../domain/sbpfVersion.js";

/**
 * The sBPF processor module REA's lane requires: it supplies the `sBPF:v1`
 * through `sBPF:v3` languages and the syscall symbols the preparation script
 * resolves call sites against. Ghidra does not ship it.
 */
export const GHIDRA_SBPF_MODULE_PATH = "Ghidra/Processors/sBPF";

/**
 * Language the lane imports with, per declared SBPF version. The module's
 * variant files are cumulative (`sBPF:v2` includes v0/v1, `sBPF:v3` adds v2
 * and v3), and it has no v0-only language, so v0 and v1 share `sBPF:v1`.
 */
export const GHIDRA_SBPF_LANGUAGES: Readonly<
  Record<Exclude<SbpfVersion, "v4">, GhidraLanguageOverride>
> = {
  v0: { languageId: "sBPF:v1", compilerSpecId: "default" },
  v1: { languageId: "sBPF:v1", compilerSpecId: "default" },
  v2: { languageId: "sBPF:v2", compilerSpecId: "default" },
  v3: { languageId: "sBPF:v3", compilerSpecId: "default" },
};

/** Every language id the lane may commit; the installation must define one. */
export const GHIDRA_SBPF_LANGUAGE_IDS: readonly string[] = [
  ...new Set(
    Object.values(GHIDRA_SBPF_LANGUAGES).map((lane) => lane.languageId),
  ),
].sort();

/** Remediation text for an installation that cannot import SBPF programs. */
export const GHIDRA_SBPF_MODULE_REMEDIATION = `Install an sBPF processor module that defines the languages ${GHIDRA_SBPF_LANGUAGE_IDS.join(", ")} under ${GHIDRA_SBPF_MODULE_PATH} in the selected Ghidra installation, then reopen the target.`;

/**
 * Keep family recognition separate from the bounded Ghidra lane. The declared
 * SBPF version lives in `e_flags`, so an image whose version the module has no
 * verified language for is refused instead of decoded as a neighbouring
 * version: the encodings differ and a mismatch silently truncates analysis.
 */
export const ghidraSbfpUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "sbpf")
    return null;
  const missingMetadata =
    "SBPF analysis requires ELF header metadata; a family name alone does not select an instruction-set version.";
  if (target.format !== "elf") return missingMetadata;
  const metadata = target.sbpf;
  if (metadata === undefined) return missingMetadata;
  if (metadata.elfClass !== 64)
    return "This Ghidra SBPF lane supports ELF64 only; 32-bit SBPF images are not admitted.";
  if (metadata.byteOrder !== "little")
    return "This Ghidra SBPF lane supports little-endian images only.";
  if (metadata.type !== 2 && metadata.type !== 3)
    return "This Ghidra SBPF lane supports ET_EXEC and ET_DYN images; relocatable objects need separate load verification.";
  if (metadata.version === "reserved")
    return `The ELF declares e_flags ${String(metadata.flags)}, which the sbpf loader reserves; the instruction-set version is unknown and is not guessed.`;
  if (metadata.version === "v4")
    return "This Ghidra SBPF lane has no verified SBPF v4 language; decoding a v4 image with a v3 language would mis-decode its encodings.";
  return null;
};

/** The language the lane imports with for the version the header declares. */
export const ghidraSbfpLanguage = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined => {
  if (target.kind !== "executable" || target.architecture !== "sbpf")
    return undefined;
  const version = target.format === "elf" ? target.sbpf?.version : undefined;
  if (version === undefined || version === "reserved" || version === "v4")
    return undefined;
  return GHIDRA_SBPF_LANGUAGES[version];
};

/** Commit the declared SBPF version as an independent load fact. */
export const ghidraSbfpProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "sbpf" ||
    target.format !== "elf" ||
    target.sbpf === undefined
  )
    return {};
  return {
    sbpf_elf: {
      elf_class: target.sbpf.elfClass,
      byte_order: target.sbpf.byteOrder,
      type: target.sbpf.type,
      flags: target.sbpf.flags,
      version: target.sbpf.version,
    },
    sbpf_syscall_relocations: "rel-dyn-r-bpf-64-32-v1",
    sbpf_support_lane: "elf64-le-generic-v1",
  };
};
