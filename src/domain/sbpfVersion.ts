/** SBPF versions an ELF header can declare in `e_flags`. */
export const SBPF_VERSIONS = ["v0", "v1", "v2", "v3", "v4"] as const;
export type SbpfVersion = (typeof SBPF_VERSIONS)[number];

/**
 * A declared SBPF version, or `reserved` when `e_flags` holds a value the sbpf
 * loader does not name. Consumers must refuse `reserved` rather than guess.
 */
export type SbpfDeclaredVersion = SbpfVersion | "reserved";

/**
 * Read the SBPF version from `e_flags`. The sbpf loader treats the whole 32-bit
 * field as the version number (`0` = V0 … `4` = V4) and reserves every other
 * value, so no bit flags are decoded here.
 */
export const sbpfVersionFromElfFlags = (flags: number): SbpfDeclaredVersion => {
  switch (flags) {
    case 0:
      return "v0";
    case 1:
      return "v1";
    case 2:
      return "v2";
    case 3:
      return "v3";
    case 4:
      return "v4";
  }
  return "reserved";
};
