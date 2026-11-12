import { describe, expect, it } from "vitest";
import type {
  BinaryTarget,
  SbpfElfMetadata,
} from "../domain/binaryTargetTypes.js";
import type { SbpfDeclaredVersion } from "../domain/sbpfVersion.js";
import {
  GHIDRA_SBPF_LANGUAGE_IDS,
  ghidraSbfpLanguage,
  ghidraSbfpProfileParameters,
  ghidraSbfpUnsupportedReason,
} from "./GhidraSbfpProfile.js";

const target = (
  change: Partial<SbpfElfMetadata> = {},
  version?: SbpfDeclaredVersion,
): BinaryTarget => ({
  path: "/fixture.so",
  sha256: "b".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "sbpf",
  availableArchitectures: ["sbpf"],
  sbpf: {
    elfClass: 64,
    byteOrder: "little",
    type: 3,
    flags: 0,
    version: version ?? "v0",
    ...change,
  },
});

describe("bounded Ghidra SBPF admission", () => {
  it("admits ELF64 little-endian images the module can decode", () => {
    expect(ghidraSbfpUnsupportedReason(target())).toBeNull();
    expect(ghidraSbfpUnsupportedReason(target({ type: 2 }))).toBeNull();
  });

  it("refuses declarations no verified lane covers", () => {
    expect(ghidraSbfpUnsupportedReason(target({ elfClass: 32 }))).toContain(
      "ELF64 only",
    );
    expect(ghidraSbfpUnsupportedReason(target({ byteOrder: "big" }))).toContain(
      "little-endian",
    );
    expect(ghidraSbfpUnsupportedReason(target({ type: 1 }))).toContain(
      "ET_EXEC and ET_DYN",
    );
    expect(
      ghidraSbfpUnsupportedReason(target({ flags: 9 }, "reserved")),
    ).toContain("reserves");
    expect(ghidraSbfpUnsupportedReason(target({ flags: 4 }, "v4"))).toContain(
      "no verified SBPF v4 language",
    );
  });

  it("leaves other families to their own lane", () => {
    expect(
      ghidraSbfpUnsupportedReason({
        ...target(),
        architecture: "x86_64",
        availableArchitectures: ["x86_64"],
      } as BinaryTarget),
    ).toBeNull();
  });
});

describe("SBPF language selection", () => {
  it.each([
    ["v0", "sBPF:v1"],
    ["v1", "sBPF:v1"],
    ["v2", "sBPF:v2"],
    ["v3", "sBPF:v3"],
  ] as const)("maps %s to %s", (version, languageId) => {
    expect(ghidraSbfpLanguage(target({}, version))).toEqual({
      languageId,
      compilerSpecId: "default",
    });
  });

  it("pins nothing when no language is verified", () => {
    expect(ghidraSbfpLanguage(target({ flags: 4 }, "v4"))).toBeUndefined();
    expect(
      ghidraSbfpLanguage(target({ flags: 9 }, "reserved")),
    ).toBeUndefined();
  });

  it("names every language the installation must define", () => {
    expect(GHIDRA_SBPF_LANGUAGE_IDS).toEqual(["sBPF:v1", "sBPF:v2", "sBPF:v3"]);
  });
});

describe("SBPF profile facts", () => {
  it("commits the declared ELF facts and the relocation policy", () => {
    expect(ghidraSbfpProfileParameters(target({ flags: 3 }, "v3"))).toEqual({
      sbpf_elf: {
        elf_class: 64,
        byte_order: "little",
        type: 3,
        flags: 3,
        version: "v3",
      },
      sbpf_syscall_relocations: "rel-dyn-r-bpf-64-32-v1",
      sbpf_support_lane: "elf64-le-generic-v1",
    });
  });

  it("commits nothing for another family", () => {
    expect(
      ghidraSbfpProfileParameters({
        ...target(),
        architecture: "arm64",
        availableArchitectures: ["arm64"],
      } as BinaryTarget),
    ).toEqual({});
  });
});
