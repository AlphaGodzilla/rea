import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { GhidraLanguageOverride } from "../../../../src/config/ghidraLanguageOverride.js";
import {
  ghidraHeadlessArguments,
  type GhidraHeadlessArgumentOptions,
} from "../../../../src/ghidra/GhidraLauncher.js";

const base = (
  options: Partial<GhidraHeadlessArgumentOptions> = {},
): GhidraHeadlessArgumentOptions => ({
  projectRoot: "/tmp/project",
  targetPath: "/tmp/program.so",
  bridgeScriptPath: "/package/bridge/ReaGhidraBridge.java",
  descriptorPath: "/tmp/session.json",
  ghidraLogPath: "/tmp/ghidra.log",
  scriptLogPath: "/tmp/script.log",
  ...options,
});

const pinned: GhidraLanguageOverride = {
  languageId: "sBPF:v1",
  compilerSpecId: "default",
};

describe("Ghidra SBPF loader preparation", () => {
  it("resolves SBPF call relocations before any analysis", () => {
    const arguments_ = ghidraHeadlessArguments(
      base({ sbpf: true, languageOverride: pinned }),
    );
    expect(arguments_).toContain("-import");
    expect(arguments_).toContain("-readOnly");
    const processor = arguments_.indexOf("-processor");
    expect(arguments_[processor + 1]).toBe("sBPF:v1");
    const prepare = arguments_.indexOf("-preScript");
    expect(arguments_[prepare + 1]).toBe(
      join("/package/bridge", "ReaGhidraPrepareSbfp.java"),
    );
    const bridge = arguments_.lastIndexOf("-postScript");
    expect(prepare).toBeLessThan(bridge);
  });

  it("refuses to combine SBPF preparation with another loader lane", () => {
    expect(() =>
      ghidraHeadlessArguments(base({ sbpf: true, dosMz: true })),
    ).toThrow(/sbpf_combined|SBPF/u);
    expect(() =>
      ghidraHeadlessArguments(
        base({
          sbpf: true,
          rawBinary: {
            languageId: "x86:LE:64:default",
            compilerSpecId: "gcc",
            baseAddr: "0x0",
          },
        }),
      ),
    ).toThrow();
  });

  it("refuses SBPF preparation for an existing project", () => {
    expect(() =>
      ghidraHeadlessArguments(
        base({
          sbpf: true,
          existingProject: {
            projectName: "rea",
            programName: "program.so",
          },
        }),
      ),
    ).toThrow();
  });
});
