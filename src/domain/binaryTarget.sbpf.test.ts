import { describe, expect, it } from "vitest";
import { parseExecutableHeader } from "./binaryTarget.js";

/** ELF64 little-endian SBPF image with the machine id and `e_flags` under test. */
const header = (
  options: {
    readonly machine?: number;
    readonly flags?: number;
    readonly bits?: 32 | 64;
    readonly little?: boolean;
  } = {},
): Buffer => {
  const bits = options.bits ?? 64;
  const little = options.little ?? true;
  const bytes = Buffer.alloc(bits === 64 ? 64 : 52);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 64 ? 2 : 1, little ? 1 : 2, 1]);
  const write16 = (value: number, offset: number) =>
    little
      ? bytes.writeUInt16LE(value, offset)
      : bytes.writeUInt16BE(value, offset);
  const write32 = (value: number, offset: number) =>
    little
      ? bytes.writeUInt32LE(value, offset)
      : bytes.writeUInt32BE(value, offset);
  write16(3, 16);
  write16(options.machine ?? 263, 18);
  write32(1, 20);
  write32(options.flags ?? 0, bits === 64 ? 48 : 36);
  write16(bytes.length, bits === 64 ? 52 : 40);
  return bytes;
};

const parse = (bytes: Buffer) => {
  const parsed = parseExecutableHeader(bytes, "x64");
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
};

describe("SBPF ELF header admission", () => {
  it.each([247, 263])(
    "recognizes e_machine %i as the SBPF family",
    (machine) => {
      expect(parse(header({ machine, flags: 0 }))).toEqual({
        format: "elf",
        architecture: "sbpf",
        availableArchitectures: ["sbpf"],
        sbpf: {
          elfClass: 64,
          byteOrder: "little",
          type: 3,
          flags: 0,
          version: "v0",
        },
      });
    },
  );

  it.each([
    [0, "v0"],
    [1, "v1"],
    [2, "v2"],
    [3, "v3"],
    [4, "v4"],
    [5, "reserved"],
    [0x20, "reserved"],
  ] as const)("reads e_flags %i as %s", (flags, version) => {
    expect(parse(header({ flags }))).toMatchObject({
      architecture: "sbpf",
      sbpf: { flags, version },
    });
  });

  it("keeps class and byte-order declarations rather than normalizing them", () => {
    expect(parse(header({ bits: 32, little: false, flags: 2 }))).toMatchObject({
      architecture: "sbpf",
      sbpf: { elfClass: 32, byteOrder: "big", flags: 2, version: "v2" },
    });
  });
});
