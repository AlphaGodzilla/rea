#!/usr/bin/env node
// Installs the pinned sBPF processor module into the Ghidra installation named by
// GHIDRA_INSTALL_DIR, then compiles its SLEIGH languages.
//
//   node scripts/install-sbpf-module.mjs --check   # report only, never mutates
//   node scripts/install-sbpf-module.mjs --dry-run # fetch and verify, do not install
//   node scripts/install-sbpf-module.mjs [--force] [--json]
//
// The module is third-party code. REA does not ship it, and this script refuses to
// replace an existing module without --force. The archive is pinned by commit and
// by the SHA-256 of the commit archive.

import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  cp,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

const MODULE_COMMIT = "907bd4476432ca83bb2352686ad1ccafdb38504c";
const MODULE_ARCHIVE_SHA256 =
  "3345cfa57798e9efe708de7f868229d39739af295af125e85355fcb444799e4f";
const MODULE_ARCHIVE_URL = `https://codeload.github.com/NWMonster/Ghidra_sBPF/zip/${MODULE_COMMIT}`;
const MODULE_DIRECTORY = "sBPF";
const REQUIRED_LANGUAGES = ["sBPF:v1", "sBPF:v2", "sBPF:v3"];
const INSTALL_TIMEOUT_MS = 900_000;

const options = {
  check: process.argv.includes("--check"),
  dryRun: process.argv.includes("--dry-run"),
  force: process.argv.includes("--force"),
  json: process.argv.includes("--json"),
};

const fail = (message, details = {}) => {
  const error = { status: "error", message, ...details };
  process.stdout.write(`${options.json ? JSON.stringify(error) : message}\n`);
  process.exit(1);
};

const installationDirectory = async () => {
  const configured = process.env.GHIDRA_INSTALL_DIR;
  if (configured === undefined || configured === "")
    fail(
      "Set GHIDRA_INSTALL_DIR to the absolute path of a Ghidra installation.",
      { setting: "GHIDRA_INSTALL_DIR" },
    );
  if (!isAbsolute(configured))
    fail("GHIDRA_INSTALL_DIR must be absolute.", {
      setting: "GHIDRA_INSTALL_DIR",
    });
  const properties = await readFile(
    join(configured, "Ghidra", "application.properties"),
    "utf8",
  ).catch(() => undefined);
  if (properties === undefined)
    fail(
      `${configured} is not a Ghidra installation: Ghidra/application.properties is missing.`,
      { install_dir: configured },
    );
  const version = /^application\.version=(.+)$/mu.exec(properties)?.[1]?.trim();
  return { installDirectory: configured, version: version ?? null };
};

/** Language ids the module's .ldefs file declares; empty when it is not installed. */
const declaredLanguages = async (languagesDirectory) => {
  const text = await readFile(
    join(languagesDirectory, "sBPF.ldefs"),
    "utf8",
  ).catch(() => undefined);
  if (text === undefined) return [];
  // Only <language id="…"> elements declare a language; compiler ids repeat "default".
  return [...text.matchAll(/<language\b[\s\S]*?\bid="([^"]+)"/gu)].map(
    (match) => match[1],
  );
};

const compiledLanguages = async (languagesDirectory) => {
  const entries = await readdir(languagesDirectory).catch(() => []);
  return entries.filter((entry) => entry.endsWith(".sla")).sort();
};

const digestOf = (bytes) => createHash("sha256").update(bytes).digest("hex");

const downloadArchive = async () => {
  const response = await fetch(MODULE_ARCHIVE_URL, { redirect: "follow" });
  if (!response.ok)
    fail(`Downloading the pinned module failed with HTTP ${response.status}.`, {
      url: MODULE_ARCHIVE_URL,
    });
  const bytes = Buffer.from(await response.arrayBuffer());
  const digest = digestOf(bytes);
  if (digest !== MODULE_ARCHIVE_SHA256)
    fail("The downloaded archive does not match the pinned SHA-256.", {
      expected: MODULE_ARCHIVE_SHA256,
      observed: digest,
    });
  return bytes;
};

const main = async () => {
  const installation = await installationDirectory();
  const processors = join(
    installation.installDirectory,
    "Ghidra",
    "Processors",
  );
  const moduleDirectory = join(processors, MODULE_DIRECTORY);
  const languagesDirectory = join(moduleDirectory, "data", "languages");
  const present = await stat(moduleDirectory).then(
    () => true,
    () => false,
  );
  const declared = present ? await declaredLanguages(languagesDirectory) : [];
  const compiled = present ? await compiledLanguages(languagesDirectory) : [];
  const missing = REQUIRED_LANGUAGES.filter((id) => !declared.includes(id));
  const status = !present
    ? "missing"
    : missing.length === 0 && compiled.length >= REQUIRED_LANGUAGES.length
      ? "installed"
      : "incomplete";
  const report = {
    status,
    install_dir: installation.installDirectory,
    ghidra_version: installation.version,
    module_directory: moduleDirectory,
    declared_languages: declared,
    compiled_languages: compiled,
    pinned_commit: MODULE_COMMIT,
    pinned_archive_sha256: MODULE_ARCHIVE_SHA256,
  };
  if (options.check) {
    process.stdout.write(
      `${options.json ? JSON.stringify(report) : JSON.stringify(report, null, 2)}\n`,
    );
    return;
  }
  if (status === "installed" && !options.force && !options.dryRun)
    fail(
      `The sBPF module is already installed in ${moduleDirectory}; pass --force to replace it.`,
      report,
    );

  const archive = await downloadArchive();
  const staging = await mkdtemp(join(tmpdir(), "rea-sbpf-module-"));
  try {
    const archivePath = join(staging, "module.zip");
    await writeFile(archivePath, archive);
    await run("unzip", ["-q", archivePath, "-d", staging], {
      timeout: INSTALL_TIMEOUT_MS,
    });
    const unpacked = join(
      staging,
      `Ghidra_sBPF-${MODULE_COMMIT}`,
      MODULE_DIRECTORY,
    );
    const unpackedLanguages = await declaredLanguages(
      join(unpacked, "data", "languages"),
    );
    const absent = REQUIRED_LANGUAGES.filter(
      (id) => !unpackedLanguages.includes(id),
    );
    if (absent.length > 0)
      fail("The pinned archive does not declare every required language.", {
        missing: absent,
      });
    if (options.dryRun) {
      process.stdout.write(
        `${options.json ? JSON.stringify({ ...report, dry_run: true, archive_verified: true }) : "archive verified; nothing installed (--dry-run)"}\n`,
      );
      return;
    }
    if (present) await rm(moduleDirectory, { recursive: true, force: true });
    await mkdir(processors, { recursive: true });
    await cp(unpacked, moduleDirectory, { recursive: true });
    // Ghidra loads .sla files; the module ships only SLEIGH sources.
    await run(
      join(installation.installDirectory, "support", "sleigh"),
      ["-a", languagesDirectory],
      { timeout: INSTALL_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 },
    );
    const afterDeclared = await declaredLanguages(languagesDirectory);
    const afterCompiled = await compiledLanguages(languagesDirectory);
    const afterMissing = REQUIRED_LANGUAGES.filter(
      (id) => !afterDeclared.includes(id),
    );
    if (
      afterMissing.length > 0 ||
      afterCompiled.length < REQUIRED_LANGUAGES.length
    )
      fail("The module was copied but its languages are not compiled.", {
        module_directory: moduleDirectory,
        declared_languages: afterDeclared,
        compiled_languages: afterCompiled,
      });
    process.stdout.write(
      `${options.json ? JSON.stringify({ ...report, status: "installed", installed: true, declared_languages: afterDeclared, compiled_languages: afterCompiled }) : `installed ${MODULE_DIRECTORY} into ${processors} and compiled ${afterCompiled.join(", ")}`}\n`,
    );
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
};

await main();
