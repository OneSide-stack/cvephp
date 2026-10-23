import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve("public");
async function describe(relative, required = true) {
  const absolute = path.join(root, relative);
  if (!existsSync(absolute)) return { path: "/" + relative, available: false, required };
  const data = await readFile(absolute);
  return {
    path: "/" + relative,
    available: true,
    required,
    bytes: data.length,
    sha256: createHash("sha256").update(data).digest("hex"),
  };
}

const manifest = {
  schemaVersion: 1,
  generatedAt: new Date(Number(process.env.SOURCE_DATE_EPOCH || 0) * 1000).toISOString(),
  v86: {
    package: "v86",
    version: "0.5.472",
    upstream: "https://github.com/copy/v86/",
    license: "BSD-2-Clause",
    wasm: await describe("v86/v86.wasm"),
    fallbackWasm: await describe("v86/v86-fallback.wasm"),
    bios: await describe("v86/seabios.bin"),
    vgaBios: await describe("v86/vgabios.bin"),
  },
  attacker: {
    id: "tinycore-11.0-range",
    operatingSystem: "Tiny Core Linux 11.0 x86 with X11",
    architecture: "x86",
    networkAddress: "192.168.10.10/24",
    memory: { standardMiB: 384, lowMiB: 256 },
    image: await describe("lab-assets/attacker-tinycore-11.0.iso"),
  },
  targets: [],
};
for (const [version, label] of [["8.2.34", "vulnerable"], ["8.2.35", "patched"]]) {
  manifest.targets.push({
    id: `alpine-php-${version}`,
    operatingSystem: "Alpine Linux 3.22.1 x86",
    architecture: "x86",
    phpVersion: version,
    phpSource: `https://github.com/php/php-src/releases/tag/php-${version}`,
    executionMode: "Apache prefork / mod_php",
    buildRole: label,
    networkAddress: "192.168.10.55/24",
    memory: { standardMiB: 512, lowMiB: 384 },
    required: version === "8.2.34",
    image: await describe(`lab-assets/target-php-${version}.iso`, version === "8.2.34"),
  });
}
await writeFile(path.join(root, "lab-assets/manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log("Wrote public/lab-assets/manifest.json");
