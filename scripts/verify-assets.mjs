import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

const manifestPath = path.resolve("public/lab-assets/manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const entries = [
  ["v86 WebAssembly", manifest.v86.wasm],
  ["SeaBIOS", manifest.v86.bios],
  ["VGA BIOS", manifest.v86.vgaBios],
  ["attacker ISO", manifest.attacker.image],
  ...manifest.targets.map((target) => [`target ${target.phpVersion}`, target.image]),
];
let failed = false;
for (const [name, asset] of entries) {
  if (!asset.available) {
    if (asset.required) {
      console.error(`MISSING ${name}: ${asset.path}`);
      failed = true;
    } else {
      console.log(`OPTIONAL MISSING ${name}: ${asset.path}`);
    }
    continue;
  }
  const data = await readFile(path.join("public", asset.path.slice(1)));
  const digest = createHash("sha256").update(data).digest("hex");
  if (digest !== asset.sha256 || data.length !== asset.bytes) {
    console.error(`CORRUPT ${name}: expected ${asset.sha256}/${asset.bytes}, got ${digest}/${data.length}`);
    failed = true;
  } else {
    console.log(`OK ${name}: ${asset.bytes} bytes ${digest}`);
  }
}
if (failed) process.exitCode = 1;
