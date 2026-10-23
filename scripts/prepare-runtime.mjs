import { copyFile, mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);
const packageJson = require.resolve("v86/package.json");
const root = path.dirname(packageJson);
const destination = path.resolve("public/v86");
await mkdir(destination, { recursive: true });
for (const name of ["v86.wasm", "v86-fallback.wasm"]) {
  await copyFile(path.join(root, "build", name), path.join(destination, name));
}
await copyFile(path.join(root, "LICENSE"), path.join(destination, "V86-LICENSE"));
console.log("Prepared pinned v86 WebAssembly runtime in public/v86");
