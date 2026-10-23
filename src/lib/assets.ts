import type { AssetDescription, AssetManifest } from "../types";
import { cacheAsset, getCachedAsset, getStoredManifest, storeManifest } from "./storage";

export interface AssetLoadCallbacks {
  onProgress: (label: string, loaded: number, total: number) => void;
  onNotice: (message: string) => void;
}

export function assertLocalAssetPath(assetPath: string, origin = globalThis.location?.origin): URL {
  if (!assetPath.startsWith("/") || assetPath.startsWith("//") || assetPath.includes("\\") || assetPath.split("/").includes("..")) {
    throw new Error(`Unsafe asset path rejected: ${assetPath}`);
  }
  if (!assetPath.startsWith("/lab-assets/") && !assetPath.startsWith("/v86/")) {
    throw new Error(`Asset path is outside the pinned runtime directories: ${assetPath}`);
  }
  const url = new URL(assetPath, origin ?? "http://localhost");
  if (origin && url.origin !== origin) throw new Error(`Cross-origin asset loading is disabled: ${assetPath}`);
  if (url.username || url.password || url.search || url.hash) throw new Error(`Unexpected credential/query component in asset path: ${assetPath}`);
  return url;
}

async function digest(buffer: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function fetchWithProgress(url: URL, expectedBytes: number, label: string, callbacks: AssetLoadCallbacks): Promise<ArrayBuffer> {
  const response = await fetch(url.href, { cache: "no-store", credentials: "same-origin", redirect: "error" });
  if (!response.ok) throw new Error(`${label}: HTTP ${response.status} ${response.statusText}`);
  const total = Number(response.headers.get("Content-Length")) || expectedBytes;
  if (!response.body) {
    const buffer = await response.arrayBuffer();
    callbacks.onProgress(label, buffer.byteLength, total);
    return buffer;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let loaded = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      loaded += value.byteLength;
      if (loaded > expectedBytes) throw new Error(`${label}: server sent more than the pinned ${expectedBytes} bytes`);
      callbacks.onProgress(label, loaded, total);
    }
  }
  const result = new Uint8Array(loaded);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result.buffer;
}

export async function loadVerifiedAsset(label: string, asset: AssetDescription, callbacks: AssetLoadCallbacks): Promise<ArrayBuffer> {
  if (!asset.available || !asset.sha256 || asset.bytes === undefined) {
    throw new Error(`${label} is not provisioned at ${asset.path}. Build the guest images with image-build/build-all.sh or download the verified image-build artifact, then place them in public/lab-assets/.`);
  }
  const cached = await getCachedAsset(asset.sha256).catch(() => undefined);
  if (cached) {
    if (cached.byteLength !== asset.bytes || await digest(cached.slice(0)) !== asset.sha256) {
      throw new Error(`${label}: cached asset failed integrity verification. Clear site data and reload the pinned image.`);
    }
    callbacks.onProgress(`${label} · verified browser cache`, cached.byteLength, cached.byteLength);
    return cached;
  }
  const url = assertLocalAssetPath(asset.path);
  let buffer: ArrayBuffer;
  try {
    buffer = await fetchWithProgress(url, asset.bytes, label, callbacks);
  } catch (error) {
    throw new Error(`${label} could not be loaded from ${url.pathname}: ${error instanceof Error ? error.message : String(error)}. No remote fallback is permitted.`);
  }
  if (buffer.byteLength !== asset.bytes) {
    throw new Error(`${label} has ${buffer.byteLength} bytes; manifest requires ${asset.bytes}. The image is missing, truncated, or incompatible.`);
  }
  const actual = await digest(buffer.slice(0));
  if (actual !== asset.sha256) {
    throw new Error(`${label} SHA-256 mismatch. Expected ${asset.sha256}, received ${actual}. Boot was refused.`);
  }
  try {
    await cacheAsset(asset.sha256, buffer);
  } catch (error) {
    callbacks.onNotice(error instanceof Error ? error.message : String(error));
  }
  return buffer;
}

export async function loadManifest(): Promise<AssetManifest> {
  try {
    const url = assertLocalAssetPath("/lab-assets/manifest.json");
    const response = await fetch(url.href, { cache: "no-store", credentials: "same-origin", redirect: "error" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const manifest = await response.json() as AssetManifest;
    if (manifest.schemaVersion !== 1 || !manifest.attacker || !Array.isArray(manifest.targets) || manifest.v86.version !== "0.5.472") {
      throw new Error("unsupported or mismatched asset manifest schema");
    }
    await storeManifest(manifest).catch(() => undefined);
    return manifest;
  } catch (error) {
    const cached = await getStoredManifest().catch(() => undefined);
    if (cached) return cached;
    throw new Error(`Cannot load the pinned asset manifest (${error instanceof Error ? error.message : String(error)}). The lab cannot start offline before its first complete cache.`);
  }
}
