import type { AssetManifest, ResourceMode, SessionInfo, SnapshotMeta } from "../types";

const DB_NAME = "enterprise-cyber-range-v1";
const DB_VERSION = 1;
const STORES = { assets: "assets", snapshots: "snapshots", progress: "progress" } as const;

export interface SnapshotRecord {
  meta: SnapshotMeta;
  session: SessionInfo;
  provisionSecret: string;
  resourceMode: ResourceMode;
  attacker: ArrayBuffer;
  target: ArrayBuffer;
}

interface StoredManifest { key: "manifest"; value: AssetManifest }
interface StoredProgress { key: string; value: unknown; savedAt: string }

let databasePromise: Promise<IDBDatabase> | null = null;

function request<T>(value: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    value.onsuccess = () => resolve(value.result);
    value.onerror = () => reject(value.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(value: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    value.oncomplete = () => resolve();
    value.onabort = () => reject(value.error ?? new Error("Browser storage transaction aborted"));
    value.onerror = () => reject(value.error ?? new Error("Browser storage transaction failed"));
  });
}

function openDatabase(): Promise<IDBDatabase> {
  if (databasePromise) return databasePromise;
  databasePromise = new Promise((resolve, reject) => {
    if (!("indexedDB" in globalThis)) {
      reject(new Error("IndexedDB is unavailable. VM snapshots and offline asset caching cannot be used."));
      return;
    }
    const opening = indexedDB.open(DB_NAME, DB_VERSION);
    opening.onupgradeneeded = () => {
      const database = opening.result;
      if (!database.objectStoreNames.contains(STORES.assets)) database.createObjectStore(STORES.assets);
      if (!database.objectStoreNames.contains(STORES.snapshots)) database.createObjectStore(STORES.snapshots, { keyPath: "meta.id" });
      if (!database.objectStoreNames.contains(STORES.progress)) database.createObjectStore(STORES.progress, { keyPath: "key" });
    };
    opening.onsuccess = () => {
      opening.result.onversionchange = () => opening.result.close();
      resolve(opening.result);
    };
    opening.onerror = () => reject(opening.error ?? new Error("Unable to open browser-local lab storage"));
    opening.onblocked = () => reject(new Error("Lab storage upgrade is blocked by another tab. Close older range tabs and retry."));
  });
  return databasePromise;
}

async function get<T>(store: string, key: string): Promise<T | undefined> {
  const database = await openDatabase();
  const transaction = database.transaction(store, "readonly");
  return request<T | undefined>(transaction.objectStore(store).get(key));
}

async function put(store: string, key: string | null, value: unknown): Promise<void> {
  const database = await openDatabase();
  const transaction = database.transaction(store, "readwrite");
  if (key === null) transaction.objectStore(store).put(value);
  else transaction.objectStore(store).put(value, key);
  await transactionDone(transaction);
}

async function remove(store: string, key: string): Promise<void> {
  const database = await openDatabase();
  const transaction = database.transaction(store, "readwrite");
  transaction.objectStore(store).delete(key);
  await transactionDone(transaction);
}

export async function getCachedAsset(digest: string): Promise<ArrayBuffer | undefined> {
  return get<ArrayBuffer>(STORES.assets, digest);
}

export async function cacheAsset(digest: string, buffer: ArrayBuffer): Promise<void> {
  try {
    await put(STORES.assets, digest, buffer.slice(0));
  } catch (error) {
    throw new Error(`The verified image loaded, but browser caching failed (${error instanceof Error ? error.message : String(error)}). The lab can continue without offline caching.`);
  }
}

export async function storeManifest(manifest: AssetManifest): Promise<void> {
  const record: StoredManifest = { key: "manifest", value: manifest };
  await put(STORES.progress, null, record);
}

export async function getStoredManifest(): Promise<AssetManifest | undefined> {
  const record = await get<StoredManifest>(STORES.progress, "manifest");
  return record?.value;
}

export async function saveSnapshot(record: SnapshotRecord): Promise<void> {
  await put(STORES.snapshots, null, record);
}

export async function getSnapshot(id: string): Promise<SnapshotRecord | undefined> {
  return get<SnapshotRecord>(STORES.snapshots, id);
}

export async function listSnapshots(): Promise<SnapshotMeta[]> {
  const database = await openDatabase();
  const transaction = database.transaction(STORES.snapshots, "readonly");
  const records = await request<SnapshotRecord[]>(transaction.objectStore(STORES.snapshots).getAll());
  return records.map((record) => record.meta).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function deleteSnapshot(id: string): Promise<void> {
  await remove(STORES.snapshots, id);
}

export async function saveProgress(key: string, value: unknown): Promise<void> {
  const record: StoredProgress = { key, value, savedAt: new Date().toISOString() };
  await put(STORES.progress, null, record);
}

export async function loadProgress<T>(key: string): Promise<T | undefined> {
  const record = await get<StoredProgress>(STORES.progress, key);
  return record?.value as T | undefined;
}

export async function clearProgress(key: string): Promise<void> {
  await remove(STORES.progress, key);
}
