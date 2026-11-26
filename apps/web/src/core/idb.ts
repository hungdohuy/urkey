/** Minimal IndexedDB wrapper: one database, two object stores (data-model §4.1). */

const DB_NAME = "urkey";
const DB_VERSION = 1;
export type StoreName = "kv" | "keys";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // v1: everything stored here is public data, ciphertext, or non-extractable CryptoKeys.
      if (!db.objectStoreNames.contains("kv")) db.createObjectStore("kv");
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys");
    };
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(new Error("storage unavailable"));
    };
  });
}

let dbPromise: Promise<IDBDatabase> | null = null;
function db(): Promise<IDBDatabase> {
  dbPromise ??= open();
  return dbPromise;
}

async function tx<T>(store: StoreName, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(store, mode);
    const req = fn(t.objectStore(store));
    t.oncomplete = () => {
      resolve(req.result);
    };
    t.onerror = () => {
      reject(new Error("storage error"));
    };
  });
}

export const idb = {
  get: <T>(store: StoreName, key: string) => tx<T | undefined>(store, "readonly", (s) => s.get(key) as IDBRequest<T | undefined>),
  put: (store: StoreName, key: string, value: unknown) => tx(store, "readwrite", (s) => s.put(value, key)),
  del: (store: StoreName, key: string) => tx(store, "readwrite", (s) => s.delete(key)),
  async wipe(): Promise<void> {
    await tx("kv", "readwrite", (s) => s.clear());
    await tx("keys", "readwrite", (s) => s.clear());
  },
};
