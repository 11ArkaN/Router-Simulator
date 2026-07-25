// Browser ownership of the project wrapping key. IndexedDB stores a
// non-extractable device AES-KW key and only wrapped project-key bytes. The raw
// 256-bit project key exists briefly while being transferred to the C++ vault
// owner, then both the Worker and main-thread buffers are erased.

const DATABASE_NAME = "router-simulator-cryptography-v1";
const DATABASE_VERSION = 1;
const DEVICE_KEYS = "device-keys";
const PROJECT_KEYS = "project-keys";
const DEVICE_KEY_ID = "local-aes-kw-v1";
let databasePromise: Promise<IDBDatabase> | undefined;

interface StoredProjectKey {
  projectId: string;
  algorithm: "AES-KW-256";
  wrapped: ArrayBuffer;
}

export interface ProjectVaultMaterial {
  wrappingKey: Uint8Array;
  context: Uint8Array;
}

function projectContext(projectId: string): Uint8Array {
  return new TextEncoder().encode(
    `router-simulator/project-secret-vault/v1/${projectId}`);
}

function database(): Promise<IDBDatabase> {
  if (databasePromise) return databasePromise;
  databasePromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      for (const store of [DEVICE_KEYS, PROJECT_KEYS]) {
        if (!request.result.objectStoreNames.contains(store))
          request.result.createObjectStore(store);
      }
    };
    request.onsuccess = () => {
      request.result.onversionchange = () => {
        request.result.close();
        databasePromise = undefined;
      };
      resolve(request.result);
    };
    request.onerror = () => {
      databasePromise = undefined;
      reject(request.error);
    };
  });
  return databasePromise;
}

function requestValue<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function committed(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ??
      new Error("Project key transaction was aborted"));
  });
}

async function deviceWrappingKey(db: IDBDatabase): Promise<CryptoKey> {
  const read = db.transaction(DEVICE_KEYS, "readonly");
  const existing = await requestValue(read.objectStore(DEVICE_KEYS)
    .get(DEVICE_KEY_ID)) as CryptoKey | undefined;
  await committed(read);
  if (existing) return existing;

  // extractable=false is the durable security boundary. IndexedDB can clone
  // the CryptoKey for WebCrypto use, but scripts cannot export its raw bytes.
  const generated = await crypto.subtle.generateKey(
    { name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  const write = db.transaction(DEVICE_KEYS, "readwrite");
  write.objectStore(DEVICE_KEYS).add(generated, DEVICE_KEY_ID);
  try {
    await committed(write);
    return generated;
  } catch (cause) {
    // Two tabs may create the first key concurrently. Read the committed
    // winner instead of replacing it and orphaning all existing projects.
    const retry = db.transaction(DEVICE_KEYS, "readonly");
    const winner = await requestValue(retry.objectStore(DEVICE_KEYS)
      .get(DEVICE_KEY_ID)) as CryptoKey | undefined;
    await committed(retry);
    if (winner) return winner;
    throw cause;
  }
}

async function projectKey(projectId: string, db: IDBDatabase,
  deviceKey: CryptoKey): Promise<CryptoKey> {
  const read = db.transaction(PROJECT_KEYS, "readonly");
  const stored = await requestValue(read.objectStore(PROJECT_KEYS)
    .get(projectId)) as StoredProjectKey | undefined;
  await committed(read);
  if (stored) {
    if (stored.algorithm !== "AES-KW-256" ||
        !(stored.wrapped instanceof ArrayBuffer) || !stored.wrapped.byteLength)
      throw new Error("Stored project key record is invalid");
    return crypto.subtle.unwrapKey("raw", stored.wrapped, deviceKey,
      "AES-KW", { name: "AES-GCM", length: 256 }, true,
      ["encrypt", "decrypt"]);
  }

  // Project keys are extractable only so the C++ provider can receive raw key
  // bytes. At rest, IndexedDB receives only AES-KW ciphertext.
  const generated = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const wrapped = await crypto.subtle.wrapKey("raw", generated, deviceKey,
    "AES-KW");
  const write = db.transaction(PROJECT_KEYS, "readwrite");
  write.objectStore(PROJECT_KEYS).add({ projectId, algorithm: "AES-KW-256",
    wrapped } satisfies StoredProjectKey, projectId);
  try {
    await committed(write);
    return generated;
  } catch (cause) {
    // Preserve the first committed project identity if two tabs race.
    const retry = db.transaction(PROJECT_KEYS, "readonly");
    const winner = await requestValue(retry.objectStore(PROJECT_KEYS)
      .get(projectId)) as StoredProjectKey | undefined;
    await committed(retry);
    if (!winner) throw cause;
    return crypto.subtle.unwrapKey("raw", winner.wrapped, deviceKey,
      "AES-KW", { name: "AES-GCM", length: 256 }, true,
      ["encrypt", "decrypt"]);
  }
}

export async function projectVaultMaterial(
  projectId: string,
  importedWrappingKey?: Uint8Array): Promise<ProjectVaultMaterial> {
  if (!projectId || new TextEncoder().encode(projectId).byteLength > 128)
    throw new Error("Project identity is invalid for secret storage");
  if (importedWrappingKey) {
    if (importedWrappingKey.byteLength !== 32)
      throw new Error("Imported project wrapping key has an invalid size");
    return { wrappingKey: importedWrappingKey.slice(),
      context: projectContext(projectId) };
  }
  const db = await database();
  const deviceKey = await deviceWrappingKey(db);
  const unwrapped = await projectKey(projectId, db, deviceKey);
  const wrappingKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", unwrapped));
  if (wrappingKey.byteLength !== 32)
    throw new Error("Project wrapping key has an invalid size");
  return { wrappingKey, context: projectContext(projectId) };
}

export async function persistProjectWrappingKey(
  projectId: string, rawKey: Uint8Array): Promise<void> {
  if (!projectId || new TextEncoder().encode(projectId).byteLength > 128 ||
      rawKey.byteLength !== 32)
    throw new Error("Imported project key record is invalid");
  const db = await database();
  const deviceKey = await deviceWrappingKey(db);
  const imported = await crypto.subtle.importKey(
    "raw", rawKey.slice().buffer as ArrayBuffer,
    { name: "AES-GCM", length: 256 }, true,
    ["encrypt", "decrypt"]);
  const wrapped = await crypto.subtle.wrapKey(
    "raw", imported, deviceKey, "AES-KW");
  const transaction = db.transaction(PROJECT_KEYS, "readwrite");
  transaction.objectStore(PROJECT_KEYS).put({
    projectId, algorithm: "AES-KW-256", wrapped
  } satisfies StoredProjectKey, projectId);
  await committed(transaction);
}
