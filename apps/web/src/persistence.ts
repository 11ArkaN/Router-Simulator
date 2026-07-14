// IndexedDB project storage, OPFS binary storage and portable netsim manifests.
// Every import crosses the shared versioned validation boundary before use.

import { DEFAULT_PROJECT, GENERATED_PROFILE, parseProject, type LabProject, type ProjectManifestV1 } from "@router-simulator/contracts";

const DB_NAME = "router-simulator";
const STORE = "projects";
let databasePromise: Promise<IDBDatabase> | undefined;

function database(): Promise<IDBDatabase> {
  // IndexedDB stores small structured project metadata. Large captures and
  // binary snapshots belong in OPFS when their persistence path is implemented.
  // One connection is shared by autosave transactions. Opening a new connection
  // for every keystroke would retain database handles until browser collection
  // and could block a future schema upgrade in another tab.
  if (databasePromise) return databasePromise;
  databasePromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        // Closing promptly lets a newer application version upgrade the schema.
        // The next operation lazily opens a connection to the new version.
        db.close();
        databasePromise = undefined;
      };
      resolve(db);
    };
    request.onerror = () => {
      databasePromise = undefined;
      reject(request.error);
    };
  });
  return databasePromise;
}

export async function loadProject(): Promise<LabProject> {
  // Imported storage is validated before use. A fresh project is cloned so UI
  // edits cannot mutate the shared DEFAULT_PROJECT constant.
  const db = await database();
  const value = await new Promise<unknown>((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get("active");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return value ? parseProject(value) : structuredClone(DEFAULT_PROJECT);
}

export async function saveProject(project: LabProject): Promise<void> {
  // The active project is replaced atomically within one read-write transaction.
  // Validation also protects direct calls such as the toolbar Save action. A
  // partially typed address must never replace the last restorable project.
  const validated = parseProject(project);
  const db = await database();
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).put(validated, "active");
    // A request success only means that its operation ran. Durability becomes
    // observable after the containing transaction completes, so Save resolves
    // on oncomplete and reports both error and explicit abort paths.
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ?? new Error("Project save was aborted"));
  });
}

function download(name: string, value: unknown): void {
  // Blob URLs avoid routing project contents through a server or external API.
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

function base64(bytes: Uint8Array): string {
  // Chunking avoids spreading a multi-megabyte capture into one JavaScript call
  // stack. Base64 is used only for portable .netsim JSON. OPFS keeps the same
  // data binary and therefore pays no expansion during autosave.
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  if (!navigator.storage?.getDirectory) throw new Error("OPFS is not available in this browser");
  return navigator.storage.getDirectory();
}

export async function saveBinary(name: "active.pcapng" | "active.checkpoint", bytes: Uint8Array): Promise<void> {
  const handle = await (await opfsRoot()).getFileHandle(name, { create: true });
  const writer = await handle.createWritable();
  try {
    const copy = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(copy).set(bytes);
    await writer.write(copy);
    await writer.close();
  } catch (cause) {
    await writer.abort();
    throw cause;
  }
}

export async function loadBinary(name: "active.pcapng" | "active.checkpoint"): Promise<Uint8Array | undefined> {
  try {
    const file = await (await opfsRoot()).getFileHandle(name).then((handle) => handle.getFile());
    return new Uint8Array(await file.arrayBuffer());
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "NotFoundError") return undefined;
    throw cause;
  }
}

export function downloadBinary(name: string, bytes: Uint8Array, type: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function exportProject(project: LabProject): void {
  // Export uses the same validation boundary as local persistence. This avoids
  // producing a file that the application itself would correctly refuse later.
  const validated = parseProject(project);
  const manifest: ProjectManifestV1 = {
    mode: "project",
    formatVersion: 1,
    profileLock: { id: GENERATED_PROFILE.id, release: GENERATED_PROFILE.release },
    project: validated
  };
  download(`${validated.name.replaceAll(" ", "-").toLowerCase()}.netsim`, manifest);
}

export function exportCheckpoint(project: LabProject, checkpoint: Uint8Array,
  capture?: Uint8Array): void {
  const validated = parseProject(project);
  const manifest: ProjectManifestV1 = {
    mode: "checkpoint",
    formatVersion: 1,
    profileLock: { id: GENERATED_PROFILE.id, release: GENERATED_PROFILE.release },
    project: validated,
    checkpointBase64: base64(checkpoint),
    ...(capture?.length ? { captureBase64: base64(capture) } : {})
  };
  download(`${validated.name.replaceAll(" ", "-").toLowerCase()}-checkpoint.netsim`, manifest);
}

export async function importNetsim(file: File): Promise<{ project: LabProject; checkpoint?: Uint8Array; capture?: Uint8Array }> {
  const decoded = JSON.parse(await file.text()) as Partial<ProjectManifestV1>;
  const project = parseProject(decoded && typeof decoded === "object" && "project" in decoded
    ? decoded.project : decoded);
  if (decoded.profileLock && (decoded.profileLock.id !== GENERATED_PROFILE.id ||
      decoded.profileLock.release !== GENERATED_PROFILE.release)) {
    throw new Error("The .netsim profile lock is incompatible");
  }
  return {
    project,
    checkpoint: typeof decoded.checkpointBase64 === "string" ? decodeBase64(decoded.checkpointBase64) : undefined,
    capture: typeof decoded.captureBase64 === "string" ? decodeBase64(decoded.captureBase64) : undefined
  };
}

export async function importProject(file: File): Promise<LabProject> {
  // Import never trusts the file extension or wrapper metadata. Only a project
  // that passes the same versioned schema used for IndexedDB can replace the
  // active lab, preventing partial state from reaching the runtime.
  const decoded = JSON.parse(await file.text()) as unknown;
  const wrapped = decoded && typeof decoded === "object" && "project" in decoded
    ? (decoded as { project: unknown }).project
    : decoded;
  return parseProject(wrapped);
}
