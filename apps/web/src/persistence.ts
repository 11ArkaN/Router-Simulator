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
  // atob rejects malformed alphabet or padding before any bytes reach the
  // checkpoint decoder. Uint8Array then preserves all values including NUL.
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function opfsRoot(): Promise<FileSystemDirectoryHandle> {
  // OPFS is mandatory only for binary persistence actions. Project editing can
  // still use IndexedDB until the user requests a capture or checkpoint write.
  if (!navigator.storage?.getDirectory) throw new Error("OPFS is not available in this browser");
  return navigator.storage.getDirectory();
}

export async function saveBinary(name: "active.pcapng" | "active.checkpoint", bytes: Uint8Array): Promise<void> {
  // createWritable commits on close and discards an aborted temporary file.
  // Copying severs ownership from a transferable runtime buffer before await.
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
  // Absence is a normal fresh-lab state. Any permission, quota or I/O error is
  // propagated because treating it as absence would hide lost persistence.
  try {
    const file = await (await opfsRoot()).getFileHandle(name).then((handle) => handle.getFile());
    return new Uint8Array(await file.arrayBuffer());
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "NotFoundError") return undefined;
    throw cause;
  }
}

export function downloadBinary(name: string, bytes: Uint8Array, type: string): void {
  // A Blob copy creates a browser-owned immutable download source. The URL is
  // revoked after click because the download subsystem already holds it.
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
  const manifest = createProjectManifest(validated);
  download(`${validated.name.replaceAll(" ", "-").toLowerCase()}.netsim`, manifest);
}

function profileLock(): ProjectManifestV1["profileLock"] {
  // Project identity and checkpoint executable compatibility travel together.
  // Plain projects ignore buildHash on import, while structural state requires
  // every field to match before any runtime is created.
  return {
    id: GENERATED_PROFILE.id,
    release: GENERATED_PROFILE.release,
    profileHash: GENERATED_PROFILE.profileHash,
    buildHash: GENERATED_PROFILE.buildHash,
    checkpointAbi: GENERATED_PROFILE.abi.checkpoint
  };
}

export function createProjectManifest(project: LabProject): ProjectManifestV1 {
  // Plain project export deliberately carries no forwarding state. Importing
  // it must start a new runtime with empty ARP, queues and protocol progress.
  return {
    mode: "project",
    formatVersion: 1,
    profileLock: profileLock(),
    project: parseProject(project)
  };
}

export function exportCheckpoint(project: LabProject, checkpoint: Uint8Array,
  capture?: Uint8Array): void {
  // Structural bytes and optional diagnostics share one profile-locked wrapper
  // so a user cannot pair a capture with another lab generation accidentally.
  const validated = parseProject(project);
  const manifest = createCheckpointManifest(validated, checkpoint, capture);
  download(`${validated.name.replaceAll(" ", "-").toLowerCase()}-checkpoint.netsim`, manifest);
}

export function createCheckpointManifest(project: LabProject,
  checkpoint: Uint8Array, capture?: Uint8Array): ProjectManifestV1 {
  // An empty structural payload can never be a valid checkpoint and would make
  // fallback behavior ambiguous, so reject it before creating the manifest.
  if (!checkpoint.length) throw new Error("A checkpoint export cannot be empty");
  return {
    mode: "checkpoint",
    formatVersion: 1,
    profileLock: profileLock(),
    project: parseProject(project),
    checkpointBase64: base64(checkpoint),
    ...(capture?.length ? { captureBase64: base64(capture) } : {})
  };
}

export class IncompatibleCheckpointError extends Error {
  constructor() {
    // A dedicated type lets App request explicit project-only consent without
    // matching text or exposing checkpoint ABI details in the router console.
    super("The checkpoint ABI or build is incompatible; the project can be imported without live state");
    this.name = "IncompatibleCheckpointError";
  }
}

export function parseNetsim(text: string, allowProjectOnly = false):
  { project: LabProject; checkpoint?: Uint8Array; capture?: Uint8Array } {
  // Header, project schema and profile identity are validated before binary
  // decoding. No caller receives a partly trusted manifest on any failure.
  const decoded = JSON.parse(text) as Partial<ProjectManifestV1>;
  if (!decoded || typeof decoded !== "object" || decoded.formatVersion !== 1 ||
      (decoded.mode !== "project" && decoded.mode !== "checkpoint"))
    throw new Error("The .netsim manifest header is invalid");
  const project = parseProject(decoded && typeof decoded === "object" && "project" in decoded
    ? decoded.project : decoded);
  if (!decoded.profileLock || decoded.profileLock.id !== GENERATED_PROFILE.id ||
      decoded.profileLock.release !== GENERATED_PROFILE.release ||
      decoded.profileLock.profileHash !== GENERATED_PROFILE.profileHash) {
    throw new Error("The .netsim profile lock is incompatible");
  }
  const checkpointCompatible = decoded.profileLock.buildHash === GENERATED_PROFILE.buildHash &&
    decoded.profileLock.checkpointAbi === GENERATED_PROFILE.abi.checkpoint;
  if (decoded.mode === "checkpoint" && !checkpointCompatible && !allowProjectOnly)
    throw new IncompatibleCheckpointError();
  if (decoded.mode === "checkpoint" &&
      typeof decoded.checkpointBase64 !== "string")
    throw new Error("The checkpoint manifest has no structural state");
  if (decoded.mode === "checkpoint" && !checkpointCompatible)
    return { project };
  return {
    project,
    checkpoint: typeof decoded.checkpointBase64 === "string" ? decodeBase64(decoded.checkpointBase64) : undefined,
    capture: typeof decoded.captureBase64 === "string" ? decodeBase64(decoded.captureBase64) : undefined
  };
}

export async function importNetsim(file: File, allowProjectOnly = false):
  Promise<{ project: LabProject; checkpoint?: Uint8Array; capture?: Uint8Array }> {
  // File is read once to avoid a replacement race between header validation
  // and binary extraction on mutable host-backed File implementations.
  return parseNetsim(await file.text(), allowProjectOnly);
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
