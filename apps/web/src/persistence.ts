// Persistent storage for the only supported project and manifest formats.
// IndexedDB owns structured project intent. OPFS owns large binary artifacts.
// No compatibility reader exists, so old single-router data can never become
// live state by normalization, migration or a hidden default topology.

import {
  createEmptyProjectV4,
  parseLabProjectV4,
  parseTerminalPresentationV2,
  type HostProjectV4,
  type LabProjectV4,
  type LinkProjectV4,
  type ProjectManifestV3,
  type RouterProjectV4,
  type TerminalPresentationV2
} from "@router-simulator/contracts";

const DATABASE_NAME = "router-simulator-v4";
const DATABASE_VERSION = 1;
const HEADS = "project-heads";
const ROUTERS = "project-routers";
const HOSTS = "project-hosts";
const LINKS = "project-links";
const PRESENTATION = "project-presentation";
const ACTIVE = "active-project";
let databasePromise: Promise<IDBDatabase> | undefined;
let saveTail = Promise.resolve();

interface ProjectHead {
  projectId: string;
  name: string;
  notes: string;
  // Canvas annotations are small presentation records with no separate
  // revision history, so they ride in the head next to notes and layout rather
  // than in their own object store like routers, hosts and links.
  annotations: LabProjectV4["annotations"];
  layout: LabProjectV4["layout"];
  updatedAt: string;
  routers: string[];
  hosts: string[];
  links: string[];
}

interface StoredObject<T> {
  projectId: string;
  objectId: string;
  revision: number;
  fingerprint: string;
  value: T;
}

export interface PersistedPresentation {
  projectId: string;
  selectedNodeId?: string;
  terminal?: TerminalPresentationV2;
}

export interface ProjectRevisionSummary {
  routersWritten: number;
  hostsWritten: number;
  linksWritten: number;
}

type ProjectObject = RouterProjectV4 | HostProjectV4 | LinkProjectV4;

function database(): Promise<IDBDatabase> {
  // One long-lived connection avoids accumulating handles during autosave.
  // A version change closes it promptly so a later application build can
  // upgrade without another tab blocking the browser transaction.
  if (databasePromise) return databasePromise;
  databasePromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      for (const store of [HEADS, ROUTERS, HOSTS, LINKS, PRESENTATION, ACTIVE]) {
        if (!request.result.objectStoreNames.contains(store)) {
          request.result.createObjectStore(store);
        }
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
  // IndexedDB requests are event based. Converting that boundary once keeps
  // every caller waiting for the real browser result instead of observing a
  // transaction that is still pending.
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function committed(transaction: IDBTransaction): Promise<void> {
  // Request success is not durability. A later request may abort the entire
  // transaction, therefore save operations resolve only on oncomplete.
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error ??
      new Error("Project transaction was aborted"));
  });
}

function key(projectId: string, objectId: string): string {
  // Contract identifiers cannot contain NUL, making this composite key
  // unambiguous without allocating nested object stores per project.
  return `${projectId}\u0000${objectId}`;
}

function head(project: LabProjectV4): ProjectHead {
  return {
    projectId: project.projectId,
    name: project.name,
    notes: project.notes,
    annotations: project.annotations,
    layout: project.layout,
    updatedAt: project.updatedAt,
    routers: project.routers.map((item) => item.id),
    hosts: project.hosts.map((item) => item.id),
    links: project.links.map((item) => item.id)
  };
}

async function currentRecords<T extends ProjectObject>(db: IDBDatabase,
  storeName: string, projectId: string, values: readonly T[]):
  Promise<Map<string, StoredObject<T>>> {
  // Read only records referenced by the incoming project. Removed identities
  // are obtained from the previous head during the atomic write below.
  const transaction = db.transaction(storeName, "readonly");
  const store = transaction.objectStore(storeName);
  const records = await Promise.all(values.map(async (value) => [value.id,
    await requestValue(store.get(key(projectId, value.id))) as
      StoredObject<T> | undefined] as const));
  await committed(transaction);
  return new Map(records.filter((entry): entry is readonly [string, StoredObject<T>] =>
    entry[1] !== undefined));
}

async function saveNow(input: LabProjectV4): Promise<ProjectRevisionSummary> {
  // Full validation precedes the first write. Invalid form drafts therefore
  // leave every previously durable entity and the active-project pointer intact.
  const project = parseLabProjectV4(input);
  const db = await database();
  const previousHead = await requestValue(db.transaction(HEADS).objectStore(HEADS)
    .get(project.projectId)) as ProjectHead | undefined;
  const [routerRecords, hostRecords, linkRecords] = await Promise.all([
    currentRecords(db, ROUTERS, project.projectId, project.routers),
    currentRecords(db, HOSTS, project.projectId, project.hosts),
    currentRecords(db, LINKS, project.projectId, project.links)
  ]);
  const transaction = db.transaction([HEADS, ROUTERS, HOSTS, LINKS, ACTIVE], "readwrite");
  const summary: ProjectRevisionSummary = {
    routersWritten: 0,
    hostsWritten: 0,
    linksWritten: 0
  };

  const write = <T extends ProjectObject>(storeName: string, values: readonly T[],
    previous: Map<string, StoredObject<T>>, counter: keyof ProjectRevisionSummary) => {
    const store = transaction.objectStore(storeName);
    for (const value of values) {
      const fingerprint = JSON.stringify(value);
      const before = previous.get(value.id);
      if (before?.fingerprint === fingerprint) continue;
      store.put({ projectId: project.projectId, objectId: value.id,
        revision: (before?.revision ?? 0) + 1, fingerprint, value } satisfies StoredObject<T>,
      key(project.projectId, value.id));
      summary[counter] += 1;
    }
  };
  write(ROUTERS, project.routers, routerRecords, "routersWritten");
  write(HOSTS, project.hosts, hostRecords, "hostsWritten");
  write(LINKS, project.links, linkRecords, "linksWritten");

  const removeMissing = (storeName: string, before: readonly string[] | undefined,
    after: readonly string[]) => {
    const live = new Set(after);
    const store = transaction.objectStore(storeName);
    for (const id of before ?? []) {
      if (!live.has(id)) store.delete(key(project.projectId, id));
    }
  };
  removeMissing(ROUTERS, previousHead?.routers, project.routers.map((item) => item.id));
  removeMissing(HOSTS, previousHead?.hosts, project.hosts.map((item) => item.id));
  removeMissing(LINKS, previousHead?.links, project.links.map((item) => item.id));
  transaction.objectStore(HEADS).put(head(project), project.projectId);
  transaction.objectStore(ACTIVE).put(project.projectId, "id");
  await committed(transaction);
  return summary;
}

export function saveLabProjectV4(project: LabProjectV4): Promise<ProjectRevisionSummary> {
  // Serializing autosaves prevents a slower older transaction from landing
  // after a newer edit and resurrecting a removed router or link.
  const operation = saveTail.then(() => saveNow(project));
  saveTail = operation.then(() => undefined, () => undefined);
  return operation;
}

export async function loadLabProjectV4(projectId: string): Promise<LabProjectV4 | undefined> {
  const db = await database();
  const projectHead = await requestValue(db.transaction(HEADS).objectStore(HEADS)
    .get(projectId)) as ProjectHead | undefined;
  if (!projectHead) return undefined;
  const read = async <T extends ProjectObject>(storeName: string,
    ids: readonly string[]): Promise<T[]> => {
    const transaction = db.transaction(storeName, "readonly");
    const store = transaction.objectStore(storeName);
    const records = await Promise.all(ids.map((id) => requestValue(
      store.get(key(projectId, id))) as Promise<StoredObject<T> | undefined>));
    await committed(transaction);
    if (records.some((record) => record === undefined)) {
      throw new Error("Stored project is missing an object revision");
    }
    return records.map((record) => record!.value);
  };
  const [routers, hosts, links] = await Promise.all([
    read<RouterProjectV4>(ROUTERS, projectHead.routers),
    read<HostProjectV4>(HOSTS, projectHead.hosts),
    read<LinkProjectV4>(LINKS, projectHead.links)
  ]);
  return parseLabProjectV4({
    format: "router-simulator-project",
    version: 4,
    projectId: projectHead.projectId,
    name: projectHead.name,
    notes: projectHead.notes,
    // A head written before annotations existed has none. parseLabProjectV4
    // also tolerates the absent field; the fallback keeps the reconstructed
    // object shape explicit here.
    annotations: projectHead.annotations ?? [],
    layout: projectHead.layout,
    updatedAt: projectHead.updatedAt,
    routers,
    hosts,
    links
  });
}

export async function loadActiveProjectV4(): Promise<LabProjectV4> {
  // Absence is the only fresh-start case. The returned project has no router,
  // host or link because topology creation belongs exclusively to the user.
  const db = await database();
  const id = await requestValue(db.transaction(ACTIVE).objectStore(ACTIVE).get("id"));
  if (typeof id !== "string") return createEmptyProjectV4();
  return await loadLabProjectV4(id) ?? createEmptyProjectV4();
}

export async function saveProjectPresentation(projectId: string,
  input: PersistedPresentation): Promise<void> {
  if (input.projectId !== projectId) {
    throw new Error("Presentation project identity does not match");
  }
  const value: PersistedPresentation = {
    projectId,
    ...(input.selectedNodeId ? { selectedNodeId: input.selectedNodeId } : {}),
    ...(input.terminal
      ? { terminal: parseTerminalPresentationV2(input.terminal) } : {})
  };
  const db = await database();
  const transaction = db.transaction(PRESENTATION, "readwrite");
  transaction.objectStore(PRESENTATION).put(value, projectId);
  await committed(transaction);
}

export async function loadProjectPresentation(projectId: string):
  Promise<PersistedPresentation | undefined> {
  const db = await database();
  const value = await requestValue(db.transaction(PRESENTATION)
    .objectStore(PRESENTATION).get(projectId)) as PersistedPresentation | undefined;
  if (!value) return undefined;
  return {
    projectId,
    ...(typeof value.selectedNodeId === "string"
      ? { selectedNodeId: value.selectedNodeId } : {}),
    ...(value.terminal
      ? { terminal: parseTerminalPresentationV2(value.terminal) } : {})
  };
}

function base64(bytes: Uint8Array): string {
  // Chunking avoids one enormous JavaScript argument list for large captures.
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function strictBase64(value: unknown, field: string): Uint8Array | undefined {
  // atob accepts noncanonical padding in some engines. Portable manifests use
  // one representation so truncation and hand-edited whitespace fail closed.
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.length || value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`${field} is not canonical base64`);
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function createProjectManifestV3(project: LabProjectV4,
  capture?: Uint8Array): ProjectManifestV3 {
  return {
    mode: "project",
    formatVersion: 3,
    checkpointAbi: 6,
    project: parseLabProjectV4(project),
    ...(capture?.length ? { captureBase64: base64(capture) } : {})
  };
}

export function createCheckpointManifestV3(project: LabProjectV4,
  checkpoint: Uint8Array, capture?: Uint8Array,
  terminalPresentation?: TerminalPresentationV2): ProjectManifestV3 {
  if (!checkpoint.length) throw new Error("A checkpoint export cannot be empty");
  return {
    mode: "checkpoint",
    formatVersion: 3,
    checkpointAbi: 6,
    project: parseLabProjectV4(project),
    checkpointBase64: base64(checkpoint),
    ...(capture?.length ? { captureBase64: base64(capture) } : {}),
    ...(terminalPresentation
      ? { terminalPresentation: parseTerminalPresentationV2(terminalPresentation) } : {})
  };
}

export function parseNetsimV3(text: string): {
  project: LabProjectV4;
  checkpoint?: Uint8Array;
  capture?: Uint8Array;
  terminalPresentation?: TerminalPresentationV2;
} {
  // No raw-project or previous-manifest branch exists. Unsupported bytes stop
  // before project replay, leaving the active Worker and project untouched.
  const decoded = JSON.parse(text) as Partial<ProjectManifestV3>;
  if (!decoded || typeof decoded !== "object" || decoded.formatVersion !== 3 ||
      decoded.checkpointAbi !== 6 ||
      (decoded.mode !== "project" && decoded.mode !== "checkpoint")) {
    throw new Error("The .netsim manifest format is not supported");
  }
  if (decoded.mode === "checkpoint" && decoded.checkpointBase64 === undefined) {
    throw new Error("The checkpoint manifest has no structural state");
  }
  if (decoded.mode === "project" &&
      (decoded.checkpointBase64 !== undefined || decoded.terminalPresentation !== undefined)) {
    throw new Error("A project manifest contains checkpoint-only state");
  }
  return {
    project: parseLabProjectV4(decoded.project),
    ...(decoded.checkpointBase64 !== undefined
      ? { checkpoint: strictBase64(decoded.checkpointBase64, "Checkpoint") } : {}),
    ...(decoded.captureBase64 !== undefined
      ? { capture: strictBase64(decoded.captureBase64, "Capture") } : {}),
    ...(decoded.terminalPresentation !== undefined
      ? { terminalPresentation: parseTerminalPresentationV2(decoded.terminalPresentation) } : {})
  };
}

function download(name: string, value: unknown): void {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)],
    { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function exportProjectV4(project: LabProjectV4, capture?: Uint8Array): void {
  const validated = parseLabProjectV4(project);
  download(`${validated.name.replaceAll(" ", "-").toLowerCase()}.netsim`,
    createProjectManifestV3(validated, capture));
}

export async function importNetsimV3(file: File) {
  return parseNetsimV3(await file.text());
}

function validateStorageIdentity(value: string): void {
  if (!/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/i.test(value)) {
    throw new Error("Storage identity is invalid");
  }
}

async function projectDirectory(projectId: string): Promise<FileSystemDirectoryHandle> {
  validateStorageIdentity(projectId);
  if (!navigator.storage?.getDirectory) throw new Error("OPFS is not available");
  const root = await navigator.storage.getDirectory();
  const projects = await root.getDirectoryHandle("projects", { create: true });
  return projects.getDirectoryHandle(projectId, { create: true });
}

export async function projectCheckpointNameV4(project: LabProjectV4):
  Promise<`checkpoint-v6-${string}.bin`> {
  // Recovery identity covers every portable project field except updatedAt.
  // That timestamp changes after the checkpoint has already been written and
  // therefore cannot participate in the name used on the next application
  // start. Keeping layout in the digest is intentional: a checkpoint saved
  // before a topology edit must never be mistaken for the current project.
  const { updatedAt: _volatileTimestamp, ...stableProject } = parseLabProjectV4(project);
  const bytes = new TextEncoder().encode(JSON.stringify(stableProject));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hexadecimal = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `checkpoint-v6-${hexadecimal}.bin`;
}

type ProjectBinaryName = "capture.pcapng" | `checkpoint-v6-${string}.bin`;

export async function saveProjectBinaryV4(projectId: string,
  name: ProjectBinaryName, bytes: Uint8Array): Promise<void> {
  // Project identity has already been validated by projectDirectory. Binary
  // names are checked separately because an imported project must not escape
  // its OPFS directory through a crafted recovery filename.
  if (name !== "capture.pcapng" &&
      !/^checkpoint-v6-[0-9a-f]{64}\.bin$/.test(name)) {
    throw new Error("Project binary name is invalid");
  }
  // createWritable commits atomically on close. A private copy severs the
  // transferred Wasm buffer before the first asynchronous write.
  const handle = await (await projectDirectory(projectId)).getFileHandle(name, { create: true });
  const writer = await handle.createWritable();
  try {
    const copy = bytes.slice().buffer;
    await writer.write(copy);
    await writer.close();
  } catch (cause) {
    await writer.abort();
    throw cause;
  }
}

export async function loadProjectBinaryV4(projectId: string,
  name: ProjectBinaryName): Promise<Uint8Array | undefined> {
  if (name !== "capture.pcapng" &&
      !/^checkpoint-v6-[0-9a-f]{64}\.bin$/.test(name)) {
    throw new Error("Project binary name is invalid");
  }
  try {
    const file = await (await projectDirectory(projectId)).getFileHandle(name)
      .then((handle) => handle.getFile());
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
  anchor.hidden = true;
  // Keep the anchor connected for the click and retain the object URL until
  // the browser has queued its download task. Immediate revocation can race
  // Chromium's Blob navigation and silently cancel a valid large export.
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  self.setTimeout(() => URL.revokeObjectURL(url), 0);
}
