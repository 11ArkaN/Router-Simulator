// Main-thread client for runtime protocol 3. React sends typed operations with
// stable node and session IDs; this module alone converts them to netstrings.

import {
  LAB_RUNTIME_PROTOCOL,
  PROFILE_CATALOG,
  parseLabRuntimeSnapshotV5,
  type LabProjectV3,
  type LabRuntimeSnapshotV5,
  type RouterInterfaceIntent,
  type RouterPortIntent
} from "@router-simulator/contracts";
import { readTelemetrySnapshot, type TelemetryLayout,
  type TelemetryPage } from "./telemetry-contract";

type TextPending = { resolve(value: string): void; reject(error: Error): void };
type BinaryPending = { resolve(value: Uint8Array): void; reject(error: Error): void };
type WorkerResponse = {
  id?: number;
  ok?: boolean;
  value?: string;
  error?: string;
  kind?: string;
  buffer?: SharedArrayBuffer;
  offset?: number;
  size?: number;
  layout?: TelemetryLayout;
  bytes?: ArrayBuffer;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface RouterTerminalState {
  engine: "md" | "classic";
  historyRegion: "md-operational" | "md-configuration" | "classic";
  banner: string;
  prompt: string;
}

function protocolMessage(operation: string, fields: readonly string[] = []): string {
  // C++ consumes UTF-8 byte lengths. JavaScript string length would corrupt
  // framing for non-ASCII system names and descriptions.
  return [operation, ...fields].map((value) =>
    `${encoder.encode(value).byteLength}:${value},`).join("");
}

function boolean(value: boolean): string { return value ? "1" : "0"; }

function expectSuccess(value: string): string {
  if (value.startsWith("ERROR:")) throw new Error(value.slice(6).trim());
  return value;
}

function terminalSuffix(value: string): { output: string; state: RouterTerminalState } {
  // Command output is opaque and may contain digits and colons. A valid state
  // is exactly four netstrings consuming the complete suffix, so scanning
  // candidate starts cannot truncate legitimate output accidentally.
  const bytes = encoder.encode(value);
  for (let offset = 0; offset < bytes.length; ++offset) {
    if (offset && bytes[offset - 1] >= 48 && bytes[offset - 1] <= 57) continue;
    const fields: string[] = [];
    let cursor = offset;
    while (cursor < bytes.length) {
      let colon = cursor;
      while (colon < bytes.length && bytes[colon] >= 48 && bytes[colon] <= 57) ++colon;
      if (colon === cursor || bytes[colon] !== 58) break;
      const length = Number(decoder.decode(bytes.subarray(cursor, colon)));
      const start = colon + 1;
      const end = start + length;
      if (!Number.isSafeInteger(length) || end >= bytes.length || bytes[end] !== 44) break;
      fields.push(decoder.decode(bytes.subarray(start, end)));
      cursor = end + 1;
    }
    if (cursor === bytes.length && fields.length === 4 &&
        (fields[0] === "md" || fields[0] === "classic") &&
        (fields[1] === "md-operational" || fields[1] === "md-configuration" ||
         fields[1] === "classic")) {
      return { output: decoder.decode(bytes.subarray(0, offset)), state: {
        engine: fields[0], historyRegion: fields[1], banner: fields[2], prompt: fields[3]
      } };
    }
  }
  throw new Error("Runtime terminal response is malformed");
}

export class MultiRouterRuntimeClient {
  private readonly worker: Worker;
  private readonly pending = new Map<number, TextPending>();
  private readonly binaryPending = new Map<number, BinaryPending>();
  private telemetryPage?: TelemetryPage;
  private nextRequestId = 1;
  private closed = false;

  constructor() {
    // Shared memory and pthreads are product requirements. A missing isolation
    // header is a startup error, never a request to run a different emulator.
    if (!crossOriginIsolated || typeof SharedArrayBuffer === "undefined") {
      throw new Error("WebAssembly threads require COOP and COEP isolation");
    }
    this.worker = new Worker(new URL("./runtime.worker.ts", import.meta.url),
      { type: "module" });
    this.worker.onmessage = ({ data }: MessageEvent<WorkerResponse>) => {
      if (data.kind === "telemetry-page" && data.buffer &&
          data.offset !== undefined && data.size && data.layout) {
        this.telemetryPage = { buffer: data.buffer, offset: data.offset,
          size: data.size, layout: data.layout };
        return;
      }
      if (data.id !== undefined && data.bytes) {
        const pending = this.binaryPending.get(data.id);
        if (!pending) return;
        this.binaryPending.delete(data.id);
        pending.resolve(new Uint8Array(data.bytes));
        return;
      }
      if (data.id !== undefined && data.ok === false &&
          this.binaryPending.has(data.id)) {
        const pending = this.binaryPending.get(data.id)!;
        this.binaryPending.delete(data.id);
        pending.reject(new Error(data.error ?? "Runtime binary operation failed"));
        return;
      }
      const pending = this.pending.get(data.id ?? -1);
      if (!pending) return;
      this.pending.delete(data.id!);
      if (data.ok) pending.resolve(data.value ?? "");
      else pending.reject(new Error(data.error ?? "Runtime operation failed"));
    };
    this.worker.onerror = (event) => {
      const error = new Error(event.message || "Runtime Worker failed");
      for (const pending of this.pending.values()) pending.reject(error);
      for (const pending of this.binaryPending.values()) pending.reject(error);
      this.pending.clear();
      this.binaryPending.clear();
    };
  }

  private send(operation: string, fields: readonly string[] = []): Promise<string> {
    const id = this.nextRequestId++;
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error("Runtime client is closed"));
        return;
      }
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, command: protocolMessage(operation, fields) });
    });
  }

  private binary(action: "capture-export" | "checkpoint-export",
    bytes?: Uint8Array): Promise<Uint8Array> {
    const id = this.nextRequestId++;
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error("Runtime client is closed"));
        return;
      }
      this.binaryPending.set(id, { resolve, reject });
      const buffer = bytes?.slice().buffer;
      this.worker.postMessage({ id, action, bytes: buffer }, buffer ? [buffer] : []);
    });
  }

  async snapshot(): Promise<LabRuntimeSnapshotV5> {
    return parseLabRuntimeSnapshotV5(JSON.parse(expectSuccess(
      await this.send(LAB_RUNTIME_PROTOCOL.snapshot))));
  }

  private async mutation(operation: string,
    fields: readonly string[]): Promise<LabRuntimeSnapshotV5> {
    // Every mutating C++ operation returns the complete low-frequency
    // projection after its owner turn. React never predicts operational state.
    return parseLabRuntimeSnapshotV5(JSON.parse(expectSuccess(
      await this.send(operation, fields))));
  }

  createRouter(id: string, profileId: string, systemName: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.router_create,
      [id, profileId, systemName]);
  }

  deleteRouter(id: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.router_delete, [id]);
  }

  setSystemName(routerId: string, systemName: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.system_name_set,
      [routerId, systemName]);
  }

  replaceRouterConfiguration(router: LabProjectV3["routers"][number]) {
    // The nested payload is one outer protocol field. Its own netstrings make
    // every description and interface name unambiguous while C++ stages the
    // complete value before changing hardware, RIB or FIB owners.
    const values: string[] = [router.systemName, String(router.running.ports.length)];
    for (const port of router.running.ports) {
      values.push(port.id, boolean(port.admin === "up"), String(port.mtu),
        String(port.speedMbps), port.description);
    }
    values.push(String(router.running.interfaces.length));
    for (const item of router.running.interfaces) {
      values.push(item.name, item.portId, item.address,
        boolean(item.admin === "up"));
    }
    values.push(String(router.running.staticRoutes.length));
    for (const route of router.running.staticRoutes)
      values.push(route.prefix, route.nextHop);
    return this.mutation(LAB_RUNTIME_PROTOCOL.router_configuration_replace,
      [router.id, protocolMessage(values[0], values.slice(1))]);
  }

  createHost(id: string, name: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.host_create, [id, name]);
  }

  deleteHost(id: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.host_delete, [id]);
  }

  setCard(routerId: string, slot: number, provisioned: string | null,
    equipped: string | null) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.hardware_card_set,
      [routerId, String(slot), provisioned ?? "", equipped ?? ""]);
  }

  setMda(routerId: string, cardSlot: number, mdaSlot: number,
    provisioned: string | null, equipped: string | null) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.hardware_mda_set,
      [routerId, String(cardSlot), String(mdaSlot), provisioned ?? "", equipped ?? ""]);
  }

  setCardAdmin(routerId: string, slot: number, enabled: boolean) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.hardware_card_admin_set,
      [routerId, String(slot), boolean(enabled)]);
  }

  setMdaAdmin(routerId: string, cardSlot: number, mdaSlot: number,
    enabled: boolean) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.hardware_mda_admin_set,
      [routerId, String(cardSlot), String(mdaSlot), boolean(enabled)]);
  }

  configurePort(routerId: string, port: RouterPortIntent) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.port_configure,
      [routerId, port.id, boolean(port.admin === "up"), String(port.mtu),
        String(port.speedMbps), port.description]);
  }

  configureInterface(routerId: string, item: RouterInterfaceIntent) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.interface_configure,
      [routerId, item.name, item.portId, item.address,
        boolean(item.admin === "up")]);
  }

  deleteInterface(routerId: string, interfaceName: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.interface_delete,
      [routerId, interfaceName]);
  }

  addStaticRoute(routerId: string, prefix: string, nextHop: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.static_route_add,
      [routerId, prefix, nextHop]);
  }

  deleteStaticRoute(routerId: string, prefix: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.static_route_delete,
      [routerId, prefix]);
  }

  createLink(id: string, firstNode: string, firstPort: string,
    secondNode: string, secondPort: string, propagationDelayNs: number,
    admin: boolean) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.link_create,
      [id, firstNode, firstPort, secondNode, secondPort,
        String(propagationDelayNs), boolean(admin)]);
  }

  deleteLink(id: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.link_delete, [id]);
  }

  setLinkAdmin(id: string, enabled: boolean) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.link_admin_set,
      [id, boolean(enabled)]);
  }

  setLinkProperties(id: string, enabled: boolean, propagationDelayNs: number) {
    // JavaScript safe-integer validation is performed by LabProjectV3 before
    // framing. C++ repeats the signed nanosecond bound before touching fabric
    // deadlines, so hand-written bridge messages cannot overflow duration.
    return this.mutation(LAB_RUNTIME_PROTOCOL.link_properties_set,
      [id, boolean(enabled), String(propagationDelayNs)]);
  }

  configureHost(id: string, mac: string, address: string, gateway: string,
    mtu: number) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.host_configure,
      [id, mac, address, gateway, String(mtu)]);
  }

  createConfiguredHost(id: string, name: string, mac: string, address: string,
    gateway: string, mtu: number) {
    // Creation and protocol-stack configuration share one C++ transaction.
    return this.mutation(LAB_RUNTIME_PROTOCOL.host_create_configured,
      [id, name, mac, address, gateway, String(mtu)]);
  }

  setHostName(id: string, name: string) {
    // Name changes retain stable node and host handles. The protocol operation
    // updates the C++ registry so snapshots, checkpoint exports and topology
    // labels cannot diverge from the accepted project intent.
    return this.mutation(LAB_RUNTIME_PROTOCOL.host_name_set, [id, name]);
  }

  updateHost(id: string, name: string, mac: string, address: string,
    gateway: string, mtu: number) {
    // One framed operation lets the control owner commit registry display data
    // and host-stack identity together. This avoids UI-level rollback across
    // two independently acknowledged mutations.
    return this.mutation(LAB_RUNTIME_PROTOCOL.host_update,
      [id, name, mac, address, gateway, String(mtu)]);
  }

  createSession(sessionId: string, routerId: string,
    mode: "operational" | "global" | "exclusive" | "private" | "read-only" =
      "operational") {
    return this.mutation(LAB_RUNTIME_PROTOCOL.session_create,
      [sessionId, routerId, mode]);
  }

  closeSession(sessionId: string) {
    return this.mutation(LAB_RUNTIME_PROTOCOL.session_close, [sessionId]);
  }

  sessionState(sessionId: string) {
    return this.send(LAB_RUNTIME_PROTOCOL.session_state, [sessionId]).then(expectSuccess);
  }

  async terminalState(sessionId: string): Promise<RouterTerminalState> {
    return terminalSuffix(await this.sessionState(sessionId)).state;
  }

  executeSession(sessionId: string, input: string) {
    return this.send(LAB_RUNTIME_PROTOCOL.session_execute,
      [sessionId, input]).then(expectSuccess);
  }

  async terminalExecute(sessionId: string, input: string): Promise<string> {
    let response = terminalSuffix(await this.executeSession(sessionId, input));
    let output = response.output;
    while (response.state.banner === "pending") {
      // Polling only transfers completed terminal output. All send intervals,
      // reply timeouts and cancellation decisions use steady-clock deadlines
      // in C++, so timer throttling cannot accelerate emulated network time.
      await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 25));
      response = terminalSuffix(await this.send(
        LAB_RUNTIME_PROTOCOL.session_poll, [sessionId]).then(expectSuccess));
      output += response.output;
    }
    return output;
  }

  cancelSession(sessionId: string) {
    return this.send(LAB_RUNTIME_PROTOCOL.session_cancel,
      [sessionId]).then(expectSuccess);
  }

  completeSession(sessionId: string, input: string,
    trigger: "tab" | "question" | "space") {
    return this.send(LAB_RUNTIME_PROTOCOL.session_complete,
      [sessionId, input, trigger]).then(expectSuccess);
  }

  async startHostPing(sourceId: string, destination: string, sequence: number) {
    expectSuccess(await this.send(LAB_RUNTIME_PROTOCOL.host_ping_start,
      [sourceId, destination, String(sequence)]));
  }

  hostPingStatus(sourceId: string, sequence: number) {
    return this.send(LAB_RUNTIME_PROTOCOL.host_ping_status,
      [sourceId, String(sequence)]).then(expectSuccess);
  }

  setCapturePoint(kind: "link-direction" | "router-ingress" |
    "router-egress" | "cpm-punt", objectId: string, portId: string,
    direction: 0 | 1, selected: boolean) {
    // Stable project IDs identify the requested location. C++ resolves them
    // to generation-bearing handles and allocates the persistent PCAPNG point
    // identity, so React cannot accidentally target a reused runtime slot.
    return this.mutation(LAB_RUNTIME_PROTOCOL.capture_point_set,
      [kind, objectId, portId, String(direction), boolean(selected)]);
  }

  replaceCaptureSelection(points: ReadonlyArray<{
    kind: "link-direction" | "router-ingress" | "router-egress" | "cpm-punt";
    objectId: string; portId: string; direction: 0 | 1;
  }>) {
    // The forwarding owner receives one complete desired set. A rejected
    // location rolls the whole C++ transaction back instead of leaving the UI
    // to reverse an unknown prefix of independently accepted mutations.
    const values = points.flatMap((point) => [point.kind, point.objectId,
      point.portId, String(point.direction), "1"]);
    const payload = protocolMessage(String(points.length), values);
    return this.mutation(LAB_RUNTIME_PROTOCOL.capture_selection_replace,
      [payload]);
  }

  exportCapture(): Promise<Uint8Array> { return this.binary("capture-export"); }
  exportCheckpoint(): Promise<Uint8Array> { return this.binary("checkpoint-export"); }

  importCheckpoint(bytes: Uint8Array): Promise<string> {
    const id = this.nextRequestId++;
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error("Runtime client is closed"));
        return;
      }
      const buffer = bytes.slice().buffer;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, action: "checkpoint-import", bytes: buffer }, [buffer]);
    });
  }

  async applyProject(project: LabProjectV3): Promise<LabRuntimeSnapshotV5> {
    // This method is used on a fresh replacement Worker. A failed replay never
    // mutates the currently visible runtime owned by the caller's old client.
    let snapshot = await this.snapshot();
    if (snapshot.routers.length || snapshot.hosts.length || snapshot.links.length) {
      throw new Error("Project replay requires an empty runtime");
    }
    for (const router of project.routers) {
      snapshot = await this.createRouter(router.id, router.profileId, router.systemName);
      // The same generated catalog used by project validation decides whether
      // card inventory is mutable. No chassis name is embedded in this branch.
      const catalogProfile = PROFILE_CATALOG.profiles.find(
        (item) => item.id === router.profileId)!;
      if (!catalogProfile.fixed) {
        for (const card of router.hardware.cards) {
          snapshot = await this.setCard(router.id, card.slot,
            card.provisionedType, card.equippedType);
          for (const mda of card.mdas) {
            if (mda.provisionedType || mda.equippedType) {
              snapshot = await this.setMda(router.id, card.slot, mda.slot,
                mda.provisionedType, mda.equippedType);
            }
            if (mda.provisionedType)
              snapshot = await this.setMdaAdmin(router.id, card.slot, mda.slot,
                mda.admin === "up");
          }
          if (card.provisionedType)
            snapshot = await this.setCardAdmin(router.id, card.slot,
              card.admin === "up");
        }
      }
      for (const port of router.running.ports) {
        // Running port intent is independent from physical presence. The core
        // validates that the coordinate and speed are possible for the chassis
        // and withholds carrier if later equipment is incompatible.
        snapshot = await this.configurePort(router.id, port);
      }
      for (const item of router.running.interfaces) {
        snapshot = await this.configureInterface(router.id, item);
      }
      for (const route of router.running.staticRoutes) {
        snapshot = await this.addStaticRoute(router.id, route.prefix, route.nextHop);
      }
    }
    for (const host of project.hosts) {
      snapshot = await this.createConfiguredHost(host.id, host.name,
        host.eth0.mac, host.eth0.address, host.eth0.gateway, host.eth0.mtu);
    }
    for (const link of project.links) {
      snapshot = await this.createLink(link.id, link.endpoints[0].nodeId,
        link.endpoints[0].portId, link.endpoints[1].nodeId,
        link.endpoints[1].portId, link.propagationDelayNs, link.admin === "up");
    }
    return snapshot;
  }

  telemetrySnapshot(base: LabRuntimeSnapshotV5): LabRuntimeSnapshotV5 {
    // Absence during startup is expected. Returning the same object makes the
    // display polling loop a no-op until the Worker publishes its page.
    return this.telemetryPage ? readTelemetrySnapshot(this.telemetryPage, base)
      : base;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const pending of this.pending.values()) {
      pending.reject(new Error("Runtime client is closing"));
    }
    for (const pending of this.binaryPending.values()) {
      pending.reject(new Error("Runtime client is closing"));
    }
    this.pending.clear();
    this.binaryPending.clear();
    this.worker.postMessage({ id: 0, shutdown: true });
    window.setTimeout(() => this.worker.terminate(), 2000);
  }
}
