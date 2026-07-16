// Existing Router Lab composition connected to the multi-device runtime. The
// DOM hierarchy and CSS classes remain the approved UI contract. React owns
// portable format 3 intent while C++ owns every operational state transition.

import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import { createEmptyProjectV3, createRouterProjectV3, equippedRouterPorts,
  parseLabProjectV3, PROFILE_CATALOG, type DeviceProfileId,
  type HostProjectV3, type LabProjectV3, type LabRuntimeSnapshotV5,
  type LinkProjectV3, type RouterProjectV3, type RuntimeRouterV5,
  type TerminalPresentationV2 } from "@router-simulator/contracts";
import { MultiRouterRuntimeClient, type RouterTerminalState } from "../runtime/multi-router-client";
import { createCheckpointManifestV2, downloadBinary, exportProjectV3,
  importNetsimV2, loadActiveProjectV3, loadProjectBinaryV3,
  loadProjectPresentation, projectCheckpointNameV3, saveLabProjectV3, saveProjectBinaryV3,
  saveProjectPresentation } from "../persistence";
import { Inspector, type RouterTab } from "./Inspector";
import { PanelResizeHandle } from "./PanelResizeHandle";
import { TerminalPanel } from "./TerminalPanel";
import type { TerminalCheckpointProvider } from "./terminal-model";
import type { TerminalPanelPresentation } from "./terminal-contract";
import { Topology } from "./Topology";
import { automaticTopologyLayout } from "./topology-layout";
import { CaptureWorkspace, ConfigWorkspace, DevicesWorkspace, NotesWorkspace,
  SettingsWorkspace, SnapshotWorkspace, type WorkspaceView } from "./WorkspaceViews";
import { Camera, Cable, ChevronDown, CircleUser, Download, EllipsisVertical,
  Monitor, NotebookPen, Radio, Router as RouterIcon, Save, Server,
  Settings, SlidersHorizontal, Waypoints, X } from "lucide-react";

type CaptureKind = "link-direction" | "router-ingress" | "router-egress" |
  "cpm-punt";
type CaptureSelection = { key: string; kind: CaptureKind; objectId: string;
  portId: string; direction: 0 | 1 };

function captureKey(kind: CaptureKind, objectId: string, portId: string,
  direction: 0 | 1): string {
  // Delimited keys are local React identity only. The runtime still receives
  // separate typed fields and resolves generation-bearing handles itself.
  return `${kind}:${objectId}:${portId}:${direction}`;
}

function captureSelectionsFromSnapshot(snapshot: LabRuntimeSnapshotV5):
  CaptureSelection[] {
  // Runtime numeric IDs remain an internal capture-store concern. React keys
  // are reconstructed from portable locations so a restored selection binds
  // to the same visible checkbox without exposing handle generations.
  return snapshot.capturePoints.map((point) => ({
    key: captureKey(point.kind, point.objectId, point.portId, point.direction),
    kind: point.kind, objectId: point.objectId, portId: point.portId,
    direction: point.direction
  }));
}

function visibleFailure(area: "startup" | "operation", cause: unknown): string {
  console.error(`Lab ${area} failure`, cause);
  return cause instanceof Error ? cause.message : area === "startup"
    ? "The lab could not start." : "The operation could not be completed.";
}

function freeId(prefix: string, values: readonly string[]): string {
  const used = new Set(values);
  for (let index = 1; ; ++index) {
    const id = `${prefix}${index}`;
    if (!used.has(id)) return id;
  }
}

function downloadManifest(name: string, value: unknown): void {
  const bytes = new TextEncoder().encode(JSON.stringify(value, null, 2));
  downloadBinary(name, bytes, "application/json");
}

function mergeRuntimeRouter(project: LabProjectV3,
  runtimeRouter: RuntimeRouterV5): LabProjectV3 {
  const before = project.routers.find((router) => router.id === runtimeRouter.id);
  if (!before) return project;
  const livePorts = new Map(runtimeRouter.ports.map((port) => [port.id, port]));
  const retained = before.running.ports.filter((port) => !livePorts.has(port.id));
  const router: RouterProjectV3 = {
    ...before,
    systemName: runtimeRouter.systemName,
    hardware: { cards: runtimeRouter.cards.map((card) => ({
      slot: card.slot, admin: card.admin ? "up" : "down",
      provisionedType: card.provisionedType,
      equippedType: card.equippedType,
      mdas: card.mdas.map((mda) => ({ slot: mda.slot,
        admin: mda.admin ? "up" : "down",
        provisionedType: mda.provisionedType,
        equippedType: mda.equippedType }))
    })) },
    running: {
      systemName: runtimeRouter.systemName,
      ports: [...retained, ...runtimeRouter.ports.map((port) => ({
        id: port.id, admin: port.admin ? "up" as const : "down" as const,
        mtu: port.mtu, speedMbps: port.speedMbps,
        description: port.description
      }))],
      interfaces: runtimeRouter.interfaces.map((item) => ({
        name: item.name, portId: item.portId, address: item.address,
        admin: item.admin ? "up" as const : "down" as const
      })),
      staticRoutes: runtimeRouter.staticRoutes.map((route) => ({ ...route }))
    }
  };
  return { ...project, routers: project.routers.map((item) =>
    item.id === router.id ? router : item) };
}

function snapshotMatchesProject(project: LabProjectV3,
  snapshot: LabRuntimeSnapshotV5): boolean {
  // A recovery checkpoint is accepted only for the exact portable object
  // graph. This prevents an older, still ABI-compatible lab from replacing a
  // newer project merely because both were saved under the same browser key.
  const routerKeys = project.routers.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const liveRouterKeys = snapshot.routers.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const hostKeys = project.hosts.map((item) => item.id).sort();
  const liveHostKeys = snapshot.hosts.map((item) => item.id).sort();
  const linkKeys = project.links.map((item) => item.id).sort();
  const liveLinkKeys = snapshot.links.map((item) => item.id).sort();
  return JSON.stringify([routerKeys, hostKeys, linkKeys]) ===
    JSON.stringify([liveRouterKeys, liveHostKeys, liveLinkKeys]);
}

function mergeRuntimeProject(project: LabProjectV3,
  snapshot: LabRuntimeSnapshotV5): LabProjectV3 {
  let merged = project;
  for (const router of snapshot.routers)
    merged = mergeRuntimeRouter(merged, router);
  merged = {
    ...merged,
    hosts: merged.hosts.map((host) => {
      const live = snapshot.hosts.find((item) => item.id === host.id);
      return live ? { ...host, name: live.name, eth0: { ...host.eth0,
        mac: live.mac, address: live.address, gateway: live.gateway,
        mtu: live.mtu } } : host;
    }),
    links: merged.links.map((link) => {
      const live = snapshot.links.find((item) => item.id === link.id);
      return live ? { ...link, admin: live.admin ? "up" as const : "down" as const,
        propagationDelayNs: live.propagationDelayNs,
        endpoints: live.endpoints } : link;
    })
  };
  return parseLabProjectV3(merged);
}

export function App() {
  const [project, setProject] = useState<LabProjectV3>(() => createEmptyProjectV3());
  const [snapshot, setSnapshot] = useState<LabRuntimeSnapshotV5>();
  const [telemetrySnapshot, setTelemetrySnapshot] = useState<LabRuntimeSnapshotV5>();
  const [selected, setSelected] = useState<string>();
  const [runtimeError, setRuntimeError] = useState<string>();
  const [operationError, setOperationError] = useState<string>();
  const [runtime, setRuntime] = useState<MultiRouterRuntimeClient>();
  const [projectLoaded, setProjectLoaded] = useState(false);
  const [view, setView] = useState<WorkspaceView>("topology");
  const [captureSelections, setCaptureSelections] = useState<CaptureSelection[]>([]);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const [confirmNewProject, setConfirmNewProject] = useState(false);
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved">("idle");
  const [topologyTool, setTopologyTool] = useState<"select" | "link">("select");
  const [routerTab, setRouterTab] = useState<RouterTab>("chassis");
  const [terminalPresentations, setTerminalPresentations] = useState<
    Record<string, TerminalPanelPresentation>>({});
  const [terminalGeneration, setTerminalGeneration] = useState(0);
  const [activeSession, setActiveSession] = useState<string>();
  const [pendingRouterPosition, setPendingRouterPosition] = useState<
    { x: number; y: number; systemName: string } | undefined>();
  const [pendingHost, setPendingHost] = useState<{
    id: string; position: { x: number; y: number }; name: string; mac: string;
    address: string; gateway: string; mtu: string;
  }>();
  const [linkNodes, setLinkNodes] = useState<readonly [string, string]>();
  const [linkPorts, setLinkPorts] = useState<readonly [string, string]>(["", ""]);
  const importRef = useRef<HTMLInputElement>(null);
  const checkpointRef = useRef<HTMLInputElement>(null);
  const terminalCheckpointProviderRef = useRef<TerminalCheckpointProvider | undefined>(undefined);
  const runtimeRef = useRef<MultiRouterRuntimeClient | undefined>(undefined);
  runtimeRef.current = runtime;

  useEffect(() => {
    let cancelled = false;
    let client: MultiRouterRuntimeClient | undefined;
    void (async () => {
      const stored = await loadActiveProjectV3();
      const recoveryName = await projectCheckpointNameV3(stored);
      const [checkpoint, presentation] = await Promise.all([
        loadProjectBinaryV3(stored.projectId, recoveryName),
        loadProjectPresentation(stored.projectId)
      ]);
      client = new MultiRouterRuntimeClient();
      let live = await client.applyProject(stored);
      if (checkpoint) {
        try {
          await client.importCheckpoint(checkpoint);
          const recovered = await client.snapshot();
          if (snapshotMatchesProject(stored, recovered)) live = recovered;
          else throw new Error("Recovery checkpoint object graph is stale");
        } catch {
          client.close();
          client = new MultiRouterRuntimeClient();
          live = await client.applyProject(stored);
        }
      }
      if (cancelled) return client.close();
      const recoveredProject = mergeRuntimeProject(stored, live);
      setProject(recoveredProject);
      setSnapshot(live);
      setCaptureSelections(captureSelectionsFromSnapshot(live));
      setRuntime(client);
      setSelected(presentation?.selectedNodeId ?? recoveredProject.routers[0]?.id ??
        recoveredProject.hosts[0]?.id);
      if (presentation?.terminal) {
        const restored = Object.fromEntries(presentation.terminal.sessions.map(
          (item) => [item.sessionId, { editors: item.editors,
            queuedInput: item.queuedInput, ...(item.pager ? { pager: item.pager } : {}) }]
        ));
        setTerminalPresentations(restored);
        const restoredActive = presentation.terminal.activeSessionId;
        if (restoredActive && live.sessions.some((item) => item.id === restoredActive)) {
          setActiveSession(restoredActive);
          setTerminalOpen(true);
        }
      }
      setProjectLoaded(true);
    })().catch((cause) => !cancelled && setRuntimeError(visibleFailure("startup", cause)));
    return () => {
      cancelled = true;
      runtimeRef.current?.close();
      if (!runtimeRef.current) client?.close();
    };
  }, []);

  useEffect(() => {
    if (!projectLoaded) return;
    try { parseLabProjectV3(project); } catch { return; }
    const timer = window.setTimeout(() => {
      const save = async () => {
        const client = runtimeRef.current;
        const active = terminalCheckpointProviderRef.current?.snapshot();
        const presentations = { ...terminalPresentations,
          ...(activeSession && active ? { [activeSession]: active } : {}) };
        const terminal: TerminalPresentationV2 = { version: 2,
          ...(activeSession && presentations[activeSession]
            ? { activeSessionId: activeSession } : {}),
          sessions: (snapshot?.sessions ?? []).flatMap((session) => {
            const value = presentations[session.id];
            return value ? [{ sessionId: session.id, routerId: session.routerId,
              engine: session.engine, editors: value.editors,
              queuedInput: value.queuedInput,
              ...(value.pager ? { pager: value.pager } : {}) }] : [];
          }) };
        // The checkpoint is written before the project head. A crash can leave
        // an older project, but startup verifies the recovered object graph
        // before making it visible.
        if (client) {
          const checkpoint = await client.exportCheckpoint();
          const recoveryName = await projectCheckpointNameV3(project);
          await saveProjectBinaryV3(project.projectId,
            recoveryName, checkpoint);
        }
        await saveLabProjectV3({ ...project, updatedAt: new Date().toISOString() });
        await saveProjectPresentation(project.projectId,
          { projectId: project.projectId, selectedNodeId: selected, terminal });
      };
      void save().catch((cause) =>
        setOperationError(visibleFailure("operation", cause)));
    }, 350);
    return () => clearTimeout(timer);
  }, [activeSession, project, projectLoaded, selected, snapshot,
    terminalPresentations]);

  useEffect(() => {
    // Slow snapshots continue to drive persistence and structural operations.
    // This separate projection updates only visible counters and port state,
    // avoiding a checkpoint write every time the display samples telemetry.
    setTelemetrySnapshot(snapshot);
    if (!runtime || !snapshot) return;
    const timer = window.setInterval(() => {
      setTelemetrySnapshot((current) => runtime.telemetrySnapshot(
        current ?? snapshot));
    }, PROFILE_CATALOG.runtime.telemetry_publish_interval_milliseconds);
    return () => clearInterval(timer);
  }, [runtime, snapshot]);

  const mutate = useCallback(async (next: LabProjectV3,
    operation: (client: MultiRouterRuntimeClient) => Promise<LabRuntimeSnapshotV5>) => {
    const client = runtimeRef.current;
    if (!client) throw new Error("Runtime is not ready");
    try {
      // Structural validation and runtime mutation share one visible failure
      // path. Invalid form input therefore cannot become an unhandled promise
      // rejection or a generic browser console error.
      const validated = parseLabProjectV3(next);
      const live = await operation(client);
      setProject(validated);
      setSnapshot(live);
      setOperationError(undefined);
      return live;
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
      throw cause;
    }
  }, []);

  const addRouter = useCallback((profileId: DeviceProfileId) => {
    const nodeIds = [...project.routers, ...project.hosts].map((item) => item.id);
    const id = freeId("r", nodeIds);
    const systemName = pendingRouterPosition?.systemName.trim() ?? "";
    if (!systemName) return;
    const router = createRouterProjectV3(id, profileId, systemName);
    const next = { ...project, routers: [...project.routers, router], layout: {
      ...project.layout, nodes: { ...project.layout.nodes,
        [id]: pendingRouterPosition ? { x: pendingRouterPosition.x,
          y: pendingRouterPosition.y } : {
          x: 330 + project.routers.length * 45, y: 220
        } } } };
    // The node appears only after the C++ owner accepts the generated profile.
    // This avoids a canvas-only router when catalog capacity or validation
    // rejects the operation and keeps project intent aligned with live state.
    void mutate(next, (client) => client.createRouter(id, profileId, router.systemName))
      .then(() => { setSelected(id); setPendingRouterPosition(undefined); })
      .catch(() => undefined);
  }, [mutate, pendingRouterPosition, project]);

  const addDevice = useCallback((kind: "router" | "host", position?: { x: number; y: number }) => {
    if (kind === "router") {
      // A chassis profile changes slot inventory and resource bounds, so a
      // generic drag cannot silently select one. The drop coordinate is kept
      // until the user confirms a generated catalog entry in the dialog.
      const nodeIds = [...project.routers, ...project.hosts].map((item) => item.id);
      const suggested = freeId("r", nodeIds).toUpperCase();
      const target = position ?? { x: 330 + project.routers.length * 45, y: 220 };
      // The first free R1..R16 name is a convenience only. It stays editable
      // because system-name is router configuration and cannot be derived from
      // a registry slot or canvas order.
      setPendingRouterPosition({ ...target, systemName: suggested });
    } else {
      const nodeIds = [...project.routers, ...project.hosts].map((item) => item.id);
      const id = freeId("h", nodeIds);
      // Addressing and MAC identity are network configuration, not canvas
      // decoration. The host is therefore not created until the user supplies
      // a complete interface record and project validation accepts it.
      setPendingHost({ id, position: position ?? {
        x: 90, y: 150 + project.hosts.length * 120
      }, name: id.toUpperCase(), mac: "", address: "", gateway: "", mtu: "" });
    }
  }, [project]);

  const addHost = useCallback(() => {
    if (!pendingHost) return;
    const mtu = Number(pendingHost.mtu);
    const host: HostProjectV3 = { id: pendingHost.id, kind: "host",
      name: pendingHost.name, eth0: { mac: pendingHost.mac,
        address: pendingHost.address, gateway: pendingHost.gateway, mtu,
        mode: "ethernet" } };
    const next = { ...project, hosts: [...project.hosts, host], layout: {
      ...project.layout, nodes: { ...project.layout.nodes,
        [host.id]: pendingHost.position } } };
    void mutate(next, (client) => client.createConfiguredHost(host.id,
      host.name, host.eth0.mac, host.eth0.address, host.eth0.gateway,
      host.eth0.mtu)).then(() => { setSelected(host.id); setPendingHost(undefined); })
      .catch(() => undefined);
  }, [mutate, pendingHost, project]);

  const updateLayout = useCallback((id: string, position: { x: number; y: number }) => {
    if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) return;
    setProject((current) => ({ ...current, layout: { ...current.layout,
      nodes: { ...current.layout.nodes, [id]: position } } }));
  }, []);

  const selectDevice = useCallback((id: string) => {
    setSelected(id);
    setInspectorOpen(true);
  }, []);

  const availablePorts = (nodeId: string) => {
    const router = project.routers.find((item) => item.id === nodeId);
    const ports = router ? equippedRouterPorts(router).map((item) => item.id) : ["eth0"];
    const used = new Set(project.links.flatMap((link) => link.endpoints
      .filter((endpoint) => endpoint.nodeId === nodeId).map((endpoint) => endpoint.portId)));
    return ports.filter((port) => !used.has(port));
  };

  const createLink = () => {
    if (!linkNodes || !linkPorts[0] || !linkPorts[1]) return;
    const id = freeId("link", project.links.map((item) => item.id));
    const link: LinkProjectV3 = { id, endpoints: [
      { nodeId: linkNodes[0], portId: linkPorts[0] },
      { nodeId: linkNodes[1], portId: linkPorts[1] }
    ], admin: "up", propagationDelayNs: 0 };
    void mutate({ ...project, links: [...project.links, link] }, (client) =>
      client.createLink(id, linkNodes[0], linkPorts[0], linkNodes[1], linkPorts[1], 0, true))
      .then(() => setLinkNodes(undefined)).catch(() => undefined);
  };

  const setLink = useCallback((linkId: string, up: boolean) => {
    const next = { ...project, links: project.links.map((link) =>
      link.id === linkId ? { ...link, admin: up ? "up" as const : "down" as const } : link) };
    return mutate(next, (client) => client.setLinkAdmin(linkId, up))
      .catch(() => undefined);
  }, [mutate, project]);

  const updateLink = useCallback((linkId: string, up: boolean,
    propagationDelayNs: number) => {
    const next = { ...project, links: project.links.map((link) => link.id === linkId
      ? { ...link, admin: up ? "up" as const : "down" as const,
        propagationDelayNs } : link) };
    void mutate(next, (client) => client.setLinkProperties(linkId, up,
      propagationDelayNs)).catch(() => undefined);
  }, [mutate, project]);

  const deleteLink = useCallback((linkId: string) => {
    const next = { ...project, links: project.links.filter((link) => link.id !== linkId) };
    void mutate(next, (client) => client.deleteLink(linkId)).then(() => {
      setSelected((current) => current === linkId ? undefined : current);
      setCaptureSelections((current) => current.filter((item) =>
        !(item.kind === "link-direction" && item.objectId === linkId)));
    }).catch(() => undefined);
  }, [mutate, project]);

  const deleteNode = useCallback((nodeId: string) => {
    const router = project.routers.find((item) => item.id === nodeId);
    const host = project.hosts.find((item) => item.id === nodeId);
    if (!router && !host) return;
    const nodes = { ...project.layout.nodes };
    delete nodes[nodeId];
    const next = { ...project,
      routers: project.routers.filter((item) => item.id !== nodeId),
      hosts: project.hosts.filter((item) => item.id !== nodeId),
      links: project.links.filter((link) => !link.endpoints.some(
        (endpoint) => endpoint.nodeId === nodeId)),
      layout: { ...project.layout, nodes } };
    void mutate(next, (client) => router ? client.deleteRouter(nodeId)
      : client.deleteHost(nodeId)).then(() => {
        setSelected((current) => current === nodeId ? undefined : current);
        // Router deletion closes every runtime-owned session for that router.
        // Remove matching renderer snapshots too, otherwise a later session
        // reusing an ID could inherit an unrelated edit buffer or pager.
        const removedSessions = snapshot?.sessions.filter((item) =>
          item.routerId === nodeId).map((item) => item.id) ?? [];
        if (removedSessions.includes(activeSession ?? "")) {
          setActiveSession(undefined);
          setTerminalOpen(false);
        }
        setTerminalPresentations((current) => Object.fromEntries(
          Object.entries(current).filter(([id]) => !removedSessions.includes(id))));
        setCaptureSelections((current) => current.filter((item) =>
          item.objectId !== nodeId));
      }).catch(() => undefined);
  }, [activeSession, mutate, project, snapshot]);

  const updateHost = useCallback((host: HostProjectV3) => {
    const previous = project.hosts.find((item) => item.id === host.id);
    if (!previous) return;
    const next = { ...project, hosts: project.hosts.map((item) => item.id === host.id ? host : item) };
    if (JSON.stringify(previous) === JSON.stringify(host)) return;
    void mutate(next, (client) => client.updateHost(host.id, host.name,
      host.eth0.mac, host.eth0.address, host.eth0.gateway, host.eth0.mtu))
      .catch(() => undefined);
  }, [mutate, project]);

  const updateRouter = useCallback((router: RouterProjectV3) => {
    const previous = project.routers.find((item) => item.id === router.id);
    if (!previous) return;
    const next = { ...project, routers: project.routers.map((item) => item.id === router.id ? router : item) };
    // One runtime operation stages and validates the complete datastore. The
    // project is published only after the control owner commits every change.
    void mutate(next, (client) => client.replaceRouterConfiguration(router))
      .catch(() => undefined);
  }, [mutate, project]);

  const setCard = (routerId: string, slot: number, provisioned: string | null,
    equipped: string | null) => {
    const router = project.routers.find((item) => item.id === routerId);
    if (!router) return;
    const next = { ...project, routers: project.routers.map((item) => item.id === routerId
      ? { ...item, hardware: { cards: item.hardware.cards.map((card) => card.slot === slot
        ? { ...card, admin: provisioned ? card.admin : "down" as const,
          provisionedType: provisioned, equippedType: equipped } : card) } } : item) };
    void mutate(next, (client) => client.setCard(routerId, slot, provisioned, equipped))
      .catch(() => undefined);
  };

  const setMda = (routerId: string, cardSlot: number, mdaSlot: number,
    provisioned: string | null, equipped: string | null) => {
    const next = { ...project, routers: project.routers.map((item) => item.id === routerId
      ? { ...item, hardware: { cards: item.hardware.cards.map((card) => card.slot === cardSlot
        ? { ...card, mdas: card.mdas.map((mda) => mda.slot === mdaSlot
          ? { ...mda, admin: provisioned ? mda.admin : "down" as const,
            provisionedType: provisioned, equippedType: equipped } : mda) } : card) } } : item) };
    void mutate(next, (client) => client.setMda(routerId, cardSlot, mdaSlot, provisioned, equipped))
      .catch(() => undefined);
  };

  const setCardAdmin = (routerId: string, slot: number, enabled: boolean) => {
    const next = { ...project, routers: project.routers.map((item) =>
      item.id === routerId ? { ...item, hardware: { cards: item.hardware.cards.map(
        (card) => card.slot === slot ? { ...card, admin: enabled ? "up" as const
          : "down" as const } : card) } } : item) };
    void mutate(next, (client) => client.setCardAdmin(routerId, slot, enabled))
      .catch(() => undefined);
  };

  const setMdaAdmin = (routerId: string, cardSlot: number, mdaSlot: number,
    enabled: boolean) => {
    const next = { ...project, routers: project.routers.map((item) =>
      item.id === routerId ? { ...item, hardware: { cards: item.hardware.cards.map(
        (card) => card.slot === cardSlot ? { ...card, mdas: card.mdas.map((mda) =>
          mda.slot === mdaSlot ? { ...mda, admin: enabled ? "up" as const
            : "down" as const } : mda) } : card) } } : item) };
    void mutate(next, (client) => client.setMdaAdmin(routerId, cardSlot,
      mdaSlot, enabled)).catch(() => undefined);
  };

  const preserveActiveTerminal = useCallback(() => {
    // The checkpoint provider is borrowed from the currently mounted xterm.
    // Sample it synchronously before changing the key, because unmount clears
    // the provider and deliberately destroys the renderer-owned objects.
    const presentation = terminalCheckpointProviderRef.current?.snapshot();
    if (activeSession && presentation) {
      setTerminalPresentations((current) => ({ ...current,
        [activeSession]: presentation }));
    }
  }, [activeSession]);

  const selectTerminalSession = useCallback((sessionId: string) => {
    if (sessionId === activeSession) return;
    preserveActiveTerminal();
    setActiveSession(sessionId);
    setTerminalGeneration((value) => value + 1);
    setTerminalOpen(true);
  }, [activeSession, preserveActiveTerminal]);

  const createConsole = useCallback((routerId: string) => {
    const client = runtimeRef.current;
    if (!client) return;
    const liveSessions = snapshot?.sessions ?? [];
    const routerSessionCount = liveSessions.filter((item) =>
      item.routerId === routerId).length;
    if (routerSessionCount >= PROFILE_CATALOG.limits.sessions_per_router) {
      setOperationError(`Router ${routerId} has reached its terminal session limit.`);
      return;
    }
    // Compact global session IDs stay within the protocol identifier bound
    // even when a user chooses the longest legal router ID.
    const sessionId = freeId("s", liveSessions.map((item) => item.id));
    void client.createSession(sessionId, routerId).then((live) => {
      preserveActiveTerminal();
      setSnapshot(live);
      setSelected(routerId);
      setActiveSession(sessionId);
      setTerminalGeneration((value) => value + 1);
      setTerminalOpen(true);
      setOperationError(undefined);
    }).catch((cause) => setOperationError(visibleFailure("operation", cause)));
  }, [preserveActiveTerminal, snapshot]);

  const openConsole = useCallback((routerId: string) => {
    const existing = snapshot?.sessions.find((item) => item.routerId === routerId);
    if (existing) {
      setSelected(routerId);
      selectTerminalSession(existing.id);
      return;
    }
    createConsole(routerId);
  }, [createConsole, selectTerminalSession, snapshot]);

  const closeTerminalSession = useCallback((sessionId: string) => {
    const client = runtimeRef.current;
    if (!client) return;
    if (sessionId === activeSession) preserveActiveTerminal();
    void client.closeSession(sessionId).then((live) => {
      const remaining = live.sessions;
      setSnapshot(live);
      setTerminalPresentations((current) => Object.fromEntries(
        Object.entries(current).filter(([id]) => id !== sessionId)));
      if (sessionId === activeSession) {
        const next = remaining[0]?.id;
        setActiveSession(next);
        setTerminalOpen(Boolean(next));
        setTerminalGeneration((value) => value + 1);
      }
      setOperationError(undefined);
    }).catch((cause) => setOperationError(visibleFailure("operation", cause)));
  }, [activeSession, preserveActiveTerminal]);

  const terminalState = async (): Promise<RouterTerminalState> => {
    if (!runtime || !activeSession) throw new Error("No router console is selected");
    return runtime.terminalState(activeSession);
  };
  const execute = async (command: string) => {
    if (!runtime || !activeSession) throw new Error("No router console is selected");
    const routerId = snapshot?.sessions.find((item) =>
      item.id === activeSession)?.routerId;
    const output = await runtime.terminalExecute(activeSession, command);
    // Candidate navigation has no running-state effect, while classic writes
    // and MD commits can change the project. Always read the owner projection
    // after completion so autosave cannot later replay stale React intent.
    const live = await runtime.snapshot();
    setSnapshot(live);
    const changedRouter = live.routers.find((item) => item.id === routerId);
    if (changedRouter) setProject((current) =>
      parseLabProjectV3(mergeRuntimeRouter(current, changedRouter)));
    return output;
  };
  const complete = async (input: string, trigger: "tab" | "question" | "space") => {
    if (!runtime || !activeSession) throw new Error("No router console is selected");
    return runtime.completeSession(activeSession, input, trigger);
  };
  const cancelTerminal = () => {
    if (runtime && activeSession) void runtime.cancelSession(activeSession)
      .catch((cause) => setOperationError(visibleFailure("operation", cause)));
  };

  const ping = async (sourceId: string, destination: string) => {
    if (!runtime) throw new Error("Runtime is not ready");
    const sequence = Date.now() & 0x7fffffff;
    await runtime.startHostPing(sourceId, destination, sequence);
    return runtime.hostPingStatus(sourceId, sequence);
  };

  const persistNow = async () => {
    setSaveState("saving");
    try { await saveLabProjectV3({ ...project, updatedAt: new Date().toISOString() }); setSaveState("saved"); }
    catch (cause) { setSaveState("idle"); setOperationError(visibleFailure("operation", cause)); }
  };
  const exportCaptureNow = async () => {
    if (!runtime) return;
    const bytes = await runtime.exportCapture();
    await saveProjectBinaryV3(project.projectId, "capture.pcapng", bytes);
    downloadBinary(`${project.name}.pcapng`, bytes, "application/vnd.tcpdump.pcap");
  };
  const setCaptureSelection = async (kind: CaptureKind, objectId: string,
    portId: string, direction: 0 | 1, selected: boolean) => {
    if (!runtime) return;
    const key = captureKey(kind, objectId, portId, direction);
    try {
      const live = await runtime.setCapturePoint(kind, objectId, portId,
        direction, selected);
      setSnapshot(live);
      setCaptureSelections((current) => selected
        ? current.some((item) => item.key === key) ? current
          : [...current, { key, kind, objectId, portId, direction }]
        : current.filter((item) => item.key !== key));
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  };
  const toggleCapture = async () => {
    if (!runtime) return;
    if (!project.links.length) {
      setOperationError("Add a physical link before starting packet capture.");
      return;
    }
    const selected = captureSelections.length === 0;
    try {
      // The initial capture surface represents both wire directions of every
      // physical link. The runtime applies the complete set atomically while
      // later hierarchy controls can still toggle one location independently.
      const targets: CaptureSelection[] = selected
        ? project.links.flatMap((link) => ([0, 1] as const).map((direction) => ({
          key: captureKey("link-direction", link.id, "", direction),
          kind: "link-direction" as const, objectId: link.id, portId: "",
          direction
        }))) : captureSelections;
      const live = await runtime.replaceCaptureSelection(selected ? targets : []);
      setSnapshot(live);
      setCaptureSelections(captureSelectionsFromSnapshot(live));
      setOperationError(undefined);
    } catch (cause) {
      // The C++ replacement transaction leaves both the previous selection and
      // retained records untouched when any requested location is invalid.
      setOperationError(visibleFailure("operation", cause));
    }
  };
  const exportCheckpointNow = async () => {
    if (!runtime) return;
    const [checkpoint, capture] = await Promise.all([runtime.exportCheckpoint(), runtime.exportCapture()]);
    const active = terminalCheckpointProviderRef.current?.snapshot();
    const presentations = { ...terminalPresentations,
      ...(activeSession && active ? { [activeSession]: active } : {}) };
    const terminal: TerminalPresentationV2 = { version: 2,
      ...(activeSession && presentations[activeSession]
        ? { activeSessionId: activeSession } : {}),
      sessions: (snapshot?.sessions ?? []).flatMap((session) => {
        const value = presentations[session.id];
        return value ? [{ sessionId: session.id, routerId: session.routerId,
          engine: session.engine, editors: value.editors,
          queuedInput: value.queuedInput,
          ...(value.pager ? { pager: value.pager } : {}) }] : [];
      }) };
    const recoveryName = await projectCheckpointNameV3(project);
    await saveProjectBinaryV3(project.projectId, recoveryName, checkpoint);
    downloadManifest(`${project.name}.checkpoint.netsim`, createCheckpointManifestV2(
      project, checkpoint, capture, terminal));
  };
  const importFile = async (file?: File) => {
    if (!file) return;
    let replacement: MultiRouterRuntimeClient | undefined;
    try {
      const decoded = await importNetsimV2(file);
      replacement = new MultiRouterRuntimeClient();
      let live = await replacement.applyProject(decoded.project);
      if (decoded.checkpoint) { await replacement.importCheckpoint(decoded.checkpoint); live = await replacement.snapshot(); }
      const previous = runtimeRef.current;
      setRuntime(replacement); runtimeRef.current = replacement;
      setProject(decoded.project); setSnapshot(live); setSelected(decoded.project.routers[0]?.id ?? decoded.project.hosts[0]?.id);
      const importedPresentations = decoded.terminalPresentation
        ? Object.fromEntries(decoded.terminalPresentation.sessions.map((item) =>
          [item.sessionId, { editors: item.editors, queuedInput: item.queuedInput,
            ...(item.pager ? { pager: item.pager } : {}) }])) : {};
      const importedActive = decoded.terminalPresentation?.activeSessionId;
      setTerminalPresentations(importedPresentations);
      setActiveSession(importedActive && live.sessions.some((item) =>
        item.id === importedActive) ? importedActive : undefined);
      setTerminalOpen(Boolean(importedActive && live.sessions.some((item) =>
        item.id === importedActive)));
      setCaptureSelections(captureSelectionsFromSnapshot(live));
      previous?.close(); replacement = undefined;
    } catch (cause) { replacement?.close(); setOperationError(visibleFailure("operation", cause)); }
  };
  const importCheckpointFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; event.target.value = "";
    if (!file || !runtime) return;
    let replacement: MultiRouterRuntimeClient | undefined;
    try {
      replacement = new MultiRouterRuntimeClient();
      await replacement.applyProject(project);
      await replacement.importCheckpoint(new Uint8Array(await file.arrayBuffer()));
      const live = await replacement.snapshot();
      if (!snapshotMatchesProject(project, live))
        throw new Error("Checkpoint belongs to a different laboratory topology");
      const previous = runtimeRef.current;
      runtimeRef.current = replacement;
      setRuntime(replacement);
      replacement = undefined;
      setSnapshot(live);
      setProject(mergeRuntimeProject(project, live));
      setCaptureSelections(captureSelectionsFromSnapshot(live));
      previous?.close();
    }
    catch (cause) {
      replacement?.close();
      setOperationError(visibleFailure("operation", cause));
    }
  };

  const resetProject = () => {
    const empty = createEmptyProjectV3();
    const replacement = new MultiRouterRuntimeClient();
    void replacement.snapshot().then((live) => {
      runtimeRef.current?.close(); runtimeRef.current = replacement; setRuntime(replacement);
      setProject(empty); setSnapshot(live); setSelected(undefined); setActiveSession(undefined);
      setTerminalOpen(false); setTerminalPresentations({}); setCaptureSelections([]);
      setConfirmNewProject(false);
      setProjectMenuOpen(false);
    }).catch((cause) => { replacement.close(); setOperationError(visibleFailure("operation", cause)); });
  };
  const resetLayout = () => setProject((current) => ({ ...current, layout: {
    ...current.layout,
    // Reset means a useful deterministic arrangement, not deletion of every
    // coordinate followed by the renderer's overlapping fallback positions.
    nodes: automaticTopologyLayout(current.routers.map((item) => item.id),
      current.hosts.map((item) => item.id))
  } }));
  const resizePanel = (field: "sidebarWidth" | "inspectorWidth" | "terminalHeight", value: number) =>
    setProject((current) => ({ ...current, layout: { ...current.layout, [field]: value } }));
  const registerTerminalCheckpointProvider = (provider: TerminalCheckpointProvider | undefined) => {
    terminalCheckpointProviderRef.current = provider;
  };
  const closeTerminal = () => {
    preserveActiveTerminal();
    setTerminalOpen(false);
  };
  const navigate = (next: WorkspaceView) => {
    setView(next); setProjectMenuOpen(false); setAccountMenuOpen(false); setMoreMenuOpen(false);
  };
  const selectedRouter = project.routers.find((item) => item.id === selected);
  const terminalTabs = (snapshot?.sessions ?? []).map((session) => ({
    id: session.id,
    label: `${project.routers.find((router) => router.id === session.routerId)
      ?.systemName ?? session.routerId} console`
  }));
  const activeTerminalSession = snapshot?.sessions.find((item) =>
    item.id === activeSession);
  const activeTerminalRouter = project.routers.find((item) =>
    item.id === activeTerminalSession?.routerId);
  const visibleError = runtimeError ?? operationError;
  const displaySnapshot = telemetrySnapshot ?? snapshot;
  const shellStyle = { "--library-preferred-width": `${project.layout.sidebarWidth}px`,
    "--inspector-preferred-width": `${project.layout.inspectorWidth}px`,
    "--terminal-preferred-height": `${project.layout.terminalHeight}px` } as CSSProperties;

  return <main className={`app-shell ${inspectorOpen ? "" : "inspector-closed"} ${terminalOpen ? "" : "terminal-closed"}`} style={shellStyle}>
    <header className="topbar"><div className="brand-area"><button className="brand" aria-expanded={projectMenuOpen} onClick={() => setProjectMenuOpen((value) => !value)}><span className="brand-mark"><Waypoints size={17} strokeWidth={2.1} /></span><strong>Router Lab</strong><ChevronDown className="chevron" size={15} /></button>{projectMenuOpen && <div className="header-menu project-menu"><strong>{project.name}</strong><small>SR OS {PROFILE_CATALOG.release}</small>{confirmNewProject ? <div className="confirm-row"><span>Reset this lab?</span><button onClick={resetProject}>Reset</button><button onClick={() => setConfirmNewProject(false)}>Cancel</button></div> : <button onClick={() => setConfirmNewProject(true)}>New lab</button>}<button onClick={() => importRef.current?.click()}>Import project</button></div>}</div>
      <div className="top-context" aria-hidden><span className="top-context-name">{project.name}</span><span className="top-context-view">{view}</span></div>
      <div className="top-actions"><button className="icon-action" onClick={() => void persistNow()}><Save size={16} /> <span>{saveState === "saving" ? "Saving" : saveState === "saved" ? "Saved" : "Save"}</span></button><button className="icon-action" onClick={() => exportProjectV3(project)}><Download size={16} /> <span>Export</span></button><div className="more-wrap"><button className="more-action" title="More project actions" aria-expanded={moreMenuOpen} onClick={() => setMoreMenuOpen((value) => !value)}><EllipsisVertical size={18} /></button>{moreMenuOpen && <div className="header-menu more-menu"><button onClick={() => { setMoreMenuOpen(false); void exportCheckpointNow(); }}>Export checkpoint</button><button onClick={() => navigate("settings")}>Project settings</button></div>}</div><input ref={importRef} hidden type="file" accept=".netsim,application/json" onChange={(event) => { void importFile(event.target.files?.[0]); event.target.value = ""; }} /></div>
    </header>
    <div className="workspace"><aside className="library"><div className="panel-kicker">WORKSPACE</div><nav className="side-nav"><button className={view === "topology" ? "active" : ""} onClick={() => navigate("topology")}><span><Waypoints size={18} /></span>Topology</button><button className={view === "devices" ? "active" : ""} onClick={() => navigate("devices")}><span><Server size={18} /></span>Devices</button><button className={view === "captures" ? "active" : ""} onClick={() => navigate("captures")}><span><Radio size={18} /></span>Captures</button></nav><div className="side-divider" /><div className="panel-kicker">DEVICE PALETTE</div>
      <section><h3>ENDPOINTS</h3><button className="library-item" draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-router-lab-device", "host"); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => addDevice("host")}><span className="mini-icon"><Monitor size={18} /></span><span><strong>IP Host</strong><small>{project.hosts.length} configured</small></span></button></section>
      <section><h3>ROUTERS</h3><button className="library-item active" draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-router-lab-device", "router"); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => addDevice("router")}><span className="mini-icon router"><RouterIcon size={18} /></span><span><strong>7750 SR</strong><small>SR OS {PROFILE_CATALOG.release}</small></span></button></section>
      <section><h3>MEDIA</h3><button className={`library-item ${topologyTool === "link" ? "active" : ""}`} onClick={() => { navigate("topology"); setTopologyTool("link"); }}><span className="mini-icon link"><Cable size={17} /></span><span><strong>Physical link</strong><small>Connect free physical ports</small></span></button></section><div className="side-divider" /><div className="panel-kicker">PROJECT</div><nav className="project-nav"><button className={view === "configs" ? "active" : ""} onClick={() => navigate("configs")}><SlidersHorizontal size={16} /> <span>Configuration</span></button><button className={view === "snapshots" ? "active" : ""} onClick={() => navigate("snapshots")}><Camera size={16} /> <span>Snapshots</span></button><button className={view === "notes" ? "active" : ""} onClick={() => navigate("notes")}><NotebookPen size={16} /> <span>Notes</span></button></nav><div className="side-footer"><button className={view === "settings" ? "active" : ""} onClick={() => navigate("settings")}><Settings size={18} /> <span>Settings</span></button><div className="account-wrap"><button aria-expanded={accountMenuOpen} onClick={() => setAccountMenuOpen((value) => !value)}><CircleUser size={18} /> <span>admin</span><b><ChevronDown size={14} /></b></button>{accountMenuOpen && <div className="account-menu"><strong>Local administrator</strong><small>Browser-only session</small><button onClick={() => setAccountMenuOpen(false)}>Close</button></div>}</div></div><PanelResizeHandle axis="x" className="library-resizer" defaultValue={194} direction={1} label="Resize sidebar" min={64} max={Math.max(64, window.innerWidth - 64)} value={project.layout.sidebarWidth} onChange={(value) => resizePanel("sidebarWidth", value)} /></aside>
      <section className="center-stage">{visibleError && <div className="runtime-error"><strong>{runtimeError ? "Lab unavailable" : "Operation failed"}</strong><span>{visibleError}</span>{!runtimeError && <button onClick={() => setOperationError(undefined)}>Dismiss</button>}</div>}
        {view === "topology" ? <Topology project={project} snapshot={displaySnapshot} selected={selected} onSelect={selectDevice} onLayoutChange={updateLayout} onLinkToggle={(id, up) => void setLink(id, up)} onConnect={(first, second) => { setLinkNodes([first, second]); setLinkPorts(["", ""]); }} onDropDevice={(kind, position) => addDevice(kind, position)} onOpenHardware={() => { if (selectedRouter) setRouterTab("cards"); }} tool={topologyTool} onToolChange={setTopologyTool} /> : view === "devices" ? <DevicesWorkspace project={project} snapshot={displaySnapshot} onInspect={selectDevice} onConsole={openConsole} /> : view === "captures" ? <CaptureWorkspace project={project} snapshot={displaySnapshot} selections={captureSelections.map((item) => item.key)} onSelection={(kind, objectId, portId, direction, value) => void setCaptureSelection(kind, objectId, portId, direction, value)} onToggle={() => void toggleCapture()} onExport={() => void exportCaptureNow()} onCheckpoint={() => void exportCheckpointNow()} /> : view === "configs" ? <ConfigWorkspace router={selectedRouter} onChange={updateRouter} /> : view === "snapshots" ? <SnapshotWorkspace checkpointInput={checkpointRef} onExport={() => void exportCheckpointNow()} onImport={(event) => void importCheckpointFile(event)} /> : view === "notes" ? <NotesWorkspace value={project.notes} onChange={(notes) => setProject((current) => ({ ...current, notes }))} /> : <SettingsWorkspace project={project} onChange={setProject} onResetLayout={resetLayout} />}
      </section>
      {inspectorOpen && <Inspector selected={selected} tab={routerTab} onTabChange={setRouterTab} project={project} snapshot={displaySnapshot} updateHost={updateHost} updateRouter={updateRouter} setCard={setCard} setMda={setMda} setCardAdmin={setCardAdmin} setMdaAdmin={setMdaAdmin} setLink={(id, up) => void setLink(id, up)} updateLink={updateLink} deleteLink={deleteLink} deleteNode={deleteNode} ping={ping} width={project.layout.inspectorWidth} onWidthChange={(value) => resizePanel("inspectorWidth", value)} openConsole={openConsole} close={() => setInspectorOpen(false)} />}
    </div>
    {terminalOpen && activeSession && <TerminalPanel key={terminalGeneration} ready={Boolean(runtime && !runtimeError)} systemName={activeTerminalRouter?.systemName ?? "Router"} historyKey={`${project.projectId}:${activeTerminalSession?.routerId ?? "unknown"}:${activeSession}`} execute={execute} complete={complete} cancel={cancelTerminal} state={terminalState} restorePresentation={terminalPresentations[activeSession]} registerCheckpointProvider={registerTerminalCheckpointProvider} tabs={terminalTabs} activeTab={activeSession} selectTab={selectTerminalSession} newTab={() => { if (activeTerminalSession) createConsole(activeTerminalSession.routerId); }} closeTab={closeTerminalSession} height={project.layout.terminalHeight} onHeightChange={(value) => resizePanel("terminalHeight", value)} close={closeTerminal} />}
    {pendingRouterPosition && <div className="modal-backdrop"><div className="lab-dialog"><header><strong>Configure router</strong><button aria-label="Close dialog" onClick={() => setPendingRouterPosition(undefined)}><X size={18} /></button></header><label>System name<input value={pendingRouterPosition.systemName} maxLength={32} onChange={(event) => setPendingRouterPosition({ ...pendingRouterPosition, systemName: event.target.value })} /></label><div className="panel-kicker dialog-kicker">CHASSIS PROFILE</div>{PROFILE_CATALOG.profiles.map((profile) => <button key={profile.id} className="primary" disabled={!pendingRouterPosition.systemName.trim()} onClick={() => addRouter(profile.id as DeviceProfileId)}>{profile.chassis}</button>)}</div></div>}
    {pendingHost && <div className="modal-backdrop"><div className="lab-dialog"><header><strong>Configure host interface</strong><button aria-label="Close dialog" onClick={() => setPendingHost(undefined)}><X size={18} /></button></header>
      <label>Name<input value={pendingHost.name} onChange={(event) => setPendingHost({ ...pendingHost, name: event.target.value })} /></label>
      <label>MAC address<input placeholder="xx:xx:xx:xx:xx:xx" value={pendingHost.mac} onChange={(event) => setPendingHost({ ...pendingHost, mac: event.target.value })} /></label>
      <label>IPv4 prefix<input placeholder="address/prefix-length" value={pendingHost.address} onChange={(event) => setPendingHost({ ...pendingHost, address: event.target.value })} /></label>
      <label>Default gateway<input placeholder="IPv4 address" value={pendingHost.gateway} onChange={(event) => setPendingHost({ ...pendingHost, gateway: event.target.value })} /></label>
      <label>Interface MTU<input inputMode="numeric" placeholder="bytes" value={pendingHost.mtu} onChange={(event) => setPendingHost({ ...pendingHost, mtu: event.target.value })} /></label>
      <button className="primary" onClick={addHost}>Add host</button></div></div>}
    {linkNodes && <div className="modal-backdrop"><div className="lab-dialog"><header><strong>Connect physical ports</strong><button aria-label="Close dialog" onClick={() => setLinkNodes(undefined)}><X size={18} /></button></header>{linkNodes.map((node, index) => <label key={node}>{node}<select value={linkPorts[index]} onChange={(event) => setLinkPorts(index === 0 ? [event.target.value, linkPorts[1]] : [linkPorts[0], event.target.value])}><option value="">Select a free port</option>{availablePorts(node).map((port) => <option key={port}>{port}</option>)}</select></label>)}<button className="primary" disabled={!linkPorts[0] || !linkPorts[1]} onClick={createLink}>Connect</button></div></div>}
  </main>;
}
