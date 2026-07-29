// Existing Router Lab composition connected to the multi-device runtime. The
// DOM hierarchy and CSS classes remain the approved UI contract. React owns
// portable format 4 intent while C++ owns every operational state transition.

import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import { ANNOTATION_LIMITS, createAnnotationV4, createEmptyProjectV4,
  createRouterProjectV4, createSwitchProjectV5, equippedRouterPorts, hostInterfaceId,
  createDhcpServerProjectV5,
  parseLabProjectV4, PROFILE_CATALOG, type DeviceProfileId,
  type DhcpServerProjectV5, type HostProjectV4, type LabProjectV4,
  type LabRuntimeSnapshotV6,
  type LinkProjectV4, type RouterProjectV4, type RuntimeRouterV6,
  type TopologyAnnotationV4 } from "@router-simulator/contracts";
import { MultiRouterRuntimeClient, type RouterTerminalState } from "../runtime/multi-router-client";
import { waitForHostPing } from "../runtime/host-ping";
import { createUnconfiguredHost, materializeStableIidSecret } from
  "../runtime/secure-random";
import { createCheckpointManifestV4, downloadBinary,
  selectBinarySaveDestination,
  createProjectManifestV4, importNetsimV4, isProtectedNetsimV4,
  loadActiveProjectV4, loadProjectBinaryV4, protectNetsimV4,
  loadProjectPresentation, projectCheckpointNameV4, saveProjectBinaryV4 } from "../persistence";
import { persistProjectWrappingKey,
  projectVaultMaterial } from "../runtime/project-secret-vault";
import { Inspector, type RouterTab } from "./Inspector";
import { PanelResizeHandle } from "./PanelResizeHandle";
import { TerminalPanel } from "./TerminalPanel";
import type { TerminalCheckpointProvider } from "./terminal-model";
import type { TerminalPanelPresentation } from "./terminal-contract";
import {
  DurableProjectSaveQueue,
  persistDurableProject,
  terminalPresentationForSessions
} from "./durable-project-save";
import { DEMO_LAB_CATALOG, type DemoLabId } from "./demo-catalog";
import { projectNeedsReplacementConfirmation } from "./demo-launch";
import { Topology, type TopologyTool } from "./Topology";
import { automaticTopologyLayout } from "./topology-layout";
import { CaptureWorkspace, ConfigWorkspace, DemosWorkspace, DevicesWorkspace,
  NotesWorkspace, SettingsWorkspace, SnapshotWorkspace,
  type WorkspaceView } from "./WorkspaceViews";
import { Camera, Cable, ChevronDown, CircleUser, Download, EllipsisVertical,
  Menu, NotebookPen, Radio, Rocket, Server,
  Settings, SlidersHorizontal, Type, Waypoints, X } from "lucide-react";

type CaptureKind = "link-direction" | "router-ingress" | "router-egress" |
  "cpm-punt";
type CaptureSelection = { key: string; kind: CaptureKind; objectId: string;
  portId: string; direction: 0 | 1 };
type ProtectedFileAction = { kind: "project" } | { kind: "checkpoint" } |
  { kind: "import"; file: File };

function captureKey(kind: CaptureKind, objectId: string, portId: string,
  direction: 0 | 1): string {
  // Delimited keys are local React identity only. The runtime still receives
  // separate typed fields and resolves generation-bearing handles itself.
  return `${kind}:${objectId}:${portId}:${direction}`;
}

async function transferCaptureStorage(previous: MultiRouterRuntimeClient | undefined,
  next: MultiRouterRuntimeClient): Promise<void> {
  // Only one dedicated Worker may own the synchronous OPFS handle. If the new
  // runtime cannot acquire it, restore the still-live predecessor before
  // surfacing failure so packet capture is not left detached from storage.
  if (previous) await previous.releaseCaptureStorage();
  try {
    await next.activateCaptureStorage();
  } catch (cause) {
    if (previous) await previous.activateCaptureStorage();
    throw cause;
  }
}

function captureSelectionsFromSnapshot(snapshot: LabRuntimeSnapshotV6):
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
  // Worker and C++ errors describe implementation boundaries and are valuable
  // in the developer console, but they are not product copy. In particular,
  // text about owners, transactions, runtime rollback or an unchanged lab
  // exposes mechanics that do not help a user correct the selected values.
  // Keep the complete diagnostic here and expose only the outcome and a useful
  // next action in the page notification.
  console.error(`Lab ${area} failure`, cause);
  return area === "startup"
    ? "Reload the page or open another project."
    : "Check the selected values and try again.";
}

function freeId(prefix: string, values: readonly string[]): string {
  const used = new Set(values);
  for (let index = 1; ; ++index) {
    const id = `${prefix}${index}`;
    if (!used.has(id)) return id;
  }
}

function mergeRuntimeRouter(project: LabProjectV4,
  runtimeRouter: RuntimeRouterV6): LabProjectV4 {
  const before = project.routers.find((router) => router.id === runtimeRouter.id);
  if (!before) return project;
  const livePorts = new Map(runtimeRouter.ports.map((port) => [port.id, port]));
  const retained = before.running.ports.filter((port) => !livePorts.has(port.id));
  const router: RouterProjectV4 = {
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
      maximumEcmpPaths: runtimeRouter.maximumEcmpPaths,
      ports: [...retained, ...runtimeRouter.ports.map((port) => ({
        id: port.id, admin: port.admin ? "up" as const : "down" as const,
        mtu: port.mtu, speedMbps: port.speedMbps,
        description: port.description
      }))],
      interfaces: runtimeRouter.interfaces.map((item) => ({
        name: item.name, portId: item.portId, address: item.address,
        arpTimeoutSeconds: item.arpTimeoutSeconds,
        arpRetryTimerDeciseconds: item.arpRetryTimerDeciseconds,
        ipv6Addresses: item.ipv6Addresses.map((address) => ({ ...address })),
        admin: item.admin ? "up" as const : "down" as const
      })),
      staticRoutes: runtimeRouter.staticRoutes.map((route) => ({ ...route })),
      ipv6StaticRoutes: runtimeRouter.ipv6StaticRoutes.map((route) => ({ ...route })),
      policyOptions: structuredClone(runtimeRouter.policyOptions),
      // The control owner projects canonical configuration, never inferred
      // operational routes or adjacencies. Terminal commits can therefore be
      // persisted without the browser reconstructing protocol intent.
      ospf: structuredClone(runtimeRouter.ospf)
    }
  };
  return { ...project, routers: project.routers.map((item) =>
    item.id === router.id ? router : item) };
}

function mergeRuntimeDhcpServer(project: LabProjectV4,
  runtimeServer: RuntimeRouterV6): LabProjectV4 {
  const before = project.dhcpServers.find((server) =>
    server.id === runtimeServer.id);
  if (!before) return project;
  const livePorts = new Map(runtimeServer.ports.map((port) => [port.id, port]));
  const retained = before.running.ports.filter((port) => !livePorts.has(port.id));
  const fixedInventory = PROFILE_CATALOG.profiles.find(
    (profile) => profile.id === before.profileId)?.fixed;
  const server: DhcpServerProjectV5 = {
    ...before,
    name: runtimeServer.systemName,
    // Fixed server NIC inventory is immutable project intent. The compact
    // runtime projection may omit child MDA records that have no editable
    // state, so replacing the canonical fixed record from that projection
    // would create an impossible zero-MDA device on the next Apply.
    hardware: fixedInventory ? before.hardware : { cards:
      runtimeServer.cards.map((card) => ({
      slot: card.slot, admin: card.admin ? "up" : "down",
      provisionedType: card.provisionedType,
      equippedType: card.equippedType,
      mdas: card.mdas.map((mda) => ({
        slot: mda.slot, admin: mda.admin ? "up" : "down",
        provisionedType: mda.provisionedType,
        equippedType: mda.equippedType
      }))
    })) },
    running: {
      systemName: runtimeServer.systemName,
      maximumEcmpPaths: 1,
      ports: [...retained, ...runtimeServer.ports.map((port) => ({
        id: port.id, admin: port.admin ? "up" as const : "down" as const,
        mtu: port.mtu, speedMbps: port.speedMbps,
        description: port.description
      }))],
      interfaces: runtimeServer.interfaces.map((item) => ({
        name: item.name, portId: item.portId, address: item.address,
        arpTimeoutSeconds: item.arpTimeoutSeconds,
        arpRetryTimerDeciseconds: item.arpRetryTimerDeciseconds,
        ipv6Addresses: item.ipv6Addresses.map((address) => ({ ...address })),
        admin: item.admin ? "up" as const : "down" as const
      })),
      staticRoutes: runtimeServer.staticRoutes.map((route) => ({ ...route })),
      ipv6StaticRoutes: runtimeServer.ipv6StaticRoutes.map((route) =>
        ({ ...route })),
      policyOptions: { prefixLists: [], statements: [] },
      ospf: { instances: [] }
    }
  };
  return { ...project, dhcpServers: project.dhcpServers.map((item) =>
    item.id === server.id ? server : item) };
}

function snapshotMatchesProject(project: LabProjectV4,
  snapshot: LabRuntimeSnapshotV6): boolean {
  // A recovery checkpoint is accepted only for the exact portable object
  // graph. This prevents an older, still ABI-compatible lab from replacing a
  // newer project merely because both were saved under the same browser key.
  const routerKeys = project.routers.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const liveRouterKeys = snapshot.routers.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const dhcpServerKeys = project.dhcpServers.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const liveDhcpServerKeys = snapshot.dhcpServers.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const hostKeys = project.hosts.map((item) => item.id).sort();
  const liveHostKeys = snapshot.hosts.map((item) => item.id).sort();
  const switchKeys = project.switches.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const liveSwitchKeys = snapshot.switches.map((item) =>
    `${item.id}:${item.profileId}`).sort();
  const linkKeys = project.links.map((item) => item.id).sort();
  const liveLinkKeys = snapshot.links.map((item) => item.id).sort();
  return JSON.stringify(
    [routerKeys, dhcpServerKeys, hostKeys, switchKeys, linkKeys]) ===
    JSON.stringify(
      [liveRouterKeys, liveDhcpServerKeys, liveHostKeys, liveSwitchKeys,
        liveLinkKeys]);
}

function mergeRuntimeProject(project: LabProjectV4,
  snapshot: LabRuntimeSnapshotV6): LabProjectV4 {
  let merged = project;
  for (const router of snapshot.routers)
    merged = mergeRuntimeRouter(merged, router);
  for (const server of snapshot.dhcpServers)
    merged = mergeRuntimeDhcpServer(merged, server);
  merged = {
    ...merged,
    hosts: merged.hosts.map((host) => {
      const live = snapshot.hosts.find((item) => item.id === host.id);
      return live ? { ...host, name: live.name, eth0: { ...host.eth0,
        mac: live.mac, address: live.address, gateway: live.gateway,
        mtu: live.mtu } } : host;
    }),
    switches: merged.switches.map((ethernetSwitch) => {
      const live = snapshot.switches.find(
        (item) => item.id === ethernetSwitch.id);
      return live ? {
        ...ethernetSwitch,
        name: live.name,
        ports: live.ports.map((port) => ({
          id: port.id,
          admin: port.admin ? "up" as const : "down" as const,
          speedMbps: port.speedMbps,
          mtu: port.mtu
        }))
      } : ethernetSwitch;
    }),
    links: merged.links.map((link) => {
      const live = snapshot.links.find((item) => item.id === link.id);
      return live ? { ...link, admin: live.admin ? "up" as const : "down" as const,
        propagationDelayNs: live.propagationDelayNs,
        endpoints: live.endpoints } : link;
    })
  };
  // Runtime snapshots are already validated at the Wasm protocol boundary.
  // Do not run a throwing persistence validator inside a React state updater:
  // React may evaluate that updater during render, where a schema disagreement
  // would replace the entire workspace with the router's error component.
  // Autosave performs portable-format validation outside render and refuses
  // to persist an invalid projection without destroying the live laboratory.
  return merged;
}

export function App() {
  const [project, setProject] = useState<LabProjectV4>(() => createEmptyProjectV4());
  const [snapshot, setSnapshot] = useState<LabRuntimeSnapshotV6>();
  const [telemetrySnapshot, setTelemetrySnapshot] = useState<LabRuntimeSnapshotV6>();
  const [selected, setSelected] = useState<string>();
  const [runtimeError, setRuntimeError] = useState<string>();
  const [operationError, setOperationError] = useState<string>();
  const [continuityNotice, setContinuityNotice] = useState<string>();
  const [runtime, setRuntime] = useState<MultiRouterRuntimeClient>();
  const [projectLoaded, setProjectLoaded] = useState(false);
  const [view, setView] = useState<WorkspaceView>("topology");
  const [captureSelections, setCaptureSelections] = useState<CaptureSelection[]>([]);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const [confirmNewProject, setConfirmNewProject] = useState(false);
  const [confirmDemoId, setConfirmDemoId] = useState<DemoLabId>();
  const [pendingDemoId, setPendingDemoId] = useState<DemoLabId>();
  const [topologyTool, setTopologyTool] = useState<TopologyTool>("select");
  const [routerTab, setRouterTab] = useState<RouterTab>("chassis");
  const [terminalPresentations, setTerminalPresentations] = useState<
    Record<string, TerminalPanelPresentation>>({});
  const [terminalGeneration, setTerminalGeneration] = useState(0);
  const [activeSession, setActiveSession] = useState<string>();
  const [hiddenTerminalSessions, setHiddenTerminalSessions] = useState<
    ReadonlySet<string>>(() => new Set());
  const [pendingRouterPosition, setPendingRouterPosition] = useState<
    { x: number; y: number; systemName: string; explicitPlacement: boolean }
    | undefined>();
  const [linkNodes, setLinkNodes] = useState<readonly [string, string]>();
  const [linkPorts, setLinkPorts] = useState<readonly [string, string]>(["", ""]);
  const [protectedFileAction, setProtectedFileAction] =
    useState<ProtectedFileAction>();
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirmation, setPassphraseConfirmation] = useState("");
  const [passphraseBusy, setPassphraseBusy] = useState(false);
  const importRef = useRef<HTMLInputElement>(null);
  const checkpointRef = useRef<HTMLInputElement>(null);
  const terminalCheckpointProviderRef = useRef<TerminalCheckpointProvider | undefined>(undefined);
  const runtimeRef = useRef<MultiRouterRuntimeClient | undefined>(undefined);
  const durableSaveQueueRef = useRef(new DurableProjectSaveQueue());
  runtimeRef.current = runtime;

  useEffect(() => {
    let cancelled = false;
    let client: MultiRouterRuntimeClient | undefined;
    void (async () => {
      const stored = await loadActiveProjectV4();
      const recoveryName = await projectCheckpointNameV4(stored);
      const [checkpoint, presentation] = await Promise.all([
        loadProjectBinaryV4(stored.projectId, recoveryName),
        loadProjectPresentation(stored.projectId)
      ]);
      client = new MultiRouterRuntimeClient();
      let live: LabRuntimeSnapshotV6;
      if (checkpoint) {
        try {
          // The checkpoint is authoritative for configuration committed
          // through terminal sessions. Restore it into an empty worker before
          // replaying the UI projection. Replaying first can be impossible
          // when a CLI-created port is already referenced by a physical link,
          // and it would discard the only complete runtime record before
          // recovery had a chance to run.
          const recovered = await client.restoreProjectCheckpoint(
            stored.projectId, checkpoint);
          if (snapshotMatchesProject(stored, recovered)) live = recovered;
          else throw new Error("Recovery checkpoint object graph is stale");
        } catch (recoveryCause) {
          client.close();
          client = new MultiRouterRuntimeClient();
          try {
            live = await client.applyProject(stored);
          } catch (replayCause) {
            // Preserve both independent failure causes. Without the recovery
            // cause, a replay failure can misleadingly implicate only the
            // portable project even when checkpoint compatibility was the
            // first fault. AggregateError also keeps both original stacks for
            // local browser diagnostics.
            const recoveryMessage = recoveryCause instanceof Error
              ? recoveryCause.message : String(recoveryCause);
            const replayMessage = replayCause instanceof Error
              ? replayCause.message : String(replayCause);
            throw new AggregateError([recoveryCause, replayCause],
              `Recovery failed: ${recoveryMessage}; replay failed: ${replayMessage}`);
          }
        }
      } else live = await client.applyProject(stored);
      await client.activateCaptureStorage();
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
    try { parseLabProjectV4(project); } catch { return; }
    const timer = window.setTimeout(() => {
      const save = async () => {
        const client = runtimeRef.current;
        const active = terminalCheckpointProviderRef.current?.snapshot();
        const presentations = { ...terminalPresentations,
          ...(activeSession && active ? { [activeSession]: active } : {}) };
        await durableSaveQueueRef.current.persist(project, selected, activeSession,
          presentations, snapshot?.sessions ?? [], client);
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

  useEffect(() => {
    if (!runtime) return;
    let active = true;
    const unsubscribe = runtime.onContinuityEvent((event) => {
      if (!event.recovered) {
        setRuntimeError("Reload the page to reopen the project.");
        return;
      }
      void runtime.snapshot().then((live) => {
        if (!active) return;
        // Runtime recovery may roll back a small interval of accepted intent.
        // Rebuild React's portable projection from the restored owner so the
        // inspector and the next persisted project cannot disagree with C++.
        setSnapshot(live);
        setTelemetrySnapshot(live);
        setProject((current) => mergeRuntimeProject(current, live));
        setCaptureSelections(captureSelectionsFromSnapshot(live));
        setOperationError(undefined);
        setContinuityNotice("The project has been reopened from its latest saved state.");
      }).catch((cause) => {
        if (active) setRuntimeError(visibleFailure("startup", cause));
      });
    });
    const unsubscribeCapture = runtime.onCaptureStorageError((error) => {
      if (active) setOperationError(visibleFailure("operation", error));
    });
    return () => {
      active = false;
      unsubscribe();
      unsubscribeCapture();
    };
  }, [runtime]);

  const mutate = useCallback(async (next: LabProjectV4,
    operation: (client: MultiRouterRuntimeClient) => Promise<LabRuntimeSnapshotV6>) => {
    const client = runtimeRef.current;
    if (!client) throw new Error("Runtime is not ready");
    try {
      // Structural validation and runtime mutation share one visible failure
      // path. Invalid form input therefore cannot become an unhandled promise
      // rejection or a generic browser console error.
      const validated = parseLabProjectV4(next);
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
    const nodeIds = [...project.routers, ...project.dhcpServers,
      ...project.hosts,
      ...project.switches].map((item) => item.id);
    const id = freeId("r", nodeIds);
    // Capture the dialog record once. Besides satisfying React's asynchronous
    // state model, this prevents coordinates from being read from a later
    // dialog instance while the current chassis choice is being committed.
    const pending = pendingRouterPosition;
    const systemName = pending?.systemName.trim() ?? "";
    if (!pending || !systemName) return;
    const router = createRouterProjectV4(id, profileId, systemName);
    // A canvas drop is an explicit user coordinate and must never be moved.
    // A palette click has no geometric intent, but the layout still belongs to
    // the user. The fallback may choose a coordinate for the new node only.
    // Replacing old coordinates here made every existing cable jump when one
    // device was added and silently destroyed a carefully arranged topology.
    const automaticNodes = automaticTopologyLayout(
      [...project.routers.map((item) => item.id),
        ...project.dhcpServers.map((item) => item.id),
        ...project.switches.map((item) => item.id), id],
      project.hosts.map((item) => item.id));
    const next = { ...project, routers: [...project.routers, router], layout: {
      ...project.layout, nodes: pending.explicitPlacement
        ? { ...project.layout.nodes, [id]: { x: pending.x,
          y: pending.y } }
        : { ...project.layout.nodes, [id]: automaticNodes[id] } } };
    // The node appears only after the C++ owner accepts the generated profile.
    // This avoids a canvas-only router when catalog capacity or validation
    // rejects the operation and keeps project intent aligned with live state.
    void mutate(next, (client) => client.createRouter(id, profileId, router.systemName))
      .then(() => { setSelected(id); setPendingRouterPosition(undefined); })
      .catch(() => undefined);
  }, [mutate, pendingRouterPosition, project]);

  const addDevice = useCallback((
    kind: "router" | "dhcp-server" | "host" | "switch",
    position?: { x: number; y: number }) => {
    if (kind === "router") {
      // A chassis profile changes slot inventory and resource bounds, so a
      // generic drag cannot silently select one. The drop coordinate is kept
      // until the user confirms a generated catalog entry in the dialog.
      const nodeIds = [...project.routers, ...project.dhcpServers,
        ...project.hosts,
        ...project.switches].map((item) => item.id);
      const suggested = freeId("r", nodeIds).toUpperCase();
      // The temporary coordinate keeps the dialog data complete. It is used
          // only for a real drop. Palette clicks receive a fallback coordinate
          // without changing any coordinate already owned by the project.
      const target = position ?? { x: 0, y: 0 };
      // The first free R1..R16 name is a convenience only. It stays editable
      // because system-name is router configuration and cannot be derived from
      // a registry slot or canvas order.
      setPendingRouterPosition({ ...target, systemName: suggested,
        explicitPlacement: Boolean(position) });
    } else if (kind === "dhcp-server") {
      const profile = PROFILE_CATALOG.profiles.find((item) =>
        item.role === "dhcp-server");
      if (!profile) return;
      const nodeIds = [...project.routers, ...project.dhcpServers,
        ...project.hosts, ...project.switches].map((item) => item.id);
      const id = freeId("dhcp", nodeIds);
      const server = createDhcpServerProjectV5(
        id, profile.id as DeviceProfileId, id.toUpperCase());
      const automaticNodes = automaticTopologyLayout(
        [...project.routers.map((item) => item.id),
          ...project.dhcpServers.map((item) => item.id),
          ...project.switches.map((item) => item.id), id],
        project.hosts.map((item) => item.id));
      const next = {
        ...project,
        dhcpServers: [...project.dhcpServers, server],
        layout: { ...project.layout,
          nodes: position
            ? { ...project.layout.nodes, [id]: position }
            : { ...project.layout.nodes, [id]: automaticNodes[id] } }
      };
      void mutate(next, async (client) => {
        await client.createDhcpServer(id, server.profileId, server.name);
        return client.replaceRouterConfiguration(server);
      }).then(() => setSelected(id)).catch(() => undefined);
    } else if (kind === "host") {
      const nodeIds = [...project.routers, ...project.dhcpServers,
        ...project.hosts,
        ...project.switches].map((item) => item.id);
      const id = freeId("h", nodeIds);
      const host = createUnconfiguredHost(id, id.toUpperCase(),
        new Set(project.hosts.map((item) => item.eth0.mac.toLowerCase())));
      // Canvas placement creates a usable Ethernet endpoint immediately.
      // Addressing remains an independent Inspector transaction, while the
      // generated MAC and default MTU make the new physical port linkable.
      const automaticNodes = automaticTopologyLayout(
        [...project.routers.map((item) => item.id),
          ...project.dhcpServers.map((item) => item.id),
          ...project.switches.map((item) => item.id)],
        [...project.hosts.map((item) => item.id), host.id]);
      const next = { ...project, hosts: [...project.hosts, host], layout: {
        ...project.layout, nodes: position
          ? { ...project.layout.nodes, [host.id]: position }
          : { ...project.layout.nodes, [host.id]: automaticNodes[host.id] } } };
      void mutate(next, (client) => client.createConfiguredHost(host.id,
        host.name, host.eth0.mac, host.eth0.address, host.eth0.gateway,
        host.eth0.mtu, host.eth0.ipv6.interfaceId,
        host.eth0.ipv6.autoconfiguration,
        host.eth0.ipv6.interfaceIdentifierMode,
        host.eth0.ipv6.stableIidSecret, host.eth0.ipv6.networkId,
        host.eth0.transportSecretHex))
        .then(() => setSelected(host.id))
        .catch(() => undefined);
    } else {
      const profile = PROFILE_CATALOG.switch_profiles[0];
      if (!profile) return;
      const nodeIds = [...project.routers, ...project.dhcpServers,
        ...project.hosts,
        ...project.switches].map((item) => item.id);
      const id = freeId("s", nodeIds);
      const ethernetSwitch = createSwitchProjectV5(id, profile.id,
        id.toUpperCase());
      const automaticNodes = automaticTopologyLayout(
        [...project.routers.map((item) => item.id),
          ...project.dhcpServers.map((item) => item.id),
          ...project.switches.map((item) => item.id), id],
        project.hosts.map((item) => item.id));
      const next = { ...project,
        switches: [...project.switches, ethernetSwitch],
        layout: { ...project.layout,
          nodes: position
            ? { ...project.layout.nodes, [id]: position }
            : { ...project.layout.nodes, [id]: automaticNodes[id] } } };
      void mutate(next, (client) =>
        client.createSwitch(id, profile.id, ethernetSwitch.name))
        .then(() => setSelected(id))
        .catch(() => undefined);
    }
  }, [mutate, project]);

  const updateLayout = useCallback((id: string, position: { x: number; y: number }) => {
    if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) return;
    setProject((current) => ({ ...current, layout: { ...current.layout,
      nodes: { ...current.layout.nodes, [id]: position } } }));
  }, []);

  const selectDevice = useCallback((id: string) => {
    setSelected(id);
    setInspectorOpen(true);
  }, []);

  // Annotations are browser-only presentation, so every operation is a local
  // project edit. They never call mutate() because the runtime owns no
  // annotation state; autosave persists them through the project head exactly
  // like node coordinates.
  const createAnnotation = useCallback((position: { x: number; y: number }) => {
    const used = [...project.routers, ...project.dhcpServers, ...project.hosts,
      ...project.switches].map((item) => item.id)
      .concat(project.links.map((item) => item.id))
      .concat(project.annotations.map((item) => item.id));
    const id = freeId("note", used);
    const annotation = createAnnotationV4(id, Math.round(position.x),
      Math.round(position.y));
    setProject((current) => ({ ...current,
      annotations: [...current.annotations, annotation] }));
    setSelected(id);
    setInspectorOpen(true);
  }, [project.annotations, project.dhcpServers, project.hosts, project.links,
    project.routers,
    project.switches]);

  const moveAnnotation = useCallback((id: string,
    position: { x: number; y: number }) => {
    if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) return;
    setProject((current) => ({ ...current,
      annotations: current.annotations.map((item) => item.id === id
        ? { ...item, x: Math.round(position.x), y: Math.round(position.y) }
        : item) }));
  }, []);

  const resizeAnnotation = useCallback((id: string,
    geometry: { x: number; y: number; width: number }) => {
    // React Flow's resize control already honours the min and max, but the
    // clamp keeps a hand-crafted geometry inside the validated project bounds.
    const width = Math.round(Math.min(Math.max(geometry.width,
      ANNOTATION_LIMITS.minWidth), ANNOTATION_LIMITS.maxWidth));
    setProject((current) => ({ ...current,
      annotations: current.annotations.map((item) => item.id === id
        ? { ...item, x: Math.round(geometry.x), y: Math.round(geometry.y), width }
        : item) }));
  }, []);

  const commitAnnotationText = useCallback((id: string, text: string) => {
    setProject((current) => ({ ...current,
      annotations: current.annotations.map((item) => item.id === id
        ? { ...item, text } : item) }));
  }, []);

  const updateAnnotation = useCallback((annotation: TopologyAnnotationV4) => {
    setProject((current) => ({ ...current,
      annotations: current.annotations.map((item) =>
        item.id === annotation.id ? annotation : item) }));
  }, []);

  const deleteAnnotation = useCallback((id: string) => {
    setProject((current) => ({ ...current,
      annotations: current.annotations.filter((item) => item.id !== id) }));
    setSelected((current) => current === id ? undefined : current);
  }, []);

  const availablePorts = (nodeId: string) => {
    const router = project.routers.find((item) => item.id === nodeId);
    const dhcpServer = project.dhcpServers.find((item) => item.id === nodeId);
    const ethernetSwitch = project.switches.find(
      (item) => item.id === nodeId);
    const ports = router ? equippedRouterPorts(router).map((item) => item.id)
      : dhcpServer ? equippedRouterPorts(dhcpServer).map((item) => item.id)
      : ethernetSwitch ? ethernetSwitch.ports.map((item) => item.id)
        : ["eth0"];
    const used = new Set(project.links.flatMap((link) => link.endpoints
      .filter((endpoint) => endpoint.nodeId === nodeId).map((endpoint) => endpoint.portId)));
    return ports.filter((port) => !used.has(port));
  };

  const createLink = () => {
    if (!linkNodes || !linkPorts[0] || !linkPorts[1]) return;
    const id = freeId("link", project.links.map((item) => item.id));
    const link: LinkProjectV4 = { id, endpoints: [
      { nodeId: linkNodes[0], portId: linkPorts[0] },
      { nodeId: linkNodes[1], portId: linkPorts[1] }
    ], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 0 };
    void mutate({ ...project, links: [...project.links, link] }, (client) =>
      client.createLink(id, linkNodes[0], linkPorts[0], linkNodes[1],
        linkPorts[1], 0, true, null))
      .then(() => {
        // A physical-link gesture configures exactly one link. Returning to
        // select here makes the next drag move a device instead of starting an
        // accidental second connection.
        setLinkNodes(undefined);
        setTopologyTool("select");
      }).catch(() => undefined);
  };

  const setLink = useCallback((linkId: string, up: boolean) => {
    const next = { ...project, links: project.links.map((link) =>
      link.id === linkId ? { ...link, admin: up ? "up" as const : "down" as const } : link) };
    return mutate(next, (client) => client.setLinkAdmin(linkId, up))
      .catch(() => undefined);
  }, [mutate, project]);

  const updateLink = useCallback((linkId: string, up: boolean,
    propagationDelayNs: number, configuredSpeedMbps: number | null) => {
    const next = { ...project, links: project.links.map((link) => link.id === linkId
      ? { ...link, admin: up ? "up" as const : "down" as const,
        propagationDelayNs, configuredSpeedMbps } : link) };
    void mutate(next, (client) => client.setLinkProperties(linkId, up,
      propagationDelayNs, configuredSpeedMbps)).catch(() => undefined);
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
    const dhcpServer = project.dhcpServers.find((item) => item.id === nodeId);
    const host = project.hosts.find((item) => item.id === nodeId);
    const ethernetSwitch = project.switches.find(
      (item) => item.id === nodeId);
    if (!router && !dhcpServer && !host && !ethernetSwitch) return;
    const nodes = { ...project.layout.nodes };
    delete nodes[nodeId];
    const next = { ...project,
      routers: project.routers.filter((item) => item.id !== nodeId),
      dhcpServers: project.dhcpServers.filter((item) => item.id !== nodeId),
      hosts: project.hosts.filter((item) => item.id !== nodeId),
      switches: project.switches.filter((item) => item.id !== nodeId),
      links: project.links.filter((link) => !link.endpoints.some(
        (endpoint) => endpoint.nodeId === nodeId)),
      layout: { ...project.layout, nodes } };
    void mutate(next, (client) => router ? client.deleteRouter(nodeId)
      : dhcpServer ? client.deleteDhcpServer(nodeId)
        : host ? client.deleteHost(nodeId)
        : client.deleteSwitch(nodeId)).then(() => {
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

  const updateHost = useCallback((host: HostProjectV4) => {
    const previous = project.hosts.find((item) => item.id === host.id);
    if (!previous) return;
    // Materialization preserves an existing secret and creates a new one only
    // on the first committed switch to RFC 7217 stable opaque addressing.
    const resolved = materializeStableIidSecret(host);
    const next = { ...project, hosts: project.hosts.map((item) =>
      item.id === resolved.id ? resolved : item) };
    if (JSON.stringify(previous) === JSON.stringify(resolved)) return;
    // Endpoint identity and application protocols are committed together.
    // This matters when a user switches from static IPv4 to DHCP: publishing
    // 0.0.0.0/0 without a successfully bound client would strand the host.
    void mutate(next, (client) => client.replaceHostIpv4(resolved))
      .catch(() => undefined);
  }, [mutate, project]);

  const updateDhcpServer = useCallback((server: DhcpServerProjectV5) => {
    const previous = project.dhcpServers.find((item) => item.id === server.id);
    if (!previous || JSON.stringify(previous) === JSON.stringify(server))
      return;
    const next = { ...project,
      dhcpServers: project.dhcpServers.map((item) =>
        item.id === server.id ? server : item) };
    // Network interfaces and both DHCP families form one runtime transaction.
    // Publishing the project after only the interface step would make a pool
    // appear saved even when its control-plane owner rejected the attachment.
    void mutate(next, (client) => client.replaceDhcpServer(previous, server))
      .catch(() => undefined);
  }, [mutate, project]);

  const updateRouter = useCallback((router: RouterProjectV4) => {
    const previous = project.routers.find((item) => item.id === router.id);
    if (!previous) return;
    const next = { ...project, routers: project.routers.map((item) => item.id === router.id ? router : item) };
    // One runtime operation stages and validates the complete datastore. The
    // project is published only after the control owner commits every change.
    void mutate(next, (client) => client.replaceRouterConfiguration(router))
      .catch(() => undefined);
  }, [mutate, project]);

  const setSwitchName = useCallback((switchId: string, name: string) => {
    const current = project.switches.find((item) => item.id === switchId);
    if (!current || current.name === name) return;
    const next = { ...project, switches: project.switches.map((item) =>
      item.id === switchId ? { ...item, name } : item) };
    // Runtime acceptance precedes publication of the project record, matching
    // the transaction rule used by router and host configuration.
    void mutate(next, (client) => client.setSwitchName(switchId, name))
      .catch(() => undefined);
  }, [mutate, project]);

  const setSwitchPort = useCallback((switchId: string, portId: string,
    enabled: boolean, speedMbps: number, mtu: number) => {
    const current = project.switches.find((item) => item.id === switchId);
    if (!current?.ports.some((port) => port.id === portId)) return;
    const next = { ...project, switches: project.switches.map((item) =>
      item.id === switchId ? { ...item, ports: item.ports.map((port) =>
        port.id === portId ? { ...port, admin: enabled ? "up" as const
          : "down" as const, speedMbps, mtu } : port) } : item) };
    // The port owner validates speed and MTU against the selected generated
    // hardware profile before the edited project becomes visible.
    void mutate(next, (client) => client.configureSwitchPort(switchId, portId,
      enabled, speedMbps, mtu)).catch(() => undefined);
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
    // Selecting an existing background session makes only its presentation
    // visible again. The router-owned session has continued processing input,
    // output and protocol notifications while its tab was hidden.
    setHiddenTerminalSessions((current) => {
      if (!current.has(sessionId)) return current;
      const next = new Set(current);
      next.delete(sessionId);
      return next;
    });
    if (sessionId === activeSession) {
      // Closing the panel preserves its router-owned session. Opening that
      // console again therefore selects the same identifier, but it still has
      // to restore panel visibility. Returning without this state transition
      // left an active Open console button with no terminal on screen.
      setTerminalOpen(true);
      return;
    }
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
    if (sessionId === activeSession) preserveActiveTerminal();
    // A tab close is presentation-only. Do not call the runtime closeSession
    // operation: SR OS sessions belong to the router and must continue in the
    // background independently from whether xterm currently renders them.
    const nextHidden = new Set(hiddenTerminalSessions);
    nextHidden.add(sessionId);
    setHiddenTerminalSessions(nextHidden);
    if (sessionId === activeSession) {
      const next = (snapshot?.sessions ?? []).find((candidate) =>
        candidate.id !== sessionId && !nextHidden.has(candidate.id))?.id;
      setActiveSession(next);
      setTerminalOpen(Boolean(next));
      setTerminalGeneration((value) => value + 1);
    }
    setOperationError(undefined);
  }, [activeSession, hiddenTerminalSessions, preserveActiveTerminal, snapshot]);

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
    if (changedRouter)
      setProject((current) => mergeRuntimeRouter(current, changedRouter));
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
    // ICMP Echo carries a 16-bit sequence number. The previous 31-bit mask was
    // rejected by the C++ protocol boundary before any frame reached the host.
    // Browser cryptographic randomness avoids coupling packet identity to wall
    // clock changes and remains inside the exact wire field width.
    const sequence = crypto.getRandomValues(new Uint16Array(1))[0]!;
    await runtime.startHostPing(sourceId, destination, sequence);
    return await waitForHostPing(runtime, sourceId, sequence)
      ? `Reply received from ${destination}.`
      : `Request to ${destination} timed out.`;
  };

  const exportCaptureNow = async () => {
    if (!runtime) return;
    try {
      // Reserve the file before awaiting the Worker. Chromium intentionally
      // expires transient click activation across asynchronous work, which
      // otherwise leaves the button apparently inert for a large capture.
      const destination = await selectBinarySaveDestination(
        `${project.name}.pcapng`, "application/vnd.tcpdump.pcap",
        "PCAP Next Generation capture");
      if (!destination) return;
      const bytes = await runtime.exportCapture();
      // The runtime Worker already flushed this generation to the project
      // OPFS file. The selected destination receives a snapshot and never
      // competes for ownership of the live capture handle.
      await destination.save(bytes);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
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
      // Starting from the stopped state creates a new capture session. Reset
      // happens before point installation so no packet from the prior section
      // can race into the visually new recording.
      if (selected) await runtime.clearCapture();
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
  const exportProjectNow = async (secret: string) => {
    const material = await projectVaultMaterial(project.projectId);
    try {
      const protectedText = await protectNetsimV4(
        createProjectManifestV4(project), material.wrappingKey, secret);
      downloadBinary(
        `${project.name.replaceAll(" ", "-").toLowerCase()}.netsim`,
        new TextEncoder().encode(protectedText), "application/json");
    } finally {
      material.wrappingKey.fill(0);
      material.context.fill(0);
    }
  };
  const exportCheckpointNow = async (secret: string) => {
    if (!runtime) return;
    const [checkpoint, capture] = await Promise.all([runtime.exportCheckpoint(), runtime.exportCapture()]);
    const active = terminalCheckpointProviderRef.current?.snapshot();
    const presentations = { ...terminalPresentations,
      ...(activeSession && active ? { [activeSession]: active } : {}) };
    const terminal = terminalPresentationForSessions(
      activeSession, presentations, snapshot?.sessions ?? []);
    const recoveryName = await projectCheckpointNameV4(project);
    await saveProjectBinaryV4(project.projectId, recoveryName, checkpoint);
    const material = await projectVaultMaterial(project.projectId);
    try {
      const protectedText = await protectNetsimV4(
        createCheckpointManifestV4(project, checkpoint, capture, terminal),
        material.wrappingKey, secret);
      downloadBinary(`${project.name}.checkpoint.netsim`,
        new TextEncoder().encode(protectedText), "application/json");
    } finally {
      material.wrappingKey.fill(0);
      material.context.fill(0);
    }
  };
  const importFile = async (file?: File, secret?: string) => {
    if (!file) return;
    let replacement: MultiRouterRuntimeClient | undefined;
    let previous: MultiRouterRuntimeClient | undefined;
    let storageTransferred = false;
    let importedWrappingKey: Uint8Array | undefined;
    try {
      const decoded = await importNetsimV4(file, secret);
      importedWrappingKey = "projectWrappingKey" in decoded
        ? decoded.projectWrappingKey : undefined;
      replacement = new MultiRouterRuntimeClient();
      let live = await replacement.applyProject(
        decoded.project, importedWrappingKey);
      if (decoded.checkpoint) { await replacement.importCheckpoint(decoded.checkpoint); live = await replacement.snapshot(); }
      previous = runtimeRef.current;
      await transferCaptureStorage(previous, replacement);
      storageTransferred = true;
      if (decoded.capture) await replacement.importCapture(decoded.capture);
      else await replacement.clearCapture();
      // Persist the imported project key only after the replacement runtime,
      // checkpoint and capture have all validated. Until this point the active
      // project and its device-bound key record remain untouched.
      if (importedWrappingKey)
        await persistProjectWrappingKey(
          decoded.project.projectId, importedWrappingKey);
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
    } catch (cause) {
      if (storageTransferred && replacement && previous) {
        try {
          await replacement.releaseCaptureStorage();
          await previous.activateCaptureStorage();
        } catch {
          // Preserve the original import error. The next explicit capture
          // operation will retry storage activation on the visible runtime.
        }
      }
      replacement?.close();
      setOperationError(visibleFailure("operation", cause));
      throw cause;
    } finally {
      importedWrappingKey?.fill(0);
    }
  };
  const requestImport = async (file?: File) => {
    if (!file) return;
    try {
      if (isProtectedNetsimV4(await file.text())) {
        setPassphrase("");
        setPassphraseConfirmation("");
        setProtectedFileAction({ kind: "import", file });
      } else {
        await importFile(file);
      }
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  };
  const runProtectedFileAction = async () => {
    const action = protectedFileAction;
    if (!action || !passphrase ||
        (action.kind !== "import" && passphrase !== passphraseConfirmation))
      return;
    setPassphraseBusy(true);
    try {
      if (action.kind === "project")
        await exportProjectNow(passphrase);
      else if (action.kind === "checkpoint")
        await exportCheckpointNow(passphrase);
      else
        await importFile(action.file, passphrase);
      setProtectedFileAction(undefined);
      setPassphrase("");
      setPassphraseConfirmation("");
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    } finally {
      setPassphraseBusy(false);
    }
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
      await transferCaptureStorage(previous, replacement);
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
    const empty = createEmptyProjectV4();
    const replacement = new MultiRouterRuntimeClient();
    const previous = runtimeRef.current;
    let storageTransferred = false;
    void replacement.applyProject(empty).then(async (live) => {
      await transferCaptureStorage(previous, replacement);
      storageTransferred = true;
      await replacement.clearCapture();
      previous?.close(); runtimeRef.current = replacement; setRuntime(replacement);
      setProject(empty); setSnapshot(live); setSelected(undefined); setActiveSession(undefined);
      setTerminalOpen(false); setTerminalPresentations({}); setCaptureSelections([]);
      // Startup failure leaves projectLoaded false because no durable project
      // was ever published to React. A successful replacement runtime is now
      // the authoritative empty laboratory, so enable the normal checkpoint-
      // before-head autosave pipeline. Without this transition a user could
      // build an entire replacement topology that existed only in memory and
      // the next reload would reactivate the previously failing project head.
      setProjectLoaded(true);
      // A new laboratory is a fresh runtime boundary.  In particular, an
      // error produced while decoding the previous project's persisted graph
      // must not remain visible after the replacement worker has proved that
      // its empty snapshot is usable.  Clearing the error before that proof
      // would briefly advertise a runtime which might still fail to start.
      setRuntimeError(undefined); setOperationError(undefined); setContinuityNotice(undefined);
      setConfirmNewProject(false);
      setProjectMenuOpen(false);
    }).catch(async (cause) => {
      if (storageTransferred && previous) {
        try {
          await replacement.releaseCaptureStorage();
          await previous.activateCaptureStorage();
        } catch {
          // Preserve the reset failure. The visible runtime will retry its
          // storage acquisition on the next explicit capture operation.
        }
      }
      replacement.close();
      setOperationError(visibleFailure("operation", cause));
    });
  };
  const resetLayout = () => setProject((current) => ({ ...current, layout: {
    ...current.layout,
    // Reset means a useful deterministic arrangement, not deletion of every
    // coordinate followed by the renderer's overlapping fallback positions.
    nodes: automaticTopologyLayout(
      [...current.routers.map((item) => item.id),
        ...current.switches.map((item) => item.id)],
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
    setView(next); setProjectMenuOpen(false); setAccountMenuOpen(false);
    setMoreMenuOpen(false); setSidebarOpen(false);
  };
  const launchDemo = async (id: DemoLabId) => {
    const demo = DEMO_LAB_CATALOG.find((item) => item.id === id);
    if (!demo) return;
    let replacement: MultiRouterRuntimeClient | undefined;
    let previous: MultiRouterRuntimeClient | undefined;
    let storageTransferred = false;
    setPendingDemoId(id);
    try {
      const nextProject = demo.createProject();
      replacement = new MultiRouterRuntimeClient();
      const live = await replacement.applyProject(nextProject);
      previous = runtimeRef.current;
      await transferCaptureStorage(previous, replacement);
      storageTransferred = true;
      await replacement.clearCapture();
      setRuntime(replacement);
      runtimeRef.current = replacement;
      setProject(nextProject);
      setSnapshot(live);
      setTelemetrySnapshot(live);
      setSelected(demo.primarySelection);
      setView("topology");
      setCaptureSelections([]);
      setTerminalOpen(false);
      setTerminalPresentations({});
      setActiveSession(undefined);
      setHiddenTerminalSessions(new Set());
      setTerminalGeneration((value) => value + 1);
      setTopologyTool("select");
      setLinkNodes(undefined);
      setPendingRouterPosition(undefined);
      setConfirmDemoId(undefined);
      setProjectLoaded(true);
      setRuntimeError(undefined);
      setOperationError(undefined);
      setContinuityNotice(undefined);
      setProjectMenuOpen(false);
      setAccountMenuOpen(false);
      setMoreMenuOpen(false);
      setSidebarOpen(false);
      previous?.close();
      replacement = undefined;
    } catch (cause) {
      if (storageTransferred && replacement && previous) {
        try {
          await replacement.releaseCaptureStorage();
          await previous.activateCaptureStorage();
        } catch {
          // Preserve the launch failure. The visible runtime will retry its
          // storage acquisition on the next explicit capture operation.
        }
      }
      replacement?.close();
      setOperationError(visibleFailure("operation", cause));
    } finally {
      setPendingDemoId((current) => current === id ? undefined : current);
    }
  };
  const requestDemoLaunch = (id: DemoLabId) => {
    setProjectMenuOpen(false);
    setAccountMenuOpen(false);
    setMoreMenuOpen(false);
    if (projectNeedsReplacementConfirmation(project,
      snapshot?.sessions.length ?? 0)) {
      setConfirmDemoId(id);
      return;
    }
    void launchDemo(id);
  };
  const selectedRouter = project.routers.find((item) => item.id === selected);
  const terminalTabs = (snapshot?.sessions ?? [])
    .filter((session) => !hiddenTerminalSessions.has(session.id))
    .map((session) => ({
    id: session.id,
    label: `${project.routers.find((router) => router.id === session.routerId)
      ?.systemName ?? session.routerId} console`
  }));
  const activeTerminalSession = snapshot?.sessions.find((item) =>
    item.id === activeSession);
  const activeTerminalRouter = project.routers.find((item) =>
    item.id === activeTerminalSession?.routerId);
  const visibleMessage = runtimeError ?? operationError ?? continuityNotice;
  const visibleMessageTitle = runtimeError ? "Project unavailable"
    : operationError ? "Changes not applied" : "Project reopened";
  const displaySnapshot = telemetrySnapshot ?? snapshot;
  const confirmDemo = DEMO_LAB_CATALOG.find((item) =>
    item.id === confirmDemoId);
  const shellStyle = { "--library-preferred-width": `${project.layout.sidebarWidth}px`,
    "--inspector-preferred-width": `${project.layout.inspectorWidth}px`,
    "--terminal-preferred-height": `${project.layout.terminalHeight}px` } as CSSProperties;

  return <main className={`app-shell ${inspectorOpen ? "" : "inspector-closed"} ${terminalOpen ? "" : "terminal-closed"} ${sidebarOpen ? "sidebar-open" : ""}`} style={shellStyle}>
    <header className="topbar"><button className="nav-toggle" aria-label="Toggle navigation" aria-expanded={sidebarOpen} onClick={() => setSidebarOpen((value) => !value)}>{sidebarOpen ? <X size={20} /> : <Menu size={20} />}</button><div className="brand-area"><button className="brand" aria-expanded={projectMenuOpen} onClick={() => setProjectMenuOpen((value) => !value)}><span className="brand-mark"><Waypoints size={17} strokeWidth={2.1} /></span><strong>Router Lab</strong><ChevronDown className="chevron" size={15} /></button>{projectMenuOpen && <div className="header-menu project-menu"><strong>{project.name}</strong><small>SR OS {PROFILE_CATALOG.release}</small>{confirmNewProject ? <div className="confirm-row"><span>Reset this lab?</span><button onClick={resetProject}>Reset</button><button onClick={() => setConfirmNewProject(false)}>Cancel</button></div> : <button onClick={() => setConfirmNewProject(true)}>New lab</button>}<button onClick={() => importRef.current?.click()}>Import project</button></div>}</div>
      <div className="top-context" aria-hidden><span className="top-context-name">{project.name}</span><span className="top-context-view">{view}</span></div>
      <div className="top-actions"><button className="icon-action" onClick={() => { setPassphrase(""); setPassphraseConfirmation(""); setProtectedFileAction({ kind: "project" }); }}><Download size={16} /> <span>Export</span></button><div className="more-wrap"><button className="more-action" title="More project actions" aria-expanded={moreMenuOpen} onClick={() => setMoreMenuOpen((value) => !value)}><EllipsisVertical size={18} /></button>{moreMenuOpen && <div className="header-menu more-menu"><button onClick={() => { setMoreMenuOpen(false); setPassphrase(""); setPassphraseConfirmation(""); setProtectedFileAction({ kind: "checkpoint" }); }}>Export checkpoint</button><button onClick={() => navigate("settings")}>Project settings</button></div>}</div><input ref={importRef} hidden type="file" accept=".netsim,application/json" onChange={(event) => { void requestImport(event.target.files?.[0]); event.target.value = ""; }} /></div>
    </header>
    {sidebarOpen && <div className="sidebar-backdrop" onClick={() => setSidebarOpen(false)} />}
    <div className="workspace"><aside className="library"><div className="panel-kicker">WORKSPACE</div><nav className="side-nav"><button className={view === "topology" ? "active" : ""} onClick={() => navigate("topology")}><span><Waypoints size={18} /></span>Topology</button><button className={view === "demos" ? "active" : ""} onClick={() => navigate("demos")}><span><Rocket size={18} /></span>Demos</button><button className={view === "devices" ? "active" : ""} onClick={() => navigate("devices")}><span><Server size={18} /></span>Devices</button><button className={view === "captures" ? "active" : ""} onClick={() => navigate("captures")}><span><Radio size={18} /></span>Captures</button></nav><div className="side-divider" /><div className="panel-kicker">DEVICE PALETTE</div>
      <section><h3>ENDPOINTS</h3><button className="library-item" draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-router-lab-device", "host"); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => { setSidebarOpen(false); addDevice("host"); }}><span className="mini-icon device-symbol"><img src="/assets/topology/host-diagram.png" alt="" draggable={false} /></span><span><strong>IP Host</strong><small>{project.hosts.length} configured</small></span></button><button className="library-item" draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-router-lab-device", "dhcp-server"); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => { setSidebarOpen(false); addDevice("dhcp-server"); }}><span className="mini-icon"><Server size={17} /></span><span><strong>DHCP server</strong><small>{project.dhcpServers.length} configured</small></span></button></section>
      <section><h3>ROUTERS</h3><button className="library-item active" draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-router-lab-device", "router"); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => { setSidebarOpen(false); addDevice("router"); }}><span className="mini-icon device-symbol router"><img src="/assets/topology/router-diagram.png" alt="" draggable={false} /></span><span><strong>7750 SR</strong><small>SR OS {PROFILE_CATALOG.release}</small></span></button></section>
      <section><h3>SWITCHES</h3><button className="library-item" draggable onDragStart={(event) => { event.dataTransfer.setData("application/x-router-lab-device", "switch"); event.dataTransfer.effectAllowed = "copy"; }} onClick={() => { setSidebarOpen(false); addDevice("switch"); }}><span className="mini-icon device-symbol switch"><img src="/assets/topology/switch-diagram.png" alt="" draggable={false} /></span><span><strong>Ethernet switch</strong><small>{project.switches.length} configured</small></span></button></section>
      <section><h3>MEDIA</h3><button className={`library-item ${topologyTool === "link" ? "active" : ""}`} onClick={() => { setSidebarOpen(false); setTopologyTool((current) => current === "link" ? "select" : "link"); navigate("topology"); }}><span className="mini-icon link"><Cable size={17} /></span><span><strong>Physical link</strong><small>Drag between free physical ports</small></span></button></section>
      <section><h3>ANNOTATE</h3><button className={`library-item ${topologyTool === "text" ? "active" : ""}`} onClick={() => { setSidebarOpen(false); navigate("topology"); setTopologyTool("text"); }}><span className="mini-icon"><Type size={17} /></span><span><strong>Text label</strong><small>Document addressing on the canvas</small></span></button></section><div className="side-divider" /><div className="panel-kicker">PROJECT</div><nav className="project-nav"><button className={view === "configs" ? "active" : ""} onClick={() => navigate("configs")}><SlidersHorizontal size={16} /> <span>Configuration</span></button><button className={view === "snapshots" ? "active" : ""} onClick={() => navigate("snapshots")}><Camera size={16} /> <span>Snapshots</span></button><button className={view === "notes" ? "active" : ""} onClick={() => navigate("notes")}><NotebookPen size={16} /> <span>Notes</span></button></nav><div className="side-footer"><button className={view === "settings" ? "active" : ""} onClick={() => navigate("settings")}><Settings size={18} /> <span>Settings</span></button><div className="account-wrap"><button aria-expanded={accountMenuOpen} onClick={() => setAccountMenuOpen((value) => !value)}><CircleUser size={18} /> <span>admin</span><b><ChevronDown size={14} /></b></button>{accountMenuOpen && <div className="account-menu"><strong>Local administrator</strong><small>Browser-only session</small><button onClick={() => setAccountMenuOpen(false)}>Close</button></div>}</div></div><PanelResizeHandle axis="x" className="library-resizer" defaultValue={194} direction={1} label="Resize sidebar" min={64} max={Math.max(64, window.innerWidth - 64)} value={project.layout.sidebarWidth} onChange={(value) => resizePanel("sidebarWidth", value)} /></aside>
      <section className="center-stage">{visibleMessage && <div className="runtime-error"><strong>{visibleMessageTitle}</strong><span>{visibleMessage}</span>{!runtimeError && <button onClick={() => { setOperationError(undefined); setContinuityNotice(undefined); }}>Dismiss</button>}</div>}
        {view === "topology" ? <Topology project={project} snapshot={displaySnapshot} selected={selected} onSelect={selectDevice} onLayoutChange={updateLayout} onConnect={(first, second) => { setLinkNodes([first, second]); setLinkPorts(["", ""]); }} onDropDevice={(kind, position) => addDevice(kind, position)} onOpenHardware={() => { if (selectedRouter) setRouterTab("cards"); }} onAnnotationCreate={createAnnotation} onAnnotationMove={moveAnnotation} onAnnotationResize={resizeAnnotation} onAnnotationCommitText={commitAnnotationText} onAnnotationDelete={deleteAnnotation} tool={topologyTool} onToolChange={setTopologyTool} /> : view === "demos" ? <DemosWorkspace demos={DEMO_LAB_CATALOG} pendingDemoId={pendingDemoId} onLaunch={requestDemoLaunch} /> : view === "devices" ? <DevicesWorkspace project={project} snapshot={displaySnapshot} onInspect={selectDevice} onConsole={openConsole} /> : view === "captures" ? <CaptureWorkspace project={project} snapshot={displaySnapshot} selections={captureSelections.map((item) => item.key)} onSelection={(kind, objectId, portId, direction, value) => void setCaptureSelection(kind, objectId, portId, direction, value)} onToggle={() => void toggleCapture()} onExport={() => void exportCaptureNow()} onCheckpoint={() => { setPassphrase(""); setPassphraseConfirmation(""); setProtectedFileAction({ kind: "checkpoint" }); }} /> : view === "configs" ? <ConfigWorkspace router={selectedRouter} onChange={updateRouter} /> : view === "snapshots" ? <SnapshotWorkspace checkpointInput={checkpointRef} onExport={() => { setPassphrase(""); setPassphraseConfirmation(""); setProtectedFileAction({ kind: "checkpoint" }); }} onImport={(event) => void importCheckpointFile(event)} /> : view === "notes" ? <NotesWorkspace value={project.notes} onChange={(notes) => setProject((current) => ({ ...current, notes }))} /> : <SettingsWorkspace project={project} onChange={setProject} onResetLayout={resetLayout} />}
      </section>
      {inspectorOpen && <Inspector selected={selected} tab={routerTab} onTabChange={setRouterTab} project={project} snapshot={displaySnapshot} updateHost={updateHost} updateDhcpServer={updateDhcpServer} updateRouter={updateRouter} setCard={setCard} setMda={setMda} setCardAdmin={setCardAdmin} setMdaAdmin={setMdaAdmin} setSwitchName={setSwitchName} setSwitchPort={setSwitchPort} setLink={(id, up) => void setLink(id, up)} updateLink={updateLink} deleteLink={deleteLink} deleteNode={deleteNode} updateAnnotation={updateAnnotation} deleteAnnotation={deleteAnnotation} ping={ping} width={project.layout.inspectorWidth} onWidthChange={(value) => resizePanel("inspectorWidth", value)} openConsole={openConsole} close={() => setInspectorOpen(false)} />}
    </div>
    {terminalOpen && activeSession && <TerminalPanel key={terminalGeneration} ready={Boolean(runtime && !runtimeError)} systemName={activeTerminalRouter?.systemName ?? "Router"} historyKey={`${project.projectId}:${activeTerminalSession?.routerId ?? "unknown"}:${activeSession}`} execute={execute} complete={complete} cancel={cancelTerminal} state={terminalState} restorePresentation={terminalPresentations[activeSession]} registerCheckpointProvider={registerTerminalCheckpointProvider} tabs={terminalTabs} activeTab={activeSession} selectTab={selectTerminalSession} newTab={() => { if (activeTerminalSession) createConsole(activeTerminalSession.routerId); }} closeTab={closeTerminalSession} height={project.layout.terminalHeight} onHeightChange={(value) => resizePanel("terminalHeight", value)} close={closeTerminal} />}
    {confirmDemo && <div className="modal-backdrop"><div className="lab-dialog"><header><strong>Replace current lab?</strong><button aria-label="Close dialog" disabled={Boolean(pendingDemoId)} onClick={() => setConfirmDemoId(undefined)}><X size={18} /></button></header><p className="dialog-copy">Launching {confirmDemo.title} will replace the active lab and close open console sessions.</p><div className="dialog-actions"><button disabled={Boolean(pendingDemoId)} onClick={() => setConfirmDemoId(undefined)}>Cancel</button><button className="primary" disabled={Boolean(pendingDemoId)} onClick={() => void launchDemo(confirmDemo.id)}>{pendingDemoId ? "Loading" : "Replace and launch"}</button></div></div></div>}
    {pendingRouterPosition && <div className="modal-backdrop"><div className="lab-dialog"><header><strong>Configure router</strong><button aria-label="Close dialog" onClick={() => setPendingRouterPosition(undefined)}><X size={18} /></button></header><label>System name<input value={pendingRouterPosition.systemName} maxLength={32} onChange={(event) => setPendingRouterPosition({ ...pendingRouterPosition, systemName: event.target.value })} /></label><div className="panel-kicker dialog-kicker">CHASSIS PROFILE</div>{PROFILE_CATALOG.profiles.filter((profile) => profile.role === "router").map((profile) => <button key={profile.id} className="primary" disabled={!pendingRouterPosition.systemName.trim()} onClick={() => addRouter(profile.id as DeviceProfileId)}>{profile.chassis}</button>)}</div></div>}
    {linkNodes && <div className="modal-backdrop"><div className="lab-dialog"><header><strong>Connect physical ports</strong><button aria-label="Close dialog" onClick={() => { setLinkNodes(undefined); setTopologyTool("select"); }}><X size={18} /></button></header>{linkNodes.map((node, index) => <label key={node}>{node}<select value={linkPorts[index]} onChange={(event) => setLinkPorts(index === 0 ? [event.target.value, linkPorts[1]] : [linkPorts[0], event.target.value])}><option value="">Select a free port</option>{availablePorts(node).map((port) => <option key={port}>{port}</option>)}</select></label>)}<button className="primary" disabled={!linkPorts[0] || !linkPorts[1]} onClick={createLink}>Connect</button></div></div>}
    {protectedFileAction && <div className="modal-backdrop"><form className="lab-dialog" onSubmit={(event) => { event.preventDefault(); void runProtectedFileAction(); }}><header><strong>{protectedFileAction.kind === "import" ? "Unlock project" : "Protect project export"}</strong><button type="button" aria-label="Close dialog" disabled={passphraseBusy} onClick={() => setProtectedFileAction(undefined)}><X size={18} /></button></header><label>Passphrase<input type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} /></label>{protectedFileAction.kind !== "import" && <label>Confirm<input type="password" autoComplete="new-password" value={passphraseConfirmation} onChange={(event) => setPassphraseConfirmation(event.target.value)} /></label>}<button className="primary" type="submit" disabled={passphraseBusy || !passphrase || (protectedFileAction.kind !== "import" && passphrase !== passphraseConfirmation)}>{passphraseBusy ? "Working" : protectedFileAction.kind === "import" ? "Unlock and import" : "Encrypt and export"}</button></form></div>}
  </main>;
}
