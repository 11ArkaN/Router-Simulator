// Router Lab application composition. React owns views and project drafts while
// C++ remains the sole owner of live operational and protocol state.

import { useCallback, useEffect, useRef, useState, type CSSProperties, type ChangeEvent } from "react";
import { DEFAULT_PROJECT, GENERATED_PROFILE, parseProject, type HostConfig,
  type LabProject, type ProjectHardware, type RuntimeSnapshot } from "@router-simulator/contracts";
import { RuntimeClient, type HardwareAction, type TerminalState } from "../runtime/client";
import { downloadBinary, exportCheckpoint, exportProject, importNetsim,
  IncompatibleCheckpointError, loadProject, saveBinary, saveProject } from "../persistence";
import { Inspector, type RouterTab } from "./Inspector";
import { TerminalPanel } from "./TerminalPanel";
import { Topology } from "./Topology";
import { CaptureWorkspace, ConfigWorkspace, DevicesWorkspace, NotesWorkspace,
  SettingsWorkspace, SnapshotWorkspace, type WorkspaceView } from "./WorkspaceViews";
import { changedProjectDomains, type AppliedProjectDomains } from "./project-domains";

function projectHardware(current: ProjectHardware,
  runtime: RuntimeSnapshot["hardware"]): ProjectHardware {
  // Copy only portable intent from the live projection. If all values already
  // match, preserve object identity so React does not replay hardware restore
  // after an unrelated terminal command or counter refresh.
  let changed = false;
  const cards = runtime.cards.map((card, cardIndex) => {
    const previous = current.cards[cardIndex];
    const mdas = card.mdas.map((mda, mdaIndex) => {
      const before = previous?.mdas[mdaIndex];
      if (!before || before.slot !== mda.slot || before.provisionedType !== mda.provisionedType ||
          before.equippedType !== mda.equippedType) changed = true;
      return { slot: mda.slot, provisionedType: mda.provisionedType,
        equippedType: mda.equippedType };
    });
    if (!previous || previous.slot !== card.slot || previous.provisionedType !== card.provisionedType ||
        previous.equippedType !== card.equippedType || previous.mdas.length !== mdas.length) changed = true;
    return { slot: card.slot, provisionedType: card.provisionedType,
      equippedType: card.equippedType, mdas };
  });
  if (current.cards.length !== cards.length) changed = true;
  return changed ? { cards } : current;
}

function visibleFailure(area: "startup" | "operation", cause: unknown): string {
  // Detailed transport and core failures remain available to developers while
  // the product surface exposes only a stable, actionable message.
  console.error(`Lab ${area} failure`, cause);
  return area === "startup"
    ? "The lab could not start. Reload the page and try again."
    : "The operation could not be completed. No changes were applied.";
}

export function App() {
  // App owns portable drafts and view state only. RuntimeSnapshot values are
  // immutable acknowledgements from C++; no setter below fabricates a route,
  // adjacency, hardware lifecycle, port status or packet counter.
  const [project, setProject] = useState<LabProject>(DEFAULT_PROJECT);
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot>();
  const [selected, setSelected] = useState<string>(GENERATED_PROFILE.uiDefaults.router_id);
  // Runtime failures and project-operation failures have different lifetimes.
  // A rejected import must not disable a healthy terminal or claim that the
  // two C++ ownership domains stopped running.
  const [runtimeError, setRuntimeError] = useState<string>();
  const [operationError, setOperationError] = useState<string>();
  const [runtime, setRuntime] = useState<RuntimeClient>();
  const [projectLoaded, setProjectLoaded] = useState(false);
  const [view, setView] = useState<WorkspaceView>("topology");
  const [captureActive, setCaptureActive] = useState(true);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [terminalOpen, setTerminalOpen] = useState(true);
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const [moreMenuOpen, setMoreMenuOpen] = useState(false);
  const [confirmNewProject, setConfirmNewProject] = useState(false);
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved">("idle");
  const [topologyTool, setTopologyTool] = useState<"select" | "link">("select");
  const [routerTab, setRouterTab] = useState<RouterTab>("chassis");
  const importRef = useRef<HTMLInputElement>(null);
  const checkpointRef = useRef<HTMLInputElement>(null);
  const appliedDomainsRef = useRef<AppliedProjectDomains | undefined>(undefined);
  // Imports replace the runtime instance. The mount cleanup must close the
  // latest owner rather than the instance captured by the initial effect,
  // otherwise an imported pthread pool survives after React unmounts.
  const runtimeRef = useRef<RuntimeClient | undefined>(undefined);
  runtimeRef.current = runtime;
  const ready = snapshot?.status === "ready";

  useEffect(() => {
    // Persistence and runtime boot begin independently, but the domain bridge
    // remains gated by projectLoaded. This prevents DEFAULT_PROJECT from
    // reaching C++ while IndexedDB still holds the user's actual laboratory.
    let client: RuntimeClient | undefined;
    let cancelled = false;
    void loadProject()
      .then((value) => {
        if (!cancelled) {
          setProject(value);
          setProjectLoaded(true);
        }
      })
      .catch((cause) => {
        if (!cancelled) setOperationError(visibleFailure("operation", cause));
      });
    try {
      client = new RuntimeClient();
      setRuntime(client);
      void client.snapshot()
        .then((value) => !cancelled && setSnapshot(value))
        .catch((cause) => !cancelled && setRuntimeError(visibleFailure("startup", cause)));
    } catch (cause) {
      setRuntimeError(visibleFailure("startup", cause));
    }
    return () => {
      cancelled = true;
      runtimeRef.current?.close();
    };
  }, []);

  useEffect(() => {
    // Never let the temporary DEFAULT_PROJECT value race an IndexedDB read and
    // overwrite the active project. A failed read remains untouched until the
    // user explicitly saves a recovery project or imports a valid file.
    if (!projectLoaded) return;
    // Form fields are controlled inputs, so an address is temporarily invalid
    // while a user replaces it. Keep the last valid IndexedDB value until the
    // complete project passes the same schema used by import and restoration.
    try {
      parseProject(project);
    } catch {
      return;
    }
    const timer = window.setTimeout(() => {
      void saveProject({ ...project, updatedAt: new Date().toISOString() })
        .then(() => setOperationError(undefined))
        .catch((cause) => setOperationError(visibleFailure("operation", cause)));
    }, GENERATED_PROFILE.timing.autosave_debounce_milliseconds);
    return () => window.clearTimeout(timer);
  }, [project, projectLoaded]);

  useEffect(() => {
    if (!runtime || !projectLoaded) return;
    // Project restore follows the same dependency order as the hardware model:
    // provisioning, parent equipment, child equipment, then endpoint values.
    // Every operation is acknowledged before the next one is submitted.
    let cancelled = false;
    try {
      parseProject(project);
    } catch {
      // Invalid intermediate form text is UI draft state. It must not mutate
      // the live forwarding owner or convert a healthy runtime into blocked.
      return;
    }
    const changes = changedProjectDomains(appliedDomainsRef.current, project);
    const hardwareChanged = changes.hardware;
    const configChanged = changes.runningConfig;
    const linksChanged = changes.links;
    const hostsChanged = changes.hosts;
    if (!hardwareChanged && !configChanged && !linksChanged && !hostsChanged) return;
    void (async () => {
      try {
        const card = project.hardware.cards[GENERATED_PROFILE.lineCard.slot - 1];
        const mda = card?.mdas[GENERATED_PROFILE.mda.slot - 1];
        if (hardwareChanged) {
          await runtime.configureProvisioning(card?.provisionedType ?? null,
            mda?.provisionedType ?? null);
          await runtime.changeHardware(card?.equippedType
            ? { kind: "insert-card", slot: card.slot, type: card.equippedType }
            : { kind: "remove-card", slot: GENERATED_PROFILE.lineCard.slot });
          if (card?.equippedType) {
            await runtime.changeHardware(mda?.equippedType
              ? { kind: "insert-mda", cardSlot: card.slot, mdaSlot: mda.slot,
                  type: mda.equippedType }
              : { kind: "remove-mda", cardSlot: card.slot,
                  mdaSlot: GENERATED_PROFILE.mda.slot });
          }
          appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
            runningConfig: project.runningConfig, links: project.links, hosts: project.hosts
          }), hardware: project.hardware };
        }
        if (configChanged) {
          await runtime.configureRunning(project.runningConfig);
          appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
            hardware: project.hardware, links: project.links, hosts: project.hosts
          }), runningConfig: project.runningConfig };
        }
        // Medium timing is installed before endpoint state. Both link values
        // cross as one forwarding job, so a terminal command cannot observe a
        // half-updated pair even if a project changes while the app is open.
        if (linksChanged) {
          await runtime.configureLinks(project.links);
          appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
            hardware: project.hardware, runningConfig: project.runningConfig,
            hosts: project.hosts
          }), links: project.links };
        }
        const next = hostsChanged ? await runtime.configureHosts(project.hosts) : undefined;
        if (hostsChanged) {
          appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
            hardware: project.hardware, runningConfig: project.runningConfig,
            links: project.links
          }), hosts: project.hosts };
        }
        if (!cancelled && next) setSnapshot(next);
      } catch (cause) {
        if (!cancelled) setOperationError(visibleFailure("operation", cause));
      }
    })();
    return () => { cancelled = true; };
  }, [runtime, project.hosts, project.links, project.hardware, project.runningConfig, projectLoaded]);

  useEffect(() => {
    if (!runtime || !ready) return;
    // Fast-changing counters and port bits are copied from the seqlock-protected
    // SharedArrayBuffer page. No Worker request, JSON parse or packet event is
    // needed for this sampling path.
    const timer = window.setInterval(() => {
      setSnapshot((current) => current ? runtime.telemetry(current) : current);
    }, GENERATED_PROFILE.timing.telemetry_interval_milliseconds);
    return () => window.clearInterval(timer);
  }, [runtime, ready]);

  useEffect(() => {
    if (!runtime || !snapshot) return;
    const transitioning = snapshot.hardware.cards.some((card) =>
      card.lifecycle === "initializing" || card.mdas.some((mda) =>
        mda.lifecycle === "initializing" || mda.lifecycle === "waiting-parent"));
    if (!transitioning) return;
    // Equipment deadlines are slow control-plane changes and are intentionally
    // absent from the high-frequency telemetry page. One profile-paced read
    // while a transition is active makes the final lifecycle and alarm state
    // visible without turning JSON snapshots into packet telemetry polling.
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void runtime.snapshot()
        .then((next) => { if (!cancelled) setSnapshot(next); })
        .catch((cause) => { if (!cancelled) setOperationError(visibleFailure("operation", cause)); });
    }, GENERATED_PROFILE.timing.equipment_poll_milliseconds);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [runtime, snapshot?.hardware.cards]);

  const execute = useCallback(async (command: string) => {
    if (!runtime) throw new Error("Runtime is not ready");
    const output = await runtime.executeTerminal(command);
    const next = await runtime.snapshot();
    setSnapshot(next);
    setProject((current) => {
      // Terminal commands have already committed these domains inside C++.
      // Marking their exact portable projection as acknowledged prevents the
      // React restoration bridge from applying the same command a second time.
      const nextHardware = projectHardware(current.hardware, next.hardware);
      appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
        links: current.links, hosts: current.hosts
      }), runningConfig: next.runningConfig, hardware: nextHardware };
      return { ...current, runningConfig: next.runningConfig, hardware: nextHardware };
    });
    return output;
  }, [runtime]);

  const complete = useCallback(async (
    input: string, trigger: "tab" | "question" | "space"
  ) => {
    // Completion stays read-only and session-owned. React forwards the current
    // line and trigger without maintaining a duplicate command grammar.
    if (!runtime) return "";
    return runtime.completeTerminal(input, trigger);
  }, [runtime]);

  const cancelTerminal = useCallback(() => {
    // Cancellation is intentionally synchronous. It sets the shared signal
    // while the command promise remains pending and requires no UI state guess.
    runtime?.cancelTerminal();
  }, [runtime]);

  const terminalState = useCallback(async (): Promise<TerminalState> => {
    // Prompt, engine and history region are fetched as one router-owned value
    // so a terminal redraw cannot combine fields from different CLI contexts.
    if (!runtime) throw new Error("Runtime is not ready");
    return runtime.terminalState();
  }, [runtime]);

  const hardware = useCallback(async (action: HardwareAction) => {
    if (!runtime || !projectLoaded) return;
    try {
      // Chassis controls represent physical handling only. They never edit the
      // router datastore: an unprovisioned insertion remains waiting for CLI
      // provisioning, and a mismatched insertion remains offline until the
      // user corrects either inventory or configuration. Removal intentionally
      // preserves provisioning, matching a physical pull on SR OS.
      const next = await runtime.changeHardware(action);
      setSnapshot(next);
      // Physical changes initiated in the inspector become portable project
      // state immediately, rather than waiting for a sampled UI projection.
      setProject((current) => {
        const nextHardware = projectHardware(current.hardware, next.hardware);
        appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
          runningConfig: current.runningConfig, links: current.links, hosts: current.hosts
        }), hardware: nextHardware };
        return { ...current, hardware: nextHardware };
      });
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime, projectLoaded]);

  const updateHost = useCallback((host: HostConfig) => {
    // Host text remains a portable draft until parseProject accepts the whole
    // endpoint set. The restoration bridge then submits both hosts atomically.
    setProject((current) => ({
      ...current,
      hosts: current.hosts.map((item) => item.id === host.id ? host : item)
    }));
  }, []);

  const updateLayout = useCallback((id: string, position: { x: number; y: number }) => {
    // React Flow reports a final finite canvas coordinate. Persisting only the
    // drag end avoids autosaving every animation frame while retaining the
    // exact user-authored topology in the portable project.
    if (!Number.isFinite(position.x) || !Number.isFinite(position.y)) return;
    setProject((current) => ({ ...current, layout: { ...current.layout,
      nodes: { ...current.layout.nodes, [id]: position } } }));
  }, []);

  const selectDevice = useCallback((id: string) => {
    // Selection is navigation only. Opening an inspector never changes device
    // presence, configuration or operational state.
    setSelected(id);
    setInspectorOpen(true);
  }, []);

  const setLink = useCallback(async (portId: string, up: boolean) => {
    // Carrier changes cross the typed client and return a fresh snapshot. The
    // topology edge itself cannot set ifOperStatus or clear adjacency state.
    if (!runtime) return;
    try {
      const next = await runtime.setLink(portId, up);
      setSnapshot(next);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime]);

  const ping = useCallback(async (sourceId: string, destinationId: string) => {
    if (!runtime) throw new Error("Runtime is not ready");
    // The runtime resolves the two profile endpoint IDs and sends encoded ARP
    // and ICMP frames through the real forwarding and link shards.
    const output = await runtime.hostPing(sourceId, destinationId);
    setSnapshot(await runtime.snapshot());
    return output;
  }, [runtime]);

  const importFile = useCallback(async (file?: File) => {
    // Import is transactional at the runtime-instance boundary. The active
    // instance remains alive until the replacement validates and opens.
    if (!file) return;
    try {
      let imported: Awaited<ReturnType<typeof importNetsim>>;
      try {
        imported = await importNetsim(file);
      } catch (cause) {
        if (!(cause instanceof IncompatibleCheckpointError) ||
            !window.confirm("This checkpoint was created by an incompatible build. Import only the project and start with fresh operational state?"))
          throw cause;
        // Consent is explicit and scoped to this file. No checkpoint, ARP,
        // capture or queued packet is retained in the project-only fallback.
        imported = await importNetsim(file, true);
      }
      const replacement = new RuntimeClient();
      await replacement.snapshot();
      if (imported.checkpoint) {
        await replacement.importCheckpoint(imported.checkpoint);
        await saveBinary("active.checkpoint", imported.checkpoint);
      }
      if (imported.capture) await saveBinary("active.pcapng", imported.capture);
      const restoredSnapshot = await replacement.snapshot();
      runtime?.close();
      // A checkpoint already contains every runtime domain. A plain project
      // starts from the replacement runtime defaults and must be applied in
      // full by the restoration effect.
      const nextProject = { ...imported.project,
        runningConfig: restoredSnapshot.runningConfig };
      appliedDomainsRef.current = imported.checkpoint ? {
        hardware: nextProject.hardware,
        runningConfig: nextProject.runningConfig,
        links: nextProject.links,
        hosts: nextProject.hosts
      } : undefined;
      setRuntime(replacement);
      setSnapshot(restoredSnapshot);
      setProject(nextProject);
      setProjectLoaded(true);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime]);

  const toggleCapture = useCallback(async () => {
    // UI state flips only after C++ acknowledges the observation-store command.
    // Capture does not pause or alter forwarding.
    if (!runtime) return;
    try {
      const next = !captureActive;
      const response = await runtime.setCapture(next);
      if (response.startsWith("ERROR")) throw new Error(response);
      setCaptureActive(next);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime, captureActive]);

  const importCheckpointFile = useCallback(async (event: ChangeEvent<HTMLInputElement>) => {
    // Reading bytes is browser-owned, while checkpoint structure, ABI and
    // release compatibility are validated by the current C++ runtime owner.
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !runtime) return;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      await runtime.importCheckpoint(bytes);
      const next = await runtime.snapshot();
      await saveBinary("active.checkpoint", bytes);
      setSnapshot(next);
      setProject((current) => {
        // Import restored the C++ owner first. Synchronize portable intent and
        // mark it acknowledged so no card lifecycle deadline is restarted.
        const nextHardware = projectHardware(current.hardware, next.hardware);
        appliedDomainsRef.current = { ...(appliedDomainsRef.current ?? {
          links: current.links, hosts: current.hosts
        }), runningConfig: next.runningConfig, hardware: nextHardware };
        return { ...current, runningConfig: next.runningConfig,
          hardware: nextHardware };
      });
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime]);

  const exportCaptureNow = useCallback(async () => {
    // Export serializes the bounded C++ capture store. React receives one
    // immutable byte array and never reconstructs packets from counters.
    if (!runtime) return;
    try {
      const bytes = await runtime.exportCapture();
      await saveBinary("active.pcapng", bytes);
      downloadBinary("router-lab.pcapng", bytes, "application/vnd.tcpdump.pcap");
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime]);

  const exportCheckpointNow = useCallback(async () => {
    // Checkpoint and capture are sampled through their dedicated binary ABI and
    // persisted together before a portable archive is offered to the user.
    if (!runtime) return;
    try {
      const checkpoint = await runtime.exportCheckpoint();
      const capture = await runtime.exportCapture();
      await Promise.all([saveBinary("active.checkpoint", checkpoint), saveBinary("active.pcapng", capture)]);
      exportCheckpoint(project, checkpoint, capture);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime, project]);

  const persistNow = useCallback(async () => {
    // Manual Save bypasses debounce but uses the same versioned project store.
    // The short Saved indication is presentation state, not storage truth.
    try {
      setSaveState("saving");
      await saveProject({ ...project, updatedAt: new Date().toISOString() });
      setProjectLoaded(true);
      setOperationError(undefined);
      setSaveState("saved");
      window.setTimeout(() => setSaveState("idle"), 1400);
    } catch (cause) {
      setSaveState("idle");
      setOperationError(visibleFailure("operation", cause));
    }
  }, [project]);

  const exportNow = useCallback(() => {
    // Project export contains intent only. Runtime-owned timers and tables are
    // available through the separate checkpoint action.
    try {
      exportProject(project);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [project]);

  const resetProject = useCallback(() => {
    // Reset is explicit and keeps the current runtime owner. The normal project
    // restoration effect applies default provisioning, endpoints and links in
    // dependency order without recreating workers behind the user's back.
    setProject(structuredClone(DEFAULT_PROJECT));
    setSelected(GENERATED_PROFILE.uiDefaults.router_id);
    setView("topology");
    setInspectorOpen(true);
    setTerminalOpen(true);
    setConfirmNewProject(false);
    setProjectMenuOpen(false);
  }, []);

  const resetLayout = useCallback(() => {
    // Reset affects canvas coordinates only. It must not replace router or
    // physical-link objects that happen to share the project container.
    setProject((current) => ({ ...current, layout: { ...current.layout,
      nodes: structuredClone(GENERATED_PROFILE.uiDefaults.nodes) } }));
  }, []);

  const visibleError = runtimeError ?? operationError;
  const navigate = (next: WorkspaceView) => {
    // Navigation closes transient menus so an invisible overlay cannot retain
    // pointer ownership over the newly selected workspace.
    setView(next);
    setProjectMenuOpen(false);
    setAccountMenuOpen(false);
    setMoreMenuOpen(false);
  };
  const shellStyle = {
    "--inspector-width": `${project.layout.inspectorWidth}px`,
    "--terminal-height": `${project.layout.terminalHeight}px`
  } as CSSProperties;

  return (
    <main className={`app-shell ${inspectorOpen ? "" : "inspector-closed"} ${terminalOpen ? "" : "terminal-closed"}`} style={shellStyle}>
      <header className="topbar">
        <div className="brand-area"><button className="brand" aria-expanded={projectMenuOpen} onClick={() => setProjectMenuOpen((value) => !value)}><span className="brand-mark"><i /><i /><i /></span><strong>Router Lab</strong><span className="chevron">⌄</span></button>{projectMenuOpen && <div className="header-menu project-menu"><strong>{project.name}</strong><small>SR OS {GENERATED_PROFILE.release}</small>{confirmNewProject ? <div className="confirm-row"><span>Reset this lab?</span><button onClick={resetProject}>Reset</button><button onClick={() => setConfirmNewProject(false)}>Cancel</button></div> : <button onClick={() => setConfirmNewProject(true)}>New default lab</button>}<button onClick={() => importRef.current?.click()}>Import project</button></div>}</div>
        <nav className="top-nav"><button className={view === "topology" ? "active" : ""} onClick={() => navigate("topology")}>Topology</button><button className={view === "devices" ? "active" : ""} onClick={() => navigate("devices")}>Devices</button><button className={view === "captures" ? "active" : ""} onClick={() => navigate("captures")}>Captures</button></nav>
        <div className="top-actions">
          <button className="icon-action" onClick={() => void persistNow()}>▣ <span>{saveState === "saving" ? "Saving" : saveState === "saved" ? "Saved" : "Save"}</span></button>
          <button className="icon-action" onClick={exportNow}>⇧ <span>Export</span></button>
          <div className="more-wrap"><button className="more-action" title="More project actions" aria-expanded={moreMenuOpen} onClick={() => setMoreMenuOpen((value) => !value)}>⋮</button>{moreMenuOpen && <div className="header-menu more-menu"><button onClick={() => importRef.current?.click()}>Import project</button><button onClick={() => void exportCheckpointNow()}>Export checkpoint</button><button onClick={() => navigate("settings")}>Project settings</button></div>}</div>
          <input ref={importRef} hidden type="file" accept=".netsim,application/json"
            onChange={(event) => { void importFile(event.target.files?.[0]); event.target.value = ""; }} />
        </div>
      </header>

      <div className="workspace">
        <aside className="library">
          <div className="panel-kicker">TOPOLOGY</div>
          <nav className="side-nav">
            <button className={view === "topology" ? "active" : ""} onClick={() => navigate("topology")}><span>⌘</span>Topology</button>
            <button className={view === "devices" ? "active" : ""} onClick={() => navigate("devices")}><span>⊞</span>Devices</button>
            <button className={view === "captures" ? "active" : ""} onClick={() => navigate("captures")}><span>⌁</span>Captures</button>
          </nav>
          <div className="side-divider" />
          <div className="panel-kicker">DEVICE PALETTE</div>
          <section><h3>ENDPOINTS</h3><button className="library-item" onClick={() => { navigate("topology"); selectDevice(project.hosts[0].id); }}><span className="mini-icon">H</span><span><strong>IP Host</strong><small>{project.hosts.length} configured</small></span></button></section>
          <section><h3>ROUTERS</h3><button className="library-item active" onClick={() => { navigate("topology"); selectDevice(GENERATED_PROFILE.uiDefaults.router_id); }}><span className="mini-icon router">R</span><span><strong>{GENERATED_PROFILE.chassis}</strong><small>SR OS {GENERATED_PROFILE.release}</small></span></button></section>
          <section><h3>MEDIA</h3><button className={`library-item ${topologyTool === "link" ? "active" : ""}`} onClick={() => { navigate("topology"); setTopologyTool("link"); }}><span className="mini-icon link">↔</span><span><strong>Physical link</strong><small>Click a link to toggle carrier</small></span></button></section>
          <div className="side-divider" />
          <div className="panel-kicker">PROJECT</div>
          <nav className="project-nav"><button className={view === "topology" ? "active" : ""} onClick={() => navigate("topology")}>□ <span>Lab topology</span></button><button className={view === "configs" ? "active" : ""} onClick={() => navigate("configs")}>▤ <span>Configs</span></button><button className={view === "captures" ? "active" : ""} onClick={() => navigate("captures")}>▧ <span>Captures</span></button><button className={view === "snapshots" ? "active" : ""} onClick={() => navigate("snapshots")}>▣ <span>Snapshots</span></button><button className={view === "notes" ? "active" : ""} onClick={() => navigate("notes")}>▱ <span>Notes</span></button></nav>
          <div className="side-footer"><button className={view === "settings" ? "active" : ""} onClick={() => navigate("settings")}>⚙ <span>Settings</span></button><div className="account-wrap"><button aria-expanded={accountMenuOpen} onClick={() => setAccountMenuOpen((value) => !value)}>♙ <span>admin</span><b>⌄</b></button>{accountMenuOpen && <div className="account-menu"><strong>Local administrator</strong><small>Browser-only session</small><button onClick={() => void persistNow()}>Save session</button><button onClick={() => setAccountMenuOpen(false)}>Close</button></div>}</div></div>
        </aside>

        <section className="center-stage">
          {visibleError && <div className="runtime-error"><strong>{runtimeError ? "Lab unavailable" : "Operation failed"}</strong><span>{visibleError}</span>{!runtimeError && <button onClick={() => setOperationError(undefined)}>Dismiss</button>}</div>}
          {view === "topology" ? <Topology hosts={project.hosts} links={project.links}
            layout={project.layout} systemName={project.runningConfig.systemName}
            snapshot={snapshot} selected={selected} onSelect={selectDevice}
            onLayoutChange={updateLayout} onLinkToggle={(port, up) => void setLink(port, up)}
            onOpenHardware={() => {
              // The toolbar hardware action opens the actual Cards surface,
              // including provisioned and equipped lifecycle controls.
              selectDevice(GENERATED_PROFILE.uiDefaults.router_id);
              setRouterTab("cards");
            }}
            tool={topologyTool} onToolChange={setTopologyTool} /> : view === "devices" ?
            <DevicesWorkspace project={project} snapshot={snapshot} onInspect={selectDevice} onConsole={() => setTerminalOpen(true)} /> : view === "captures" ?
            <CaptureWorkspace snapshot={snapshot} active={captureActive} onToggle={() => void toggleCapture()} onExport={() => void exportCaptureNow()} onCheckpoint={() => void exportCheckpointNow()} /> : view === "configs" ?
            <ConfigWorkspace config={project.runningConfig} onChange={(runningConfig) => setProject((current) => ({ ...current, runningConfig }))} /> : view === "snapshots" ?
            <SnapshotWorkspace checkpointInput={checkpointRef} onExport={() => void exportCheckpointNow()} onImport={(event) => void importCheckpointFile(event)} /> : view === "notes" ?
            <NotesWorkspace value={project.notes} onChange={(notes) => setProject((current) => ({ ...current, notes }))} /> :
            <SettingsWorkspace project={project} onChange={setProject} onResetLayout={resetLayout} />}
        </section>

        {inspectorOpen && <Inspector selected={selected} tab={routerTab}
          onTabChange={setRouterTab} hosts={project.hosts} snapshot={snapshot}
          systemName={project.runningConfig.systemName} updateHost={updateHost} hardware={hardware}
          setLink={(port, up) => void setLink(port, up)} ping={ping}
          openConsole={() => setTerminalOpen(true)} close={() => setInspectorOpen(false)} />}
      </div>
      {terminalOpen && <TerminalPanel ready={Boolean(runtime && !runtimeError && projectLoaded)}
        systemName={project.runningConfig.systemName} execute={execute}
        complete={complete} cancel={cancelTerminal} state={terminalState}
        close={() => setTerminalOpen(false)} />}
    </main>
  );
}
