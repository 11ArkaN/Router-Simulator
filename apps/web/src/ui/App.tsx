// Router Lab application composition. React owns views and project drafts while
// C++ remains the sole owner of live operational and protocol state.

import { useCallback, useEffect, useRef, useState } from "react";
import { DEFAULT_PROJECT, GENERATED_PROFILE, parseProject, type HostConfig,
  type LabProject, type ProjectHardware, type RuntimeSnapshot } from "@router-simulator/contracts";
import { RuntimeClient, type HardwareAction, type TerminalState } from "../runtime/client";
import { downloadBinary, exportCheckpoint, exportProject, importNetsim, loadProject, saveBinary, saveProject } from "../persistence";
import { Inspector } from "./Inspector";
import { TerminalPanel } from "./TerminalPanel";
import { Topology } from "./Topology";

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
  const [view, setView] = useState<"topology" | "captures">("topology");
  const [captureActive, setCaptureActive] = useState(true);
  const importRef = useRef<HTMLInputElement>(null);
  const checkpointImportRef = useRef(false);
  // Imports replace the runtime instance. The mount cleanup must close the
  // latest owner rather than the instance captured by the initial effect,
  // otherwise an imported pthread pool survives after React unmounts.
  const runtimeRef = useRef<RuntimeClient | undefined>(undefined);
  runtimeRef.current = runtime;
  const ready = snapshot?.status === "ready";

  useEffect(() => {
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
    if (checkpointImportRef.current) {
      checkpointImportRef.current = false;
      return;
    }
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
    void (async () => {
      try {
        const card = project.hardware.cards[GENERATED_PROFILE.lineCard.slot - 1];
        const mda = card?.mdas[GENERATED_PROFILE.mda.slot - 1];
        await runtime.configureProvisioning(card?.provisionedType ?? null,
          mda?.provisionedType ?? null);
        await runtime.configureRunning(project.runningConfig);
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
        // Medium timing is installed before endpoint state. Both link values
        // cross as one forwarding job, so a terminal command cannot observe a
        // half-updated pair even if a project changes while the app is open.
        await runtime.configureLinks(project.links);
        const next = await runtime.configureHosts(project.hosts);
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
    setProject((current) => ({ ...current, runningConfig: next.runningConfig,
      hardware: projectHardware(current.hardware, next.hardware) }));
    return output;
  }, [runtime]);

  const complete = useCallback(async (input: string) => {
    if (!runtime) return "";
    return runtime.completeTerminal(input);
  }, [runtime]);

  const terminalState = useCallback(async (): Promise<TerminalState> => {
    if (!runtime) throw new Error("Runtime is not ready");
    return runtime.terminalState();
  }, [runtime]);

  const hardware = useCallback(async (action: HardwareAction) => {
    if (!runtime || !projectLoaded) return;
    try {
      // The palette action describes the hardware the user wants in the lab.
      // SR OS still keeps provisioned type and physical presence as distinct
      // state, so the UI sends two acknowledged control operations instead of
      // inventing ports directly. Removing equipment intentionally preserves
      // provisioning, matching a physical pull without a config deletion.
      if (action.kind === "insert-card") {
        await runtime.configureProvisioning(action.type, null);
      } else if (action.kind === "insert-mda") {
        // The mismatch action deliberately provisions the supported 10G MDA
        // and equips a different inventory type so lifecycle reconciliation,
        // alarms and absence of usable ports can be tested from the UI.
        await runtime.configureProvisioning(GENERATED_PROFILE.lineCard.type,
          GENERATED_PROFILE.mda.modeledType);
      }
      const next = await runtime.changeHardware(action);
      setSnapshot(next);
      // Physical changes initiated in the inspector become portable project
      // state immediately, rather than waiting for a sampled UI projection.
      setProject((current) => ({ ...current,
        hardware: projectHardware(current.hardware, next.hardware) }));
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime, projectLoaded]);

  const updateHost = useCallback((host: HostConfig) => {
    setProject((current) => ({
      ...current,
      hosts: current.hosts.map((item) => item.id === host.id ? host : item)
    }));
  }, []);

  const importFile = useCallback(async (file?: File) => {
    if (!file) return;
    try {
      const imported = await importNetsim(file);
      const replacement = new RuntimeClient();
      await replacement.snapshot();
      if (imported.checkpoint) {
        await replacement.importCheckpoint(imported.checkpoint);
        await saveBinary("active.checkpoint", imported.checkpoint);
        checkpointImportRef.current = true;
      }
      if (imported.capture) await saveBinary("active.pcapng", imported.capture);
      const restoredSnapshot = await replacement.snapshot();
      runtime?.close();
      setRuntime(replacement);
      setSnapshot(restoredSnapshot);
      setProject({ ...imported.project, runningConfig: restoredSnapshot.runningConfig });
      setProjectLoaded(true);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [runtime]);

  const toggleCapture = useCallback(async () => {
    if (!runtime) return;
    const next = !captureActive;
    const response = await runtime.setCapture(next);
    if (response.startsWith("ERROR")) throw new Error(response);
    setCaptureActive(next);
  }, [runtime, captureActive]);

  const exportCaptureNow = useCallback(async () => {
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
    try {
      await saveProject({ ...project, updatedAt: new Date().toISOString() });
      setProjectLoaded(true);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [project]);

  const exportNow = useCallback(() => {
    try {
      exportProject(project);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(visibleFailure("operation", cause));
    }
  }, [project]);

  const visibleError = runtimeError ?? operationError;

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark"><i /><i /><i /></span><strong>Router Lab</strong><span className="chevron">⌄</span></div>
        <nav className="top-nav"><button className={view === "topology" ? "active" : ""} onClick={() => setView("topology")}>Topology</button><button>Devices</button><button className={view === "captures" ? "active" : ""} onClick={() => setView("captures")}>Captures</button></nav>
        <div className="top-actions">
          <button className="icon-action" onClick={() => void persistNow()}>▣ <span>Save</span></button>
          <button className="icon-action" onClick={exportNow}>⇧ <span>Export</span></button>
          <button className="more-action" title="Import project" onClick={() => importRef.current?.click()}>⋮</button>
          <input ref={importRef} hidden type="file" accept=".netsim,application/json"
            onChange={(event) => void importFile(event.target.files?.[0])} />
        </div>
      </header>

      <div className="workspace">
        <aside className="library">
          <div className="panel-kicker">TOPOLOGY</div>
          <nav className="side-nav">
            <button className="active"><span>⌘</span>Topology</button>
            <button><span>⊞</span>Devices</button>
            <button className={view === "captures" ? "active" : ""} onClick={() => setView("captures")}><span>⌁</span>Captures</button>
          </nav>
          <div className="side-divider" />
          <div className="panel-kicker">DEVICE PALETTE</div>
          <section><h3>ENDPOINTS</h3><div className="library-item"><span className="mini-icon">H</span><div><strong>IP Host</strong><small>IPv4 endpoint</small></div></div></section>
          <section><h3>ROUTERS</h3><div className="library-item active"><span className="mini-icon router">R</span><div><strong>{GENERATED_PROFILE.chassis}</strong><small>SR OS {GENERATED_PROFILE.release}</small></div></div></section>
          <section><h3>MEDIA</h3><div className="library-item"><span className="mini-icon link">↔</span><div><strong>Physical link</strong><small>Full duplex</small></div></div></section>
          <div className="side-divider" />
          <div className="panel-kicker">PROJECT</div>
          <nav className="project-nav"><button>□ <span>Lab topology</span></button><button>▤ <span>Configs</span></button><button>▧ <span>Captures</span></button><button>▣ <span>Snapshots</span></button><button>▱ <span>Notes</span></button></nav>
          <div className="side-footer"><button>⚙ <span>Settings</span></button><button>♙ <span>admin</span><b>⌄</b></button></div>
        </aside>

        <section className="center-stage">
          {visibleError && <div className="runtime-error"><strong>{runtimeError ? "Lab unavailable" : "Operation failed"}</strong><span>{visibleError}</span></div>}
          {view === "topology" ? <Topology hosts={project.hosts} links={project.links}
            layout={project.layout} systemName={project.runningConfig.systemName}
            snapshot={snapshot} selected={selected} onSelect={setSelected} /> :
            <section className="capture-workspace">
              <div className="capture-workspace-head"><div><span>PACKET OBSERVATION</span><h2>Capture session</h2></div></div>
              <div className="capture-stats">
                <div><small>Records</small><strong>{snapshot?.captureCount ?? 0}</strong></div>
                <div><small>Capture drops</small><strong>{snapshot?.captureDropped ?? 0}</strong></div>
                <div><small>Observation points</small><strong>{GENERATED_PROFILE.captureInterfaces.length}</strong></div>
              </div>
              <div className="capture-actions">
                <button onClick={() => void toggleCapture()}>{captureActive ? "Stop capture" : "Start capture"}</button>
                <button onClick={() => void exportCaptureNow()}>Export PCAPNG</button>
                <button onClick={() => void exportCheckpointNow()}>Export snapshot</button>
              </div>
              <div className="capture-points">
                {GENERATED_PROFILE.captureInterfaces.map((point) => <span key={point}>{point}</span>)}
              </div>
            </section>}
        </section>

        <Inspector selected={selected} hosts={project.hosts} snapshot={snapshot}
          systemName={project.runningConfig.systemName} updateHost={updateHost} hardware={hardware} />
      </div>
      <TerminalPanel ready={Boolean(runtime && !runtimeError && projectLoaded)}
        systemName={project.runningConfig.systemName} execute={execute}
        complete={complete} state={terminalState} />
    </main>
  );
}
