// Router Lab application composition. React owns views and project drafts while
// C++ remains the sole owner of live operational and protocol state.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DEFAULT_PROJECT, GENERATED_PROFILE, parseProject, parseRuntimeSnapshot, type HostConfig, type LabProject, type RuntimeSnapshot } from "@router-simulator/contracts";
import { RuntimeClient } from "../runtime/client";
import { downloadBinary, exportCheckpoint, exportProject, importNetsim, loadProject, saveBinary, saveProject } from "../persistence";
import { Inspector } from "./Inspector";
import { TerminalPanel } from "./TerminalPanel";
import { Topology } from "./Topology";

const projectHardware = (hardware: RuntimeSnapshot["hardware"]): LabProject["hardware"] => ({
  chassis: hardware.chassis,
  cpmA: hardware.cpmA,
  card1Provisioned: hardware.card1Provisioned,
  mda11Provisioned: hardware.mda11Provisioned,
  card1: hardware.card1,
  mda11: hardware.mda11
});

export function App() {
  const [project, setProject] = useState<LabProject>(DEFAULT_PROJECT);
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot>();
  const [selected, setSelected] = useState("r1");
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
        if (!cancelled) setOperationError(cause instanceof Error ? cause.message : String(cause));
      });
    try {
      client = new RuntimeClient();
      setRuntime(client);
      void client.snapshot()
        .then((value) => !cancelled && setSnapshot(value))
        .catch((cause) => !cancelled && setRuntimeError(String(cause)));
    } catch (cause) {
      setRuntimeError(cause instanceof Error ? cause.message : String(cause));
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
        .catch((cause) => setOperationError(cause instanceof Error ? cause.message : String(cause)));
    }, 400);
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
        let raw = await runtime.command(
          `project:provisioning|${project.hardware.card1Provisioned}|${project.hardware.mda11Provisioned}`
        );
        if (raw.startsWith("ERROR")) throw new Error(raw);
        await runtime.configureRunning(project.runningConfig);
        raw = await runtime.command(project.hardware.card1 === "iom4-e"
          ? "hardware:insert-card" : "hardware:remove-card");
        if (raw.startsWith("ERROR")) throw new Error(raw);
        if (project.hardware.card1 === "iom4-e") {
          raw = await runtime.command(project.hardware.mda11 === "absent"
            ? "hardware:remove-mda"
            : `hardware:insert-mda:${project.hardware.mda11}`);
          if (raw.startsWith("ERROR")) throw new Error(raw);
        }
        // Medium timing is installed before endpoint state. Both link values
        // cross as one forwarding job, so a terminal command cannot observe a
        // half-updated pair even if a project changes while the app is open.
        await runtime.configureLinks(project.links);
        const next = await runtime.configureHosts(project.hosts);
        if (!cancelled && next) setSnapshot(next);
      } catch (cause) {
        if (!cancelled) setOperationError(cause instanceof Error ? cause.message : String(cause));
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
    }, 250);
    return () => window.clearInterval(timer);
  }, [runtime, ready]);

  useEffect(() => {
    if (!runtime || !snapshot) return;
    const transitioning = snapshot.hardware.cardLifecycle === "initializing" ||
      snapshot.hardware.mdaLifecycle === "initializing" ||
      snapshot.hardware.mdaLifecycle === "waiting-parent";
    if (!transitioning) return;
    // Equipment deadlines are slow control-plane changes and are intentionally
    // absent from the high-frequency telemetry page. One bounded 250 ms read
    // while a transition is active makes the final lifecycle and alarm state
    // visible without turning JSON snapshots into packet telemetry polling.
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void runtime.snapshot()
        .then((next) => { if (!cancelled) setSnapshot(next); })
        .catch((cause) => { if (!cancelled) setOperationError(cause instanceof Error ? cause.message : String(cause)); });
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [runtime, snapshot?.hardware.cardLifecycle, snapshot?.hardware.mdaLifecycle]);

  const execute = useCallback(async (command: string) => {
    if (!runtime) throw new Error("Runtime is not ready");
    const output = await runtime.command(`terminal:${command}`);
    const next = await runtime.snapshot();
    setSnapshot(next);
    setProject((current) => ({ ...current, runningConfig: next.runningConfig,
      hardware: projectHardware(next.hardware) }));
    return output;
  }, [runtime]);

  const complete = useCallback(async (input: string) => {
    if (!runtime) return "";
    return runtime.command(`terminal:complete:${input}`);
  }, [runtime]);

  const hardware = useCallback(async (command: string) => {
    if (!runtime || !projectLoaded) return;
    try {
      // The palette action describes the hardware the user wants in the lab.
      // SR OS still keeps provisioned type and physical presence as distinct
      // state, so the UI sends two acknowledged control operations instead of
      // inventing ports directly. Removing equipment intentionally preserves
      // provisioning, matching a physical pull without a config deletion.
      if (command === "hardware:insert-card") {
        const provisioned = await runtime.command("project:provisioning|iom4-e|absent");
        if (provisioned.startsWith("ERROR")) throw new Error(provisioned);
      } else if (command === "hardware:insert-mda:me10-10gb-sfp+" ||
                 command === "hardware:insert-mda:me1-100gb-cfp2") {
        // The mismatch action deliberately provisions the supported 10G MDA
        // and equips a different inventory type so lifecycle reconciliation,
        // alarms and absence of usable ports can be tested from the UI.
        const provisioned = await runtime.command("project:provisioning|iom4-e|me10-10gb-sfp+");
        if (provisioned.startsWith("ERROR")) throw new Error(provisioned);
      }
      const output = await runtime.command(command);
      if (output.startsWith("ERROR")) throw new Error(output);
      const next = parseRuntimeSnapshot(JSON.parse(output));
      setSnapshot(next);
      // Physical changes initiated in the inspector become portable project
      // state immediately, rather than waiting for a sampled UI projection.
      setProject((current) => ({ ...current, hardware: projectHardware(next.hardware) }));
    } catch (cause) {
      setOperationError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [runtime, projectLoaded]);

  const updateHost = useCallback((host: HostConfig) => {
    setProject((current) => ({
      ...current,
      hosts: current.hosts.map((item) => item.id === host.id ? host : item) as [HostConfig, HostConfig]
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
      setOperationError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [runtime]);

  const toggleCapture = useCallback(async () => {
    if (!runtime) return;
    const next = !captureActive;
    const response = await runtime.command(next ? "capture:start" : "capture:stop");
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
      setOperationError(cause instanceof Error ? cause.message : String(cause));
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
      setOperationError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [runtime, project]);

  const persistNow = useCallback(async () => {
    try {
      await saveProject({ ...project, updatedAt: new Date().toISOString() });
      setProjectLoaded(true);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [project]);

  const exportNow = useCallback(() => {
    try {
      exportProject(project);
      setOperationError(undefined);
    } catch (cause) {
      setOperationError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [project]);

  const runtimeLabel = useMemo(() => {
    if (runtimeError) return "runtime blocked";
    if (!snapshot) return "starting pthreads";
    return `${snapshot.ports.filter((port) => port.oper === "up").length}/${snapshot.ports.length} ports up`;
  }, [runtimeError, snapshot]);

  const visibleError = runtimeError ?? operationError;

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-mark"><i /><i /><i /></span><strong>Router Lab</strong><span className="chevron">⌄</span></div>
        <nav className="top-nav"><button className={view === "topology" ? "active" : ""} onClick={() => setView("topology")}>Topology</button><button>Devices</button><button className={view === "captures" ? "active" : ""} onClick={() => setView("captures")}>Captures</button></nav>
        <div className="top-actions">
          <span className={`runtime-chip ${runtimeError ? "bad" : ""}`}><i />{runtimeLabel}</span>
          <span className="runtime-stat"><small>Workers</small><strong>2</strong></span>
          <span className="runtime-stat"><small>Shared memory</small><strong>256 MiB</strong></span>
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
          <section><h3>ROUTERS</h3><div className="library-item active"><span className="mini-icon router">R</span><div><strong>{GENERATED_PROFILE.chassis}</strong><small>{GENERATED_PROFILE.release} profile</small></div></div></section>
          <section><h3>MEDIA</h3><div className="library-item"><span className="mini-icon link">↔</span><div><strong>Physical link</strong><small>Full duplex</small></div></div></section>
          <div className="side-divider" />
          <div className="panel-kicker">PROJECT</div>
          <nav className="project-nav"><button>□ <span>Lab topology</span></button><button>▤ <span>Configs</span></button><button>▧ <span>Captures</span></button><button>▣ <span>Snapshots</span></button><button>▱ <span>Notes</span></button></nav>
          <div className="side-footer"><button>⚙ <span>Settings</span></button><button>♙ <span>admin</span><b>⌄</b></button></div>
        </aside>

        <section className="center-stage">
          {visibleError && <div className="runtime-error"><strong>{runtimeError ? "Runtime could not start" : "Operation could not complete"}</strong><span>{visibleError}</span></div>}
          {view === "topology" ? <Topology hosts={project.hosts} snapshot={snapshot} selected={selected} onSelect={setSelected} /> :
            <section className="capture-workspace">
              <div className="capture-workspace-head"><div><span>PACKET OBSERVATION</span><h2>Capture session</h2></div><i className={captureActive ? "live" : ""} /></div>
              <div className="capture-stats">
                <div><small>Records</small><strong>{snapshot?.captureCount ?? 0}</strong></div>
                <div><small>Capture drops</small><strong>{snapshot?.captureDropped ?? 0}</strong></div>
                <div><small>Observation points</small><strong>9</strong></div>
              </div>
              <div className="capture-actions">
                <button onClick={() => void toggleCapture()}>{captureActive ? "Stop capture" : "Start capture"}</button>
                <button onClick={() => void exportCaptureNow()}>Export PCAPNG</button>
                <button onClick={() => void exportCheckpointNow()}>Export checkpoint</button>
              </div>
              <div className="capture-points">
                {["4 link directions", "2 router ingress", "2 router egress", "1 CPM punt"].map((point) => <span key={point}>{point}</span>)}
              </div>
            </section>}
          <div className="telemetry-strip">
            <div><span>CAPTURED FRAMES</span><strong>{snapshot?.captureCount ?? 0}</strong></div>
            <div><span>DROPPED</span><strong>{snapshot?.droppedPackets ?? 0}</strong></div>
            <div><span>ARP ENTRIES</span><strong>{snapshot?.arp.length ?? 0}</strong></div>
            <div><span>FIB ROUTES</span><strong>{snapshot?.routes.length ?? 0}</strong></div>
            <div className="capture-live"><i /> LIVE CAPTURE</div>
          </div>
        </section>

        <Inspector selected={selected} hosts={project.hosts} snapshot={snapshot} updateHost={updateHost} hardware={hardware} />
      </div>
      <TerminalPanel ready={Boolean(runtime && !runtimeError && projectLoaded)} execute={execute} complete={complete} />
    </main>
  );
}
