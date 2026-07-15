// Inspector for selected project devices and live router state. It emits typed
// intent only. Hardware, carrier and ping actions are executed by App through
// RuntimeClient and return here as validated operational projections.

import { useState } from "react";
import { GENERATED_PROFILE, type HostConfig, type RuntimeSnapshot } from "@router-simulator/contracts";
import type { HardwareAction } from "../runtime/client";

export type RouterTab = "chassis" | "cpm" | "cards" | "ports" | "operational";

interface Props {
  selected: string;
  tab: RouterTab;
  onTabChange(tab: RouterTab): void;
  hosts: HostConfig[];
  snapshot?: RuntimeSnapshot;
  systemName: string;
  updateHost(host: HostConfig): void;
  hardware(action: HardwareAction): void;
  setLink(portId: string, up: boolean): void;
  ping(sourceId: string, destinationId: string): Promise<string>;
  openConsole(): void;
  close(): void;
}

function StatePill({ up, children }: { up: boolean; children: string }) {
  // State styling consumes a reconciler result and never infers operation from
  // administrative intent alone.
  return <span className={`state-pill ${up ? "good" : "muted"}`}>{children}</span>;
}

function speedLabel(speedMbps: number): string {
  // Preserve exact profile units when a future platform exposes a rate which
  // is not an integral number of gigabits per second.
  return speedMbps % 1000 === 0 ? `${speedMbps / 1000}G` : `${speedMbps}M`;
}

export function Inspector({ selected, tab, onTabChange, hosts, snapshot,
  systemName, updateHost, hardware, setLink, ping, openConsole, close }: Props) {
  const [pingResult, setPingResult] = useState("");
  const [pingBusy, setPingBusy] = useState(false);
  const host = hosts.find((item) => item.id === selected);
  if (host) {
    const update = (key: keyof HostConfig, value: string) => updateHost({ ...host, [key]: value });
    const peer = hosts.find((item) => item.id !== host.id);
    const runPing = async () => {
      if (!peer || pingBusy) return;
      setPingBusy(true);
      try { setPingResult(await ping(host.id, peer.id)); }
      catch {
        // Transport and validation details remain in App's bounded error
        // surface. The inspector reports only the outcome relevant to the
        // operator and never exposes Worker or Wasm implementation details.
        setPingResult("The echo test could not be completed.");
      }
      finally { setPingBusy(false); }
    };
    return (
      <aside className="inspector">
        <div className="inspector-title"><div><h2>{host.name}</h2><p>External IPv4 host</p></div><button aria-label="Close inspector" onClick={close}>×</button></div>
        <div className="host-form">
          <label>Name<input value={host.name} onChange={(event) => update("name", event.target.value)} /></label>
          <label>IPv4 prefix<input value={host.address} onChange={(event) => update("address", event.target.value)} /></label>
          <label>Default gateway<input value={host.gateway} onChange={(event) => update("gateway", event.target.value)} /></label>
          <label>MAC address<input value={host.mac} onChange={(event) => update("mac", event.target.value)} /></label>
          <button className="inspector-action" disabled={!peer || pingBusy} onClick={() => void runPing()}>{pingBusy ? "Pinging" : `Ping ${peer?.name ?? "peer"}`}</button>
          {pingResult && <pre className="operation-result">{pingResult}</pre>}
        </div>
      </aside>
    );
  }

  const card = snapshot?.hardware.cards.find((item) => item.slot === GENERATED_PROFILE.lineCard.slot);
  const mda = card?.mdas.find((item) => item.slot === GENERATED_PROFILE.mda.slot);
  const hardwareReady = Boolean(card?.lifecycle === "ready" &&
    mda?.lifecycle === "ready");
  const runtimeReady = snapshot?.status === "ready";
  const cardEquipped = Boolean(card?.equippedType);
  const mdaEquipped = Boolean(mda?.equippedType);

  const renderTab = () => {
    // Tabs project already-owned state. They never manufacture a derived
    // protocol health value or interpret a physical carrier as device uptime.
    if (tab === "chassis") return <>
      <div className="panel-kicker inspector-section-title">CHASSIS</div>
      <div className="spec-grid"><span>Model</span><strong>{GENERATED_PROFILE.chassis}</strong><span>Slot count</span><strong>{GENERATED_PROFILE.chassisSlots}</strong><span>Release</span><strong>{GENERATED_PROFILE.release}</strong><span>Runtime state</span><strong className={runtimeReady ? "text-good" : "text-warning"}>{snapshot?.status ?? "Starting"}</strong><span>Hardware</span><strong className={hardwareReady ? "text-good" : "text-warning"}>{hardwareReady ? "Ready" : "Incomplete"}</strong><span>Uptime</span><strong>{Math.floor((snapshot?.nowMs ?? 0) / 1000)} seconds</strong></div>
      <div className="chassis-slots"><div className="panel-kicker">SLOTS</div>{snapshot?.hardware.cards.map((item) => <div key={item.slot}><span>{item.slot}</span><strong>{item.equippedType ?? "Blank"}</strong><StatePill up={item.lifecycle === "ready"}>{item.lifecycle}</StatePill></div>)}</div>
    </>;
    if (tab === "cpm") return <><div className="panel-kicker inspector-section-title">CONTROL PLANE</div><div className="spec-grid"><span>Slot</span><strong>{GENERATED_PROFILE.control.slot}</strong><span>Type</span><strong>{GENERATED_PROFILE.control.card}</strong><span>State</span><strong className="text-good">{snapshot?.hardware.control.state ?? GENERATED_PROFILE.control.initial_state}</strong></div></>;
    if (tab === "cards") return <>
      <div className="hardware-slot"><div className="slot-head"><span>SLOT {GENERATED_PROFILE.lineCard.slot}</span><StatePill up={card?.lifecycle === "ready"}>{cardEquipped ? card?.lifecycle ?? "equipped" : "absent"}</StatePill></div><strong>{card?.equippedType ?? "No line card"}</strong><button onClick={() => hardware(cardEquipped ? { kind: "remove-card", slot: GENERATED_PROFILE.lineCard.slot } : { kind: "insert-card", slot: GENERATED_PROFILE.lineCard.slot, type: GENERATED_PROFILE.lineCard.type })}>{cardEquipped ? "Remove card" : `Insert ${GENERATED_PROFILE.lineCard.type}`}</button></div>
      <div className="hardware-slot"><div className="slot-head"><span>MDA {GENERATED_PROFILE.lineCard.slot}/{GENERATED_PROFILE.mda.slot}</span><StatePill up={Boolean(mda?.compatible && mda.lifecycle === "ready")}>{mdaEquipped ? (mda?.compatible ? mda.lifecycle : "mismatch") : "absent"}</StatePill></div><strong>{mda?.equippedType ?? "No adapter"}</strong><div className="button-pair">{mdaEquipped ? <button onClick={() => hardware({ kind: "remove-mda", cardSlot: GENERATED_PROFILE.lineCard.slot, mdaSlot: GENERATED_PROFILE.mda.slot })}>Remove MDA</button> : GENERATED_PROFILE.mda.supportedTypes.map((type) => <button key={type} disabled={!cardEquipped} onClick={() => hardware({ kind: "insert-mda", cardSlot: GENERATED_PROFILE.lineCard.slot, mdaSlot: GENERATED_PROFILE.mda.slot, type })}>Insert {type}</button>)}</div></div>
    </>;
    if (tab === "ports") return <div className="ports-summary"><div className="panel-kicker">PHYSICAL PORTS</div>{snapshot?.ports.length ? snapshot.ports.map((port) => {
      // Only profile links own an external medium. Rendering a carrier button
      // for an unbound port would imply that the UI can conjure a cable which
      // does not exist in the project graph.
      const linked = GENERATED_PROFILE.links.some((link) => link.router_port === port.id);
      return <div key={port.id}><span><i className={port.oper === "up" ? "dot-good" : "dot-muted"} />{port.id}</span><strong>{port.admin} · {speedLabel(port.speedMbps)}</strong>{linked ? <button onClick={() => setLink(port.id, !port.physicalLink)}>{port.physicalLink ? "Disconnect" : "Connect"}</button> : <small>No medium</small>}</div>;
    }) : <p className="empty-copy inspector-empty">No ports are exposed by equipped hardware.</p>}</div>;
    return <div className="operational-panel"><div className="metric-strip compact"><div><small>Routes</small><strong>{snapshot?.routes.length ?? 0}</strong></div><div><small>ARP</small><strong>{snapshot?.arp.length ?? 0}</strong></div><div><small>Alarms</small><strong>{snapshot?.alarms.length ?? 0}</strong></div></div><button className="inspector-action" onClick={openConsole}>Open console</button><div className="operational-list"><h3>Active routes</h3>{snapshot?.routes.map((route) => <div key={route.prefix}><strong>{route.prefix}</strong><span>{route.port} · {route.source}</span></div>)}</div></div>;
  };

  return (
    <aside className="inspector">
      <div className="inspector-title"><div><h2>{systemName}<i className={runtimeReady ? "dot-good" : "dot-muted"} /></h2><p>{runtimeReady ? "Running" : "Unavailable"}</p></div><button aria-label="Close inspector" onClick={close}>×</button></div>
      <nav className="inspector-tabs">{(["chassis", "cpm", "cards", "ports", "operational"] as const).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => onTabChange(item)}>{item === "cpm" ? "CPM" : item[0].toUpperCase() + item.slice(1)}</button>)}</nav>
      {renderTab()}
    </aside>
  );
}
