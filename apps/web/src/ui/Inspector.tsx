import { GENERATED_PROFILE, type HardwareState, type HostConfig, type RuntimeSnapshot } from "@router-simulator/contracts";

interface Props {
  selected: string;
  hosts: [HostConfig, HostConfig];
  snapshot?: RuntimeSnapshot;
  updateHost(host: HostConfig): void;
  hardware(command: string): void;
}

function StatePill({ up, children }: { up: boolean; children: string }) {
  return <span className={`state-pill ${up ? "good" : "muted"}`}>{children}</span>;
}

export function Inspector({ selected, hosts, snapshot, updateHost, hardware }: Props) {
  const host = hosts.find((item) => item.id === selected);
  if (host) {
    const update = (key: keyof HostConfig, value: string) => updateHost({ ...host, [key]: value });
    return (
      <aside className="inspector">
        <div className="panel-kicker">NODE INSPECTOR</div>
        <h2>{host.name}</h2>
        <p className="panel-subtitle">External IPv4 host</p>
        <label>Name<input value={host.name} onChange={(event) => update("name", event.target.value)} /></label>
        <label>IPv4 prefix<input value={host.address} onChange={(event) => update("address", event.target.value)} /></label>
        <label>Default gateway<input value={host.gateway} onChange={(event) => update("gateway", event.target.value)} /></label>
        <label>MAC address<input value={host.mac} onChange={(event) => update("mac", event.target.value)} /></label>
      </aside>
    );
  }

  const hardwareState: HardwareState = snapshot?.hardware ?? {
    chassis: GENERATED_PROFILE.chassis,
    cpmA: "active-ready",
    card1Provisioned: "absent",
    mda11Provisioned: "absent",
    card1: "absent",
    mda11: "absent"
  };
  const card = hardwareState.card1 !== "absent";
  const mda = hardwareState.mda11 !== "absent";
  const compatible = hardwareState.mda11 === "me10-10gb-sfp+";
  // Unwired ports are expected to remain down, so router health cannot be
  // derived from every physical port being up. Hardware lifecycle readiness
  // is the correct equipment-level signal; per-port oper state stays visible
  // independently in the list below.
  const linkedPortsOperational = Boolean(snapshot && snapshot.ports.length >= 2 &&
    snapshot.ports[0].oper === "up" && snapshot.ports[1].oper === "up");
  const routerOperational = (hardwareState.cardLifecycle === "ready" &&
    hardwareState.mdaLifecycle === "ready") || linkedPortsOperational;
  return (
    <aside className="inspector">
      <div className="inspector-title"><div><h2>R1</h2><p>{routerOperational ? "Operational" : "Degraded"}</p></div><button>×</button></div>
      <nav className="inspector-tabs"><button className="active">Chassis</button><button>CPM</button><button>Cards</button><button>Ports</button><button>Operational</button></nav>

      <div className="panel-kicker inspector-section-title">CHASSIS</div>
      <div className="spec-grid">
        <span>Model</span><strong>{GENERATED_PROFILE.chassis}</strong>
        <span>Slot count</span><strong>{GENERATED_PROFILE.chassisSlots}</strong>
        <span>Release</span><strong>{GENERATED_PROFILE.release}</strong>
        <span>System state</span><strong className="text-good">Operational</strong>
        <span>CPM A</span><strong className="text-good">active / ready</strong>
      </div>

      <div className="hardware-slot">
        <div className="slot-head"><span>SLOT 1</span><StatePill up={card}>{card ? "equipped" : "absent"}</StatePill></div>
        <strong>{card ? "IOM4-e" : "No line card"}</strong>
        <button onClick={() => hardware(card ? "hardware:remove-card" : "hardware:insert-card")}>{card ? "Remove card" : "Insert IOM4-e"}</button>
      </div>

      <div className="hardware-slot">
        <div className="slot-head"><span>MDA 1/1</span><StatePill up={compatible}>{mda ? (compatible ? "operational" : "mismatch") : "absent"}</StatePill></div>
        <strong>{mda ? hardwareState.mda11 : "No adapter"}</strong>
        <div className="button-pair">
          {mda ? <button onClick={() => hardware("hardware:remove-mda")}>Remove</button> : <>
            <button disabled={!card} onClick={() => hardware("hardware:insert-mda:me10-10gb-sfp+")}>Insert 10G MDA</button>
            <button disabled={!card} onClick={() => hardware("hardware:insert-mda:me1-100gb-cfp2")}>Insert 100G MDA</button>
          </>}
        </div>
      </div>

      <div className="ports-summary">
        <div className="panel-kicker">PORTS</div>
        {snapshot?.ports.map((port) => <div key={port.id}><span>{port.id}</span><strong>{port.oper} · {GENERATED_PROFILE.portSpeedMbps / 1000}G</strong></div>)}
      </div>
    </aside>
  );
}
