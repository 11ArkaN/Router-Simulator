// Inspector for profile-driven endpoint and router state. It emits structured
// user intent and never encodes runtime protocol strings.

import { GENERATED_PROFILE, type HostConfig, type RuntimeSnapshot } from "@router-simulator/contracts";
import type { HardwareAction } from "../runtime/client";

interface Props {
  selected: string;
  hosts: HostConfig[];
  snapshot?: RuntimeSnapshot;
  systemName: string;
  updateHost(host: HostConfig): void;
  hardware(action: HardwareAction): void;
}

function StatePill({ up, children }: { up: boolean; children: string }) {
  // The pill visualizes an already computed state and never derives router
  // operation from CSS or user selection.
  return <span className={`state-pill ${up ? "good" : "muted"}`}>{children}</span>;
}

function speedLabel(speedMbps: number): string {
  // Preserve exact profile units when speed is not a whole gigabit value.
  return speedMbps % 1000 === 0 ? `${speedMbps / 1000}G` : `${speedMbps}M`;
}

export function Inspector({ selected, hosts, snapshot, systemName, updateHost, hardware }: Props) {
  // Selection chooses one validated project object. Editing a host updates the
  // project draft, while router hardware actions remain structured intent.
  const host = hosts.find((item) => item.id === selected);
  if (host) {
    // Host fields stay controlled even while temporarily invalid. App retains
    // them as draft text and persistence validates the complete project later.
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

  // The inspector displays the modeled profile slot, but hardware snapshots
  // still contain every chassis slot. Selection therefore uses explicit slot
  // identity and never assumes that the modeled card is array element zero.
  const card = snapshot?.hardware.cards.find((item) => item.slot === GENERATED_PROFILE.lineCard.slot);
  const mda = card?.mdas.find((item) => item.slot === GENERATED_PROFILE.mda.slot);
  const linkedPortsOperational = GENERATED_PROFILE.links.every((link) =>
    snapshot?.ports.find((port) => port.id === link.router_port)?.oper === "up");
  const routerOperational = Boolean(card?.lifecycle === "ready" &&
    mda?.lifecycle === "ready" && linkedPortsOperational);

  // Physical presence controls Remove versus Insert. Readiness is displayed
  // separately because an initializing or mismatched item is still equipped.
  const cardEquipped = Boolean(card?.equippedType);
  const mdaEquipped = Boolean(mda?.equippedType);
  return (
    <aside className="inspector">
      <div className="inspector-title"><div><h2>{systemName}</h2><p>{routerOperational ? "Operational" : "Degraded"}</p></div><button>×</button></div>
      <nav className="inspector-tabs"><button className="active">Chassis</button><button>CPM</button><button>Cards</button><button>Ports</button><button>Operational</button></nav>

      <div className="panel-kicker inspector-section-title">CHASSIS</div>
      <div className="spec-grid">
        <span>Model</span><strong>{GENERATED_PROFILE.chassis}</strong>
        <span>Slot count</span><strong>{GENERATED_PROFILE.chassisSlots}</strong>
        <span>Release</span><strong>{GENERATED_PROFILE.release}</strong>
        <span>System state</span><strong className={routerOperational ? "text-good" : ""}>{routerOperational ? "Operational" : "Degraded"}</strong>
        <span>Control {GENERATED_PROFILE.control.slot}</span><strong className="text-good">{GENERATED_PROFILE.control.card} / {GENERATED_PROFILE.control.initial_state}</strong>
      </div>

      <div className="hardware-slot">
        {/* Physical presence and provisioning remain separate in the snapshot.
            This control changes inventory and lets App provision explicitly. */}
        <div className="slot-head"><span>SLOT {GENERATED_PROFILE.lineCard.slot}</span><StatePill up={cardEquipped}>{cardEquipped ? "equipped" : "absent"}</StatePill></div>
        <strong>{card?.equippedType ?? "No line card"}</strong>
        <button onClick={() => hardware(cardEquipped
          ? { kind: "remove-card", slot: GENERATED_PROFILE.lineCard.slot }
          : { kind: "insert-card", slot: GENERATED_PROFILE.lineCard.slot,
              type: GENERATED_PROFILE.lineCard.type })}>
          {cardEquipped ? "Remove card" : `Insert ${GENERATED_PROFILE.lineCard.type}`}
        </button>
      </div>

      <div className="hardware-slot">
        <div className="slot-head"><span>MDA {GENERATED_PROFILE.lineCard.slot}/{GENERATED_PROFILE.mda.slot}</span><StatePill up={Boolean(mda?.compatible && mda.lifecycle === "ready")}>{mdaEquipped ? (mda?.compatible ? mda.lifecycle : "mismatch") : "absent"}</StatePill></div>
        <strong>{mda?.equippedType ?? "No adapter"}</strong>
        <div className="button-pair">
          {mdaEquipped ? <button onClick={() => hardware({ kind: "remove-mda",
            cardSlot: GENERATED_PROFILE.lineCard.slot, mdaSlot: GENERATED_PROFILE.mda.slot })}>Remove</button> :
            GENERATED_PROFILE.mda.supportedTypes.map((type) => <button key={type}
              disabled={!cardEquipped} onClick={() => hardware({ kind: "insert-mda",
                cardSlot: GENERATED_PROFILE.lineCard.slot, mdaSlot: GENERATED_PROFILE.mda.slot,
                type })}>Insert {type}</button>)}
        </div>
      </div>

      <div className="ports-summary">
        <div className="panel-kicker">PORTS</div>
        {/* Runtime emits only ports exposed by compatible equipped inventory.
            No placeholder rows are manufactured for absent line hardware. */}
        {snapshot?.ports.map((port) => <div key={port.id}><span>{port.id}</span><strong>{port.oper} · {speedLabel(port.speedMbps)}</strong></div>)}
      </div>
    </aside>
  );
}
