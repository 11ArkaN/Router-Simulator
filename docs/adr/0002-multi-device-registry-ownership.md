# Multi-device registry ownership

## Decision

`RuntimeSupervisor` is the public lifecycle boundary. One control shard owns `DeviceRegistry`, `HostRegistry`, `TopologyRegistry` and `SessionRegistry`. Other shards carry generation-checked handles and bounded value messages. They never retain pointers into registry slots.

Stable project IDs and runtime handles serve different purposes. Project IDs survive save, reload and rename. Runtime handles use a bounded slot index plus a generation. Reusing storage after deletion advances its generation, so delayed work cannot target a replacement object.

Router deletion is ordered as quiesce, session close, topology detach, owned-work drain, arena release and registry erase. A failure before registry erase leaves the identity valid and quiescing. The supervisor does not partially reuse that slot.

## Invariants

- Each mutable registry has one control-shard writer.
- Device system name is never used as object identity.
- One physical port can bind to at most one point-to-point link.
- A topology link can retain textual port intent while hardware is absent.
- Cross-shard messages contain handles and owned values only.
- Erasing an object invalidates every older handle generation.

## Consequences

The runtime has deterministic bounded lookup and deletion behavior for 16 routers, 16 hosts, 64 links and 64 sessions. Linear control-path scans avoid a second mutable index. Packet paths use compact handles and do not scan project strings.
