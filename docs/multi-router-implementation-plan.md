# Multi-router laboratory implementation plan

## Scope

The first multi-router release supports:

- up to 16 routers
- up to 16 hosts
- up to 64 full-duplex point-to-point Ethernet links
- up to four terminal sessions per router
- Nokia SR OS 26.7.R1 profiles for 7750 SR-1, 7750 SR-7 and 7750 SR-12
- documented chassis, card, MDA, port and compatibility constraints for those profiles
- static IPv4 routing over multiple router hops
- one capture session with user-selected observation points

The runtime uses one WebAssembly module, one shared memory, shared packet and capture pools, and a fixed pthread pool. Logical devices are assigned to control, forwarding and link shards. A router does not receive its own WebAssembly instance or browser Worker.

OSPF, IS-IS, BGP, VLAN, LAG, bridging, shared Ethernet segments, switches and hubs are outside this scope. Every link has exactly two endpoints. A host has one Ethernet interface. Terminal users are limited to `admin`; AAA is outside this scope.

## Versioned contracts

### Project format

`LabProjectV3` contains:

- `projectId`
- `routers`
- `hosts`
- `links`
- project notes
- UI layout
- update timestamp

Each `RouterProject` contains a stable `NodeId`, `profileId`, release, system name, hardware intent and running configuration. The system name is display and router configuration data, not object identity.

Each `HostProject` contains a stable `NodeId`, name and one `eth0` interface with MAC address, IPv4 prefix, gateway, MTU and Ethernet mode.

Each link contains a stable link ID, two `PortRef` values and its administrative state and propagation delay. `PortRef` contains `nodeId` and `portId`. A router port can belong to at most one point-to-point link.

The runtime uses typed `DeviceHandle`, `PortHandle`, `LinkHandle`, `SessionHandle` and 32-bit `CapturePointId` values. Handles include generation data so a delayed message cannot target a deleted object whose storage has been reused.

The change introduces these versions:

- project format 3
- manifest format 2
- runtime protocol 3
- runtime snapshot ABI 5
- telemetry ABI 5
- checkpoint ABI 5
- terminal presentation format 2

Project formats 1 and 2 and checkpoint ABI 4 are rejected. No automatic migration is provided.

### Profile catalog

The single generated profile constant is replaced with `PROFILE_CATALOG`. Runtime-wide limits, timing and memory values are separated from per-device release and hardware profiles.

An offline generator compiles profile YAML into C++ and TypeScript data. Production code never downloads vendor documentation or YANG models. Validation rejects:

- more than 16 routers, 16 hosts or 64 links
- unknown profile or release IDs
- duplicate node, link or session IDs
- invalid chassis, card, MDA or port combinations
- duplicate use of a physical port
- incompatible Ethernet modes
- dangling references
- invalid MAC or IPv4 values
- unsupported hardware capabilities

A link can remain configured when its router hardware is removed. Its carrier becomes down until compatible hardware and port inventory return.

### Runtime bridge

Every router or terminal operation carries a router ID and, where required, a session ID. The browser does not depend on a selected global router to route an operation.

Typed operations cover:

- create and delete router
- create and delete host
- create, edit and delete link
- change hardware intent or physical inventory
- change running configuration
- create, close and execute terminal session
- request a router snapshot
- configure capture selection
- export and import project or checkpoint data

## Runtime ownership

### Supervisor and registries

`RuntimeSupervisor` owns runtime lifecycle and the public command boundary. It contains:

- `DeviceRegistry`
- `SessionRegistry`
- `TopologyRegistry`
- `ProfileRegistry`
- one global `LinkFabric`
- one `CaptureSession`
- shared packet, capture and terminal output arenas

Each registry has one mutable-state owner. Other components use handles and bounded messages, not mutable pointers into registry storage.

The initial thread policy is:

- up to 4 logical CPUs: one control shard and one combined forwarding and link shard
- 5 to 8 logical CPUs: one control shard, two forwarding shards and one link shard
- more than 8 logical CPUs: two control shards, three forwarding shards and one link shard

Stable handles determine shard assignment. Live devices do not migrate between shards in this release. Work loops use bounded budgets and fair rotation so one busy device cannot starve other devices.

SPSC rings connect known producer and consumer pairs. A matrix of SPSC rings is preferred over a shared MPSC queue. Any MPSC use requires a documented ownership reason. Shards wait on mailbox signals or local `steady_clock` deadlines. There is no global future-event queue and no simulated clock.

### Memory

WebAssembly initial memory is 320 MiB. The laboratory shares:

- one 64 MiB packet pool
- one forwarding-owned incremental PCAPNG encoder drained to project OPFS
- one 16 MiB terminal output arena

Per-router arenas are sized from the selected hardware profile. The build calculates the maximum storage required by 16 SR-12 routers and fails if the configured memory budget is exceeded. Stable arena addresses prevent pointer invalidation.

Each terminal result can occupy at most 1 MiB in the shared output arena. Exhaustion applies backpressure or returns an explicit error. Output is never silently truncated or overwritten.

### Device and link processing

Each router forwarding instance owns its FIB, adjacency table, pending-resolution queues, counters and pipeline state. Host protocol stacks are separate logical endpoints. The global `LinkFabric` owns transmitter serialization, Ethernet interpacket gap, propagation deadlines, in-flight frames and carrier calculation.

A frame crosses these ownership boundaries:

```text
router egress
  -> bounded forwarding-to-link ring
  -> link transmitter
  -> serialization and propagation
  -> bounded link-to-forwarding ring
  -> destination router or host ingress
```

No router calls another router or reads another router's RIB, FIB, adjacency table or configuration. All network information crosses a physical port as encoded Ethernet, ARP, IPv4 or ICMP bytes.

Carrier state derives from equipped hardware, media compatibility, Ethernet mode and link state. Administrative state remains separate from physical link and operational state.

Ping becomes an asynchronous operation state machine. It cannot block a shard while waiting for ARP, propagation or reply deadlines. Every router hop performs its own FIB lookup, TTL decrement, IPv4 checksum update, next-hop ARP resolution and queue admission. ICMP errors are encoded and returned through the packet path.

Router deletion follows a quiesce operation:

1. reject new operations for the device
2. close its terminal sessions
3. detach its link endpoints
4. drain or discard owned queued work under explicit policies
5. increment handle generations
6. release device-owned arena allocations
7. remove the registry entry

Other routers and links continue to run.

## Terminal sessions

Each router supports four independent sessions. A session owns:

- active MD-CLI or classic CLI engine
- current and previous context for each engine
- command line editor state
- operational, configuration and classic histories
- pager state
- pending output
- workflow and candidate metadata
- one cancellation word for a running command

The router owns running configuration and one global candidate datastore. Each private MD-CLI session owns its private candidate and base generation. Implemented MD-CLI workflows are:

- global
- exclusive
- private
- read-only

Exclusive mode enforces a single writer. Private commits detect conflicts against the base generation. Read-only mode rejects configuration changes. Classic CLI applies supported changes immediately and respects locks held by MD-CLI workflows. The `//` engine switch remains local to a session.

Router interfaces can be created and deleted dynamically. A blank project must not rely on profile-created interface names or addresses.

## Telemetry, capture and checkpoints

Telemetry ABI 5 contains a directory for up to 16 devices, global worker health, terminal session status and offsets to variable-size port bitsets. Each device block has its own sequence lock. React receives JSON snapshots for selection changes and configuration mutations. Fast counters are read from shared memory at a bounded display rate.

Capture selection supports:

- either direction of a physical link
- router ingress
- router egress
- CPM punt

PCAPNG interface names include stable node identity, current system name, port and direction. Complete packet blocks are appended to project OPFS during capture, and runtime checkpoints retain only selection and accounting metadata. Removing a point emits its final interface statistics before releasing owner-local metadata.

Checkpoint ABI 5 stores:

- every device and terminal session
- running and candidate datastores
- RIB, FIB and adjacency state
- hardware inventory and lifecycle
- physical links and carrier state
- device, fabric and protocol queues
- encoded frames in flight
- relative local deadlines
- capture state and selected observation points
- counters and handle generations

Import validates the complete object graph and resource bounds before mutation. Shard barriers freeze owners for the final commit. A failed import leaves the active laboratory unchanged.

Terminal transcripts are stored in OPFS under project, router and session namespaces. Only the active terminal rendering window is kept in browser memory.

## User interface

A new project opens an empty topology. The user can add a router or host. Adding a router requires a hardware profile selection. A free name from `R1` through `R16` is suggested and remains editable.

Each router has one visual connection handle. After two nodes are selected, a dialog lists only free, compatible physical ports. The created edge displays endpoint ports, negotiated speed, carrier state and propagation delay. The link inspector edits delay and administrative state and can disconnect or delete the link.

The inspector and workspace views follow the selected router. Device collections use virtualized lists. Terminal tabs identify router and session. One xterm renderer is attached to the active tab; inactive sessions retain editor state and transcript storage without additional renderers.

The capture panel presents a hierarchy of links, directions, router ports and CPM points. The existing dark industrial layout, responsive resizers and no-vendor-logo rule remain unchanged.

The repository includes a multi-router test project with:

- R1 using SR-1
- R2 using SR-7
- R3 using SR-12
- R4 using SR-7
- four hosts
- a chain from R1 through R2 and R3 to R4
- a direct R1 to R4 link
- static routes for direct and multi-hop paths

## Persistence

IndexedDB stores project format 3. Autosave revisions are tracked per router, host and link so a small edit does not reconstruct unrelated project objects. Unsupported stored versions remain available for recovery export but are not opened as a live laboratory.

OPFS paths include the project ID and stable object IDs. Reload restores the selected project, terminal presentation and compatible checkpoint without changing router identities.

## Source and capability requirements

Every hardware catalog entry, CLI workflow, packet behavior and platform constraint requires:

- a source-catalog record
- an implementation path
- a test path
- a capability-matrix entry

Specialized card functions outside Ethernet and IPv4 forwarding remain explicitly unsupported even when the hardware inventory and port layout are modeled. The project does not present a successful no-op for those functions.

## Implementation sequence

1. Add ADRs for registry ownership, shard placement, shared arenas and the profile catalog.
2. Split runtime-wide configuration from device profiles and generate the SR-1, SR-7 and SR-12 catalog.
3. Add project format 3, stable IDs, empty projects and hard resource limits.
4. Introduce `RuntimeSupervisor` and registries while preserving the current one-router behavior as a parity test.
5. Replace the per-router fabric with the global point-to-point fabric and asynchronous packet operations. Establish two-router tests before the four-router reference topology.
6. Add the session registry and all four MD-CLI candidate workflows.
7. Add telemetry ABI 5, selected capture points and checkpoint ABI 5.
8. Update IndexedDB, OPFS and `.netsim` manifest format 2.
9. Update topology editing, port selection, router-aware workspaces, terminal tabs and capture selection.
10. Add 16-router limits, performance gates and browser acceptance tests, then update documentation and the capability matrix.

## Verification

Hardware tests cover every generated catalog entry, invalid combinations, SR-1 fixed hardware behavior and profile-filtered CLI completion.

Packet tests cover a four-router ping, ARP on every physical link, TTL changes at every hop, encoded ICMP Time Exceeded, MTU handling, IPv4 fragmentation and link failure. Route and FIB tests verify that a failure changes only devices whose local state is affected.

Isolation tests verify handle routing, device deletion, stale message rejection and unchanged state on unrelated routers. Session tests cover 64 active sessions, rejection of a fifth session, exclusive locking, global visibility, private conflicts, read-only rejection and classic CLI interaction with locks.

Persistence tests cover project and checkpoint round trips, rejection of 17 routers, 17 hosts, 65 links and all stale formats, fuzzed invalid object graphs and atomic failure.

Capture tests verify selected observation points, stable IDs across rename and deletion, and PCAPNG decoding with `tshark`.

Performance verification keeps the existing 10 percent packet primitive regression gate and adds 1-router, 4-router and 16-router scenarios. The 16-router case exercises 64 links, 64 terminal sessions, telemetry and checkpoint export within the generated memory envelope. Idle runtime tests reject busy loops and fairness tests reject shard starvation.

Browser acceptance runs with cross-origin isolation in Chrome, Edge and Firefox. It covers an empty project, adding all router models, hardware changes, link creation, multi-hop traffic, multiple sessions, capture selection, failures, deletion, checkpoint restore, reload, panel resizing and UI responsiveness.
