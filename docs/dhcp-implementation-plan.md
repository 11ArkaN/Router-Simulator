# DHCP implementation plan

## 1. Objective

Implement DHCPv4 and DHCPv6 as real control-plane protocols operating through the
existing multithreaded network runtime. Packets must traverse encoded Ethernet,
IP, UDP, interface queues and physical links using the delivery path appropriate
to broadcast, multicast, link-local, direct L2 and routed traffic.

The implementation covers:

- DHCPv4 clients, servers and relay agents
- DHCPv6 clients, servers and relay agents
- Base-router local DHCP servers
- DHCP relay on supported Base and IES interfaces
- BOF and out-of-band autoconfiguration supported by the selected platform profile
- a dedicated multihomed DHCP server device
- DHCPv4 failover based on `draft-ietf-dhc-failover-12`
- DHCPv6 failover based on RFC 8156
- configuration and operational commands documented for SR OS 26.7.R1
- persistence, atomic runtime checkpoints, packet capture and operational state

The implementation does not claim that RFC failover is Nokia Multi-Chassis
Synchronization. Nokia MCS uses a vendor protocol and TCP port 45067 whose wire
format is not publicly specified. The router profile uses the selected RFC
failover implementation as an emulator capability and does not expose it under
an MCS name.

## 2. Normative source hierarchy

Protocol behavior is derived from current standards and their normative
dependencies. SR OS command syntax, defaults, constraints and output are derived
from the official 26.7.R1 documentation and verified device behavior where
documentation is insufficient.

Primary protocol sources:

- RFC 2131, Dynamic Host Configuration Protocol
- RFC 2132, DHCP Options and BOOTP Vendor Extensions
- RFC 3046, DHCP Relay Agent Information Option
- RFC 3396, Encoding Long Options in DHCPv4
- RFC 3527, Link Selection sub-option
- RFC 6842, Client Identifier option behavior
- RFC 9915, Dynamic Host Configuration Protocol for IPv6
- RFC 8415 only where referenced historically by implementations
- RFC 4861, Neighbor Discovery for IPv6
- RFC 4862, IPv6 Stateless Address Autoconfiguration
- RFC 6603, Prefix Exclude option
- RFC 9762, DHCPv6 Prefix Delegation preference flag
- RFC 8156, DHCPv6 failover
- draft-ietf-dhc-failover-12, historical DHCPv4 failover protocol
- RFC 3074, DHCP load balancing
- RFC 4388, DHCPv4 Leasequery
- RFC 6926, DHCPv4 Bulk Leasequery
- RFC 7724, DHCPv4 Active Leasequery
- RFC 5007, DHCPv6 Leasequery

Primary product sources:

- SR OS 26.7.R1 DHCP management documentation
- SR OS 26.7.R1 MD-CLI command reference
- SR OS 26.7.R1 classic CLI command reference
- SR OS 26.7.R1 BOF command reference
- official SR OS YANG models for the selected release

Each implemented feature and command must have a source-catalog entry, test and
capability-matrix record. Unsupported dependency branches return a documented
error and never a successful no-op.

## 3. Closed implementation matrix

Before exposing a command, maintain a machine-readable matrix containing:

```text
feature-id
protocol-family
device-profile
routing-context
MD-CLI path
classic CLI path
dependencies
runtime owner
packet effects
state effects
default values
validation rules
operational commands
expected output fixtures
source identifiers
support status
```

The supported surface includes every SR OS DHCP command whose dependencies are
implemented in Base and existing IES contexts. Commands that require VPRN, BNG,
subscriber management, RADIUS, LUDB or other excluded systems are not presented
by help or completion and are rejected explicitly when entered.

Lease display commands are separate from wire protocols. Basic Leasequery,
Bulk Leasequery, Active Leasequery and DHCPv6 Leasequery each have independent
capability records. The SR OS DHCPv6 lease query restriction to Client ID is
preserved unless a documented profile supports another query form.

## 4. Architecture and state ownership

### 4.1. Module boundaries

```text
core/common/protocol-codecs
  raw DHCPv4 and DHCPv6 packet parsing
  normalized message views
  validation and canonical encoding

network shard
  packet buffers
  Ethernet, IPv4, IPv6, UDP and TCP
  broadcast, multicast and unicast delivery
  interface and link queues
  UDP and TCP demultiplexing

control-plane shard
  DHCP client state machines
  DHCP server state machines
  relay behavior
  lease repositories
  allocation policy
  failover state machines
  BOF autoconfiguration

management shard
  MD-CLI and classic CLI session semantics
  configuration transactions
  operational projections
```

Packet codecs are pure modules without thread ownership. They may be used by
tests and packet capture without depending on a runtime shard. Forwarding code
does not interpret DHCP options beyond UDP demultiplexing.

### 4.2. Mutable owners

- each DHCP client owns its transactions, retransmission state and acquired data
- each DHCP server instance owns its lease repository and pending offers
- each relay instance owns its transaction correlation and relay metadata
- the RA and ND manager owns the Default Router List, Prefix List and on-link routes
- the SLAAC manager owns addresses created from autonomous prefixes
- the address manager records ownership as static, dhcpv4, dhcpv6, slaac or ra-nd
- each failover relationship owns its protocol connection and partner state
- the runtime checkpoint coordinator owns snapshot epochs and barriers

No other component receives a mutable pointer to these structures.

### 4.3. Cross-shard queue contracts

Every queue is generated from a contract table containing:

```text
producer
consumer
message type
capacity source
ordering key
delivery guarantee
backpressure
overflow policy
cancellation behavior
checkpoint behavior
deduplication identifier
```

Required messages include:

- udp-datagram-delivered
- tcp-stream-data
- dhcp-send-request
- lease-reserved
- lease-committed
- lease-released
- failover-binding-update
- failover-update-ack
- timer-expired
- interface-state-changed
- checkpoint-barrier

SPSC queues are used where one producer and one consumer exist. Any MPSC use
requires a documented ownership reason. Queue exhaustion increments bounded
operational counters and applies the declared backpressure or drop rule.

## 5. Packet representations and limits

### 5.1. Raw representation

`RawDhcpPacket` preserves:

- every option occurrence
- original option order
- source field for DHCPv4 options, `file` and `sname`
- padding and overload information
- nested DHCPv6 option boundaries
- unknown option bytes
- original payload when no semantic mutation is required

### 5.2. Normalized representation

`NormalizedDhcpMessage` contains:

- RFC 3396 concatenated DHCPv4 option values
- typed known options
- validated message-specific constraints
- nested IA, IAADDR and IAPREFIX structures
- unknown options as bounded byte views
- references into the packet buffer where ownership permits

Relay modification causes canonical re-encoding. Unmodified forwarding may
preserve the original wire representation.

### 5.3. Resource profile

All limits come from versioned resource profiles, not literals distributed
through protocol code. Profiles define:

- maximum UDP payload accepted by each protocol
- maximum option count
- maximum normalized option length
- maximum DHCPv6 nesting depth
- maximum relay-forward depth
- concurrent client transactions
- pending offers
- declined entries
- leases per server
- pools per server
- relay targets per interface
- failover updates in flight
- diagnostic packet retention

A malformed or over-limit packet is rejected before any mutable protocol state
changes. The correct counter is incremented and optional diagnostic retention is
bounded.

## 6. DHCPv4

### 6.1. Client state machine

Implement the complete RFC 2131 client lifecycle:

```text
INIT
SELECTING
REQUESTING
BOUND
RENEWING
REBINDING
INIT-REBOOT
REBOOTING
```

The implementation covers:

- DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE and INFORM
- transaction identifiers created for a new transaction and retained through retransmissions
- stable Option 61 Client Identifier
- retransmission timing and bounded randomization from a supplied entropy source
- T1, T2 and lease expiration
- INIT-REBOOT validation of retained configuration
- conflict detection before using an address
- broadcast and unicast response rules
- requested address and server identifier validation
- DHCPFORCERENEW where supported by the selected command surface

### 6.2. Server lease identity

A DHCPv4 binding key contains:

```text
server-instance
routing-context
link-identity
client-key
```

`client-key` uses Option 61 when present and validated, otherwise the RFC-defined
hardware identity. The repository differentiates the same identifier on distinct
allocation links.

### 6.3. Server transaction state

Server binding and reservation states include:

```text
PENDING-OFFER
ACTIVE
EXPIRED
RELEASED
DECLINED
CONFLICT
RESERVED
```

A pending offer makes the address unavailable to other transactions until it is
committed or its profile-defined lifetime expires.

### 6.4. Allocation priority

Allocation follows this exact order:

1. matching static reservation
2. valid existing lease
3. valid sticky binding
4. requested address if it belongs to the selected scope and is available
5. allocator result
6. protocol-defined exhaustion behavior

Before selection, candidates are removed for exclusions, reservations owned by
another client, active leases, pending offers, DECLINED hold-down, detected
conflicts and failover ownership restrictions.

Standalone allocation is deterministic first-free within the selected pool.
Failover allocation first restricts the set according to binding state,
ownership and load balancing, then uses deterministic order within that set.
Concurrent requests are serialized by the lease repository owner.

### 6.5. Pool selection

Pool selection resolves exactly one `allocation-scope` from:

- server instance and routing context
- trusted link-selection information
- non-zero `giaddr`
- receiving interface for directly attached clients
- configured subnet and pool bindings

The algorithm validates relay trust, overlapping ranges and ambiguous matches.
It never selects the first matching pool based only on storage order. Zero or
multiple valid scopes produce a defined protocol result and operational counter.

### 6.6. Option 82

Relay processing includes:

- Circuit ID
- Remote ID
- Link Selection
- configured trust per ingress interface
- policy for retaining, replacing or rejecting an existing option
- stripping relay information before delivery to the client where required
- rejection of untrusted packets with zero `giaddr` and pre-existing Option 82
- loop detection and hop-count handling

The trust policy belongs to relay configuration and not to the packet codec.

## 7. DHCPv6

### 7.1. Identity and transaction lifecycle

- DUID is created when the device is created or when the client is first enabled
- DUID remains stable through runtime restart and project migration
- IAID is stable for an interface and IA type and unique within the client
- IAID mappings are persisted
- a transaction ID is created for each new transaction and retained through retransmissions
- entropy comes from a core-provided source that supports reproducible tests without fixed production values

### 7.2. Client and server behavior

Implement and verify:

- Solicit, Advertise, Request, Confirm, Renew and Rebind
- Reply, Release, Decline, Reconfigure and Information-request
- Rapid Commit
- Reconfigure Accept validation
- status codes and message-specific option constraints
- IA_NA with multiple IAADDR values
- IA_PD with multiple IAPREFIX values
- multiple IAs of the same or different type for one client
- preferred and valid lifetimes for every address and prefix
- T1 and T2 per IA
- DAD before an IA_NA address becomes usable
- Confirm only for addresses
- no IA_PD in Decline

The allocation identity contains:

```text
server-instance
link-identity
DUID
IA-type
IAID
```

Addresses or prefixes and their lifetimes are stored below that identity.

### 7.3. DHCPv6 allocation

DHCPv6 does not allocate sequential, easily predictable addresses by default.
The deterministic implementation uses an HMAC-SHA256 based PRF keyed by a
persisted server allocator secret and fed with pool identity, DUID, IAID, IA type
and an allocation attempt counter. It preserves repeatable tests while avoiding
first-free address predictability.

### 7.4. Prefix delegation

IA_PD is fully supported by codecs, servers, relays, lease repositories,
Leasequery where applicable and failover. Prefix Exclude is encoded inside
IAPREFIX and validates:

- excluded prefix length
- derived excluded subprefix
- containment within the delegated prefix
- at most one Prefix Exclude option per IAPREFIX

No router or host claims to consume a delegated prefix in this stage. There is
no CPE device and no undocumented SR OS IA_PD client. This prevents IA_PD from
becoming a successful no-op.

### 7.5. RA, ND and host automatic mode

RA and ND have an owner separate from DHCPv6 and SLAAC. They own:

- Default Router List
- Prefix List
- Router Lifetime
- on-link routes
- reachable router state

Host IPv6 modes are:

- static
- SLAAC
- stateful DHCPv6
- SLAAC plus stateless DHCPv6
- auto

Automatic behavior evaluates:

- M flag for stateful address configuration
- O flag for other configuration
- A flag in each Prefix Information Option for SLAAC
- L flag for on-link status
- Router Lifetime for default-router state

The P flag is parsed and exposed but does not start IA_PD because no requesting
router role is present. Removing M or O in a later RA does not immediately erase
a still-valid lease. Lease lifecycle remains controlled by DHCPv6 timers and
subsequent protocol behavior.

DHCPv6 IA_NA never installs a default route. Without RA on-link information, an
acquired address is treated as a host address rather than proof that the full
prefix is on-link.

### 7.6. Relay

Relay-forward and Relay-reply support:

- UDP ports 546 and 547
- All_DHCP_Relay_Agents_and_Servers multicast
- link-local source requirements
- link-address selection
- peer-address preservation
- Interface-ID and Remote-ID
- bounded nesting and hop count
- exact transaction correlation
- routing of relay to server through normal FIB and neighbor resolution

## 8. Packet delivery paths

Every message traverses the appropriate real packet path:

- DHCPv4 initial client messages use limited broadcast from `0.0.0.0` without ARP
- direct DHCPv4 server replies use broadcast or direct L2 unicast according to client state and flags
- DHCPv4 relay-to-server traffic uses normal routed IPv4 delivery
- DHCPv6 client and server traffic uses link-local addresses, multicast and UDP 546 or 547 as required
- DHCPv6 relay-to-server traffic uses normal IPv6 routing and ND where needed

ARP or ND is performed only when the chosen transmission mode requires neighbor
resolution. No protocol object crosses directly between devices.

## 9. Router roles

### 9.1. Base local server

Local DHCPv4 and DHCPv6 servers are configured in Base. Existing IES interfaces
can provide client-facing attachment or relay according to documented SR OS
behavior. There is no separate local DHCP server instance inside an IES context.

### 9.2. BOF and out-of-band autoconfiguration

For platform profiles documented by SR OS 26.7.R1, BOF autoconfiguration supports:

- DHCPv4 client on the management interface
- DHCPv6 client on the management interface
- NDP and RA processing
- the documented command syntax, defaults and operational state

This capability does not create a general DHCPv6 client on Base or IES
interfaces. It does not request IA_PD.

## 10. Dedicated DHCP server device

Add a canvas device with a versioned profile and multiple user-configurable
interfaces. It behaves as a multihomed server host:

- `ip-forwarding=false` by default
- connected routes for configured interfaces
- local routing table
- optional default gateway
- responses for local addresses
- no forwarding of transit traffic
- sockets bound to explicit interfaces, addresses or documented wildcard rules

Inspector configuration includes interfaces, addresses, gateways, DHCPv4 and
DHCPv6 server instances, pools, reservations, relay relationships, failover,
security material and operational state.

Mutations validate dependencies. Removing or changing an interface cannot leave
an ambiguous allocation scope or orphaned pool. Active leases remain historical
records or are invalidated according to an explicit server policy and never
silently reassigned.

## 11. Failover

### 11.1. DHCPv4

Implement `draft-ietf-dhc-failover-12` as a historical protocol, including:

- TCP port 647
- primary and secondary roles
- binding updates and acknowledgements
- MCLT
- load balancing based on RFC 3074
- communications-interrupted
- partner-down
- recovery and full resynchronization
- update retransmission and deduplication
- manual partner-down through an operational command
- optional timed transition where configured

Security modes map exactly to protocol negotiation:

- no TLS
- TLS desired
- TLS required
- shared-secret message digest using the historical HMAC-MD5 mechanism
- TLS 1.0 with the draft-required historical cipher where selected

Legacy cryptography is isolated inside simulated TCP and is not used by the web
application transport or host operating system.

### 11.2. DHCPv6

Implement RFC 8156 with:

- TCP port 647
- partner state machine
- binding updates and acknowledgements
- recovery and resynchronization
- manual and timed partner-down transitions allowed by the protocol
- TLS 1.2 mode

TLS configuration includes:

- private keys
- certificates
- trust anchors
- partner identity
- endpoint address validation
- certificate error reporting
- connection limits
- handshake state and restart policy

Secret material uses the existing secret vault and never appears in project
telemetry, logs or CLI output.

### 11.3. Router compatibility boundary

The RFC failover implementation is not named MCS in commands, output or UI.
Nokia MCS is not implemented until a verifiable wire format is available. This
boundary is recorded in the source and capability catalogs without an
experimental UI label.

## 12. Configuration and CLI

Both MD-CLI and classic CLI use one canonical configuration model but retain
their distinct session and apply semantics.

Implementation includes:

- configuration of Base DHCPv4 and DHCPv6 servers
- IES and Base relay configuration where documented
- BOF autoconfiguration
- pools, exclusions, reservations and lease lifetimes
- Option 82 trust and sub-options
- DHCPv6 IA_NA and IA_PD pools
- failover relationship and security configuration where exposed by the emulator profile
- operational clear and force actions
- server, client, relay, lease, pool, transaction and failover show commands
- message statistics including FORCERENEW and supported Leasequery messages
- help, completion, contextual validation, pager and output formatting
- commands entered from documented deep contexts

Every accepted command must change real configuration or operational state, or
perform a real read. Missing dependencies produce the documented error.

## 13. Persistence and checkpointing

### 13.1. Separate formats

`ProjectConfiguration` stores:

- devices and interfaces
- addresses and routing configuration
- pools and reservations
- client configuration
- relay configuration
- failover configuration
- persistent identities and allocator secrets through protected references

`RuntimeCheckpoint` stores:

- ProjectConfiguration reference or embedded versioned copy
- lease repositories
- client and server transactions
- pending offers
- declined state
- DUID and IAID mappings
- local deadlines and timer generations
- queued protocol messages
- TCP and failover runtime state needed for coherent restoration
- RA, ND and SLAAC state

A normal autosave never mistakes transient runtime state for project
configuration.

### 13.2. Atomic checkpoint barrier

1. The coordinator announces a snapshot epoch.
2. Every shard finishes its current bounded operation.
3. Each shard stops consuming the next message.
4. Owners serialize state and inbound and outbound queues.
5. The coordinator commits only after every owner acknowledges the same epoch.
6. Runtime processing resumes.

No checkpoint may contain a committed lease with an unrecorded ACK or the reverse.

### 13.3. Real-time semantics

The runtime continues to use only `std::chrono::steady_clock`. There is no global
simulation timestamp, event heap or replayed virtual time.

Checkpointing stores remaining durations and timer generations. Restoring a
checkpoint freezes protocol time across the offline interval. No fictional
packets or missed timer events are synthesized for time during which the runtime
did not execute.

If browser execution continuity is lost, the invalid runtime stops and reports
the interruption. Recovery starts from the last coherent checkpoint or from
project configuration. Failover TCP sessions reconnect and resynchronize through
their actual state machines rather than restoring host socket internals.

### 13.4. Project migration

Project schemas use a versioned migrator. Older supported versions are converted
through explicit deterministic migrations. Unknown or unsupported versions are
rejected with a clear version error.

## 14. Performance

After warm-up, forwarding uses bounded packet pools and bounded message envelopes.
The forwarding hot path does not create object counts proportional to DHCP option
count. Option data is copied at most once when the protocol owner must retain it.

Benchmarks record:

- packets per second by delivery path
- allocation count and bytes per packet
- copies per packet
- queue occupancy and overflow
- lease allocation latency
- memory use for configured client counts
- checkpoint duration and size
- failover resynchronization time
- impact on the existing 16-router runtime benchmark

Claims of improvement require a retained baseline and threshold.

## 15. Verification

### 15.1. Codecs

- official and independently captured golden packets
- option overload
- RFC 3396 concatenation
- duplicate and unknown options
- malformed lengths
- nested DHCPv6 options
- Prefix Exclude
- relay nesting
- fuzzing and property tests

### 15.2. State machines

- every DHCPv4 client transition including INIT-REBOOT and REBOOTING
- DHCPv4 retransmission, T1, T2, NAK, conflict and expiration
- DHCPv6 Solicit through Reply
- Rapid Commit
- Renew, Rebind, Confirm, Decline and Release
- Reconfigure opt-in and validation
- multiple IA and multiple resources per IA

### 15.3. Address allocation

- reservation precedence
- existing and sticky lease reuse
- requested address
- pool exhaustion
- overlapping and ambiguous pools
- concurrent requests
- pending offer expiration
- DECLINED hold-down
- IPv4 conflict detection
- IPv6 DAD
- failover ownership

### 15.4. Relay

- direct and relayed clients
- multiple relay levels
- hop limit
- Option 82 trust
- Interface-ID and Remote-ID
- zero link-address behavior
- response loss
- loop detection

### 15.5. Failover

- loss of routing
- loss of TCP
- protocol keepalive timeout
- manual partner-down
- timed partner-down
- MCLT
- recovery and full resynchronization
- incompatible security mode
- invalid secret, certificate or identity
- lost binding acknowledgement

### 15.6. CLI

- golden MD-CLI transcripts
- golden classic CLI transcripts
- help and completion
- commands entered from deep contexts
- transaction commit and discard behavior
- immediate classic CLI behavior
- empty and large operational tables
- filters, pagination and dependency errors

### 15.7. Checkpoints

- SELECTING
- after OFFER before REQUEST
- after allocation before ACK or Reply
- during DAD
- packet queued between shards
- active failover synchronization
- remaining time around T1, T2 and valid lifetime
- restoration after browser continuity loss

### 15.8. Manual Browser Use acceptance

With cross-origin isolation active:

1. Create a user-owned topology through drag and drop.
2. Add routers, hosts, relays and a dedicated DHCP server.
3. Configure DHCPv4 and DHCPv6 using MD-CLI from nested contexts.
4. Repeat representative configuration and show operations in classic CLI.
5. Acquire addresses directly and through relays.
6. Verify routes, ARP, ND, RA, SLAAC and default-router ownership.
7. Ping over IPv4 and IPv6 using dynamically acquired configuration.
8. Exercise renew, rebind, release, decline and pool exhaustion.
9. Interrupt a link and verify recovery and failover behavior.
10. Capture packets and verify the exported PCAPNG message sequence.
11. Save, reload and restore a checkpoint.
12. Inspect browser errors, runtime errors, layout and terminal scrolling.

Manual acceptance is not replaced by scripted browser tests.

## 16. Completion criteria

The DHCP stage is complete only when:

- every matrix entry marked supported has production behavior
- source catalog and capability matrix validate
- no command succeeds without a real effect
- no network information crosses devices outside encoded packet paths
- all mutable state has one documented owner
- resource limits and overflow behavior come from profiles
- protocol and CLI tests pass
- the exact staged tree passes `pnpm verify`
- `git diff --check` and repository status are clean apart from intended files
- Browser Use acceptance passes for both terminal engines and both IP families
- README describes the resulting current capability without future-tense claims
