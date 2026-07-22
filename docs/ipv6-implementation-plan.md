# Full IPv6 and dual-stack services implementation plan

## Objective

The laboratory will gain a complete IPv6 stack that operates alongside IPv4 on every supported router, host, interface, port and link. IPv6, DHCPv6 and DNS traffic must always cross the existing packet path as encoded Ethernet frames. No service may use host sockets, browser networking or direct calls between simulated devices.

The implementation covers:

- global, unicast, link-local and multicast IPv6 addressing,
- canonical text representation, address scopes and source address selection,
- ICMPv6, Neighbor Discovery, Neighbor Unreachability Detection, Duplicate Address Detection and Redirect,
- Router Solicitation, Router Advertisement, SLAAC and RDNSS,
- stable opaque and modified EUI-64 interface identifiers,
- MLDv1 and MLDv2,
- stateful and stateless DHCPv6, relay operation and prefix delegation,
- IPv6 RIB and FIB with connected, local and static routes,
- Path MTU Discovery, source fragmentation and destination reassembly,
- IPv6 extension header parsing and forwarding,
- shared dual-stack UDP and TCP transports,
- IPv4 and IPv6 IPsec with AH, ESP, IKEv2, NAT traversal and policy-driven security associations,
- an internal authoritative DNS hierarchy and recursive resolver,
- DNSSEC signing and validation,
- DNS over TLS, DNS over HTTP/2, DNS over HTTP/3, DNS over QUIC and DDR,
- local PKI, CRL and OCSP,
- CLI, UI, PCAPNG capture, telemetry, checkpoints and project persistence.

## Conformance baseline

Production behavior must be derived from normative standards, the pinned SR OS release profile and verified packet traces. Every exposed feature requires a source-catalog record, capability entry and test. A schema-only feature must not appear in completion or UI controls.

Primary IPv6 sources include:

- RFC 8200 for the IPv6 packet format and extension header processing,
- RFC 4291 for addressing architecture,
- RFC 4007 for scoped addresses and zones,
- RFC 5952 for canonical text formatting,
- RFC 6724 for source and destination address selection,
- RFC 4443 for ICMPv6,
- RFC 4861 for Neighbor Discovery and NUD,
- RFC 4862 for SLAAC and DAD,
- RFC 7217 for stable opaque interface identifiers,
- RFC 4191 and RFC 8106 for router preference and RDNSS,
- RFC 8201 for Path MTU Discovery,
- RFC 6980, RFC 5722 and RFC 6946 for fragment handling,
- RFC 3810 for MLDv2,
- RFC 9915 for DHCPv6,
- Nokia SR OS 26.7.R1 command references and platform documentation.

IPsec behavior is based on RFC 4301 for the security architecture, RFC 4302 for AH, RFC 4303 for ESP, RFC 7296 for IKEv2, RFC 7383 for IKEv2 fragmentation, RFC 8221 for mandatory algorithms, RFC 3947 and RFC 3948 for NAT traversal, RFC 4106 for AES-GCM and the applicable IANA IPsec registries. Algorithm availability and every exposed command are restricted further by the pinned SR OS release and platform profiles.

DNS and encrypted transport behavior is based on the corresponding RFC Editor publications for DNS, DNSSEC, EDNS, TLS 1.3, HTTP/2, QUIC, HTTP/3, DoT, DoH, DoQ and DDR. Algorithms and record assignments come from current IANA registries.

## Public contracts and versions

The following contract versions are introduced together so that no runtime can accept a partially compatible object graph:

- project format 4,
- manifest format 3,
- runtime protocol 4,
- snapshot ABI 6,
- telemetry ABI 6,
- checkpoint ABI 6.

Older project and checkpoint formats are rejected before the live runtime is modified. No migration code is retained.

Core public types include allocation-free `IpAddress`, `IpPrefix`, `Ipv6Address`, `Ipv6Prefix` and `ScopedIpv6Address`. A scoped link-local address always carries an interface identifier. Family-specific configuration types describe address assignment, address lifetime, DAD policy, primary preference, router advertisement, DHCPv6, resolver endpoints and static routes.

Generated schemas remain the sole source of protocol operation names, field identifiers, ABI constants and profile limits. TypeScript, C++ and UI code consume generated contracts instead of duplicating literals.

## Packet and addressing layer

The IPv6 codec operates on bounded views over packet-pool storage and does not allocate for normal parsing or encoding. It validates the fixed header, payload length, next-header chain and upper-layer checksum pseudo-header.

Extension processing recognizes Hop-by-Hop Options, Destination Options, Routing, Fragment, Authentication Header and Encapsulating Security Payload. Unknown options follow the action encoded in their high-order bits. Unknown next headers and malformed chains produce the required ICMPv6 Parameter Problem response when the standard permits a response.

AH and ESP payloads are handed to the IPsec owner before any inner protocol is parsed. A packet without a matching inbound security association is discarded and counted. It must never be interpreted as ordinary UDP, TCP or ICMP merely from the untrusted AH Next Header field. Transit nodes forward AH and ESP as opaque payloads unless a local tunnel or transport policy terminates the security association.

IPv6 multicast includes solicited-node, all-nodes, all-routers and MLD membership state. Ethernet multicast addresses are derived from the IPv6 destination. Delivery still uses physical link ownership and receive queues.

Routers never fragment IPv6 packets. An oversized forwarded packet results in ICMPv6 Packet Too Big and updates the sender's path MTU cache. Only the originating endpoint inserts a Fragment header. Reassembly is destination-only, bounded by profile resources and rejects overlapping fragments.

## Interfaces, routing and forwarding

An interface may carry IPv4 and IPv6 addresses simultaneously. Address and route limits come from the selected platform profile. Address changes are applied atomically and trigger the appropriate DAD, connected-route, local-route, multicast-membership and neighbor-state changes.

The route manager owns separate IPv4 and IPv6 RIB indexes while sharing route selection mechanisms. IPv6 lookup supports prefixes from `/0` through `/128`, connected and local routes, active static routes, recursive next-hop resolution and scoped link-local next hops. A link-local next hop without an outgoing interface is rejected.

The forwarding shard owns the programmed IPv6 FIB and performs hop-limit processing, longest-prefix lookup, adjacency resolution, MTU checks and ICMPv6 error generation. It cannot read mutable control-plane state directly. FIB programming remains an explicit message from the route owner.

Source address selection follows RFC 6724. Stable SLAAC identifiers follow RFC 7217 and use a persisted per-host secret, interface identity, network identifier and DAD counter. Modified EUI-64 derives its value from the configured interface MAC.

## ICMPv6 and Neighbor Discovery

ICMPv6 covers Echo Request, Echo Reply, Destination Unreachable, Packet Too Big, Time Exceeded, Parameter Problem, Router Solicitation, Router Advertisement, Neighbor Solicitation, Neighbor Advertisement, Redirect and MLD messages.

The adjacency manager is the single owner of Neighbor Cache entries. It implements INCOMPLETE, REACHABLE, STALE, DELAY and PROBE, reachable-time randomization, retransmission, queued packets, failure notification and garbage collection. All deadlines use the monotonic runtime clock.

DAD uses tentative addresses and the required solicited-node multicast exchange. A duplicate prevents assignment and produces an operational alarm. ND messages that violate hop-limit, source-address, target-address or option constraints are discarded according to the applicable RFC.

## Router Advertisement, SLAAC and DHCPv6

Router Advertisement is configured per router interface and supports prefix information, autonomous and on-link flags, managed and other-configuration flags, router lifetime, preference, MTU, reachable time, retransmission timer and RDNSS lifetime.

Hosts maintain independently expiring default-router, prefix, address and RDNSS state. Preferred and valid lifetimes are handled separately. A router withdrawal or expired prefix updates operational state without deleting static user intent.

DHCPv6 implements client, server and relay roles, stateful and stateless exchanges, DUID, IA_NA, IA_PD, rapid commit where supported, renew, rebind, release, decline, relay-forward and relay-reply. IA_TA, Server Unicast and UseMulticast are not active features because RFC 9915 obsoletes them. Their numeric wire values remain recognizable for capture analysis and safe interoperability. A normal host can run the DHCPv6 server. Router roles are exposed through SR OS CLI only when the pinned profile documents them.

## UDP and TCP

UDP and TCP are internal dual-stack transports. Their socket API accepts emulator addresses and packet buffers only. Binding, ephemeral ports, checksums, demultiplexing, receive queues and errors are owned by a transport shard and are included in checkpoints.

TCP follows RFC 9293 and includes the complete connection state machine, sequence-space validation, retransmission, RTO, flow control, congestion control, delayed acknowledgements, window scaling, timestamps and SACK. Loss, duplication, reordering and MTU changes originate from the existing link and queue models.

No TCP or UDP implementation path may call Winsock, browser fetch, WebSocket or another host networking API.

## IPsec and IKEv2

The IPsec subsystem is shared by IPv4 and IPv6. It implements policy-based transport and tunnel mode without bypassing the existing interface, route, adjacency, queue and link path. AH uses IP protocol 51, ESP uses IP protocol 50, IKEv2 uses UDP port 500 and NAT traversal uses UDP port 4500 with the required non-ESP marker. Encapsulated traffic is always emitted as an encoded packet and resolves its outer next hop normally.

The Security Policy Database is the sole owner of ordered inbound, outbound and forwarding policies. Selectors cover address family, source and destination prefixes, upper-layer protocol, source and destination port ranges, interface or tunnel scope and protect, bypass or discard action. Policy lookup uses compiled indexes while retaining the configured priority order. A protect result identifies an IPsec proposal or an existing Security Association bundle and never silently falls back to cleartext.

The Security Association Database owns unidirectional AH and ESP state. Each entry records SPI, destination, protocol, mode, algorithms, keys, salt, sequence state, optional extended sequence numbers, anti-replay window, lifetimes, byte and packet counters, tunnel endpoints and creation provenance. Inbound lookup uses destination, security protocol and SPI. Outbound lookup follows the selected SPD result. Sequence exhaustion, hard lifetime expiry, authentication failure, replay, selector mismatch and missing state all fail closed and increment distinct operational counters.

AH authenticates the immutable IPv4 or IPv6 fields, the AH header and payload using the RFC 4302 canonicalization rules. ESP authenticates and encrypts the protected payload, padding, Pad Length and Next Header according to RFC 4303. Authenticated encryption uses AEAD semantics with the correct associated data and explicit nonce construction. Integrity is verified in constant time before any protected inner packet reaches routing, transport or ICMP processing.

The initial standards profile includes the mandatory-to-implement and SR OS documented algorithms only. Algorithm identifiers, key lengths, salts, ICV lengths, Diffie-Hellman groups and PRFs are generated from source data. Weak, deprecated or undocumented suites are rejected during configuration instead of being accepted as successful no-ops. Cryptographic operations use the pinned OpenSSL build through memory-only callbacks and never through host sockets.

IKEv2 owns IKE SA state, CHILD SA negotiation, identities, proposals, nonces, key derivation, traffic selectors, certificate or pre-shared-key authentication, liveness, informational exchanges, deletion, reauthentication, rekey and simultaneous rekey collision handling. Message identifiers and retransmission are maintained independently in both directions. IKE fragmentation, NAT detection, UDP encapsulation and endpoint address changes follow their standards and operate on real runtime deadlines.

The key and credential owner keeps pre-shared keys, private keys and derived key material out of telemetry, capture metadata, CLI output and ordinary checkpoints. Project persistence encrypts secret material in the existing vault. Checkpoints serialize enough protected state to reconstruct active IKE and CHILD SAs without resetting sequence numbers or replay windows, while never writing plaintext secrets into an unprotected project record.

Tunnel mode performs an inner route and policy decision, protects the complete inner IP packet, builds the configured outer IPv4 or IPv6 header and then performs the normal outer route and adjacency lookup. Inbound tunnel processing authenticates and decrypts first, validates tunnel selectors, prevents recursive decapsulation abuse and submits the inner packet to the correct forwarding or local-delivery owner. Transport mode protects only the upper-layer payload and preserves the applicable outer IP header semantics.

Path MTU handling accounts for AH, ESP, IV, ICV, padding, tunnel headers and UDP encapsulation overhead. IPv6 routers never fragment the outer packet. Sources use the established IPv6 fragmentation rules and consume authenticated Packet Too Big information. IPv4 encapsulation follows the configured DF policy and RFC behavior. IKEv2 fragmentation is independent of IP fragmentation.

IPsec capture exposes outer AH, ESP, IKEv2 and NAT traversal packets exactly as transmitted. Decrypted inner payload capture is disabled by default and, when explicitly enabled for a laboratory, is a separate local observation point with a visible security warning and no secret-key export. Operational projections are rate limited and contain counters and public SA metadata only.

Every supported SR OS 26.7.R1 IPsec, IKE, tunnel, key, certificate, show, clear, statistics and troubleshooting command is generated from the release command profile and connected to real state. Unsupported platform-specific paths remain absent from completion and return the documented error when entered explicitly. Configuration validation prevents incomplete policies, invalid selector combinations, duplicate SPI ownership and proposals that cannot negotiate.

## DNS services

Ordinary hosts can run root, TLD, authoritative and recursive DNS roles. The recursive resolver begins with project-owned root hints and performs iterative resolution entirely within the laboratory.

The DNS wire codec supports compression safely, detects pointer loops and preserves unknown RR types. Managed records include SOA, NS, A, AAAA, CNAME, DNAME, PTR, MX, TXT, SRV, CAA, SVCB, HTTPS, TLSA, DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM and OPT.

The resolver implements referrals, glue and bailiwick validation, QNAME minimization, EDNS0, UDP retry, server selection, TCP fallback, positive caching, negative caching, TTL expiration and CNAME or DNAME loop detection.

Zones are managed through the existing inspector design and standard master-file import and export. The implementation supports authoritative responses, delegations, glue and DNSSEC signing. AXFR, IXFR, RFC 2136 and TSIG are not included in this stage.

## DNSSEC, PKI and encrypted DNS

DNSSEC implements KSK and ZSK lifecycle, DS creation, RRSIG generation and verification, NSEC, NSEC3, secure, insecure and bogus validation states, trust anchors and the AD, CD and DO semantics. Supported algorithms are generated from the selected standards profile and current IANA assignments.

The project PKI supports a local CA, PEM import, certificate issuance, chain construction, hostname validation, time validity, EKU, CRL and OCSP. Private keys are immediately stored in an encrypted project vault and are never exported as plaintext.

TLS 1.3 and X.509 use OpenSSL 3.5.7 LTS. HTTP/2 uses nghttp2 1.69.0. QUIC uses ngtcp2 1.24.0. HTTP/3 uses nghttp3 1.17.0. Release archives, signatures or checksums, licenses and source records are pinned in the repository.

DNS transports include UDP and TCP port 53, DoT, DoH over HTTP/2, DoH over HTTP/3 and DoQ. DDR and SVCB discover encrypted endpoints, with explicitly configured policy controlling authenticated fallback. ODoH, DNSCrypt, mDNS and LLMNR are outside this stage.

Third-party libraries receive memory-buffer callbacks, entropy, wall time and emulator transport callbacks. They never own a system socket and never bypass the packet path.

## State ownership and threading

IPv6 extends the existing owner model instead of creating a separate runtime. Control-plane owners manage configuration, addresses, routes, ND, RA, DHCPv6 and service intent. Forwarding owners manage FIB and packet processing. Link owners manage serialization, propagation and physical delivery.

A logical service shard owns DNS, TLS, HTTP and QUIC connections. Each connection remains on one owner. Cross-owner operations use bounded rings with documented producer, consumer, capacity, ordering, memory ordering and overflow behavior.

No feature introduces a simulated clock, global future-event queue or direct device-to-device call.

## Shared memory growth

Shared WebAssembly memory starts at 320 MiB, grows in linear 64 MiB steps and has a 1 GiB maximum. Only the runtime allocator owner may request growth.

`WebAssembly.Memory.grow()` does not suspend the entire laboratory. Existing C++ offsets remain valid. Workers can continue processing already allocated packet and state memory while the requesting allocation waits for new pages.

The allocator publishes a monotonically increasing `memoryEpoch` after successful growth. JavaScript and worker bridges compare the epoch before every shared-memory projection and recreate their typed-array views from the current `memory.buffer`. UI components never retain a raw shared-memory view.

Checkpoint preparation cannot begin during an uncommitted growth operation. A failed growth returns a resource-exhaustion error for the requesting operation without partially changing the laboratory. Timers and packet processing are not artificially paused or advanced.

Browser tab suspension is handled separately. A detected continuity loss does not fast-forward network state. The runtime reports the loss and performs controlled recovery from the last compatible checkpoint.

## Persistence and checkpoints

Checkpoint ABI 6 stores all IPv6 addresses and lifetimes, ND and MLD state, RIB and FIB entries, path MTU entries, fragments, DHCPv6 leases, transport connections, DNS transactions and caches, DNSSEC state, PKI state, link transmissions, queues, relative deadlines and counters.

Checkpoint records contain canonical values and stable identifiers, never raw native pointers. External-library contexts must be reconstructed from module-owned serializable state. A feature is incomplete until an active operation can survive a checkpoint and continue with the same application-visible result.

Project persistence stores user intent separately from operational state. Imported configuration is fully validated before a replacement runtime is created.

## CLI and UI

MD-CLI and classic CLI remain terminal engines for the same router. IPv6 commands, context help, completion, validation, errors, prompts and output are added only from release-specific command profiles and verified transcripts.

Every capability added to the simulator, including but not limited to IPv6, must include the complete set of related SR OS 26.7.R1 configuration, operational, inspection, clear, debug and troubleshooting commands documented for the supported platform profile. This includes all parent contexts, required parameters, optional parameters, defaults, validation rules, abbreviations, completion candidates, help text, output columns, error paths and configuration semantics in both terminal engines. Adding only the command used by a UI action or a single happy-path command is not sufficient.

CLI coverage is tracked per command path in the capability matrix. A protocol, service, hardware feature or operational mechanism remains incomplete when its runtime behavior exists but any directly related supported SR OS command is missing, behaves differently, returns fabricated data or accepts an unsupported successful no-op. This rule applies to all future development, not only the work described by this plan.

The existing UI design is retained. IPv6, DHCPv6, DNS, DNSSEC and PKI controls are added to current inspectors, configuration workspaces and capture views. Controls execute real runtime operations and remain hidden until their capability is implemented.

Operational views show IPv6 addresses, DAD, default routers, neighbor states, RIB, FIB, path MTU, DHCPv6 leases, DNS cache and encrypted transport status from rate-limited runtime projections.

## Implementation sequence

1. Add source records, ADRs, contract versions, dual-stack value types and pinned dependency builds.
2. Add IPv6 codecs, extension headers, checksums, multicast, ICMPv6, PMTUD, fragmentation and reassembly.
3. Extend interfaces, RIB, FIB, forwarding, source selection, ND, NUD and DAD.
4. Add RS, RA, SLAAC, RDNSS, MLD and full DHCPv6 with relay and IA_PD.
5. Add shared dual-stack UDP and TCP with checkpoint support.
6. Add authoritative DNS, internal root hierarchy, recursive resolution, caching and zone management.
7. Add DNSSEC, the key vault, CA, certificates, CRL, OCSP and TLS 1.3.
8. Add DoT, HTTP/2, QUIC, HTTP/3, DoH2, DoH3, DoQ and DDR.
9. Add SPD, SAD, AH, ESP, IKEv2, NAT traversal, transport mode and tunnel mode for IPv4 and IPv6.
10. Extend CLI, UI, capture, telemetry, project persistence and checkpoints.
11. Complete conformance, performance, interoperability and browser acceptance testing.

Each sequence item must deliver working vertical behavior. No placeholder command or successful no-op is permitted.

## Verification

Unit tests cover codecs, checksums, every prefix length, address selection, extension chains, invalid lengths, unknown options and all implemented ICMPv6 messages.

State-machine tests cover ND and NUD transitions, duplicate detection, neighbor loss, RA lifetime changes, SLAAC deprecation, default-router replacement and DHCPv6 renew and rebind.

MTU tests verify that routers never fragment IPv6, Packet Too Big contains the correct MTU, path MTU entries expire correctly, sources fragment correctly and destinations reject overlapping fragments.

Routing tests cover connected, local and static routes, recursive resolution, link-local next hops, longest-prefix selection, hardware removal, carrier failure and FIB reprogramming.

DNS tests cover malformed compression, pointer loops, referrals, glue, bailiwick, caching, negative caching, EDNS0, TCP fallback, DNSSEC validation and encrypted transport failure policies.

IPsec tests cover RFC and independent implementation vectors for AH, ESP, AES-GCM, key derivation and IKEv2 messages. State-machine tests cover negotiation, authentication failure, CHILD SA creation, transport and tunnel selectors, rekey, deletion, liveness, NAT traversal and checkpoint restore. Replay tests cover duplicates, reordering, window movement, extended sequence rollover and exhaustion. Negative tests prove that unauthenticated inner payloads, selector mismatches, invalid padding, invalid ICVs and unknown SPIs never reach an upper-layer parser.

Native Windows interoperability tests use independent implementations and official vectors. Captured traffic must be accepted without malformed-protocol warnings by Wireshark or tshark.

Checkpoint tests run while ND, DHCPv6, TCP, TLS, QUIC and DNS operations are active. Restore must not lose application-visible state or silently restart configuration.

Performance verification retains the existing packet-primitive regression gate and adds IPv6, TCP, DNS and cryptographic baselines. A 16-router connected dual-stack laboratory with hosts exercises failures, concurrent traffic, DNSSEC, DoT, DoH3, DoQ, telemetry, captures, checkpoints and memory growth beyond the 320 MiB baseline.

The final verification includes formatting, dependency checks, static analysis, sanitizers, fuzzers, native tests, Wasm tests, production build and benchmarks. Browser Use is the primary manual browser validation tool. Playwright is used only if Browser Use is unavailable.

Browser Use acceptance must configure every supported router model from an empty project through both terminal engines. It covers physical cards and MDAs, ports, router interfaces, IPv4 and IPv6 addresses, static routes, ND, RA, SLAAC-facing behavior, DHCPv6 relay roles, DNS-related router state, IPsec policy, IKEv2, transport and tunnel SAs, failures, clear commands, show commands, configuration persistence, checkpoint restore and reload. The resulting packets and operational state must be verified, not only the command transcript.

## Explicit boundaries

- The current UI appearance and layout remain unchanged.
- The laboratory never uses Internet DNS or host networking.
- SRv6 policy is outside this stage.
- AXFR, IXFR, dynamic DNS update and TSIG are outside this stage.
- ODoH, DNSCrypt, mDNS and LLMNR are outside this stage.
- A feature is visible only after its implementation, source record, capability entry and tests are complete.

## Post-IPv6 closure audit

After every IPv6 and dual-stack item above is implemented and the complete automated, interoperability, performance and Browser Use acceptance suite passes, the resulting coherent change set is committed.

Work then continues without an implementation pause into a repository-wide closure audit of all functionality that predates that commit. The audit is not limited to IPv6 and includes IPv4, Ethernet, ARP, ICMP, routing, hardware inventory, cards, MDAs, ports, interfaces, hosts, links, queues, forwarding, captures, telemetry, persistence, checkpoints, failure behavior and every other active subsystem.

For every supported capability, the audit verifies:

- standards-conformant wire behavior and state transitions,
- complete source-catalog and capability-matrix coverage,
- all applicable SR OS 26.7.R1 configuration, operational, show, clear, debug and troubleshooting commands in both terminal engines,
- parent contexts, defaults, validation, completion, help, abbreviations, prompts, errors and output fields,
- absence of fabricated state, successful no-ops, hidden direct communication and unexplained hardcoded policy,
- correct mutable-state ownership, shard affinity, bounded queue behavior and overload reporting,
- complete project persistence and active-operation checkpoint reconstruction,
- realistic interaction between related systems instead of isolated unit behavior,
- appropriate automated, manual terminal, packet-capture, performance and Browser Use tests.

Missing systems, commands, state transitions and tests discovered during the audit are implemented and verified immediately. The audit is complete only when every currently advertised capability has an implemented vertical path from user configuration through encoded network traffic and operational inspection, or is explicitly hidden and marked unsupported when the pinned sources do not support it.
