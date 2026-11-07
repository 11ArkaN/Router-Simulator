# Control generation ownership transfer

## Decision

IS-IS configuration generations use fixed shared slots with two SPSC handle rings. The serialized control owner reserves and edits a slot, then publishes its handle to the protocol owner. The protocol owner may move the generation's owned containers into its state before returning the handle. No pointer or container representation is copied into a ring.

The slot count bounds outstanding configuration transfers. It does not define the number of active processes, the configuration instance-ID range or a Nokia platform limit. Active process admission has a separate measured resource limit.

## Ownership and ordering

- One producer owns edit reservations and its free list.
- One consumer owns received leases.
- The ready ring release-publishes initialized values and the consumer acquires them before access.
- The return ring release-publishes completed consumption and the producer acquires it before destroying or reusing the slot value.
- Both rings preserve FIFO order and have one usable entry per shared slot plus a sentinel.
- Full rejects new reservations. Duplicate or unknown operations reject without returning an additional credit.
- A lease cannot be accessed after publication, cancellation or release. Generation values own their allocations and do not retain mutable references to another owner.
- Sensitive plaintext must be erased before a consumer returns its slot.

## Installation results

Receipt-enabled transfers retain the same two SPSC handle rings. The consumer writes its final result inside its owned slot before release. The producer must explicitly acquire that result before the credit can be reused; acquiring another edit cannot silently discard an installation failure. Result views expire on the producer's next acquisition. Reinitialization destroys and constructs the value inside its fixed slot, avoiding profile-sized temporaries on a protocol stack.

Route publication exposes an immutable complete generation to the RIB owner. Only after validating and finishing the actual RIB/FIB transaction may that owner return installed. Refusals preserve explicit stale, invalid, capacity or forwarding-failure results. Completion compares the expected device handle and route generation before releasing a slot, so a delayed result cannot complete a reused slot. The producer receives a small copied receipt, without borrowing route storage.

The OSPF consumption-only channel shares the same ownership primitive and common generation data. Its existing release means completed consumption and does not acquire the installation guarantee of the receipt-enabled variant. Two route slots bound outstanding transfers; they do not change router, instance or FIB scale. IS-IS route installation and per-protocol RIB merging remain separate integration work.

## Dual-family FIB programming

The forwarding owner preflights both supplied family generations before changing either table. Counts, stale generations and changed equal-generation replays reject the complete operation. At least one nonzero generation is required. A null family preserves its current table; an empty generation explicitly withdraws that family's routes.

Both commits run inside one uninterrupted forwarding command turn without allocation or external callbacks. Packet handling and state projections cannot interleave between the family writes. After preflight, a refusal would be an internal ownership violation and fails closed. Existing single-family APIs preserve their generation semantics.

RIB compilation can write directly into an exclusively owned transfer arena. It copies active selections and repair paths and clears unused rows, so reuse cannot retain withdrawn route values. The network route manager uses this forwarding API for complete dual-family transactions. Protocol installation receipts remain separate integration work.

## Circuit generations

Packet metadata carries device generation, logical interface ID, physical port and circuit configuration generation. The IS-IS worker and forwarding owner must reject an obsolete configuration generation before applying a frame or receipt. A current device handle alone cannot identify a reconfigured circuit.

The IS-IS owner retains one maximum retired circuit epoch per device handle. Removing or replacing a circuit raises this floor at commit; preparing and aborting a generation cannot raise it. A newly admitted logical circuit must exceed the floor, while an unchanged live circuit may keep its independent older epoch. Withdrawing every circuit and unregistering the protocol retains the floor for that same router handle. A valid replacement device handle starts a fresh scope. This bounded guard prevents remove-and-readd from resetting tickets under an old transport identity without retaining an unbounded history of logical interface IDs. Active protocol checkpoints must preserve the floor with their configuration and transmission state.

An egress receipt identifies the original encoded PDU. The level owner additionally compares LSP sequence, checksum and purge state before clearing a flood obligation. An old receipt cannot clear a newer LSP's obligation.

Each outstanding transmission class also owns a nonzero monotonic ticket. Forwarding returns this ticket unchanged. Operational cancellation, including loss of DIS role, clears the pending reservation without rewinding the ticket high-water mark. A delayed receipt cannot complete replacement output within the same configuration epoch. Ticket exhaustion stops the affected class explicitly. Checkpoint continuity must preserve both the high-water mark and any pending reservation.

The metadata includes a protocol-defined reservation epoch, transmission class and local instance ID; IS-IS uses the wire PDU type for its class. Independent instances and Hello, LSP and SNP ticket sequences may contain the same number. A forwarding owner that delegates physical admission to the link owner therefore validates the complete returned metadata before releasing a borrowed frame handle. An old receipt cannot release a reused slot belonging to another instance, class, epoch or ticket. The local instance ID is distinct from the encoded IID, which remains part of frame acceptance. The control producer supplies the reservation epoch; forwarding and link owners echo it unchanged under the same release/acquire receipt contract. Zero remains valid for protocols without a separate reservation scope. Instance update owners retain synchronization fences across slot reuse. Before reconstructing an entity, its parent must retain the maximum fence and choose a strictly greater initial epoch. Exhaustion requires refusal rather than identity reuse.

Full router generations are prepared before publication. Preparation validates canonical ordering, duplicate wire selectors, resource limits and immutable configuration for retained epochs. Changed circuits are constructed in staging; unchanged circuits remain live until commit moves their current state into preallocated output. Abort preserves live circuits. Intervening control mutations reject while preparation is pending, while packet work, timers and queries continue.

The forwarding barrier excludes packet observers while multicast membership and independent forwarding/link transport projections change. Multicast ownership exchanges return the previous preallocated vectors, allowing rollback without allocation. A physical port-generation change also requires a new circuit epoch. Forwarding and the link owner independently validate epoch and encoded instance selection before physical admission.

Parallel forwarding keeps each IS-IS slot borrowed after its transfer-ring enqueue. A separate link-producer, forwarding-consumer SPSC ring has one usable receipt entry per protocol frame credit. The link owner publishes the result of its actual fabric-queue attempt. Forwarding alone performs guarded slot release and wakes the protocol producer. A refused receipt publication is retained without repeating physical enqueue; returned reverse-ring credits wake the link owner. The combined placement applies the same physical-port check and returns actual admission directly.

## Instance update bindings

The protocol pthread owns each instance at a stable heap address. Circuit-vector moves preserve that address and the stable level slot. Preparing a generation reserves new Down bindings before publication. A unique owner-local admission ticket guards reverse-order abort, including reuse of a previously active slot. Abort restores the prior free binding configuration. Commit first emits old adjacency Down and releases removed bindings, then rebinds changed slots without replacing their level coordinators or databases.

The instance parent preserves a per-instance maximum synchronization fence outside the entity. Removing every interface leaves the instance and its databases alive. Removing the instance cancels Hello reservations, emits local Down and retains that fence before destroying the entity. Recreating it starts strictly above the fence. Router removal unregisters both circuits and instances; a fresh device handle starts a fresh scope.

Local update scheduling reserves its bounded retry metadata before binding publication. Circuit pacing credits cover L1 and L2 together. LSP retry deadlines are anchored only by actual successful physical admission of the current version. A failed physical attempt preserves SRM. Per-level SNP timers use owner-local jitter, and CSNP ranges advance only after matching physical receipts. Pending output waits for completion credits rather than polling a past deadline. The prototype takes explicit effective timer and burst values; production default resolution remains with the configuration owner.

Registered update instances reject structural checkpoints even when they have no interfaces. Until their integrations exist, authentication selection and nonzero update IIDs reject admission. Product CLI and protocol persistence remain separate required work.

## Lifecycle and verification

The protocol pthread starts only after its queues, condition variable, mutex, atomics and owned registries are initialized. Destruction requests shutdown, wakes the worker and joins it before shared slots are destroyed.

Forwarding threads start only after all protocol callback targets are published. During shutdown, protocol stop joins the thread without destroying its notification storage. Forwarding producers may still return frame credits and notify that stopped object. They join before protocol objects are destroyed. Stop is idempotent on the serialized control owner; new control submissions reject after stop, and the thread identity is cleared on exit.

Runtime startup creates separate permanent OSPF and IS-IS protocol owners before any router configuration. The generated CPU policy reserves three, five or seven Emscripten pthreads in addition to the browser control Worker. Telemetry publishes each protocol owner's distinct startup identity through its acquire-loaded publication. Protocol consumers join before forwarding producers, and both join before their SPSC channel storage is released.

Encoded protocol output wakes its selected forwarding consumer. Route generations wake the link owner that consumes them. Returning a forwarding transfer credit also sets a persistent atomic work predicate, so notify-before-sleep cannot strand pending protocol output. Notifications carry no packet or configuration state. A bounded drainer schedules immediate continuation while its input still has ready frames and its output has capacity; full output waits for returned credits.

Two-thread tests transfer variable-length values and verify complete publication, move ownership, cancellation, full backpressure and duplicate-return rejection. Configuration admission, runtime fairness and active-process limits are verified separately from this transport contract. No MPSC or MPMC queue is introduced.

### Prepared external advertisements

The OSPF owner can prepare a complete replacement of redistributed routes before the network owner installs the corresponding FIB. Preparation allocates and validates every replacement vector without changing live advertisements. It leases that router's process layout until commit or abort. Other commands for that router reject while the lease exists, and checkpoint or restore rejects while any lease exists. Protocol packet processing and timers continue on their existing owner.

Commit swaps only prepared vectors, marks coordination pending and releases the lease. It does not allocate. Abort discards preparation without changing live advertisements. Existing callers may commit without an explicit preparation command; that path prepares first and can still refuse. The network RIB transaction must use explicit preparation before changing the FIB.

### Network RIB transaction

The network owner rebuilds both configured address families in heap-owned scratch RIBs. Refusal leaves both active RIBs and their installed generation counters unchanged. Selection comparison includes repair paths and compares against the target router, independently of which router last used the scratch tables.

A single fixed transfer arena contains the two compiled FIBs. The network owner lends that arena to exactly one forwarding owner through one synchronous command. The command identity and complete device handle guard the borrow. The existing SPSC command release and result acquire delimit ownership; while awaiting the result, the network owner only drains frame egress and cannot enter another route transaction. The command envelope does not duplicate both family arrays in each ring slot. Combined forwarding uses the same preflight directly on its owner.

The transaction prepares redistributed advertisements against the staged RIBs before sending the forwarding command. Forwarding refusal aborts preparation. Success commits the prepared advertisements without allocation, swaps the active RIB pointers and advances only the installed family counters. Counter exhaustion refuses instead of wrapping. Scratch tables, FIBs and connected-input reserves are included in the existing control-memory reserve check.

### Checkpoint route provenance

Checkpoint ABI 9 stores stable logical interface IDs and their configuration generations in route inputs and selected FIB rows. IS-IS source, path type and prefix-distance rank are independent of OSPF path types. A decoded IS-IS route requires valid family/level/rank provenance, a nonzero logical scope generation and a supported instance ID. Connected and static rows cannot carry protocol path metadata.

The codec ABI comes from the generated profile and is checked against its versioned namespace. Browser manifest creation and parsing use the same generated protocol value. Magic, ABI and schema identity must match before a detached graph can be decoded. There is no compatibility reader for older checkpoint images. Portable project format 5 and runtime snapshot ABI 9 retain their current shapes.

This value-format contract preserves owned route data. It does not add an active IS-IS owner checkpoint or bypass the existing admission error for that unsupported operation.

### Forwarding request materialization

Synchronous forwarding requests borrow their programming payload only for the duration of the call. The link owner copies the value header and materializes the complete payload in its existing heap-owned command scratch before publishing an owned command. Only the owned specialization enters the SPSC ring; a request payload pointer never crosses that boundary.

Combined and separate forwarding placements share this materialization step. The serialized network owner cannot enter another configuration command while one is being applied or awaiting its result. Encoded frame egress can still drain while waiting. Counter exhaustion refuses admission rather than reusing a command identity.

A request initialized from a temporary payload is valid only within the complete synchronous call expression. A retained local command uses the owned payload type. This distinction keeps repeated maximum-size command temporaries off the control stack without changing queue capacity, the production stack limit or payload ownership.

### IS-IS candidate admission

The network owner retains OSPF and IS-IS candidates independently. Rebuild reads two immutable spans against one generated input budget; no concatenated route arena is allocated. Every configuration or OSPF rebuild explicitly supplies retained IS-IS spans. A complete local IS-IS generation must name a current device, local instance, logical interface, physical port and configuration generation. The consumer prepares bounded candidate capacity before the dual-family RIB/FIB transaction, then copies accepted values only after it succeeds. Empty router admission allocates no candidate arrays; active protocol storage may request checked runtime heap growth, like an LSDB. The unchanged initial-memory proof includes all eager per-router RIB allocations. Each arena contains two protocol partitions under one generated route ceiling. Replacing the first partition shifts the retained second partition within the same allocation; no second full protocol reserve or concatenation buffer is allocated. Growth, shrink, withdrawal and combined-capacity refusal preserve the other partition. Selection refusal and forwarding refusal return distinct results. Failed generations do not advance the accepted IS-IS key. Empty generations withdraw IS-IS while preserving other route sources. Circuit replacement must retain every installed IS-IS scope until the protocol owner has withdrawn its candidates. Automatic producer publication and receipt-channel integration are still required.

### IS-IS route publication

The IS-IS owner calculates independent IPv4 and IPv6 wide MT0 decisions with explicit budgets and preferences. Each publication contains all configured instances, families and levels for one router. Exact instance epochs and decision revisions form the pending snapshot; no hash or remote state substitutes for this fence. Publication waits for every required decision to consume its current revision. Calculation refusal preserves the installed generation.

Next hops come from accepted Hellos and current local circuit identity. RFC 1195 permits multiple interface addresses without ranking them. The emulator chooses the numerically lowest usable advertised address, independently of TLV ordering. This is a local policy, not a claim about undocumented SR OS multiple-address ranking. IPv6 requires a scoped link-local next hop. ARP and ND exchange actual packets on the forwarding owner.

A fixed receipt-enabled SPSC channel carries complete generations to the network owner. The consumer installs both families before returning the device, generation and installation or refusal status. The producer consumes the receipt before slot reuse. Refusal retries at the explicitly configured emulator recovery period; a full channel waits for completion notification. Same-handle protocol removal preserves publication high water. Idle registration waits for acknowledged empty withdrawal. Production activation, complete lifecycle transactions and active protocol checkpointing remain integration work.

### Forwarding pause acknowledgements

A forwarding owner clears its resume predicate before release-publishing a pause acknowledgement. The consumer may capture state and resume immediately after acquiring that result. Clearing the predicate after acknowledgement could overwrite that early resume and leave the owner waiting forever. The subsequent wait acquires the predicate and therefore also handles a resume that arrived before the wait began. Repeated live-router snapshots exercise this ordering while protocol workers remain active. This barrier is internal state ownership, not a simulation control.

### Ready frame snapshots

The existing consumer may inspect a bounded snapshot of published ready entries without removing them. It captures its own tail and acquires the producer head. The producer cannot reuse any visited ring slot while that consumer leaves tail unchanged. Later publications are outside the captured extent. The callback must not mutate the ring or retain a reference, and no second consumer or observer reads shared slot bytes.

The packet channel applies this query to initialized metadata and encoded frame bytes whose ready handles have been published. These frames cannot return to the producer free list until the normal consumer pop and release. The query allocates nothing, copies no packet, changes no credits and preserves FIFO order. Both ordinary ingress and completion-enabled egress keep the same ownership rules.

LAN scheduling can use this contract to classify pending LSPs for the current interface and generation without consuming packets out of order. The protocol owner must inspect its own incoming channel, decode the actual frame and retain only a local bounded projection. Port-specific LAN backlog integration remains separate from this queue primitive.

### IS-IS circuit medium ownership

A router generation selects exactly one P2P or LAN program for each logical interface and local instance. The protocol owner constructs only that medium's state. A LAN aggregate contains independent L1 and L2 neighbor, DIS and Hello owners under one immutable local identity. Cold admission requires explicit level groups and rejects mixed P2P/LAN input, inconsistent identities and same-epoch edits before publishing any replacement.

Each LAN level has a separate Hello transmission window. Encoded PDU type, interface epoch and local instance distinguish physical admission receipts even when both levels use the same ticket number. Callback contexts borrow the current circuit and level only during synchronous service; moving a generation retains no pointer to its previous vector element.

The same prepared transport projection determines active level memberships and checks encoded selectors on protocol, forwarding and link owners. LAN and logical P2P media remain distinct even when both use Ethernet. Queries copy actual accepted-neighbor counts, per-level DIS selections and selected Hello next-hop bindings; no P2P adjacency is synthesized for LAN.

Experimental LAN Hello generations use the permanent protocol pthread and existing physical frame channels. Experimental LAN update-instance admission requires explicit scan and CSNP separation values and a positive complete-set period. Accepted same-level neighbor MACs and actual DIS roles update the instance synchronously. A single LSP scan and pending level/epoch/ticket fence cover both levels; complete SNPs have a separate shared receipt fence and minimum spacing. The next periodic complete-set timer is armed before transmission work. Last-neighbor or role loss cancels only the affected reservations. The protocol owner classifies queued LSPs through one consumer-only snapshot per ingress channel after bounded draining. Active protocol checkpointing remains blocked. The general circuit-generation API and the existing P2P entry point apply the same transaction.

Effective update transmission values may be supplied per interface. Cold admission validates the complete override and circuit-generation equality includes it. The egress owner keeps one resolved value for SNP periods, LSP retries, PDU bounds and shared L1/L2 credits. Without an override it uses the explicit experimental instance policy. A policy edit requires a new transport epoch. LAN restart uses the retained PRNG continuation, restores ordinary Hello scheduling and repeats startup election without reviving a received neighbor or old DIS.

LAN origination reserves bounded pseudonode records and neighbor-composition scratch before publication. Actual Up peers supply pseudonode edges, and actual per-level DIS role controls activation and withdrawal. Remote DIS changes invalidate root content even when this router remains non-DIS. Holding-time and election transitions run before fresh origination and decisions. Each successful family/level decision retains its exact first-hop binding catalog; publication cannot reconstruct tokens from a later adjacency projection. Catalog capacity is bounded by the existing backend token storage independently of selected ECMP width. LAN physical forwarding tests cover off-subnet IPv4 and IPv6 with real ARP and ND.
