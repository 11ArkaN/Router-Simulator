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
