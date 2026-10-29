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

An egress receipt identifies the original encoded PDU. The level owner additionally compares LSP sequence, checksum and purge state before clearing a flood obligation. An old receipt cannot clear a newer LSP's obligation.

Each outstanding transmission class also owns a nonzero monotonic ticket. Forwarding returns this ticket unchanged. Operational cancellation, including loss of DIS role, clears the pending reservation without rewinding the ticket high-water mark. A delayed receipt cannot complete replacement output within the same configuration epoch. Ticket exhaustion stops the affected class explicitly. Checkpoint continuity must preserve both the high-water mark and any pending reservation.

The metadata includes a protocol-defined transmission class; IS-IS uses the wire PDU type. Independent Hello, LSP and SNP ticket sequences may contain the same number. A forwarding owner that delegates physical admission to the link owner therefore validates the complete returned metadata before releasing a borrowed frame handle. An old receipt cannot release a reused slot belonging to another class, epoch or ticket.

## Lifecycle and verification

The protocol pthread starts only after its queues, condition variable, mutex, atomics and owned registries are initialized. Destruction requests shutdown, wakes the worker and joins it before shared slots are destroyed.

Runtime startup creates separate permanent OSPF and IS-IS protocol owners before any router configuration. The generated CPU policy reserves three, five or seven Emscripten pthreads in addition to the browser control Worker. Telemetry publishes each protocol owner's distinct startup identity through its acquire-loaded publication. Protocol consumers join before forwarding producers, and both join before their SPSC channel storage is released.

Encoded protocol output wakes its selected forwarding consumer. Route generations wake the link owner that consumes them. Returning a forwarding transfer credit also sets a persistent atomic work predicate, so notify-before-sleep cannot strand pending protocol output. Notifications carry no packet or configuration state. A bounded drainer schedules immediate continuation while its input still has ready frames and its output has capacity; full output waits for returned credits.

Two-thread tests transfer variable-length values and verify complete publication, move ownership, cancellation, full backpressure and duplicate-return rejection. Configuration admission, runtime fairness and active-process limits are verified separately from this transport contract. No MPSC or MPMC queue is introduced.
