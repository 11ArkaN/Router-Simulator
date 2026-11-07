# Quiescent protocol channel checkpoints

## Decision

Protocol packet channels retain two SPSC rings and fixed shared frame slots. Persistence may inspect or replace their complete ownership partition only after both live owners have stopped at safe points and release-acknowledged the same enclosing barrier. The coordinator acquires both acknowledgements before accessing any producer-owned or consumer-owned field. Ordinary sending, receiving and completion paths keep their existing ownership and memory ordering.

A nonzero snapshot-cohort identifier joins channel images to the enclosing protocol and link state. It is independent of host time, configuration generations and transmission tickets. A matching identifier validates cohort membership; it does not establish quiescence. The runtime coordinator must establish the barrier separately.

## Protocol-owner acknowledgement

The IS-IS worker enters quiescence through an internal begin-barrier command. It refuses an uncommitted configuration generation, an already active barrier or exhausted owner-local token space. A successful command returns a new monotonic token through the existing release/acquire result ring. This acknowledgement publishes prior protocol mutations before the coordinator can inspect state.

While the token is active, the worker handles its worker-status query, matching end-barrier command and shutdown. Capture and restore preparation, commit and abort also require the current token. Other commands return an explicit barrier-pending error. It performs no ingress consumption, egress completion, route receipt processing, timer work, decision or output publication. Coalesced wakeups do not resume protocol work. Ending requires the exact current token; stale and repeated release refuse. Shutdown still joins a quiescent worker.

An internal synchronous capture command requires the matching active token and a capture anchor no earlier than the worker's entry into quiescence. Future anchors and absent transfer destinations refuse. The caller owns the detached destination until the exact command result returns. Capture stages a complete registry image before replacing that destination; allocation, clock-range or invariant failure preserves it. The image includes child owners, egress policy and retry state, previous-DIS work, recovery gates, fair cursors and route publication stamps. Scratch buffers, callbacks, pointer projections and the worker's control rendezvous are omitted. Scheduling min/max sentinels remain explicit meanings, while observed times retain exact relative ages.

The protocol acknowledgement does not stop forwarding or links. The enclosing runtime must acquire all required owner acknowledgements before capturing a joined image, and must unwind every acquired barrier on failure. These commands provide no application or CLI time controls.

Restore preparation validates the source cohort separately from the current barrier token and constructs a detached registry. It validates ordinary admission policy, child images, medium configuration, Hello transmission windows, timer representations and route catalogs before publication. Heap-stable instance owners bind only candidate circuits. A pending candidate prevents barrier release and another capture. Commit requires the same source cohort, swaps registries without allocation and consumes the candidate once. Abort destroys the candidate without changing the live registry or releasing the barrier. The current worker's barrier high water never rewinds with restored protocol state.

## Preserved ownership

Each slot belongs to exactly one of four disjoint roles:

- the producer's available stack, preserving its complete LIFO order;
- the ready FIFO, preserving packet order;
- the consumer's borrowed set, retaining numeric handles for pending physical-admission work;
- the returned FIFO, retaining completion results until the producer consumes them.

Owned control-value channels also preserve a fifth role: a producer edit that has been reserved but not published. Editing and borrowed catalogs remain distinct. Route publication restores producer-edit and consumer-borrowed pointer projections from the validated handles into new storage, without acquiring another credit.

Every non-free packet slot retains its complete immutable metadata and exact live frame prefix. Free-slot bytes are omitted. Borrowed and occupied catalogs use ascending handles, while ring and available-stack order remain significant. Unknown, duplicate, missing or out-of-range handles, mismatched capacity or completion mode, and oversized frames reject before mutation.

The generic channel does not interpret protocol identities or acknowledge output. The enclosing owner validates encoded selectors, configuration epochs, protocol epochs, pending tickets and physical link receipt references against the same snapshot cohort.

## Restoration

All old borrowed frame views expire before restoration. Pending physical-admission references are reconstructed from their validated saved handles and metadata. Restore uses existing frame slots and bounded handle-only scratch. It validates the complete image before changing metadata, bytes, available credits, borrowed flags or either FIFO. No allocation occurs after validation.

The coordinator release-publishes the complete restored state before resuming either owner. No third consumer operates concurrently with a live SPSC direction, and no additional shared count or lock is added to packet handling. Persistence failure must release every acquired pause through scoped cleanup without consuming, replaying or fabricating a frame.

Owned-value restoration has separate preparation and commit operations. Preparation validates the detached partition and copy-constructs every value directly in heap storage. Failed allocation or a throwing value copy leaves all live channels intact. The coordinator prepares every dependent channel before its first commit. Commit moves validated owned values into fixed slots, restores roles and FIFOs, and consumes the preparation once without allocation. Profile-sized route generations never materialize as stack temporaries.

Route transfer snapshots retain both pending generations and actual installation or refusal results. Ready, borrowed and editing slots retain pending result state; returned slots retain a final result. Capture does not decide whether a queued generation is admissible to the RIB. The same RIB owner must accept or refuse it after resume under its ordinary validation rules.

## Capture time and protection

Sample the common persistence anchor only after every relevant owner has acknowledged quiescence. Sampling before the barrier can incorrectly classify a recently refreshed timer as lying in the future. Relative protocol durations freeze while the runtime is absent. This anchor creates no simulation clock, future-event queue or user-facing time control.

Wire images can contain simple authentication fields. The enclosing persistence codec must protect secret-bearing wire before serializing it. Internal owned transfer values are not an unencrypted portable file format. Active IS-IS structural persistence remains blocked until the protocol, channels, link receipts, route transfers and protected codec share one validated barrier.

## Verification

Tests preserve mixed free, ready, borrowed and returned roles across ring wrap, destroy original channels, continue pending guarded receipts and check FIFO delivery and exact credit reuse. Both completion-enabled egress and consumption-only ingress retain their distinct reclamation semantics. Malformed images preserve the live destination. Existing two-thread channel tests retain their release/acquire and physical-completion guarantees. A separate two-thread barrier test release-acknowledges both owners, restores their shared channel while they are stopped, then resumes exact packets, receipts and credits. Owned-value tests retain all five roles, resume a partial producer edit, inject a copy failure before commit and transfer a 2 MiB fixed payload with the default 1 MiB native stack. Route tests destroy the old channel before continuing borrowed installations and preserve forwarding/capacity refusals and both address-family payloads. A real IS-IS pthread test holds queued ingress and an unconsumed physical completion across multiple Hello periods, checks stale-token and pending-generation refusal, then resumes ordinary receive/completion processing.
