# Repository Working Rules

## Priorities

Make implementation decisions in this order:

1. source conformance and behavioral correctness,
2. data safety and runtime stability,
3. modularity and unambiguous state ownership,
4. performance confirmed by measurement,
5. the fewest executable lines of code.

## Architecture

- Every module must have a small, explicit contract and one owner of mutable state.
- Connect modules through versioned types, messages or narrow interfaces.
- A new feature must not require changes to unrelated modules.
- Do not create a global simulation clock, future event queue, Run, Pause or Step controls, time seeking or a speed multiplier.
- Network information between devices must always travel as an encoded frame or packet through a port, queue and link.
- The core must not depend on React, the DOM, IndexedDB, OPFS, xterm.js or hosting infrastructure.
- MD-CLI and classic CLI are two terminal engines for the same router and session. Do not present them as two global application modes.

## Multithreading

- The runtime must use WebAssembly threads, pthreads and `SharedArrayBuffer`.
- Do not add a single-threaded fallback. Missing cross-origin isolation must stop startup with a clear error.
- The runtime must run outside the UI thread and have at least a separate control-plane shard and forwarding/link shard.
- Prefer SPSC. Use MPSC only with a documented justification. Use MPMC only when the ownership and traffic topology cannot be represented safely with SPSC or MPSC, and require a benchmark plus an ADR for that decision.
- Every shared type must document its owner, flow direction, memory guarantee and overflow behavior.

## Performance and Code Size

- Optimize data layout, allocation count, packet copying, synchronization and UI update frequency from the start.
- Do not claim a performance improvement without a benchmark or profile. Keep a baseline result and a regression threshold.
- Minimize executable lines by sharing mechanisms and data, not through code golf, macros that hide logic or merged responsibilities.
- Comments, tests, schemas and source records are not subject to line-count minimization.
- React must not receive an event for every packet. The UI consumes rate-limited state projections.

## Comments

- Start every module with a header comment describing its responsibility, state owner and permitted dependency direction.
- Document public APIs with preconditions, postconditions, error codes, memory ownership and shard affinity.
- Every concurrent structure must identify its producer, consumer, capacity, ordering, overflow policy and memory ordering.
- Comment decisions, not obvious syntax.
- Describe invariants, state ownership, thread affinity, memory ordering, overload behavior, conformance source and performance assumptions.
- For non-trivial code, explain why the selected mechanism is safe and what could violate that safety.
- Do not leave comments that repeat a function name or a single statement.

## Conformance

- Do not guess SR OS behavior, commands, default values or platform limits.
- A production feature requires a source-catalog record, a test and a capability-matrix entry.
- An unimplemented feature must return an explicit error. A successful no-op is prohibited.
- The baseline profile is Nokia SR OS 26.7.R1, but the interface must not use the Nokia logo.

## Style

- Do not put metatext in created artifacts.
- Do not use an em dash, en dash or another long-dash variant.
- Use the plain hyphen `-` only where needed.

## Change Verification

- A functional change must include a test at the appropriate level.
- A change that alters user-facing behavior, capabilities, requirements, setup steps, commands or repository layout must update `README.md` in the same change. The README must stay current with the code and must not lag behind it.
- Every commit must be preceded by local verification of the exact staged tree. Do not use a remote workflow as a substitute for a local result.
- Before committing, bootstrap the pinned toolchain and production dependencies with `pnpm toolchain:bootstrap` and `pnpm dependencies:bootstrap` when their lock inputs or local installations changed.
- Before every commit, run `pnpm verify`. This mandatory gate covers source records, generated-file drift, dependency boundaries, public-release policy, TypeScript checks, C++ and TypeScript tests, packet and 16-router runtime benchmarks, and the production build.
- Before every commit, run `git diff --check` and inspect `git status --short` so whitespace defects, generated build products, secrets and unrelated files are not committed.
- A failed mandatory check blocks the commit. Fix the cause and repeat the complete affected gate. Do not weaken warnings, tests, sanitizer settings, benchmark thresholds or conformance checks to obtain a passing result.
- For UI or browser-runtime changes, verify the current product manually through Browser Use with cross-origin isolation active. Build a representative user-owned topology through product controls, exercise the affected CLI and UI paths, inspect browser errors, and verify persistence or recovery when the change can affect them. Do not use stale scripted browser scenarios as evidence.
