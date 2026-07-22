// Monotonic browser-runtime continuity policy. The runtime Worker is the sole
// mutable owner. This module has no DOM, React, storage or Wasm dependency and
// only classifies observations supplied by that owner.

export interface RuntimeContinuityObservation {
  // elapsedMilliseconds is measured by performance.now in the Worker. Wall
  // clock changes therefore cannot manufacture or hide a suspension.
  elapsedMilliseconds: number;
  continuityLost: boolean;
  recoveryCheckpointDue: boolean;
}

export interface RuntimeCheckpointAdapter {
  // The adapter must return an owned copy. Undefined means that checkpoint
  // preparation failed and the previous compatible image must be retained.
  exportCheckpoint(): Uint8Array | undefined;
  // Import is transactional. Throwing means that the live runtime did not
  // accept the image and must not process another command as if it recovered.
  importCheckpoint(bytes: Uint8Array): void;
}

export type RuntimeRecoveryResult = {
  state: "stable" | "checkpointed" | "recovered" | "unrecoverable";
  elapsedMilliseconds: number;
  checkpointAgeMilliseconds: number;
  error?: string;
};

export class RuntimeContinuityGuard {
  private previousObservation: number;
  private lastRecoveryCheckpoint: number;
  private awaitingRecovery = false;

  constructor(private readonly checkpointIntervalMilliseconds: number,
    private readonly lossThresholdMilliseconds: number,
    initialNowMilliseconds: number) {
    // Profile generation proves these relationships for production. Runtime
    // validation keeps unit tests and direct callers from creating a policy
    // that can never save a checkpoint before declaring continuity lost.
    if (!Number.isFinite(checkpointIntervalMilliseconds) ||
        checkpointIntervalMilliseconds <= 0 ||
        !Number.isFinite(lossThresholdMilliseconds) ||
        lossThresholdMilliseconds <= checkpointIntervalMilliseconds ||
        !Number.isFinite(initialNowMilliseconds) ||
        initialNowMilliseconds < 0) {
      throw new RangeError("Runtime continuity policy is invalid");
    }
    this.previousObservation = initialNowMilliseconds;
    this.lastRecoveryCheckpoint = initialNowMilliseconds;
  }

  observe(nowMilliseconds: number): RuntimeContinuityObservation {
    // performance.now is monotonic by contract. A non-finite or backwards
    // sample therefore indicates a broken observation boundary and is treated
    // as lost continuity instead of allowing protocol deadlines to continue.
    const valid = Number.isFinite(nowMilliseconds) && nowMilliseconds >= 0;
    const elapsed = valid ? nowMilliseconds - this.previousObservation
      : Number.POSITIVE_INFINITY;
    const continuityLost = this.awaitingRecovery || elapsed < 0 ||
      elapsed > this.lossThresholdMilliseconds;
    if (valid) this.previousObservation = nowMilliseconds;
    if (continuityLost) this.awaitingRecovery = true;
    return {
      elapsedMilliseconds: elapsed,
      continuityLost,
      recoveryCheckpointDue: !continuityLost && valid &&
        nowMilliseconds - this.lastRecoveryCheckpoint >=
          this.checkpointIntervalMilliseconds
    };
  }

  checkpointCompleted(nowMilliseconds: number): void {
    // The Worker calls this only after it copied the complete prepared image
    // out of Wasm. Failed or empty exports retain the preceding recovery point.
    if (this.awaitingRecovery || !Number.isFinite(nowMilliseconds) ||
        nowMilliseconds < this.lastRecoveryCheckpoint) return;
    this.lastRecoveryCheckpoint = nowMilliseconds;
  }

  recovered(nowMilliseconds: number): void {
    // Recovery imports relative deadlines from the saved image and establishes
    // a new observation baseline. The suspended duration is never added to a
    // restored timer, and it cannot trigger a second recovery immediately.
    if (!Number.isFinite(nowMilliseconds) || nowMilliseconds < 0)
      throw new RangeError("Runtime recovery time is invalid");
    this.previousObservation = nowMilliseconds;
    this.lastRecoveryCheckpoint = nowMilliseconds;
    this.awaitingRecovery = false;
  }

  checkpointAge(nowMilliseconds: number): number {
    if (!Number.isFinite(nowMilliseconds) ||
        nowMilliseconds < this.lastRecoveryCheckpoint)
      return Number.POSITIVE_INFINITY;
    return nowMilliseconds - this.lastRecoveryCheckpoint;
  }
}

export class RuntimeRecoveryController {
  private recoveryCheckpoint?: Uint8Array;
  private unavailable = false;

  constructor(private readonly continuity: RuntimeContinuityGuard,
    private readonly adapter: RuntimeCheckpointAdapter) {}

  initialize(nowMilliseconds: number): boolean {
    // Startup costs are not a continuity interval. The first checkpoint and
    // baseline are established together after all runtime owners are ready.
    this.continuity.recovered(nowMilliseconds);
    return this.refreshRecoveryPoint(nowMilliseconds);
  }

  refreshRecoveryPoint(nowMilliseconds: number): boolean {
    if (this.unavailable) return false;
    const exported = this.adapter.exportCheckpoint();
    if (!exported?.byteLength) return false;
    // The adapter contract already requires ownership. Retaining that value
    // avoids a second multi-megabyte copy on every periodic recovery turn.
    this.recoveryCheckpoint = exported;
    this.continuity.checkpointCompleted(nowMilliseconds);
    return true;
  }

  maintain(nowMilliseconds: number): RuntimeRecoveryResult {
    const observation = this.continuity.observe(nowMilliseconds);
    const checkpointAgeMilliseconds =
      this.continuity.checkpointAge(nowMilliseconds);
    if (this.unavailable) return {
      state: "unrecoverable",
      elapsedMilliseconds: observation.elapsedMilliseconds,
      checkpointAgeMilliseconds,
      error: "Runtime continuity recovery is unavailable"
    };
    if (!observation.continuityLost) {
      if (!observation.recoveryCheckpointDue) return {
        state: "stable", elapsedMilliseconds: observation.elapsedMilliseconds,
        checkpointAgeMilliseconds
      };
      return {
        state: this.refreshRecoveryPoint(nowMilliseconds)
          ? "checkpointed" : "stable",
        elapsedMilliseconds: observation.elapsedMilliseconds,
        checkpointAgeMilliseconds
      };
    }
    if (!this.recoveryCheckpoint) {
      this.unavailable = true;
      return { state: "unrecoverable",
        elapsedMilliseconds: observation.elapsedMilliseconds,
        checkpointAgeMilliseconds,
        error: "No compatible runtime recovery point is available" };
    }
    try {
      // A private copy prevents an adapter from retaining or mutating the
      // controller's last known-good image during transactional import.
      this.adapter.importCheckpoint(this.recoveryCheckpoint.slice());
      this.continuity.recovered(nowMilliseconds);
      if (!this.refreshRecoveryPoint(nowMilliseconds))
        throw new Error("Recovered runtime could not publish a recovery point");
      return { state: "recovered",
        elapsedMilliseconds: observation.elapsedMilliseconds,
        checkpointAgeMilliseconds };
    } catch (cause) {
      this.unavailable = true;
      return { state: "unrecoverable",
        elapsedMilliseconds: observation.elapsedMilliseconds,
        checkpointAgeMilliseconds,
        error: cause instanceof Error ? cause.message : String(cause) };
    }
  }
}
