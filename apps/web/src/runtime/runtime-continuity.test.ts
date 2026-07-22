// Continuity policy tests cover monotonic gaps, checkpoint cadence and the
// post-recovery baseline without starting a browser Worker or Wasm pthreads.

import { describe, expect, it } from "vitest";
import { RuntimeContinuityGuard,
  RuntimeRecoveryController } from "./runtime-continuity";

describe("runtime continuity guard", () => {
  it("requests checkpoints at the configured cadence", () => {
    const guard = new RuntimeContinuityGuard(2000, 5000, 100);
    expect(guard.observe(2099).recoveryCheckpointDue).toBe(false);
    expect(guard.observe(2100)).toMatchObject({
      continuityLost: false, recoveryCheckpointDue: true
    });
    guard.checkpointCompleted(2100);
    expect(guard.observe(4099).recoveryCheckpointDue).toBe(false);
    expect(guard.checkpointAge(4099)).toBe(1999);
  });

  it("latches a suspension until a checkpoint restore completes", () => {
    const guard = new RuntimeContinuityGuard(2000, 5000, 0);
    expect(guard.observe(5001)).toMatchObject({
      elapsedMilliseconds: 5001,
      continuityLost: true,
      recoveryCheckpointDue: false
    });
    expect(guard.observe(5002).continuityLost).toBe(true);
    guard.recovered(5002);
    expect(guard.observe(5003)).toMatchObject({
      elapsedMilliseconds: 1,
      continuityLost: false,
      recoveryCheckpointDue: false
    });
  });

  it("fails closed on a backwards or invalid observation", () => {
    const backwards = new RuntimeContinuityGuard(2000, 5000, 100);
    expect(backwards.observe(99).continuityLost).toBe(true);
    const invalid = new RuntimeContinuityGuard(2000, 5000, 100);
    expect(invalid.observe(Number.NaN).continuityLost).toBe(true);
  });

  it("rejects policy intervals that cannot produce a recovery point", () => {
    expect(() => new RuntimeContinuityGuard(5000, 5000, 0))
      .toThrow(RangeError);
    expect(() => new RuntimeContinuityGuard(0, 5000, 0))
      .toThrow(RangeError);
  });
});

describe("runtime recovery controller", () => {
  it("restores the latest owned checkpoint after a continuity gap", () => {
    let live = new Uint8Array([1, 2, 3]);
    const imported: Uint8Array[] = [];
    const controller = new RuntimeRecoveryController(
      new RuntimeContinuityGuard(2000, 5000, 0), {
        exportCheckpoint: () => live.slice(),
        importCheckpoint: (bytes) => {
          imported.push(bytes);
          live = new Uint8Array([9, ...bytes]);
        }
      });
    expect(controller.initialize(0)).toBe(true);
    // Mutating the adapter's original buffer proves the controller owns an
    // independent saved generation rather than a borrowed view.
    live[0] = 7;
    const recovered = controller.maintain(5001);
    expect(recovered.state).toBe("recovered");
    expect(imported).toHaveLength(1);
    expect(Array.from(imported[0])).toEqual([1, 2, 3]);
    expect(controller.maintain(5002).state).toBe("stable");
  });

  it("latches an import failure and never resumes an uncertain runtime", () => {
    const controller = new RuntimeRecoveryController(
      new RuntimeContinuityGuard(2000, 5000, 0), {
        exportCheckpoint: () => new Uint8Array([1]),
        importCheckpoint: () => { throw new Error("rejected image"); }
      });
    expect(controller.initialize(0)).toBe(true);
    expect(controller.maintain(5001)).toMatchObject({
      state: "unrecoverable", error: "rejected image"
    });
    expect(controller.maintain(5002).state).toBe("unrecoverable");
  });
});
