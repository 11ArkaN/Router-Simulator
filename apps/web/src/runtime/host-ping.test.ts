// Completion tests for host probes. The fixture controls time explicitly so a
// passing test proves that pending is neither exposed as a result nor mistaken
// for packet loss, without adding wall-clock delay to the test suite.

import { describe, expect, it, vi } from "vitest";
import { waitForHostPing } from "./host-ping";

describe("host ping completion", () => {
  it("waits through pending forwarding state until the echo reply arrives", async () => {
    const statuses = ["pending", "pending", "reply"];
    const reader = { hostPingStatus: vi.fn(async () => statuses.shift() ?? "reply") };
    let clock = 0;

    const reply = await waitForHostPing(reader, "h2", 7,
      { timeoutMilliseconds: 100, statusIntervalMilliseconds: 10 },
      () => clock, async (milliseconds) => { clock += milliseconds; });

    expect(reply).toBe(true);
    expect(reader.hostPingStatus).toHaveBeenCalledTimes(3);
  });

  it("returns packet loss only after the bounded deadline", async () => {
    const reader = { hostPingStatus: vi.fn(async () => "pending") };
    let clock = 0;

    const reply = await waitForHostPing(reader, "h2", 8,
      { timeoutMilliseconds: 20, statusIntervalMilliseconds: 10 },
      () => clock, async (milliseconds) => { clock += milliseconds; });

    expect(reply).toBe(false);
    expect(reader.hostPingStatus).toHaveBeenCalledTimes(3);
  });
});
