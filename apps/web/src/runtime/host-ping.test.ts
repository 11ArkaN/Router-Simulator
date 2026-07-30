// Host ping tests exercise the public formatter with forwarding-owned outcomes.
// Controlled time keeps the suite fast without replacing any runtime timer in
// production code.

import { PROFILE_CATALOG } from "@router-simulator/contracts";
import { describe, expect, it, vi } from "vitest";
import { runHostPing, waitForHostPing } from "./host-ping";

describe("host ping presentation", () => {
  it("waits through pending state and decodes forwarding TTL and RTT", async () => {
    const statuses = ["pending", "pending", "reply:63:1250500"];
    const runtime = {
      startHostPing: vi.fn(async () => undefined),
      hostPingStatus: vi.fn(async () => statuses.shift() ?? "reply:63:1250500")
    };
    let clock = 0;

    const reply = await waitForHostPing(runtime, "h2", 7,
      { timeoutMilliseconds: 100, statusIntervalMilliseconds: 10 },
      () => clock, async (milliseconds) => { clock += milliseconds; });

    expect(reply).toEqual({ ttl: 63, elapsedNanoseconds: 1_250_500 });
    expect(runtime.hostPingStatus).toHaveBeenCalledTimes(3);
  });

  it("returns packet loss only after the catalog-bounded deadline", async () => {
    const runtime = {
      startHostPing: vi.fn(async () => undefined),
      hostPingStatus: vi.fn(async () => "pending")
    };
    let clock = 0;

    const reply = await waitForHostPing(runtime, "h2", 8,
      { timeoutMilliseconds: 20, statusIntervalMilliseconds: 10 },
      () => clock, async (milliseconds) => { clock += milliseconds; });

    expect(reply).toBeUndefined();
    expect(runtime.hostPingStatus).toHaveBeenCalledTimes(3);
  });

  it("renders the complete SR OS report for the release-defined probe count", async () => {
    const runtime = {
      startHostPing: vi.fn(async () => undefined),
      hostPingStatus: vi.fn(async (_source: string, sequence: number) =>
        `reply:62:${1_000_000 + sequence * 1_000}`)
    };

    const output = await runHostPing(runtime, "h1", "203.0.113.77", {
      randomSequence: () => 40,
      now: () => 0,
      sleep: async () => undefined
    });

    expect(runtime.startHostPing).toHaveBeenCalledTimes(
      PROFILE_CATALOG.protocol_defaults.ping_default_count);
    expect(output).toContain("PING 203.0.113.77 56 data bytes\n");
    expect(output).toContain(
      "64 bytes from 203.0.113.77: icmp_seq=1 ttl=62 time=1.04ms.");
    expect(output).toContain(
      "5 packets transmitted, 5 packets received, 0.00% packet loss");
    expect(output).toContain(
      "round-trip min = 1.04ms, avg = 1.042ms, max = 1.044ms, stddev = 0.001ms");
  });
});
