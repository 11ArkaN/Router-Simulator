// Browser-side completion adapter for asynchronous host ICMP probes. The C++
// forwarding owner starts the real packet exchange and exposes only pending or
// reply state; this module waits without blocking the UI thread and never
// fabricates success from the start acknowledgement.

export interface HostPingStatusReader {
  hostPingStatus(sourceId: string, sequence: number): Promise<string>;
}

export interface HostPingWaitPolicy {
  timeoutMilliseconds: number;
  statusIntervalMilliseconds: number;
}

export const DEFAULT_HOST_PING_WAIT: HostPingWaitPolicy = {
  // One routed probe normally completes in milliseconds, but ARP resolution
  // may precede it. Three seconds allows the standards-driven retry path to run
  // while still returning control promptly when no route or reply exists.
  timeoutMilliseconds: 3_000,
  statusIntervalMilliseconds: 10,
};

export async function waitForHostPing(reader: HostPingStatusReader,
  sourceId: string, sequence: number, policy = DEFAULT_HOST_PING_WAIT,
  now: () => number = () => performance.now(),
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds))): Promise<boolean> {
  const deadline = now() + policy.timeoutMilliseconds;
  for (;;) {
    const status = await reader.hostPingStatus(sourceId, sequence);
    if (status === "reply") return true;
    if (status !== "pending") throw new Error(`Unexpected host ping state: ${status}`);
    if (now() >= deadline) return false;
    await sleep(policy.statusIntervalMilliseconds);
  }
}
