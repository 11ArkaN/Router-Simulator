// Browser presentation adapter for a host-originated ICMP Echo operation.
// The C++ forwarding owner remains authoritative for packets, received TTL and
// RTT. This module only sequences the release-defined probe count and renders
// the same SR OS text contract used by a router terminal.

import { PROFILE_CATALOG } from "@router-simulator/contracts";

export interface HostPingRuntime {
  startHostPing(sourceId: string, destination: string,
    sequence: number): Promise<void>;
  hostPingStatus(sourceId: string, sequence: number): Promise<string>;
}

export interface HostPingOutcome {
  ttl: number;
  elapsedNanoseconds: number;
}

export interface HostPingWaitPolicy {
  timeoutMilliseconds: number;
  statusIntervalMilliseconds: number;
}

export const DEFAULT_HOST_PING_WAIT: HostPingWaitPolicy = {
  // The timeout comes from the pinned release catalog. Short polling does not
  // measure RTT: the status response carries the forwarding timestamp, so UI
  // scheduling can only delay presentation and cannot inflate the result.
  timeoutMilliseconds:
    PROFILE_CATALOG.protocol_defaults.ping_timeout_milliseconds,
  statusIntervalMilliseconds: 10,
};

function parseOutcome(status: string): HostPingOutcome | undefined {
  if (status === "pending") return undefined;
  const match = /^reply:(\d+):(\d+)$/.exec(status);
  if (!match) throw new Error(`Unexpected host ping state: ${status}`);
  const ttl = Number(match[1]);
  const elapsedNanoseconds = Number(match[2]);
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 255 ||
      !Number.isSafeInteger(elapsedNanoseconds) || elapsedNanoseconds < 0)
    throw new Error(`Invalid host ping outcome: ${status}`);
  return { ttl, elapsedNanoseconds };
}

export async function waitForHostPing(reader: HostPingRuntime,
  sourceId: string, sequence: number, policy = DEFAULT_HOST_PING_WAIT,
  now: () => number = () => performance.now(),
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds))):
  Promise<HostPingOutcome | undefined> {
  const deadline = now() + policy.timeoutMilliseconds;
  for (;;) {
    const outcome = parseOutcome(
      await reader.hostPingStatus(sourceId, sequence));
    if (outcome) return outcome;
    if (now() >= deadline) return undefined;
    await sleep(policy.statusIntervalMilliseconds);
  }
}

function milliseconds(microseconds: number) {
  // SR OS retains at least two decimal places and a third when significant.
  // RTT enters this function as an integer number of rounded microseconds.
  let text = (microseconds / 1_000).toFixed(3);
  while (text.endsWith("0") && text.slice(text.indexOf(".") + 1).length > 2)
    text = text.slice(0, -1);
  return text;
}

export interface HostPingRunDependencies {
  randomSequence(): number;
  sleep(milliseconds: number): Promise<void>;
  now(): number;
}

const defaultDependencies: HostPingRunDependencies = {
  randomSequence: () => crypto.getRandomValues(new Uint16Array(1))[0]!,
  sleep: (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
  now: () => performance.now(),
};

export async function runHostPing(runtime: HostPingRuntime, sourceId: string,
  destination: string, dependencies = defaultDependencies): Promise<string> {
  const defaults = PROFILE_CATALOG.protocol_defaults;
  const count = defaults.ping_default_count;
  const payload = defaults.ping_payload_octets;
  const rtts: number[] = [];
  let output = `PING ${destination} ${payload} data bytes\n`;
  let wireSequence = dependencies.randomSequence();

  for (let request = 1; request <= count; ++request) {
    await runtime.startHostPing(sourceId, destination, wireSequence);
    const outcome = await waitForHostPing(runtime, sourceId, wireSequence,
      DEFAULT_HOST_PING_WAIT, dependencies.now, dependencies.sleep);
    if (outcome) {
      // Forwarding reports nanoseconds. Round to the nearest microsecond before
      // accumulating, exactly like the terminal owner, so every detail line
      // and the final sufficient statistics describe the same measurements.
      const microseconds = Math.floor(
        (outcome.elapsedNanoseconds + 500) / 1_000);
      rtts.push(microseconds);
      output += `${payload + 8} bytes from ${destination}: icmp_seq=${request}` +
        ` ttl=${outcome.ttl} time=${milliseconds(microseconds)}ms.\n`;
    } else {
      output += `Request timed out. icmp_seq=${request}.\n`;
    }

    wireSequence = (wireSequence + 1) & 0xffff;
    if (request !== count)
      await dependencies.sleep(defaults.ping_interval_milliseconds);
  }

  const lost = count - rtts.length;
  output += `---- ${destination} PING Statistics ----\n` +
    `${count} packets transmitted, ${rtts.length} packets received, ` +
    `${(lost * 100 / count).toFixed(2)}% packet loss\n`;
  if (rtts.length) {
    const average = rtts.reduce((sum, value) => sum + value, 0) / rtts.length;
    const meanSquare = rtts.reduce(
      (sum, value) => sum + value * value, 0) / rtts.length;
    const deviation = Math.sqrt(Math.max(0, meanSquare - average * average));
    output += `round-trip min = ${milliseconds(Math.min(...rtts))}ms, ` +
      `avg = ${milliseconds(average)}ms, ` +
      `max = ${milliseconds(Math.max(...rtts))}ms, ` +
      `stddev = ${milliseconds(deviation)}ms\n`;
  }
  return output;
}
