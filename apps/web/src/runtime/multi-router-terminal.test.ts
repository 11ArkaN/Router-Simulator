// The client owns terminal reply framing and polling, never protocol timers.
// A controlled Worker transport supplies owner responses; tests assert the
// visible transcript without starting Wasm or bypassing the public client API.
import { LAB_RUNTIME_PROTOCOL } from "@router-simulator/contracts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MultiRouterRuntimeClient } from "./multi-router-client";

const encode = (values: readonly string[]) => values.map((value) =>
  `${new TextEncoder().encode(value).length}:${value},`).join("");
const response = (output: string, pending: boolean, engine: "md" | "classic", prompt: string) =>
  output + encode([engine, engine === "md" ? "md-operational" : "classic",
    pending ? "pending" : "", prompt]);
function transport(replies: string[]) {
  const requests: string[] = [];
  class ControlledWorker {
    onmessage?: (event: MessageEvent) => void;
    postMessage(request: { id: number; command: string }) {
      requests.push(request.command);
      const value = replies.shift();
      if (value === undefined) throw new Error("Unexpected terminal request");
      this.onmessage?.({ data: { id: request.id, ok: true, value } } as MessageEvent);
    }
  }
  vi.stubGlobal("crossOriginIsolated", true);
  vi.stubGlobal("Worker", ControlledWorker);
  return { client: new MultiRouterRuntimeClient(), requests };
}
beforeEach(() => vi.useFakeTimers());
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe("router terminal completion", () => {
  it.each(["md", "classic"] as const)("returns the final %s prompt after all poll chunks", async (engine) => {
    const prompt = engine === "md" ? "\n[/]\nA:admin@R1# " : "\n*A:R1# ";
    const { client, requests } = transport([
      response("PING 2001:db8::2\n", true, engine, "old prompt"),
      response("64 bytes from 2001:db8::2: icmp_seq=1\n", true, engine, "intermediate prompt"),
      response("1 packets transmitted, 1 packets received\n", false, engine, prompt)
    ]);
    const completed = client.terminalExecute("qa-console", "ping 2001:db8::2 count 1");
    await vi.runAllTimersAsync();
    expect(await completed).toBe("PING 2001:db8::2\n64 bytes from 2001:db8::2: icmp_seq=1\n" +
      "1 packets transmitted, 1 packets received\n" + prompt);
    expect(requests).toEqual([
      encode([LAB_RUNTIME_PROTOCOL.session_execute, "qa-console", "ping 2001:db8::2 count 1"]),
      encode([LAB_RUNTIME_PROTOCOL.session_poll, "qa-console"]),
      encode([LAB_RUNTIME_PROTOCOL.session_poll, "qa-console"])
    ]);
  });
  it.each(["md", "classic"] as const)("preserves synchronous %s output without duplicating its prompt", async (engine) => {
    const prompt = engine === "md" ? "\n[/]\nA:admin@R1# " : "\nA:R1# ";
    const output = "configured value\n" + prompt;
    const { client, requests } = transport([response(output, false, engine, prompt)]);
    expect(await client.terminalExecute("qa-console", "info")).toBe(output);
    expect(requests).toHaveLength(1);
  });
  it("restores the returned prompt after cancellation and an empty poll", async () => {
    const prompt = "\n[/]\nA:admin@R1# ";
    const { client } = transport([
      response("PING 192.0.2.2\n", true, "md", prompt),
      response("", true, "md", prompt),
      response("0 packets transmitted, 0 packets received\n", false, "md", prompt)
    ]);
    const completed = client.terminalExecute("qa-console", "ping 192.0.2.2");
    await vi.runAllTimersAsync();
    expect(await completed).toBe("PING 192.0.2.2\n0 packets transmitted, 0 packets received\n" + prompt);
  });
});
