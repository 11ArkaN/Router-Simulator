// Manifest 4 tests exercise the portable multi-router boundary without
// substituting IndexedDB or OPFS behavior with product-side mocks.

import { describe, expect, it } from "vitest";
import { createEmptyProjectV4, createRouterProjectV4 } from "@router-simulator/contracts";
import referenceManifest from "../../../examples/four-router-reference.netsim?raw";
import { createCheckpointManifestV4, createProjectManifestV4,
  parseNetsimV4, projectCheckpointNameV4, protectNetsimV4,
  unprotectNetsimV4 } from "./persistence";

function project() {
  const value = createEmptyProjectV4(new Date("2026-07-16T12:00:00Z"));
  value.projectId = "persistence-test";
  value.routers.push(createRouterProjectV4("r1", "7750-sr-1", "R1"));
  value.layout.nodes.r1 = { x: 10, y: 20 };
  return value;
}

describe("netsim manifest format 4", () => {
  it("round-trips multi-router project intent", () => {
    const value = project();
    const parsed = parseNetsimV4(JSON.stringify(createProjectManifestV4(value)));
    expect(parsed).toEqual({ project: value });
  });

  it("round-trips checkpoint, capture and terminal presentation", () => {
    const editor = { buffer: "show", cursor: 4, history: [], historyIndex: 0 };
    const presentation = { version: 2 as const, activeSessionId: "s1", sessions: [{
      sessionId: "s1", routerId: "r1", engine: "md" as const,
      editors: { "md-operational": editor, "md-configuration": editor,
        classic: editor }, queuedInput: []
    }] };
    const manifest = createCheckpointManifestV4(project(),
      Uint8Array.of(0, 1, 255), Uint8Array.of(10, 13), presentation);
    expect(parseNetsimV4(JSON.stringify(manifest))).toMatchObject({
      checkpoint: Uint8Array.of(0, 1, 255), capture: Uint8Array.of(10, 13),
      terminalPresentation: presentation
    });
  });

  it("encrypts and authenticates the complete portable manifest", async () => {
    const manifest = createCheckpointManifestV4(project(),
      Uint8Array.of(0, 1, 255));
    const wrappingKey = crypto.getRandomValues(new Uint8Array(32));
    const protectedText = await protectNetsimV4(
      manifest, wrappingKey, "correct horse battery staple");
    expect(protectedText).not.toContain(manifest.project.projectId);
    expect(protectedText).not.toContain("checkpointBase64");
    const decoded = await unprotectNetsimV4(
      protectedText, "correct horse battery staple");
    expect(decoded.project).toEqual(manifest.project);
    expect(decoded.checkpoint).toEqual(Uint8Array.of(0, 1, 255));
    expect(decoded.projectWrappingKey).toEqual(wrappingKey);
    await expect(unprotectNetsimV4(protectedText, "wrong passphrase"))
      .rejects.toThrow("incorrect or the file is corrupted");

    const envelope = JSON.parse(protectedText) as {
      ciphertextBase64: string;
    };
    const first = envelope.ciphertextBase64[0];
    envelope.ciphertextBase64 =
      `${first === "A" ? "B" : "A"}${envelope.ciphertextBase64.slice(1)}`;
    await expect(unprotectNetsimV4(
      JSON.stringify(envelope), "correct horse battery staple"))
      .rejects.toThrow("incorrect or the file is corrupted");
    wrappingKey.fill(0);
    decoded.projectWrappingKey.fill(0);
  }, 20_000);

  it("rejects stale formats and non-canonical binary payloads", () => {
    const manifest = createCheckpointManifestV4(project(), Uint8Array.of(1));
    expect(() => parseNetsimV4(JSON.stringify({ ...manifest, formatVersion: 1 })))
      .toThrow("not supported");
    expect(() => parseNetsimV4(JSON.stringify({ ...manifest,
      checkpointBase64: "AQ" }))).toThrow("canonical base64");
  });

  it("binds browser recovery to complete project intent", async () => {
    const original = project();
    const sameStateWithNewSaveTime = { ...original,
      updatedAt: "2026-07-16T13:00:00Z" };
    const changedConfiguration = structuredClone(original);
    changedConfiguration.routers[0].systemName = "CHANGED";
    changedConfiguration.routers[0].running.systemName = "CHANGED";

    // Save time is deliberately volatile, while a configuration change must
    // select a different OPFS object even if node and link IDs remain equal.
    expect(await projectCheckpointNameV4(original)).toBe(
      await projectCheckpointNameV4(sameStateWithNewSaveTime));
    expect(await projectCheckpointNameV4(changedConfiguration)).not.toBe(
      await projectCheckpointNameV4(original));
  });

  it("imports the checked-in four-router reference project", async () => {
    // The distributable example is tested through the same manifest decoder
    // used by file import, not only through its TypeScript source constructor.
    const decoded = parseNetsimV4(referenceManifest);
    expect(decoded.project.routers).toHaveLength(4);
    expect(decoded.project.hosts).toHaveLength(4);
    expect(decoded.project.links).toHaveLength(8);
  });
});
