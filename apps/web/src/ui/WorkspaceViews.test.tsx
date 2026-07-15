// Interaction tests for secondary workspaces. The suite verifies that visible
// controls emit typed project or runtime intent instead of mutating a hidden
// UI-only model. jsdom is sufficient because packet and hardware execution is
// covered below the RuntimeClient boundary by native and Wasm tests.

// @vitest-environment jsdom

import { createDefaultProject, type LabProject, type RunningConfig } from
  "@router-simulator/contracts";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRef, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CaptureWorkspace, ConfigWorkspace, DevicesWorkspace, NotesWorkspace,
  SettingsWorkspace, SnapshotWorkspace } from "./WorkspaceViews";

// Vitest does not install the Jest cleanup hook automatically. Explicit
// teardown prevents one workspace's controls from polluting later role queries.
afterEach(cleanup);

function ConfigHarness({ initial, observed }: {
  initial: RunningConfig;
  observed(config: RunningConfig): void;
}) {
  // The production component is controlled by App. Keeping the same ownership
  // pattern here proves that a sequence of edits is based on the latest draft
  // rather than a stale value captured by the first render.
  const [config, setConfig] = useState(initial);
  return <ConfigWorkspace config={config} onChange={(next) => {
    setConfig(next);
    observed(next);
  }} />;
}

function SettingsHarness({ initial, observed }: {
  initial: LabProject;
  observed(project: LabProject): void;
}) {
  const [project, setProject] = useState(initial);
  return <SettingsWorkspace project={project} onChange={(next) => {
    setProject(next);
    observed(next);
  }} onResetLayout={vi.fn()} />;
}

describe("workspace controls", () => {
  it("opens real inventory targets and the shared console", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn();
    const consoleOpen = vi.fn();
    render(<DevicesWorkspace project={createDefaultProject()} onInspect={inspect}
      onConsole={consoleOpen} />);

    await user.click(screen.getAllByRole("listitem")[0].querySelector("button")!);
    await user.click(screen.getByRole("button", { name: "Open console" }));

    expect(inspect).toHaveBeenCalledWith("r1");
    expect(consoleOpen).toHaveBeenCalledOnce();
  });

  it("routes capture actions to their runtime callbacks", async () => {
    const user = userEvent.setup();
    const toggle = vi.fn();
    const exportCapture = vi.fn();
    const checkpoint = vi.fn();
    render(<CaptureWorkspace active={false} onToggle={toggle}
      onExport={exportCapture} onCheckpoint={checkpoint} />);

    await user.click(screen.getByRole("button", { name: "Start capture" }));
    await user.click(screen.getByRole("button", { name: "Export PCAPNG" }));
    await user.click(screen.getByRole("button", { name: "Export checkpoint" }));

    expect(toggle).toHaveBeenCalledOnce();
    expect(exportCapture).toHaveBeenCalledOnce();
    expect(checkpoint).toHaveBeenCalledOnce();
  });

  it("creates an empty route draft without inventing network values", async () => {
    const user = userEvent.setup();
    const observed = vi.fn();
    const initial = createDefaultProject().runningConfig;
    render(<ConfigHarness initial={initial} observed={observed} />);

    await user.click(screen.getByRole("button", { name: "Add route" }));

    const latest = observed.mock.calls.at(-1)?.[0] as RunningConfig;
    expect(latest.staticRoutes.at(-1)).toEqual({ prefix: "", nextHop: "" });
    expect(screen.getAllByLabelText("Route prefix")).toHaveLength(1);
  });

  it("keeps notes and physical delay edits in portable project data", async () => {
    const user = userEvent.setup();
    const notes = vi.fn();
    const observed = vi.fn();
    const project = createDefaultProject();
    const { unmount } = render(<NotesWorkspace value="" onChange={notes} />);

    await user.type(screen.getByPlaceholderText(
      "Document addressing, test intent and expected results."), "ARP check");
    expect(notes).toHaveBeenLastCalledWith("k");
    unmount();

    render(<SettingsHarness initial={project} observed={observed} />);
    const delay = screen.getAllByRole("spinbutton")[0];
    await user.clear(delay);
    await user.type(delay, "250");
    const latest = observed.mock.calls.at(-1)?.[0] as LabProject;
    expect(latest.links[0].propagationDelayNs).toBe(250);
  });

  it("opens checkpoint import through the hidden binary input", async () => {
    const user = userEvent.setup();
    const input = createRef<HTMLInputElement>();
    const exportCheckpoint = vi.fn();
    const importCheckpoint = vi.fn();
    render(<SnapshotWorkspace checkpointInput={input} onExport={exportCheckpoint}
      onImport={importCheckpoint} />);

    const inputClick = vi.spyOn(input.current!, "click");
    await user.click(screen.getByRole("button", { name: "Import checkpoint" }));
    expect(inputClick).toHaveBeenCalledOnce();
  });
});
