// Interaction tests for format 3 workspaces. Controls must emit typed project
// or runtime intent for the selected stable router instead of mutating hidden
// singleton state in the browser.

// @vitest-environment jsdom

import { createEmptyProjectV3, createRouterProjectV3,
  type LabProjectV3, type RouterProjectV3 } from "@router-simulator/contracts";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRef, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CaptureWorkspace, ConfigWorkspace, DevicesWorkspace, NotesWorkspace,
  SettingsWorkspace, SnapshotWorkspace } from "./WorkspaceViews";

afterEach(cleanup);

function projectWithRouter(): LabProjectV3 {
  const project = createEmptyProjectV3();
  return { ...project, routers: [createRouterProjectV3(
    "r1", "7750-sr-1", "R1")] };
}

function ConfigHarness({ initial, observed }: {
  initial: RouterProjectV3;
  observed(router: RouterProjectV3): void;
}) {
  // Production App owns the draft. Mirroring that controlled flow catches
  // callbacks that accidentally base a second edit on an obsolete render.
  const [router, setRouter] = useState(initial);
  return <ConfigWorkspace router={router} onChange={(next) => {
    setRouter(next);
    observed(next);
  }} />;
}

describe("multi-router workspace controls", () => {
  it("addresses the selected stable router for inventory and console actions", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn();
    const consoleOpen = vi.fn();
    render(<DevicesWorkspace project={projectWithRouter()} onInspect={inspect}
      onConsole={consoleOpen} />);

    const router = screen.getByRole("listitem").querySelector("button")!;
    await user.click(router);
    await user.dblClick(router);
    expect(inspect).toHaveBeenCalledWith("r1");
    expect(consoleOpen).toHaveBeenCalledWith("r1");
  });

  it("keeps the device DOM bounded while every router remains reachable", () => {
    const project = createEmptyProjectV3();
    project.routers = Array.from({ length: 16 }, (_, index) =>
      createRouterProjectV3(`r${index + 1}`, "7750-sr-1", `R${index + 1}`));
    const { container } = render(<DevicesWorkspace project={project}
      onInspect={vi.fn()} onConsole={vi.fn()} />);
    const list = screen.getByRole("list");

    // jsdom has no layout engine, so the component uses its documented
    // one-row minimum viewport. Overscan still proves DOM size is independent
    // from the full sixteen-router collection.
    expect(screen.getAllByRole("listitem").length).toBeLessThan(16);
    Object.defineProperty(list, "scrollTop", { configurable: true, value: 15 * 63 });
    fireEvent.scroll(list);
    expect(container.textContent).toContain("R16");
    expect(screen.getAllByRole("listitem").length).toBeLessThan(16);
  });

  it("routes capture controls to runtime callbacks", async () => {
    const user = userEvent.setup();
    const toggle = vi.fn();
    const exportCapture = vi.fn();
    const checkpoint = vi.fn();
    const selection = vi.fn();
    render(<CaptureWorkspace project={projectWithRouter()} selections={[]}
      onSelection={selection} onToggle={toggle}
      onExport={exportCapture} onCheckpoint={checkpoint} />);

    await user.click(screen.getByRole("button", { name: "Start capture" }));
    await user.click(screen.getByRole("button", { name: "Export PCAPNG" }));
    await user.click(screen.getByRole("button", { name: "Export checkpoint" }));
    await user.click(screen.getByRole("button", { name: /CPM punt/ }));
    expect(toggle).toHaveBeenCalledOnce();
    expect(exportCapture).toHaveBeenCalledOnce();
    expect(checkpoint).toHaveBeenCalledOnce();
    expect(selection).toHaveBeenCalledWith("cpm-punt", "r1", "", 0, true);
  });

  it("creates an empty route draft without inventing network values", async () => {
    const user = userEvent.setup();
    const observed = vi.fn();
    render(<ConfigHarness initial={projectWithRouter().routers[0]}
      observed={observed} />);

    await user.click(screen.getByRole("button", { name: "Add route" }));
    expect(observed).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Apply" }));
    const latest = observed.mock.calls.at(-1)?.[0] as RouterProjectV3;
    expect(latest.running.staticRoutes.at(-1)).toEqual({ prefix: "", nextHop: "" });
  });

  it("keeps notes and project settings in format 3 intent", async () => {
    const user = userEvent.setup();
    const notes = vi.fn();
    const project = projectWithRouter();
    const { unmount } = render(<NotesWorkspace value="" onChange={notes} />);
    await user.type(screen.getByPlaceholderText(
      "Document addressing, test intent and expected results."), "ARP");
    expect(notes).toHaveBeenLastCalledWith("P");
    unmount();

    const changed = vi.fn();
    render(<SettingsWorkspace project={project} onChange={changed}
      onResetLayout={vi.fn()} />);
    await user.clear(screen.getByDisplayValue(project.name));
    await user.type(screen.getByRole("textbox"), "Backbone");
    expect(changed).toHaveBeenCalled();
  });

  it("opens checkpoint import through the owned binary input", async () => {
    const user = userEvent.setup();
    const input = createRef<HTMLInputElement>();
    render(<SnapshotWorkspace checkpointInput={input} onExport={vi.fn()}
      onImport={vi.fn()} />);
    const click = vi.spyOn(input.current!, "click");
    await user.click(screen.getByRole("button", { name: "Import checkpoint" }));
    expect(click).toHaveBeenCalledOnce();
  });
});
