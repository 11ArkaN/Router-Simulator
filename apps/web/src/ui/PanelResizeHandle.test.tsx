// Interaction contract for the shared panel boundary. Tests cover pointer
// direction, keyboard accessibility, generated bounds and default restoration
// without coupling to App or a particular panel's CSS position.

// @vitest-environment jsdom

import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PanelResizeHandle } from "./PanelResizeHandle";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("panel resize handle", () => {
  it("coalesces pointer movement and applies boundary direction", () => {
    let frame: FrameRequestCallback | undefined;
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
      frame = callback;
      return 7;
    });
    vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => {});
    const onChange = vi.fn();
    const { getByRole } = render(<PanelResizeHandle axis="x" className="test"
      defaultValue={200} direction={-1} label="Resize inspector" min={100}
      max={300} value={200} onChange={onChange} />);
    const handle = getByRole("separator", { name: "Resize inspector" });

    // Moving an inspector's left boundary 40 px left increases its width. A
    // second move before paint replaces the first pending value.
    fireEvent.pointerDown(handle, { pointerId: 1, clientX: 500 });
    fireEvent.pointerMove(handle, { pointerId: 1, clientX: 480 });
    fireEvent.pointerMove(handle, { pointerId: 1, clientX: 460 });
    expect(onChange).not.toHaveBeenCalled();
    frame?.(0);
    expect(onChange).toHaveBeenCalledOnce();
    expect(onChange).toHaveBeenLastCalledWith(240);
  });

  it("supports arrow bounds and double-click reset", () => {
    const onChange = vi.fn();
    const { getByRole } = render(<PanelResizeHandle axis="y" className="test"
      defaultValue={240} direction={-1} label="Resize console" min={120}
      max={300} value={296} onChange={onChange} />);
    const handle = getByRole("separator", { name: "Resize console" });

    fireEvent.keyDown(handle, { key: "ArrowUp" });
    fireEvent.keyDown(handle, { key: "Home" });
    fireEvent.doubleClick(handle);
    expect(onChange.mock.calls.map(([next]) => next)).toEqual([300, 120, 240]);
  });
});
