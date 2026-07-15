// Accessible resize boundary shared by the three major workspace panels.
// The parent owns persisted dimensions; this component owns only one active
// pointer gesture and a single animation-frame update slot. Dependencies flow
// outward through onChange, so the handle never reads project or runtime state.

import { useEffect, useRef, type KeyboardEvent, type PointerEvent } from "react";

interface Props {
  axis: "x" | "y";
  className: string;
  defaultValue: number;
  direction: 1 | -1;
  label: string;
  max: number;
  min: number;
  value: number;
  onChange(value: number): void;
}

interface DragState {
  pointerId: number;
  startCoordinate: number;
  startValue: number;
}

function clamp(value: number, min: number, max: number): number {
  // Bounds originate in the generated profile and protect both imported files
  // and live pointer input. Rounding avoids persisting fractional CSS pixels,
  // which otherwise accumulate when a project moves between display scales.
  return Math.min(max, Math.max(min, Math.round(value)));
}

export function PanelResizeHandle({ axis, className, defaultValue, direction,
  label, max, min, value, onChange }: Props) {
  const dragRef = useRef<DragState | undefined>(undefined);
  const frameRef = useRef<number | undefined>(undefined);
  const pendingRef = useRef<number | undefined>(undefined);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  const commitPending = () => {
    // At most one React project update is emitted per paint. Pointer devices
    // can report hundreds of moves per second, while topology and xterm only
    // need the newest panel boundary before the next frame is rendered.
    frameRef.current = undefined;
    if (pendingRef.current === undefined) return;
    const next = pendingRef.current;
    pendingRef.current = undefined;
    onChangeRef.current(next);
  };

  const schedule = (next: number) => {
    pendingRef.current = clamp(next, min, max);
    if (frameRef.current === undefined) {
      frameRef.current = window.requestAnimationFrame(commitPending);
    }
  };

  const flush = () => {
    // Pointer-up must persist the last coordinate even when it lands between
    // animation frames. Cancelling the queued callback also prevents a stale
    // value from being emitted after a new gesture begins.
    if (frameRef.current !== undefined) {
      window.cancelAnimationFrame(frameRef.current);
      frameRef.current = undefined;
    }
    commitPending();
  };

  useEffect(() => () => {
    // Unmounting a collapsed panel invalidates its pending visual update. The
    // latest committed project value remains owned by App and is not changed
    // during cleanup.
    if (frameRef.current !== undefined) window.cancelAnimationFrame(frameRef.current);
  }, []);

  const coordinate = (event: PointerEvent<HTMLDivElement>) =>
    axis === "x" ? event.clientX : event.clientY;

  const renderedSize = (element: HTMLDivElement): number => {
    const bounds = element.parentElement?.getBoundingClientRect();
    const measured = bounds ? (axis === "x" ? bounds.width : bounds.height) : 0;
    // Detached DOM tests and the brief pre-layout mount report a zero box. In
    // that case the validated project preference is the only meaningful base.
    return measured > 0 ? measured : value;
  };

  const begin = (event: PointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    dragRef.current = {
      pointerId: event.pointerId,
      startCoordinate: coordinate(event),
      // A preferred project value can be larger than the current viewport.
      // Starting from the rendered boundary makes the first pointer pixel take
      // effect immediately instead of traversing an invisible clipped range.
      startValue: renderedSize(event.currentTarget)
    };
    // Pointer capture keeps resizing continuous when the pointer moves across
    // React Flow, xterm or outside the thin visual handle. The optional call
    // keeps the same component testable in DOM implementations without capture.
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const move = (event: PointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    schedule(drag.startValue + direction * (coordinate(event) - drag.startCoordinate));
  };

  const end = (event: PointerEvent<HTMLDivElement>) => {
    if (dragRef.current?.pointerId !== event.pointerId) return;
    dragRef.current = undefined;
    flush();
    if (event.currentTarget.hasPointerCapture?.(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  const keyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    // Arrow meaning follows the visible boundary. Shift provides coarse 20 px
    // changes, while the normal 8 px step is precise enough for keyboard use.
    const increase = axis === "x" ? (direction === 1 ? "ArrowRight" : "ArrowLeft") :
      (direction === 1 ? "ArrowDown" : "ArrowUp");
    const decrease = axis === "x" ? (direction === 1 ? "ArrowLeft" : "ArrowRight") :
      (direction === 1 ? "ArrowUp" : "ArrowDown");
    const renderedValue = renderedSize(event.currentTarget);
    let next: number | undefined;
    if (event.key === increase) next = renderedValue + (event.shiftKey ? 20 : 8);
    else if (event.key === decrease) next = renderedValue - (event.shiftKey ? 20 : 8);
    else if (event.key === "Home") next = min;
    else if (event.key === "End") next = max;
    if (next === undefined) return;
    event.preventDefault();
    onChangeRef.current(clamp(next, min, max));
  };

  // A generic separator avoids every native button surface. This matters in a
  // dark canvas because a browser's unstyled button can flash white between
  // React insertion and stylesheet application. tabIndex and the handlers
  // retain the full keyboard contract without relying on button appearance.
  return <div role="separator" tabIndex={0}
    className={`panel-resizer ${className}`}
    aria-label={label} aria-orientation={axis === "x" ? "vertical" : "horizontal"}
    aria-valuemin={min} aria-valuemax={max} aria-valuenow={value}
    aria-valuetext={`${value} pixels`}
    title="Drag to resize. Double-click to reset."
    onPointerDown={begin} onPointerMove={move} onPointerUp={end} onPointerCancel={end}
    onKeyDown={keyDown} onDoubleClick={() => onChangeRef.current(defaultValue)} />;
}
