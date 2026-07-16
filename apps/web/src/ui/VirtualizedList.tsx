// Fixed-row virtualization for bounded operational collections. This module
// owns only scroll geometry. Callers own item identity and rendered content,
// and no runtime or network state is inferred from viewport position.

import { useLayoutEffect, useMemo, useRef, useState, type ReactNode,
  type UIEvent } from "react";

interface Props<T> {
  items: readonly T[];
  itemHeight: number;
  overscan?: number;
  className?: string;
  itemKey(item: T): string;
  renderItem(item: T): ReactNode;
}

export function VirtualizedList<T>({ items, itemHeight, overscan = 3,
  className, itemKey, renderItem }: Props<T>) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  // A nonzero first-render estimate avoids mounting the complete collection
  // before ResizeObserver reports. The observer replaces it with the exact
  // client box and never feeds geometry back into project or runtime state.
  const [viewportHeight, setViewportHeight] = useState(itemHeight * 8);

  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const measure = () => setViewportHeight(Math.max(itemHeight,
      viewport.clientHeight || itemHeight));
    measure();
    // ResizeObserver follows user-resized terminal and inspector tracks. The
    // fallback still provides a correct initial window in older test DOMs.
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(viewport);
    return () => observer.disconnect();
  }, [itemHeight]);

  const window = useMemo(() => {
    // Integer division maps scroll coordinates to stable item identities.
    // Overscan absorbs quick wheel movement without increasing DOM size with
    // collection length, which is the property required by the 32-node lab.
    const first = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const visible = Math.ceil(viewportHeight / itemHeight) + overscan * 2;
    const last = Math.min(items.length, first + visible);
    return { first, values: items.slice(first, last) };
  }, [itemHeight, items, overscan, scrollTop, viewportHeight]);

  const onScroll = (event: UIEvent<HTMLDivElement>) => {
    // Scroll is the sole high-frequency input. React receives one scalar and
    // renders only when the visible item window crosses a row boundary.
    const next = event.currentTarget.scrollTop;
    if (Math.floor(next / itemHeight) !== Math.floor(scrollTop / itemHeight))
      setScrollTop(next);
  };

  return <div className={className} role="list" ref={viewportRef}
    onScroll={onScroll}>
    <div className="virtual-list-track" style={{ height: items.length * itemHeight }}>
      {window.values.map((item, offset) => <div role="listitem"
        className="virtual-list-row" key={itemKey(item)} style={{
          height: itemHeight,
          transform: `translateY(${(window.first + offset) * itemHeight}px)`
        }}>{renderItem(item)}</div>)}
    </div>
  </div>;
}
