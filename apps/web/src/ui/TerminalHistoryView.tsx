// Virtualized reader for the complete disk-backed terminal transcript.
// React receives only the visible slice; OPFS remains the history owner.

import { useCallback, useEffect, useRef, useState } from "react";
import { TerminalHistoryArchive, type TerminalHistorySnapshot } from "./terminal-history";

interface Props {
  archive: TerminalHistoryArchive;
  fontSize: number;
  close(): void;
}

const OVERSCAN_ROWS = 12;
const MAX_SCROLL_TRACK_PX = 4_000_000;

export function TerminalHistoryView({ archive, fontSize, close }: Props) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const requestGeneration = useRef(0);
  const [snapshot, setSnapshot] = useState<TerminalHistorySnapshot>();
  const [lines, setLines] = useState<string[]>([]);
  const [firstLine, setFirstLine] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);
  const lineHeight = Math.ceil(fontSize * 1.35);
  const visibleRows = Math.max(1, Math.ceil(viewportHeight / lineHeight));
  const totalLines = snapshot?.totalLines ?? 0;
  const logicalMaximum = Math.max(0, totalLines - visibleRows);
  // Browser scroll coordinates have implementation limits. A fixed maximum
  // track maps an arbitrarily long transcript to a stable scrollbar while
  // wheel handling below still moves by exact logical rows.
  const trackHeight = Math.max(viewportHeight,
    Math.min(MAX_SCROLL_TRACK_PX, totalLines * lineHeight));
  const physicalMaximum = Math.max(0, trackHeight - viewportHeight);

  const lineFromScroll = useCallback((scrollTop: number) => physicalMaximum && logicalMaximum
    ? Math.round((scrollTop / physicalMaximum) * logicalMaximum) : 0,
  [logicalMaximum, physicalMaximum]);

  const scrollFromLine = useCallback((line: number) => logicalMaximum && physicalMaximum
    ? (line / logicalMaximum) * physicalMaximum : 0,
  [logicalMaximum, physicalMaximum]);

  useEffect(() => {
    let cancelled = false;
    void archive.snapshot().then((value) => {
      if (cancelled) return;
      setSnapshot(value);
      setFirstLine(Math.max(0, value.totalLines - visibleRows));
      requestAnimationFrame(() => {
        const viewport = viewportRef.current;
        if (viewport) viewport.scrollTop = viewport.scrollHeight;
      });
    }).catch((cause) => console.error("Terminal history could not be opened", cause));
    return () => { cancelled = true; };
  }, [archive, visibleRows]);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const resize = new ResizeObserver(([entry]) => {
      // One scalar update per panel resize is sufficient. Transcript text does
      // not participate in measurement, so old lines cannot trigger reflow.
      setViewportHeight(entry.contentRect.height);
    });
    resize.observe(viewport);
    return () => resize.disconnect();
  }, []);

  useEffect(() => {
    if (!snapshot) return;
    const generation = ++requestGeneration.current;
    const start = Math.max(0, firstLine - OVERSCAN_ROWS);
    const count = visibleRows + OVERSCAN_ROWS * 2;
    void archive.readRange(snapshot, start, count).then((value) => {
      // A slow OPFS read must not replace a newer viewport after rapid wheel or
      // scrollbar movement. The generation check makes the latest read owner.
      if (generation === requestGeneration.current) setLines(value);
    }).catch((cause) => console.error("Terminal history range could not be read", cause));
  }, [archive, firstLine, snapshot, visibleRows]);

  const start = Math.max(0, firstLine - OVERSCAN_ROWS);
  const physicalTop = scrollFromLine(start);

  return <div className="terminal-history">
    <div className="terminal-history-bar">
      <span>{totalLines.toLocaleString()} lines</span>
      <button onClick={close}>Live console</button>
    </div>
    <div className="terminal-history-viewport" ref={viewportRef}
      onScroll={(event) => setFirstLine(lineFromScroll(event.currentTarget.scrollTop))}
      onWheel={(event) => {
        // When the physical track is compressed, native pixel scrolling can
        // skip thousands of logical rows. Map wheel input to exact row steps.
        if (totalLines * lineHeight <= MAX_SCROLL_TRACK_PX) return;
        event.preventDefault();
        const next = Math.max(0, Math.min(logicalMaximum,
          firstLine + Math.sign(event.deltaY) * Math.max(1, Math.round(Math.abs(event.deltaY) / lineHeight))));
        event.currentTarget.scrollTop = scrollFromLine(next);
        setFirstLine(next);
      }}>
      <div className="terminal-history-track" style={{ height: trackHeight }} />
      <pre className="terminal-history-lines" style={{
        fontSize, lineHeight: `${lineHeight}px`, transform: `translateY(${physicalTop}px)`
      }}>{lines.join("\n")}</pre>
    </div>
  </div>;
}
