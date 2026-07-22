// Browser-only terminal renderer state. This is not a project or runtime file
// format. It exists solely to detach xterm objects when the established panel
// closes and is validated again before restoration.

export type TerminalHistoryRegion = "md-operational" | "md-configuration" | "classic";
export interface TerminalLineEditorState {
  buffer: string; cursor: number; history: string[]; historyIndex: number;
}
export interface TerminalPagerState {
  output: string; rows: number; offset: number;
  // These fields are browser-owned interactive state. Optional encoding keeps
  // an idle pager compact while allowing a checkpoint in the middle of a
  // numeric prefix or search expression to resume without losing keystrokes.
  numericPrefix?: string;
  searchDirection?: "forward" | "backward";
  searchBuffer?: string;
  lastSearchPattern?: string;
  lastSearchDirection?: "forward" | "backward";
  matchLine?: number;
  searchHighlightVisible?: boolean;
  helpVisible?: boolean;
}
export interface TerminalPanelPresentation {
  editors: Record<TerminalHistoryRegion, TerminalLineEditorState>;
  queuedInput: string[];
  pager?: TerminalPagerState;
}
export interface TerminalState {
  engine: "md" | "classic";
  historyRegion: TerminalHistoryRegion;
  banner: string;
  prompt: string;
}

export function parseTerminalPanelPresentation(input: unknown): TerminalPanelPresentation {
  if (!input || typeof input !== "object") throw new Error("Terminal presentation is invalid");
  const value = input as Partial<TerminalPanelPresentation>;
  const regions: TerminalHistoryRegion[] = ["md-operational", "md-configuration", "classic"];
  const validEditor = (editor: unknown): editor is TerminalLineEditorState => {
    if (!editor || typeof editor !== "object") return false;
    const state = editor as Partial<TerminalLineEditorState>;
    return typeof state.buffer === "string" && Number.isInteger(state.cursor) &&
      state.cursor! >= 0 && state.cursor! <= state.buffer.length &&
      Array.isArray(state.history) && state.history.length <= 50 &&
      state.history.every((line) => typeof line === "string") &&
      Number.isInteger(state.historyIndex) && state.historyIndex! >= 0 &&
      state.historyIndex! <= state.history.length;
  };
  if (!value.editors || regions.some((region) => !validEditor(value.editors?.[region])) ||
      !Array.isArray(value.queuedInput) ||
      value.queuedInput.some((chunk) => typeof chunk !== "string")) {
    throw new Error("Terminal presentation is invalid");
  }
  if (value.pager && (typeof value.pager.output !== "string" ||
      !Number.isInteger(value.pager.rows) || value.pager.rows < 2 ||
      !Number.isInteger(value.pager.offset) || value.pager.offset < 0 ||
      value.pager.offset > Math.max(0,
        value.pager.output.replaceAll("\r", "").split("\n").length -
        (value.pager.rows - 1)) ||
      (value.pager.numericPrefix !== undefined &&
       !/^\d{1,9}$/.test(value.pager.numericPrefix)) ||
      (value.pager.searchDirection !== undefined &&
       value.pager.searchDirection !== "forward" &&
       value.pager.searchDirection !== "backward") ||
      (value.pager.searchBuffer !== undefined &&
       typeof value.pager.searchBuffer !== "string") ||
      (value.pager.lastSearchPattern !== undefined &&
       typeof value.pager.lastSearchPattern !== "string") ||
      (value.pager.lastSearchDirection !== undefined &&
       value.pager.lastSearchDirection !== "forward" &&
       value.pager.lastSearchDirection !== "backward") ||
      (value.pager.matchLine !== undefined &&
       (!Number.isInteger(value.pager.matchLine) || value.pager.matchLine < 0 ||
        value.pager.matchLine >=
          value.pager.output.replaceAll("\r", "").split("\n").length)) ||
      (value.pager.helpVisible !== undefined &&
       typeof value.pager.helpVisible !== "boolean") ||
      (value.pager.searchHighlightVisible !== undefined &&
       typeof value.pager.searchHighlightVisible !== "boolean"))) {
    throw new Error("Terminal pager is invalid");
  }
  return structuredClone(value as TerminalPanelPresentation);
}
