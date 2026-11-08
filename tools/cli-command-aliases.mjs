// Release grammar owns aliases; execution owners receive one stable handler ID.
// This validator reads caller-owned rows and has no publication or file access.
export function commandHandlers(commands) {
  const rows = new Map(commands.map((command) => [command.id, command]));
  const handlers = new Map();
  const operator = (row) => row.tokens.flatMap((token) =>
    typeof token === "string" ? [token] : typeof token.literal === "string" ? [token.literal] : [])
    .filter((token) => token === "delete" || token === "no").join(" ");
  for (const row of commands) {
    const target = row.handler_id === undefined ? row : rows.get(row.handler_id);
    if (!target || (row.handler_id !== undefined && target.id === row.id) ||
        target.handler_id !== undefined || target.source_id !== row.source_id ||
        row.engines.some((engine) => !target.engines.includes(engine)) ||
        Boolean(target.enters_context) !== Boolean(row.enters_context) || operator(target) !== operator(row))
      throw new Error(`${row.id}: invalid, chained or semantically mismatched CLI alias`);
    handlers.set(row.id, target.id);
  }
  return handlers;
}
