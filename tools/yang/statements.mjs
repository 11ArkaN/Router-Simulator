// RFC 7950 statement reader for offline source inventory. Each invocation owns
// its cursor and AST. It preserves extensions and source locations, depends on
// no repository state, and does not claim schema expansion or XPath validation.

const keywordPattern = /^[A-Za-z_][A-Za-z0-9_.-]*(?::[A-Za-z_][A-Za-z0-9_.-]*)?$/;

// Preconditions: source is a complete YANG text. Postcondition: every statement
// has an argument, child list and one-based source location. Invalid syntax or
// an unsupported escape throws SyntaxError before an AST is returned. The
// caller owns the result. This development-only API has no runtime shard.
export function parseStatements(source, sourceName = "<yang>") {
  const text = source.replace(/\r\n?/g, "\n");
  let offset = 0;
  let line = 1;
  let column = 1;
  const escapeErrors = [];
  const fail = (message, location = { line, column }) => {
    throw new SyntaxError(`${sourceName}:${location.line}:${location.column}: ${message}`);
  };
  const take = () => {
    const value = text[offset++];
    if (value === "\n") { line++; column = 1; }
    else column++;
    return value;
  };
  const starts = (value) => text.startsWith(value, offset);
  const skip = () => {
    while (offset < text.length) {
      if (/\s/u.test(text[offset])) { take(); continue; }
      if (starts("//")) {
        while (offset < text.length && take() !== "\n") { /* comment */ }
      } else if (starts("/*")) {
        const start = { line, column };
        take(); take();
        while (offset < text.length && !starts("*/")) take();
        if (offset === text.length) fail("Unterminated comment", start);
        take(); take();
      } else break;
    }
  };
  const bare = () => {
    const begin = offset;
    while (offset < text.length && !/[\s;{}'"]/u.test(text[offset]) &&
      !starts("//") && !starts("/*") && !starts("*/")) take();
    if (begin === offset) fail("Expected an unquoted string");
    return text.slice(begin, offset);
  };
  const quoted = () => {
    const start = { line, column };
    const quote = take();
    let raw = "";
    let closed = false;
    while (offset < text.length) {
      const value = take();
      if (value === quote) { closed = true; break; }
      raw += value;
      if (quote === '"' && value === "\\") {
        if (offset === text.length) break;
        const escaped = take();
        raw += escaped;
        if (!['n', 't', '"', '\\'].includes(escaped))
          escapeErrors.push({ ...start, escaped });
      }
    }
    if (!closed) fail("Unterminated quoted string", start);
    if (quote === "'") return raw;
    // RFC 7950 6.1.3: physical whitespace is stripped before escapes are
    // substituted. Only a tab examined by the indentation strip becomes eight
    // spaces; a later tab must remain a tab in the resulting argument.
    const parts = raw.replace(/[ \t]+\n/g, "\n").split("\n");
    for (let i = 1; i < parts.length; i++) {
      let remaining = start.column;
      let cursor = 0;
      while (remaining > 0 && /[ \t]/.test(parts[i][cursor] ?? "")) {
        remaining -= parts[i][cursor++] === "\t" ? 8 : 1;
      }
      parts[i] = " ".repeat(Math.max(0, -remaining)) + parts[i].slice(cursor);
    }
    return parts.join("\n").replace(/\\([\s\S])/g, (match, value) =>
      ({ n: "\n", t: "\t", '"': '"', "\\": "\\" })[value] ?? match);
  };
  const argument = () => {
    if (!['"', "'"].includes(text[offset])) return bare();
    let result = quoted();
    skip();
    while (text[offset] === "+") {
      take(); skip();
      if (!['"', "'"].includes(text[offset])) fail("Concatenation requires a quoted string");
      result += quoted();
      skip();
    }
    return result;
  };
  const statements = (nested = false) => {
    const result = [];
    while (true) {
      skip();
      if (offset === text.length) {
        if (nested) fail("Unterminated statement block");
        return result;
      }
      if (text[offset] === "}") {
        if (!nested) fail("Unexpected closing brace");
        take();
        return result;
      }
      const location = { line, column };
      const keyword = bare();
      if (!keywordPattern.test(keyword)) fail(`Invalid keyword ${keyword}`, location);
      const keywordEnd = offset;
      skip();
      if (![";", "{"].includes(text[offset]) && offset === keywordEnd)
        fail("Expected whitespace or a comment before argument", location);
      const value = [";", "{"].includes(text[offset]) ? null : argument();
      skip();
      const delimiter = take();
      if (![";", "{"].includes(delimiter)) fail("Expected semicolon or statement block", location);
      result.push({ keyword, argument: value, ...location,
        children: delimiter === "{" ? statements(true) : [] });
    }
  };
  const roots = statements();
  if (roots.length !== 1 || !["module", "submodule"].includes(roots[0].keyword))
    fail("Expected one module or submodule", { line: 1, column: 1 });
  const version = roots[0].children.find((node) => node.keyword === "yang-version")?.argument ?? "1";
  if (!["1", "1.1"].includes(version)) fail(`Unsupported YANG version ${version}`);
  if (version === "1.1" && escapeErrors.length)
    fail(`Invalid double-quoted escape \\${escapeErrors[0].escaped}`, escapeErrors[0]);
  return roots[0];
}
