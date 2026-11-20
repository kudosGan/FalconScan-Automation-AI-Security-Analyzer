export type JsonLines = { lines: string[]; index: Map<string, number> };

/** Pretty-print JSON (2-space indent) while remembering which line each key path starts on. */
export function jsonLines(value: unknown): JsonLines {
  const lines: string[] = [];
  const index = new Map<string, number>();
  const push = (text: string, path: string[]) => {
    if (path.length) index.set(JSON.stringify(path), lines.length);
    lines.push(text);
  };

  const emit = (v: unknown, path: string[], indent: number, prefix: string, comma: string) => {
    const pad = "  ".repeat(indent);
    if (Array.isArray(v)) {
      if (v.length === 0) return push(`${pad}${prefix}[]${comma}`, path);
      push(`${pad}${prefix}[`, path);
      v.forEach((x, i) => emit(x, [...path, String(i)], indent + 1, "", i < v.length - 1 ? "," : ""));
      lines.push(`${pad}]${comma}`);
    } else if (v !== null && typeof v === "object") {
      const entries = Object.entries(v as Record<string, unknown>);
      if (entries.length === 0) return push(`${pad}${prefix}{}${comma}`, path);
      push(`${pad}${prefix}{`, path);
      entries.forEach(([k, x], i) =>
        emit(x, [...path, k], indent + 1, `${JSON.stringify(k)}: `, i < entries.length - 1 ? "," : ""));
      lines.push(`${pad}}${comma}`);
    } else {
      push(`${pad}${prefix}${JSON.stringify(v)}${comma}`, path);
    }
  };

  emit(value, [], 0, "", "");
  return { lines, index };
}

/** Line for a key path; falls back to the nearest parent, then the "type" line, then line 0. */
export function lineFor(index: Map<string, number>, path: string[] | undefined): number {
  const p = path ?? [];
  for (let n = p.length; n > 0; n--) {
    const hit = index.get(JSON.stringify(p.slice(0, n)));
    if (hit !== undefined) return hit;
  }
  return index.get(JSON.stringify(["type"])) ?? 0;
}
