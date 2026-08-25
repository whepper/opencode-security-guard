/**
 * Minimal JSONC (JSON with comments) support.
 *
 * Zero dependencies by design. Handles:
 *   - line comments        //
 *   - block comments
 *   - trailing commas      [1, 2, 3,] / {"a":1,}
 *
 * String literals are respected ("//" inside a string is never stripped).
 * This intentionally covers only what this repository's files use.
 */

/** Strip // and block comments, respecting string literals. */
function stripComments(text) {
  let out = ""
  let i = 0
  const n = text.length
  while (i < n) {
    const ch = text[i]
    if (ch === '"') {
      const end = readStringEnd(text, i)
      out += text.slice(i, end)
      i = end
      continue
    }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < n && text[i] !== "\n") i++
      continue
    }
    if (ch === "/" && text[i + 1] === "*") {
      i += 2
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i++
      i += 2
      out += " "
      continue
    }
    out += ch
    i++
  }
  return out
}

/** Returns index just past the closing quote of the string starting at `start`. */
function readStringEnd(text, start) {
  let i = start + 1
  while (i < text.length) {
    const c = text[i]
    if (c === "\\") {
      i += 2
      continue
    }
    if (c === '"') return i + 1
    i++
  }
  throw new SyntaxError("Unterminated string literal in JSONC")
}

/** Remove commas that are immediately followed by a closing brace/bracket. */
function stripTrailingCommas(text) {
  let out = ""
  let i = 0
  const n = text.length
  while (i < n) {
    const ch = text[i]
    if (ch === '"') {
      const end = readStringEnd(text, i)
      out += text.slice(i, end)
      i = end
      continue
    }
    if (ch === ",") {
      let j = i + 1
      while (j < n && /\s/.test(text[j])) j++
      if (text[j] === "}" || text[j] === "]") {
        i++ // drop the comma
        continue
      }
    }
    out += ch
    i++
  }
  return out
}

export function stripJsonc(text) {
  return stripTrailingCommas(stripComments(text))
}

export function parseJsonc(text) {
  return JSON.parse(stripJsonc(text))
}
