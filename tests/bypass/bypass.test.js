/**
 * Data-driven adversarial regression runner.
 *
 * Executes every case in cases.jsonc against the pure decision engine and
 * asserts the expected outcome ("block" | "ask" | null). This is the
 * automated half of the bypass suite; native-layer expectations that need a
 * live OpenCode session are documented as a manual checklist in
 * docs/installation.md (verified during release testing, recorded in
 * docs/verification-log.md).
 */
import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import path from "node:path"
import { parseJsonc } from "../../scripts/jsonc.mjs"
import { decideToolCall, decideMcpCall, GENERATED_GUARD_POLICY } from "../../plugin/security-guard.js"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")
const { cases } = parseJsonc(readFileSync(path.join(ROOT, "tests/bypass/cases.jsonc"), "utf8"))
const P = JSON.parse(JSON.stringify(GENERATED_GUARD_POLICY))

// The engine must have an opinion for every case; null means "stay silent".
for (const c of cases) {
  test(`bypass corpus ${c.id} (${c.category})`, () => {
    const norm = decideToolCall(P, {
      kind:
        c.tool === "bash" || typeof c.input.command === "string"
          ? "shell"
          : c.tool === "grep"
            ? "grep"
            : c.tool === "glob"
              ? "glob"
              : c.tool === "read" || c.input.filePath || c.input.path
                ? "path"
                : "other",
      command: c.input.command,
      pattern: c.input.pattern,
      path: c.input.path ?? c.input.filePath,
      content: c.input.content,
      mode: c.input.filePath || c.input.path ? (c.tool === "read" ? "read" : "write") : undefined,
    })
    const verdict = norm ? norm.decision : null
    const want = c.expect // "block" | "ask" | null
    assert.equal(
      verdict,
      want,
      `${c.id}: expected ${JSON.stringify(want)} for [${c.input.command ?? c.input.pattern ?? c.input.filePath}] got ${JSON.stringify(verdict)} ${norm ? `(${norm.ruleId})` : ""}`
    )
    if (c.expectRule && norm) {
      assert.ok(
        String(norm.ruleId).startsWith(c.expectRule),
        `${c.id}: expected rule prefix ${c.expectRule}, got ${norm.ruleId}`
      )
    }
    if (c.expectPathRule && norm) {
      assert.ok(
        String(norm.pathRule ?? "").startsWith(c.expectPathRule),
        `${c.id}: expected path-rule prefix ${c.expectPathRule}, got ${norm.pathRule}`
      )
    }
  })
}

test("corpus sanity: every case has an id/category/expect and ids are unique", () => {
  const seen = new Set()
  for (const c of cases) {
    assert.ok(c.id && !seen.has(c.id), `duplicate id ${c.id}`)
    seen.add(c.id)
    assert.ok(c.category)
    assert.ok(["block", "ask", null].includes(c.expect), `bad expect on ${c.id}`)
  }
})

test("corpus balance: positives and negatives both present", () => {
  assert.ok(cases.some((c) => c.expect === "block"))
  assert.ok(cases.some((c) => c.expect === "ask"))
  assert.ok(cases.filter((c) => c.expect === null).length >= 10, "need a real negative set")
})

// ---------------------------------------------------------------------------
// MCP corpus (tests/bypass/mcp-cases.jsonc) — same runner contract, driven
// through decideMcpCall with the synthetic server inventory declared in the
// corpus file. parseJsonc / decideMcpCall / GENERATED_GUARD_POLICY come from
// the existing top-level imports.
// ---------------------------------------------------------------------------
const mcpCorpus = parseJsonc(readFileSync(path.join(ROOT, "tests/bypass/mcp-cases.jsonc"), "utf8"))
const PM = JSON.parse(JSON.stringify(GENERATED_GUARD_POLICY))
PM.mcp.servers = mcpCorpus.serverTrust
for (const t of mcpCorpus.tools ?? []) (PM.mcp.tools ??= []).push(t)
const MCP_KNOWN = mcpCorpus.knownServers

for (const c of mcpCorpus.cases) {
  test(`mcp corpus ${c.id} (${c.category})`, () => {
    const v = decideMcpCall(PM, c.tool, c.input ?? {}, MCP_KNOWN)
    const verdict = v ? v.decision : null
    assert.equal(
      verdict,
      c.expect,
      `${c.id}: expected ${JSON.stringify(c.expect)} for [${c.tool}] got ${JSON.stringify(verdict)} ${v ? `(${v.ruleId})` : ""}`
    )
    if ((c.expect === "block" || c.expect === "ask") && v) {
      assert.ok(v.ruleId, `${c.id}: verdict must carry a rule ID`)
      assert.ok(!JSON.stringify(v).includes("FAKE-NOT-A-REAL-SECRET"), `${c.id}: diagnostics must not echo argument values`)
    }
  })
}

test("mcp corpus sanity: unique ids, required categories present", () => {
  const seen = new Set()
  for (const c of mcpCorpus.cases) {
    assert.ok(c.id && !seen.has(c.id), `duplicate id ${c.id}`)
    seen.add(c.id)
  }
  for (const cat of ["local-secret-access", "external-write", "chaining", "prompt-injection", "legitimate"]) {
    assert.ok(mcpCorpus.cases.some((c) => c.category === cat), `missing category ${cat}`)
  }
})
