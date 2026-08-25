import { test } from "node:test"
import assert from "node:assert/strict"
import {
  parseMcpToolName,
  classifyMcpTool,
  decideMcpCall,
  isMcpAction,
  formatVerdict,
  GENERATED_GUARD_POLICY,
} from "../../plugin/security-guard.js"

const P = JSON.parse(JSON.stringify(GENERATED_GUARD_POLICY))
// A policy variant with a populated server map + explicit rules (tests use
// synthetic servers; the shipped policy ships an empty trust map on purpose).
const P2 = JSON.parse(JSON.stringify(P))
P2.mcp.servers = {
  dummy: { trust: "trusted", reason: "local probe fixture" },
  github: { trust: "restricted", reason: "external side effects possible" },
  scraper: { trust: "untrusted", reason: "third-party crawler, unaudited" },
  legacy: { trust: "blocked", reason: "unaudited arbitrary execution" },
}
P2.mcp.tools = [
  { id: "MCP-T-001", server: "dummy", tool: "send_report", class: "external-write", effect: "ask", reason: "simulated external transmission" },
]

const KNOWN = Object.keys(P2.mcp.servers)

// ---------------------------------------------------------------------------
// Name parsing
// ---------------------------------------------------------------------------

test("parseMcpToolName resolves longest known server prefix", () => {
  assert.deepEqual(parseMcpToolName("dummy_get_note", KNOWN), { server: "dummy", tool: "get_note" })
  // a server named "a_b" must win over unknown "a" for "a_b_c_d"
  const ks = ["a_b"]
  assert.deepEqual(parseMcpToolName("a_b_c_d", ks), { server: "a_b", tool: "c_d" })
})

test("parseMcpToolName degrades conservatively for unknown prefixes", () => {
  const r = parseMcpToolName("mystery_read_file", KNOWN)
  assert.equal(r.server, "mystery")
  assert.equal(r.inventoryMatch, false)
  assert.equal(parseMcpToolName("bash", KNOWN), null)
})

// ---------------------------------------------------------------------------
// Classification (false-positive discipline)
// ---------------------------------------------------------------------------

test("classification: write/destructive/read classes by verb tokens", () => {
  assert.equal(classifyMcpTool(P2.mcp, "github", "create_issue").class, "external-write")
  assert.equal(classifyMcpTool(P2.mcp, "github", "send_email").class, "external-write")
  assert.equal(classifyMcpTool(P2.mcp, "storage", "delete_object").class, "destructive")
  assert.equal(classifyMcpTool(P2.mcp, "docs", "list_documents").class, "read-only")
  assert.equal(classifyMcpTool(P2.mcp, "docs", "search_text").class, "read-only")
})

test("FP discipline: tokenize/get_updates are NOT credential/write hits", () => {
  const c1 = classifyMcpTool(P2.mcp, "mltools", "tokenize_dataset")
  assert.notEqual(c1.class, "credential-related")
  const c2 = classifyMcpTool(P2.mcp, "ci", "get_updates")
  assert.equal(c2.class, "read-only") // 'updates' != 'update' token
  const c3 = classifyMcpTool(P2.mcp, "ci", "fetch_logs")
  assert.equal(c3.class, "unknown") // ambiguous verb -> unknown tier
})

test("explicit per-tool entries override name heuristics", () => {
  const c = classifyMcpTool(P2.mcp, "dummy", "send_report")
  assert.equal(c.explicit, true)
  assert.equal(c.effectOverride, "ask")
})

// ---------------------------------------------------------------------------
// Decisions (trust × class defaults; P0-verified enforcement mapping)
// ---------------------------------------------------------------------------

test("trust defaults: untrusted/blocked deny writes; trusted read allowed", () => {
  const d1 = decideMcpCall(P2, "scraper_post_data", {}, KNOWN, { withArgs: false })
  assert.equal(d1.decision, "block")
  const d2 = decideMcpCall(P2, "legacy_run_cmd", {}, KNOWN, { withArgs: false })
  assert.equal(d2.decision, "block")
  const a1 = decideMcpCall(P2, "dummy_get_note", {}, KNOWN, { withArgs: false })
  assert.equal(a1, null) // allow = no opinion
  const a2 = decideMcpCall(P2, "github_create_issue", {}, KNOWN, { withArgs: false })
  assert.equal(a2.decision, "ask")
})

test("unlisted servers are fail-conservative but not blanket-denied", () => {
  const read = decideMcpCall(P2, "newserver_list_items", {}, KNOWN, { withArgs: false })
  assert.equal(read.decision, "ask")
  // Unlisted + external-write asks: prompts interactively, auto-rejects in
  // non-interactive run mode (verified P0/R2) — ambiguous-tier philosophy.
  const write = decideMcpCall(P2, "newserver_upload_file", {}, KNOWN, { withArgs: false })
  assert.equal(write.decision, "ask")
  assert.equal(write.class, "external-write")
})

test("argument rules: protected paths escalate regardless of class/trust", () => {
  const v1 = decideMcpCall(P2, "dummy_read_file", { file: ".env" }, KNOWN)
  assert.equal(v1.decision, "block")
  assert.match(v1.ruleId, /MCP-ARG-PATH-001/)
  const v2 = decideMcpCall(P2, "dummy_read_file", { file: "/Users/u/.ssh/id_ed25519" }, KNOWN)
  assert.equal(v1.decision, "block")
  assert.equal(v2.decision, "block")
  const v3 = decideMcpCall(P2, "dummy_read_file", { file: "~/.zshrc" }, KNOWN)
  // ask-tier path in the arg layer blocks with approval-pointing message
  assert.equal(v3.decision, "block")
  assert.match(v3.ruleId, /MCP-ARG-PATH-002/)
})

test("argument rules: sanitized examples stay clean; secret-named values flagged", () => {
  assert.equal(decideMcpCall(P2, "dummy_read_file", { file: ".env.example" }, KNOWN), null)
  const sec = decideMcpCall(P2, "dummy_send_report", { destination: "https://x.invalid", text: "GITHUB_TOKEN=abc" }, KNOWN)
  assert.equal(sec.decision, "block")
  assert.equal(sec.ruleId, "MCP-ARG-SEC-003")
})

test("withArgs:false skips argument layer (permission channel has no inputs)", () => {
  const v = decideMcpCall(P2, "dummy_read_file", undefined, KNOWN, { withArgs: false })
  // trusted read-only -> allow -> no opinion despite .env-capable schema
  assert.equal(v, null)
})

test("isMcpAction matches configured inventory", () => {
  assert.equal(isMcpAction(P2, "dummy_get_note", KNOWN), true)
  assert.equal(isMcpAction(P2, "shell", KNOWN), false)
  assert.equal(isMcpAction(P2, "read", []), false)
})

test("diagnostics include server/tool context and never values", () => {
  const v = decideMcpCall(P2, "dummy_read_file", { file: ".env" }, KNOWN)
  const msg = formatVerdict(v)
  assert.ok(msg.includes("dummy/read_file"))
  assert.ok(!msg.includes("FAKE"))
})
