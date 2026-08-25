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

test("inventory-independent fallback: underscored non-native actions are MCP-ish", () => {
  // Regression: with an EMPTY trust map and failed mcp.list() discovery,
  // unlisted MCP tools must still be classified (v0.2 live-demo finding).
  const Pempty = JSON.parse(JSON.stringify(P))
  assert.equal(isMcpAction(Pempty, "dummy_get_note", []), true)
  assert.equal(isMcpAction(Pempty, "web_search_prime", []), true)
  for (const native of ["bash", "read", "grep", "webfetch", "external_directory", "execute"]) {
    assert.equal(isMcpAction(Pempty, native, []), false, `${native} must stay native`)
  }
  // And the full decision path enforces the unlisted-server ask:
  const v = decideMcpCall(Pempty, "dummy_get_note", {}, [])
  assert.equal(v?.decision, "ask")
})

test("diagnostics include server/tool context and never values", () => {
  const v = decideMcpCall(P2, "dummy_read_file", { file: ".env" }, KNOWN)
  const msg = formatVerdict(v)
  assert.ok(msg.includes("dummy/read_file"))
  assert.ok(!msg.includes("FAKE"))
})

// ---------------------------------------------------------------------------
// Provenance experiment (opt-in; policy.mcp.provenance.enabled)
// ---------------------------------------------------------------------------

import { createProvenanceStore, provenanceScan } from "../../plugin/security-guard.js"

test("provenance store: marked results are detected in later arguments", () => {
  const store = createProvenanceStore()
  const content = "DUMMY_TOKEN=FAKE-NOT-A-REAL-SECRET-abc123 and some padding text to pass the minimum length check"
  assert.equal(store.markSensitive(content), "PROV-001")
  const hit = provenanceScan(store, { text: `here is what I read: ${content}` })
  assert.equal(hit?.decision, "block")
  assert.equal(hit.ruleId, "MCP-PROV-001")
})

test("provenance store: short/absent markers do not trip", () => {
  const store = createProvenanceStore()
  store.markSensitive("short")
  assert.equal(provenanceScan(store, { text: "short" }), null) // below minSnippet
  assert.equal(provenanceScan(store, {}), null)
  assert.equal(provenanceScan(null, { a: "x" }), null) // disabled store
})

test("provenance store: FIFO cap bounds memory", () => {
  const store = createProvenanceStore({ maxEntries: 3 })
  for (let i = 0; i < 5; i++) {
    store.markSensitive(`marker number ${i} with enough padding to satisfy the minimum length requirement`)
  }
  assert.equal(store.size(), 3)
})

test("provenance honesty: re-encoded or paraphrased relay evades detection", () => {
  const store = createProvenanceStore()
  const original = "secret-value-payload-with-enough-length-to-be-marked-as-sensitive-content"
  store.markSensitive(original)
  assert.equal(provenanceScan(store, { text: Buffer.from("unrelated").toString("base64") }), null)
  assert.equal(provenanceScan(store, { text: "a paraphrase that shares no literal substring with the original" }), null)
})
