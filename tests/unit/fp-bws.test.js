/**
 * False-positive regression: BWS-style multi-dot identifiers like
 * discvault.backup.b2.key should NOT be flagged as .key private-key files.
 * Real single- and double-dot .key filenames MUST still be blocked.
 */
import { test } from "node:test"
import assert from "node:assert/strict"
import {
  classifyPath,
  mcpArgumentVerdicts,
  GENERATED_GUARD_POLICY,
} from "../../plugin/security-guard.js"

const P = JSON.parse(JSON.stringify(GENERATED_GUARD_POLICY))

test("BWS multi-dot identifier (3+ dots) is NOT classified as protected", () => {
  const cls = classifyPath(P, "discvault.backup.b2.key")
  assert.equal(cls.tier, "pass", "BWS secret name discvault.backup.b2.key should pass")
})

test("real single-dot .key filename IS still protected", () => {
  const cls = classifyPath(P, "server.key")
  assert.equal(cls.tier, "deny", "server.key should be denied")
  assert.equal(cls.ruleId, "GG-KEY-002")
})

test("real two-dot .key filename IS still protected", () => {
  const cls = classifyPath(P, "my.backup.key")
  assert.equal(cls.tier, "deny", "my.backup.key (2 dots) should be denied")
  assert.equal(cls.ruleId, "GG-KEY-002")
})

test("path with slashes + .key suffix IS still protected regardless of dot count", () => {
  const cls = classifyPath(P, "/etc/ssl/private/server.key")
  assert.equal(cls.tier, "deny", "/etc/ssl/private/server.key should be denied")
  assert.equal(cls.ruleId, "GG-KEY-002")
})

test("MCP argument with BWS name embedded in content should NOT block", () => {
  const verdicts = mcpArgumentVerdicts(P, { text: "discvault.backup.b2.key is the BWS secret name" }, [])
  // Should have no verdicts (empty array) or none that block
  const blocks = verdicts.filter(v => v.decision === "block")
  assert.equal(blocks.length, 0, "BWS secret name in MCP content should not block")
})

test("MCP argument with real .key file path SHOULD block", () => {
  const verdicts = mcpArgumentVerdicts(P, { file: "/etc/ssl/server.key" }, [])
  const blocks = verdicts.filter(v => v.decision === "block")
  assert.ok(blocks.length > 0, "real .key file path in MCP arg should block")
})