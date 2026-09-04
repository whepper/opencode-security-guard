/**
 * 2026-09-04e — operator content-write allowlist (contentWriteAllowlist).
 * Covers the prefix/exact/case/segment semantics and the override parsing,
 * plus the boundary: only GGW-CONTENT content asks are exempt — ask-tier
 * path writes (GG-SLF-004, GG-RC-008) stay gated. Dummy names only.
 */
import test from "node:test"
import assert from "node:assert/strict"
import {
  GENERATED_GUARD_POLICY as BASE,
  applyGuardOverride,
  decideToolCall,
} from "../../plugin/security-guard.js"

const dec = (r) => (r ? `${r.decision}:${r.ruleId}` : "null")
const withAllowlist = applyGuardOverride(BASE, { contentWriteAllowlist: ["tests/", "tools/gen.sh"] })
const write = (path, content, policy = withAllowlist) =>
  decideToolCall(policy, { kind: "path", path, mode: "write", content }, {})

test("allowlisted directories exempt the content ask (segment matching)", () => {
  // This file lives under tests/ and mentions .env — the live write of this
  // very file is the allowlist proof.
  assert.equal(write("tests/unit/probe.test.js", 'test("x", () => { /* cat .env blocks */ })'), null)
  assert.equal(write("tests/sub/dir/deep.sh", "cat .env"), null)
  // segment matching covers absolute harness paths
  assert.equal(write("/repo/tests/unit/probe.test.js", "cat .env"), null)
  // exact file entry
  assert.equal(write("tools/gen.sh", "cat .env"), null)
  // case-insensitive
  assert.equal(write("TESTS/probe.test.js", "cat .env"), null)
})

test("outside the allowlist the content ask still fires (engine tier: ask)", () => {
  // engine verdict stays ask; the adapter downgrades it to block on live betas
  assert.equal(dec(write("/tmp/other/package.json", '{"scripts":{"x":"cat .env"}}')), "ask:GGW-CONTENT-001")
  // segment semantics: "tests/" does not cover "testsuite/"
  assert.equal(dec(write("testsuite/other.js", "cat .env")), "ask:GGW-CONTENT-001")
  // base policy without the allowlist still asks
  assert.equal(
    dec(decideToolCall(BASE, { kind: "path", path: "tests/probe.test.js", mode: "write", content: "cat .env" }, {})),
    "ask:GGW-CONTENT-001",
  )
})

test("ask-tier path writes are NOT allowlistable", () => {
  assert.equal(dec(write("policy/policy.jsonc", "{}")), "ask:GG-SLF-004")
  assert.equal(dec(write("tests/.envrc", "export A=1")), "ask:GG-RC-008")
})

test("applyGuardOverride parses contentWriteAllowlist", () => {
  const p = applyGuardOverride(BASE, { contentWriteAllowlist: ["a/", "b.sh"] })
  assert.deepEqual(p.contentWriteAllowlist, ["a/", "b.sh"])
  assert.equal(applyGuardOverride(BASE, {}).contentWriteAllowlist, undefined)
  // base policy is not mutated
  assert.equal(BASE.contentWriteAllowlist, undefined)
})
