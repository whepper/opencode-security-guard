/**
 * Bypass regressions for path-representation attacks:
 *   - benign-named symlinks resolving onto protected files
 *   - env-var / alternate-separator path construction
 *
 * The engine stays filesystem-free: resolution is injected. A real-fs
 * integration case lives in adapter.test.js.
 */
import { test } from "node:test"
import assert from "node:assert/strict"
import {
  analyzeCommand,
  decideToolCall,
  GENERATED_GUARD_POLICY,
} from "../../plugin/security-guard.js"

const P = JSON.parse(JSON.stringify(GENERATED_GUARD_POLICY))

// Simulated filesystem: mynotes.txt -> .env, safe.txt -> report.md
const LINKS = {
  "mynotes.txt": ".env",
  "safe.txt": "report.md",
}
const fakeResolve = (p) => {
  const base = p.split("/").pop()
  return LINKS[base] ? `/data/${LINKS[base]}` : null
}

test("BYP-FS-LINK-001: benign-named symlink onto .env is blocked", () => {
  const r = analyzeCommand(P, "cat mynotes.txt", { resolvePath: fakeResolve })
  assert.equal(r?.decision, "block")
})

test("BYP-FS-LINK-002: read tool through benign-named symlink is blocked", () => {
  const v = decideToolCall(P, { kind: "path", path: "/work/mynotes.txt", mode: "read" }, { resolvePath: fakeResolve })
  assert.equal(v.decision, "block")
  assert.equal(v.ruleId, "GG-ENV-001")
})

test("benign symlink to a NON-protected file stays allowed", () => {
  assert.equal(analyzeCommand(P, "cat safe.txt", { resolvePath: fakeResolve }), null)
  assert.equal(decideToolCall(P, { kind: "path", path: "/work/safe.txt", mode: "read" }, { resolvePath: fakeResolve }), null)
})

test("without a resolver the literal name governs (documented native-layer parity)", () => {
  assert.equal(analyzeCommand(P, "cat mynotes.txt"), null)
})

test("env-var and separator path forms are covered", () => {
  for (const cmd of ["cat $HOME/.env", "cat ${HOME}/.env", "cat ~/.env", "cat ./.env", "cat src//.env", "cat sub/../.env"]) {
    const r = analyzeCommand(P, cmd)
    assert.equal(r?.decision, "block", `${cmd} should block`)
  }
})

test("custom/unknown helper binaries reading protected material are blocked", () => {
  const r = analyzeCommand(P, "mytool dump .env")
  assert.equal(r?.decision, "block")
  assert.equal(r.ruleId, "GGR-OTHER-001")
})
