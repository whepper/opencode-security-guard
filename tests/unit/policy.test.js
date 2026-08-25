import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import path from "node:path"
import { parseJsonc } from "../../scripts/jsonc.mjs"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")
const policy = parseJsonc(readFileSync(path.join(ROOT, "policy", "policy.jsonc"), "utf8"))

const V2_ACTIONS = new Set([
  "*", "read", "edit", "glob", "grep", "shell", "subagent", "skill",
  "question", "webfetch", "websearch", "external_directory", "execute",
])
const EFFECTS = new Set(["allow", "ask", "deny"])
// Only characters the verified V2 dialect gives meaning to; "**" is NOT part
// of it (verified: docs/permissions — "*" spans "/", no globstar).
const RESOURCE_CHARS = /^[A-Za-z0-9_.\-\/?*$~@=+ :,]*$/

test("policy parses and declares required top-level sections", () => {
  assert.equal(policy.policyVersion >= 1, true)
  for (const key of ["profiles", "permissions", "watcherIgnore", "guard"]) {
    assert.ok(policy[key], `missing section: ${key}`)
  }
})

test("every permission rule has a stable unique ID, valid action/effect, V2-safe resource", () => {
  const ids = new Set()
  const idsWithReasons = []
  for (const rule of policy.permissions) {
    assert.ok(rule.id && !ids.has(rule.id), `duplicate/missing id: ${rule.id}`)
    ids.add(rule.id)
    assert.ok(V2_ACTIONS.has(rule.action), `unknown action ${rule.action} on ${rule.id}`)
    assert.ok(EFFECTS.has(rule.effect), `bad effect on ${rule.id}`)
    assert.ok(typeof rule.resource === "string" && rule.resource.length > 0, `empty resource on ${rule.id}`)
    assert.match(rule.resource, RESOURCE_CHARS, `resource uses characters outside the V2 dialect on ${rule.id}: ${rule.resource}`)
    assert.ok(!rule.resource.includes("**"), `"**" is not valid V2 syntax (${rule.id})`)
    assert.ok(rule.reason && rule.reason.length > 10, `${rule.id} needs a real rationale`)
    idsWithReasons.push([rule.id, rule.reason])
  }
})

test("ordering invariants: allows -> denies -> asks -> safe exceptions last", () => {
  const firstDeny = policy.permissions.findIndex((r) => r.effect === "deny")
  const firstAsk = policy.permissions.findIndex((r) => r.effect === "ask")
  const firstExc = policy.permissions.findIndex((r) => r.id.startsWith("SG-EXC"))
  assert.ok(firstDeny > -1 && firstAsk > -1 && firstExc > -1)
  // every exception must come after every non-exception rule
  const lastNonExc = policy.permissions.reduce((acc, r, i) => (!r.id.startsWith("SG-EXC") ? i : acc), -1)
  assert.ok(lastNonExc < firstExc, "exceptions must be the final rules")
  // BROAD allows must precede the first deny: under last-match-wins a trailing
  // allow would resurrect everything. Exception allows are intentionally last.
  const lastBroadAllow = policy.permissions.reduce(
    (acc, r, i) => (r.effect === "allow" && /^(SG-BASE|SG-NET)/.test(r.id) ? i : acc),
    -1
  )
  assert.ok(lastBroadAllow < firstDeny, "broad allows must precede denies")
})

test("profile overrides reference existing rule IDs with valid effects", () => {
  for (const [name, prof] of Object.entries(policy.profiles)) {
    for (const [id, effect] of Object.entries(prof.overrides ?? {})) {
      assert.ok(policy.permissions.some((r) => r.id === id), `${name}: override targets unknown rule ${id}`)
      assert.ok(EFFECTS.has(effect), `${name}: bad override effect for ${id}`)
    }
    for (const gid of prof.promoteAskToDenyIds ?? []) {
      assert.ok(policy.guard.askPaths.some((p) => p.id === gid), `${name}: unknown guard promote id ${gid}`)
    }
  }
})

test("guard path rules use known forms and unique IDs", () => {
  const forms = new Set(["basename", "prefixName", "suffix", "contains", "dir", "dirSegment2", "withinDir"])
  const ids = new Set()
  for (const section of ["denyPaths", "askPaths", "exceptionPaths"]) {
    for (const rule of policy.guard[section]) {
      assert.ok(!ids.has(rule.id) && ids.add(rule.id), `duplicate guard id ${rule.id}`)
      assert.ok(forms.has(rule.form), `unknown form ${rule.form} on ${rule.id}`)
      assert.ok(rule.reason, `${rule.id} needs rationale`)
    }
  }
})

test("envVarNamePattern compiles and matches obvious secret names only", () => {
  const rx = new RegExp(policy.guard.envVarNamePattern, "i")
  for (const name of ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "MY_API_KEY", "DATABASE_PASSWORD", "CLIENT_SECRET", "PRIVATE_KEY_PATH"]) {
    assert.ok(rx.test(name), `should match ${name}`)
  }
  for (const name of ["PATH", "HOME", "SHELL", "EDITOR", "LANG", "TERM"]) {
    assert.equal(rx.test(name), false, `should NOT match ${name}`)
  }
})

test("watcher ignore list is non-empty standard globs", () => {
  assert.ok(policy.watcherIgnore.length >= 10)
  for (const w of policy.watcherIgnore) {
    assert.equal(typeof w, "string")
    assert.ok(w.length > 1)
  }
})
