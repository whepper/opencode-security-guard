/**
 * Drift test: derived artifacts (config/opencode.jsonc and the plugin's
 * generated guard-policy block) MUST match policy/policy.jsonc.
 * Equivalent to `node scripts/generate-config.mjs --check` but wired into
 * the test suite so plain `npm test` catches drift too.
 */
import { test } from "node:test"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import path from "node:path"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")

test("generated artifacts match policy source (no drift)", () => {
  execFileSync(process.execPath, [path.join(ROOT, "scripts", "generate-config.mjs"), "--check"], {
    cwd: ROOT,
    stdio: "pipe",
  })
})

test("plugin file passes Node syntax check", () => {
  execFileSync(process.execPath, ["--check", path.join(ROOT, "plugin", "security-guard.js")], {
    cwd: ROOT,
    stdio: "pipe",
  })
})
