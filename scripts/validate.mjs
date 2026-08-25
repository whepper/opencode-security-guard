#!/usr/bin/env node
/**
 * Repository validation used by CI, pre-commit habits, and scripts/doctor.mjs.
 * Checks structure, JSONC parseability, plugin syntax/metadata consistency,
 * policy drift, and corpus sanity. Exits non-zero on any problem.
 */
import { readFileSync, existsSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import path from "node:path"
import { parseJsonc } from "./jsonc.mjs"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
let failures = 0
const check = (name, fn) => {
  try {
    fn()
    console.log(`ok    ${name}`)
  } catch (err) {
    failures++
    console.error(`FAIL  ${name}: ${err.message}`)
  }
}

check("required files exist", () => {
  const required = [
    "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
    "package.json", ".gitignore",
    "policy/policy.jsonc",
    "config/opencode.jsonc",
    "plugin/security-guard.js",
    "scripts/generate-config.mjs", "scripts/jsonc.mjs",
    "docs/architecture.md", "docs/threat-model.md", "docs/limitations.md",
    "docs/incident-2026-08-21.md", "docs/mcp.md", "docs/installation.md",
    "tests/bypass/cases.jsonc",
  ]
  for (const rel of required) {
    if (!existsSync(path.join(ROOT, rel))) throw new Error(`missing ${rel}`)
  }
})

check("package.json parses and declares zero runtime dependencies", () => {
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"))
  if (pkg.dependencies && Object.keys(pkg.dependencies).length) {
    throw new Error("runtime dependencies are forbidden in this repository")
  }
  if (!pkg.private) throw new Error("package must stay private until an npm release is intended")
})

check("LICENSE contains the complete Apache-2.0 text", () => {
  const lic = readFileSync(path.join(ROOT, "LICENSE"), "utf8")
  for (const marker of ["Apache License", "Version 2.0, January 2004", "END OF TERMS AND CONDITIONS", "APPENDIX"]) {
    if (!lic.includes(marker)) throw new Error(`license text missing section: ${marker}`)
  }
  if (lic.length < 10000) throw new Error(`license suspiciously short (${lic.length} chars)`)
})

check("policy/policy.jsonc parses", () => {
  const p = parseJsonc(readFileSync(path.join(ROOT, "policy/policy.jsonc"), "utf8"))
  if (!p.permissions?.length) throw new Error("no permission rules")
})

check("config/opencode.jsonc parses and matches generated output", () => {
  execFileSync(process.execPath, [path.join(ROOT, "scripts/generate-config.mjs"), "--check"], { cwd: ROOT, stdio: "pipe" })
  const cfg = parseJsonc(readFileSync(path.join(ROOT, "config/opencode.jsonc"), "utf8"))
  if (cfg.$schema !== "https://opencode.ai/config.json") throw new Error("$schema missing")
  if (cfg.share !== "disabled") throw new Error("share must be disabled (intent marker)")
  if (!Array.isArray(cfg.permissions) || cfg.permissions.length < 40) throw new Error("permission array too small")
  if (!cfg.watcher?.ignore?.length) throw new Error("watcher ignores missing")
})

check("plugin passes Node syntax check and carries consistent metadata", () => {
  execFileSync(process.execPath, ["--check", path.join(ROOT, "plugin/security-guard.js")], { cwd: ROOT, stdio: "pipe" })
  const src = readFileSync(path.join(ROOT, "plugin/security-guard.js"), "utf8")
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"))
  const m = src.match(/export const PLUGIN_VERSION = "([^"]+)"/)
  if (!m) throw new Error("PLUGIN_VERSION missing")
  if (m[1] !== pkg.version) throw new Error(`PLUGIN_VERSION ${m[1]} != package.json ${pkg.version}`)
  if (!src.includes("BEGIN GENERATED GUARD POLICY")) throw new Error("generated guard block missing")
})

check("bypass corpus parses and is balanced", () => {
  const { cases } = parseJsonc(readFileSync(path.join(ROOT, "tests/bypass/cases.jsonc"), "utf8"))
  if (cases.length < 40) throw new Error(`corpus too small (${cases.length})`)
  const ids = new Set(cases.map((c) => c.id))
  if (ids.size !== cases.length) throw new Error("duplicate case ids")
  if (!cases.some((c) => c.category === "incident-replay")) throw new Error("incident replay case missing")
})

process.exit(failures ? 1 : 0)
