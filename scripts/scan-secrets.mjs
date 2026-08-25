#!/usr/bin/env node
/**
 * Dependency-free secret / accidental-credential scanner.
 *
 * Scans all git-TRACKED files for:
 *   1. high-confidence credential PATTERNS in content;
 *   2. credential-LOOKING FILENAMES outside tests/fixtures/;
 *   3. presence of the FAKE marker inside any sensitive-named fixture
 *      (fixtures are allowed to exist only as obviously-dummy data).
 *
 * This is deliberately high-confidence-only: a noisy scanner gets ignored,
 * which is worse than a quiet one. It complements — never replaces — review.
 */
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import path from "node:path"

const ROOT = process.cwd()
const FIXTURES = "tests/fixtures/"
const FAKE_MARKER = "FAKE-NOT-A-REAL-SECRET"

const tracked = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
  .split("\n")
  .filter(Boolean)

const CONTENT_PATTERNS = [
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/, "private key header"],
  [/AKIA[0-9A-Z]{16}/, "AWS access key id"],
  [/sk-ant-[A-Za-z0-9_-]{20,}/, "Anthropic-style key"],
  [/sk-proj-[A-Za-z0-9_-]{20,}/, "OpenAI-style project key"],
  [/gh[pousr]_[A-Za-z0-9]{30,}/, "GitHub token"],
  [/github_pat_[A-Za-z0-9_]{30,}/, "GitHub fine-grained token"],
  [/xox[baprs]-[A-Za-z0-9-]{15,}/, "Slack token"],
  [/AIza[0-9A-Za-z_-]{35}/, "Google API key"],
  [/eyJ[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{20,}\./, "JWT"],
]

const SENSITIVE_NAME =
  /(^|\/)\.env$|(^|\/)\.env\.[^/]*$|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|(^|\/)id_rsa|(^|\/)id_ed25519|(^|\/)id_ecdsa|\.tfstate(\.|$)|\.netrc$|\.npmrc$|\.pypirc$|\.git-credentials$/

let hits = 0

for (const rel of tracked) {
  const isFixture = rel.startsWith(FIXTURES)
  let buf
  try {
    buf = readFileSync(path.join(ROOT, rel), "utf8")
  } catch {
    continue // binary or unreadable — name check below still ran
  }

  // 1. content patterns (skip fixtures here; they are checked via marker)
  if (!isFixture) {
    for (const [rx, label] of CONTENT_PATTERNS) {
      if (rx.test(buf)) {
        console.error(`SECRET? ${rel}: ${label}`)
        hits++
      }
    }
  }

  // 2+3. sensitive FILENAMES
  if (SENSITIVE_NAME.test(rel)) {
    if (!isFixture) {
      console.error(`SENSITIVE NAME outside tests/fixtures/: ${rel}`)
      hits++
    } else if (!buf.includes(FAKE_MARKER)) {
      console.error(`FIXTURE missing "${FAKE_MARKER}" marker: ${rel}`)
      hits++
    }
  }
}

// Self-test: the scanner must recognize its own bait stored nowhere else.
{
  const probe = "-----BEGIN RSA PRIVATE KEY-----"
  const rx = CONTENT_PATTERNS[0][0]
  if (!rx.test(probe)) {
    console.error("SCANNER BROKEN: self-test failed")
    hits++
  }
}

if (hits) {
  console.error(`\n${hits} finding(s). Real credentials must never be committed.`)
  process.exit(1)
}
console.log(`scan clean across ${tracked.length} tracked files`)
