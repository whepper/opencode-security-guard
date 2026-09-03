# Security Policy

## Scope

Security Guard for OpenCode is security-sensitive software whose entire purpose is reducing exposure of local secrets to LLM agents. A vulnerability includes:

- a bypass that defeats a documented control (permission rule, guard detection);
- a false-negative class the docs claim is covered;
- anything that makes the guard fail **silently** (undetected absence, corrupted heartbeat, doctor false-green);
- secret material committed to this repository;
- an injection vector through policy/config parsing.

## Reporting privately

Please use GitHub's **Private vulnerability reporting** on this repository (Security tab → Report a vulnerability). If unavailable, contact the maintainers directly and expect a public advisory afterwards.

Do not open public issues for suspected vulnerabilities.

## What to include

- affected version or commit;
- OpenCode V2 version (`opencode2 --version`) and OS;
- configuration/profile involved;
- reproduction steps — ideally as a proposed `tests/bypass/cases.jsonc` or `tests/bypass/mcp-cases.jsonc` entry with **dummy** values;
- expected vs observed behavior;
- whether any real credential may have been exposed.

Never include live credentials in reports. Use obviously fake values.

## Bypass report template

```text
OpenCode version:        opencode2 <version>
Security Guard version:  <from security-test output>
OS:                      <os/version>
Layer expected to block: native permission | guard-shell | guard-mcp | provenance | other
Actual behavior:         allowed | asked-and-approved | blocked-with-wrong-rule
Reproduction:            <exact prompt/command; dummy data only>
Impact:                  what could leak, to where
Sensitive data exposed?  yes/no — if yes, rotate first, report second
security-test output:    <paste the pasteable summary block>
```

## Response expectations

- acknowledgement within 7 days;
- assessment + severity within 14 days;
- fix or documented mitigation for high-severity issues targeted within 30 days of assessment;
- credit unless you prefer otherwise.

## If you suspect a live leak

Treat any credential that may have reached an LLM provider as compromised: **rotate/revoke first**, then investigate. No control in this repository can retract transmitted data.
