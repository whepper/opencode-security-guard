# Security Policy

## Scope

OpenCode Security Guard is security-sensitive software whose entire purpose is reducing exposure of local secrets to LLM agents. A vulnerability includes:

- a bypass that defeats a documented control (permission rule, guard detection);
- a false-negative class the docs claim is covered;
- anything that makes the guard fail **silently** (undetected absence, corrupted heartbeat, doctor false-green);
- secret material committed to this repository;
- an injection vector through policy/config parsing.

## Reporting privately

Please use GitHub's **Private vulnerability reporting** on this repository (Security tab → Report a vulnerability). If unavailable, contact the maintainers directly and expect a public advisory afterwards.

Please include:

- affected version or commit;
- OpenCode version (`opencode2 --version`) and OS;
- configuration/profile involved;
- reproduction steps — ideally as a proposed `tests/bypass/cases.jsonc` entry with **dummy** values;
- expected vs observed behavior;
- whether any real credential may have been exposed.

Do not include live credentials in reports. Use obviously fake values.

## Response expectations

- acknowledgement within 7 days;
- assessment + severity within 14 days;
- fix or documented mitigation for high-severity issues targeted within 30 days of assessment;
- credit unless you prefer otherwise.

## If you suspect a live leak

Treat any credential that may have reached an LLM provider as compromised: **rotate/revoke first**, then investigate. No control in this repository can retract transmitted data.
