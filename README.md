# OpenCode Security Guard

Defense-in-depth security controls for protecting local secrets and sensitive data from LLM agents running through OpenCode.

> **Security boundary:** This project is not a sandbox and is not a complete DLP boundary. An agent with unrestricted shell and network access may still bypass content-based controls.

## Why this exists

LLM coding agents are useful precisely because they can inspect files, execute commands, and interact with development environments. Those same capabilities can accidentally expose credentials and sensitive local data to an LLM provider.

OpenCode Security Guard combines several layers:

1. **OpenCode permission rules** — deny or approval-gate sensitive resources.
2. **Watcher exclusions** — reduce accidental indexing/discovery of sensitive data.
3. **Global agent policy** — instruct the agent not to seek, print, or transmit secrets.
4. **Execution-time security guard** — inspect tool executions for semantic attempts to bypass path-based rules.

No single layer is sufficient.

## Design principles

- Deny known high-confidence secret locations.
- Ask before accessing ambiguous resources.
- Treat watcher exclusions as defense-in-depth, never as an access-control boundary.
- Detect semantic shell bypasses where simple path rules are insufficient.
- Fail safely where practical, and make failures observable.
- Test bypasses, not just happy paths.
- Be explicit about residual risk.

## Current status

This repository is the open-source development baseline derived from a real-world OpenCode hardening deployment. The initial implementation is intentionally conservative and should be treated as experimental until compatibility and bypass testing cover the relevant OpenCode versions.

## Threat model

See [docs/threat-model.md](docs/threat-model.md).

## Important limitations

See [docs/limitations.md](docs/limitations.md). In particular, this project does not provide OS-level process isolation or reliable network egress control.

## Security incidents

The initial design was informed by a real incident in which an agent read API keys from `~/.zshenv`. Existing protections correctly blocked protected filenames, but `.zshenv` itself carried no sensitive filename signal. See [docs/incident-2026-08-21.md](docs/incident-2026-08-21.md).

## Development roadmap

### v0.1 — foundation

- [x] Establish threat model and security goals
- [x] Establish four-layer architecture
- [x] Define high-confidence deny patterns
- [x] Define approval-gated patterns
- [x] Add execution-time bypass detection
- [ ] Generalize the reference configuration
- [ ] Add automated OpenCode-version compatibility tests
- [ ] Add comprehensive bypass regression suite
- [ ] Document installation and upgrade procedures
- [ ] Establish release and vulnerability-handling process

### v0.2 — stronger enforcement

- [ ] Configurable policy profiles
- [ ] Broader MCP-aware protection
- [ ] Improved command normalization and semantic analysis
- [ ] Better handling of shell indirection and archives
- [ ] Security regression corpus
- [ ] Network egress mitigation guidance

### Future

- [ ] Optional isolated execution architecture
- [ ] More robust network policy integration
- [ ] Formal adversarial evaluation harness
- [ ] OpenCode release compatibility matrix

## License

Apache License 2.0. See [LICENSE](LICENSE).
