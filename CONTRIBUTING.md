# Contributing

Bypass research and security fixes are especially welcome. This project optimizes for honest risk reduction; correctness beats feature count.

## Ground rules

- Read [docs/threat-model.md](docs/threat-model.md) and [docs/limitations.md](docs/limitations.md) first.
- **Never commit real credentials**, personal paths, usernames, domains, or machine-specific config. Test data lives in `tests/fixtures/` and must contain the `FAKE-NOT-A-REAL-SECRET` marker; the scanner enforces it.
- Zero runtime dependencies is a design constraint, not a preference.
- Every security rule needs: stable ID, rationale, and at least one regression case.

## Development setup

```sh
npm install        # no-op dependency-wise; validates tooling
npm test           # unit tests + adversarial corpus
npm run check      # syntax + structure validation + secret scan
node scripts/generate-config.mjs   # after touching policy/policy.jsonc
```

Node ≥ 20. No build step exists by design.

## Adding a bypass (the most valuable contribution)

1. Reproduce against your installed `opencode2` (note the version).
2. Add a failing entry to `tests/bypass/cases.jsonc` — id (`BYP-*`), category, exact command/tool input, expected outcome.
3. Fix the engine (or Layer 1 rule in `policy/policy.jsonc`, then regenerate).
4. Check the negative set still passes — over-blocking legitimate work is a bug too.
5. Document residual risk honestly in [docs/limitations.md](docs/limitations.md).

Explain in the PR: which control should have stopped it, why it failed, what now stops it, what remains open.

## Security-sensitive changes

Anything affecting permission matching, path classification, command analysis, plugin lifecycle/fail behavior, or installer/doctor logic requires tests and documentation updates, and will be reviewed line-by-line.

## Policy changes

Edit `policy/policy.jsonc` only. Run the generator, commit both source and regenerated artifacts together. Ordering sections are load-bearing (last-match-wins): exceptions stay last.

## Reporting vulnerabilities

Not via pull request — see [SECURITY.md](SECURITY.md).
