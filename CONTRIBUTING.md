# Contributing

Security fixes and bypass research are especially welcome.

## Before contributing

- Read the threat model.
- Read the limitations.
- Do not commit real credentials or sensitive environment files.
- Use dummy values in tests.
- Prefer regression tests for every discovered bypass.

## Security-sensitive changes

Changes affecting permission matching, command inspection, path classification, plugin behavior, or fail-open/fail-closed behavior should include tests and documentation.

When documenting a bypass, explain:

1. what control was expected to stop it;
2. how the bypass worked;
3. why the control failed;
4. what mitigation was added;
5. what residual risk remains.

## Pull requests

Keep changes focused. Explain security-relevant behavior rather than only implementation details.
