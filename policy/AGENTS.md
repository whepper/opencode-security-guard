# Security Policy for Agents

These instructions are advisory. Enforcement must come from OpenCode permissions and execution controls.

- Never intentionally read, print, transmit, or modify secret-bearing files.
- Never circumvent an OpenCode permission denial.
- Never use another tool or shell command to bypass a protected path.
- Never dump the process environment.
- Do not print secret-named environment variables.
- Treat production logs as sensitive.
- Minimize context sent to the model.
- Ask the user for a sanitized value or fixture when a secret is genuinely required.
- Treat shell startup files as potentially sensitive.
- Do not assume that a file is safe merely because its name does not contain `secret`, `token`, `key`, or `password`.
