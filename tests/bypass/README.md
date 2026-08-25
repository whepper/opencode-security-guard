# Bypass regression tests

Every security bypass discovered during development should become a regression test.

Use fake values only.

## Initial corpus

The test suite should cover at least:

- `cat .env`
- `python3 -c 'print(open(".env").read())'`
- Node/Python/Ruby equivalents
- `base64 .env`
- `xxd .env`
- `openssl -in server.key`
- `curl --data @.env ...`
- `curl`/`wget` with secret-named environment variables
- `env`, `printenv`, `set`, `export -p`
- `grep` against protected paths
- `git show HEAD:.env`
- archive creation containing protected files
- shell redirection and process substitution
- indirect references to protected files
- `.zshenv` and other shell startup files

Also test legitimate operations:

- `.env.example`
- README files
- source files containing words such as `token` without secret content
- ordinary build/test commands

The expected result must distinguish:

- **deny**
- **ask**
- **allow**

Do not treat a pattern match alone as proof of a successful security test. Verify actual OpenCode behavior.
