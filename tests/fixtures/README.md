# Test fixtures — FAKE DATA ONLY

Everything in this directory is dummy data for the bypass regression corpus
and the live smoke checklist. **No real credential may ever be committed
here.**

Rules enforced by `scripts/scan-secrets.mjs`:

1. Files whose names look sensitive (`.env`, `*.key`, ...) must exist ONLY in
   this directory.
2. Every such file must contain the marker string `FAKE-NOT-A-REAL-SECRET`
   so automated checks (and humans) can tell at a glance that values are fake.

If you discover a real-looking value anywhere in this repository, stop and
report it per SECURITY.md.
