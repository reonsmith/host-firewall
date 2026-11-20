# Contributing

Thanks for helping. Host Firewall changes a machine's firewall, so the bar is
"can't lock someone out by surprise" before "nice to have".

## Run it locally

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -v
```

To click around without UFW, use demo mode. It serves sample rules, ports and
traffic, and changes are simulated:

```bash
HOST_FIREWALL_DEMO=1 HOST_FIREWALL_DATA_DIR=./data-demo python -m backend
# open http://127.0.0.1:8080 and sign in with: host-firewall-demo
```

## Ground rules

- **Every mutation goes through confirm-or-rollback.** Snapshot `/etc/ufw`,
  apply, start the pending window. No exceptions for "small" changes.
- **Parsing must fail soft.** UFW output varies by version and locale. If a
  line doesn't parse, skip it; never crash the dashboard.
- **No new unauthenticated routes**, other than `/api/health` and the login page.
- **Keep the stack small.** FastAPI, Jinja templates, plain CSS and JS. No
  front-end build step.
- **Add a test** for parser changes, using real `ufw` / `ss` output in the test.

## Pull requests

- Keep them focused; one change per PR is easiest to review.
- Update `CHANGELOG.md` under *Unreleased*.
- For UI changes, add a screenshot (demo mode is fine) and check phone width.

## Releases

Bump the version in `pyproject.toml` and `APP_VERSION` in `backend/app.py`,
move *Unreleased* in the changelog under the new version, then tag `vX.Y.Z`.
The release workflow publishes `ghcr.io/reonsmith/host-firewall` for amd64 and arm64.
