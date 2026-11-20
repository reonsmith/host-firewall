# Host Firewall

A small web panel for managing **host UFW** on Ubuntu.

- Labeled (commented) allow/deny/reject/limit rules with IPv4/IPv6 badges
- Reorder rules (move up/down), edit, delete, insert at position
- UFW enable/disable, default policies, logging level
- App profile datalist from `ufw app list`
- Recent UFW / kernel block hits with one-click **Block IP**
- Listening ports via `ss`, with quick **Allow**
- Export `/etc/ufw` as `.tar.gz`, restore prior snapshots
- Change history of confirmed / rolled-back mutations
- **Confirm-or-rollback**: every mutation snapshots `/etc/ufw`, applies the change, then requires Confirm within 60s (configurable). If you do not confirm — or the panel becomes unreachable — the snapshot is restored and UFW is reloaded.

This is a **host** firewall UI, not a network edge firewall. Put TLS and network access control in front of it (reverse proxy, VPN, or LAN-only bind).

## Requirements

- Ubuntu (or similar) with UFW
- Docker with Compose v2, **or** Python 3.12+

## Quick start (Docker)

```bash
git clone https://github.com/reonsmith/host-firewall.git
cd host-firewall
cp .env.example .env
# set HOST_FIREWALL_PASSWORD (≥12 chars) and HOST_FIREWALL_SECRET_KEY (≥32 chars)

docker compose up -d --build
```

Open `http://<host>:8080` (or the port in `.env`).

The compose file uses `network_mode: host` and `NET_ADMIN` / `NET_RAW` so the container can talk to the host’s UFW. Mounts `/etc/ufw`, `/etc/default/ufw`, and read-only `/var/log`. The image includes `iproute2` (`ss`) for the listening-ports view.

## Configuration

| Variable | Required | Default | Notes |
|----------|----------|---------|--------|
| `HOST_FIREWALL_PASSWORD` | yes | — | Min 12 characters |
| `HOST_FIREWALL_SECRET_KEY` | yes | — | Min 32 characters (session signing) |
| `HOST_FIREWALL_PORT` | no | `8080` | Listen port |
| `HOST_FIREWALL_BIND` | no | `0.0.0.0` | Prefer a LAN IP or `127.0.0.1` behind a proxy |
| `HOST_FIREWALL_LABEL` | no | `host` | Shown in the UI header |
| `HOST_FIREWALL_CONFIRM_SECONDS` | no | `60` | Rollback window after a change |
| `HOST_FIREWALL_LOG_PATHS` | no | `/var/log/ufw.log:/var/log/kern.log:/var/log/syslog` | Colon-separated |
| `HOST_FIREWALL_LOG_LIMIT` | no | `80` | Max log rows returned |

## Development

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

Run the app locally (still needs UFW on the machine, or inject a fake runner in tests):

```bash
export HOST_FIREWALL_PASSWORD='dev-password-ok'
export HOST_FIREWALL_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m backend
```

## API sketch

Authenticated JSON under `/api/*` (session cookie after `POST /api/login`):

- `GET /api/status`, `/api/rules`, `/api/logs`, `/api/ports`, `/api/apps`, `/api/history`, `/api/snapshots`
- `POST /api/rules`, `PUT/DELETE /api/rules/{n}`, `POST /api/rules/{n}/move`
- `POST /api/ufw/enable|disable`, `/api/ufw/default`, `/api/ufw/logging`
- `GET /api/export`, `POST /api/snapshots/restore`
- `POST /api/pending/confirm|rollback`

## Safety

- Mutations always create a snapshot under the data directory before applying.
- Confirm within the timeout, or the watchdog restores the snapshot and reloads UFW.
- Destructive or client-blocking changes show an in-UI warning when detected.
- If you lock yourself out of the panel, use console/SSH or another out-of-band path — that is the point of the rollback window.

Do **not** expose this panel to the public internet without authentication at the proxy and TLS. The built-in password is a single shared secret, not multi-user IAM.

## License

MIT — see [LICENSE](LICENSE).
