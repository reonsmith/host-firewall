# Security Policy

## Supported versions

The latest release is supported. Fixes land on `main` and ship in the next tagged release.

## Reporting a vulnerability

Please open a **private** GitHub security advisory on this repository, or email the maintainer via the address on the GitHub profile. Do not file a public issue for unfixed vulnerabilities.

Include:

- Affected version / commit
- Reproduction steps
- Impact (e.g. auth bypass, RCE, firewall lockout)

## Hardening expectations

Operators should:

- Keep the panel off the public internet, or terminate TLS and extra auth at a reverse proxy
- Use a strong unique `HOST_FIREWALL_PASSWORD` and `HOST_FIREWALL_SECRET_KEY`
- Prefer binding to a management VLAN / VPN interface when possible
- Treat `network_mode: host` + `NET_ADMIN` as full host firewall privilege
