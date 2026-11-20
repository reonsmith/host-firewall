# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-11-20

### Added
- **Demo mode** (`HOST_FIREWALL_DEMO=1`): sample rules, ports and traffic with
  simulated changes, and no host access. `docker-compose.demo.yml` runs it with
  no extra capabilities.
- **Docker-published ports are flagged.** Ports owned by `docker-proxy` get a
  `docker` badge and an explanation, because Docker's iptables rules bypass UFW.
- **Login rate limiting**: five failed attempts from one IP within five minutes
  lock that IP out for five minutes (HTTP 429).
- Prebuilt multi-arch image at `ghcr.io/reonsmith/host-firewall`, published on tags.
- Container health check.
- Issue and PR templates, `CONTRIBUTING.md`, Dependabot, and a CI Docker smoke test.

### Changed
- The session cookie is marked `Secure` automatically when the request arrived
  over HTTPS, including behind a proxy that sends `X-Forwarded-Proto`.
  Override with `HOST_FIREWALL_COOKIE_SECURE`.
- `.env.example` now binds to `127.0.0.1` and explains the options. The built-in
  default is still `0.0.0.0`, so existing installs keep working.
- Docker ports no longer count towards "open ports with no rule".

## [0.3.1] - 2026-11-20

### Changed
- Wide screens (1400px and up) use a two-column lower dashboard: rules and
  traffic on the left; add rule, listening ports, backup and history on the right.

## [0.3.0] - 2026-11-20

### Added
- Summary tiles: rules, blocks in the last 24 hours, open ports with no allow
  rule, and the last change.
- Blocked-traffic chart, per hour for the last 24 hours, from the UFW log tail.
- Arrow-key reordering on the drag handle, and touch drag.
- Countdown bar on the pending-change banner.
- Empty states that say what to do next.

### Changed
- New charcoal and lime visual design.
- Drag starts from the handle only, with a clear drop line.
- The dashboard refreshes its sections in place every 45 seconds while idle,
  instead of reloading the whole page.
- Static assets are versioned, so browsers pick up new CSS and JS after an upgrade.
- Log lines repeated across `ufw.log`, `kern.log` and `syslog` are shown once.

## [0.2.2] - 2026-11-20

### Fixed
- Rule rows and the add-rule form no longer wrap mid-row.

## [0.2.1] - 2026-11-20

### Added
- Drag-and-drop rule reordering.

### Changed
- Console-style UI refresh.

## [0.2.0] - 2026-11-20

### Added
- Enable/disable UFW, default policies and logging level.
- Move rules up and down; IPv6 rule badges.
- Export `/etc/ufw` and restore snapshots.
- Listening ports from `ss`, with a quick Allow.

## [0.1.0] - 2026-11-20

### Added
- First public release: labelled UFW rules, add, edit and delete, recent log
  hits with Block IP, change history, and confirm-or-rollback for every change.

[Unreleased]: https://github.com/reonsmith/host-firewall/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/reonsmith/host-firewall/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/reonsmith/host-firewall/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/reonsmith/host-firewall/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/reonsmith/host-firewall/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/reonsmith/host-firewall/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/reonsmith/host-firewall/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/reonsmith/host-firewall/releases/tag/v0.1.0
