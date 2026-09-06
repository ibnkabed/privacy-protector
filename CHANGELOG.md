# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-06

First public release.

### Added

- Local-first Windows dashboard on `http://127.0.0.1:8733` with an English LTR interface.
- DNS Engine V3: UDP and TCP listeners, exact-domain policy with NXDOMAIN blocking,
  TTL-aware bounded cache, DNS-over-HTTPS forwarding with primary/fallback health
  tracking, and a compact self-test with measured coverage.
- Permanent evidence-based green/orange/red domain classification with an explicit
  `preliminary` or `studied` stage, a stated reason, and a confidence value.
- Bounded public HTTPS-root metadata study that rejects private, loopback, link-local,
  and reserved targets, follows no redirects, and retains no page body or credential.
- Local parsing of Apple App Privacy Report NDJSON files, entirely in the browser.
- Optional paired-iPhone features over an existing trusted pairing: application
  inventory, read-only Developer Mode check, user-initiated permission-evidence
  capture, and USB `pcapd` process attribution for plain DNS questions.
- Protection operations workspace kept separate from exact-domain policy, so moving
  or removing a hostname never creates, changes, or deletes a DNS rule.
- Launchers for foreground testing, a hidden background service, Windows sign-in
  startup installation, scoped firewall preparation, and a desktop shortcut.
- Test suite covering DNS protocol handling, caching, failover, concurrency,
  classification, activity/operations separation, launcher contracts, clean-release
  runtime isolation, and the public README privacy contract.

### Security

- The dashboard binds to loopback and state-changing API calls require a loopback
  `Host` header.
- Content Security Policy, `X-Content-Type-Options`, `Referrer-Policy`, and a
  Permissions Policy that disables camera, microphone, and geolocation.
- Windows Firewall rules are scoped to the Private profile, the local subnet, the
  selected Python executable, and port `53` over UDP and TCP.
