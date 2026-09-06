# Security Policy

Privacy Protector runs a DNS server, stores a durable local record of observed
hostnames, and can read evidence from a paired iPhone. Security reports are
welcome and taken seriously.

## Supported versions

Only the latest released version and the current `main` branch receive fixes.

## Reporting a vulnerability

Report privately. **Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this project's page.

Please include:

- What the issue is and which component it affects
  (`dns_engine.py`, `domain_classifier.py`, `app.py`, a launcher script, or the web UI).
- Steps to reproduce, ideally against the test launcher on DNS port `53053`.
- The impact you believe it has.
- Your operating system, Python version, and application version.

**Never include real capture output, activity logs, policy files, or App Privacy
Report data in a report.** Those files are a durable inventory of your own devices
and services. Reproduce with synthetic hostnames such as `example.test`, or
describe the shape of the data instead of attaching it.

## Response expectations

This is a single-maintainer project, not a funded product. Expect an
acknowledgement within seven days and an assessment within thirty. There is no
bug bounty. If a fix is needed, it lands on `main` first and the advisory is
published once users can update.

## In scope

- Remote reachability of the dashboard or API beyond the intended loopback boundary.
- Bypassing the loopback `Host` check on state-changing API calls.
- DNS cache poisoning, response forgery, or transaction-ID handling flaws.
- Any path that causes the V3 study to connect to a private, loopback, link-local,
  or reserved address, follow redirects, or retain page bodies, cookies, or credentials.
- Leakage of local activity, policy, classification, capture, or attribution data to
  any remote party.
- Privilege issues in the firewall preparation or startup installation scripts.
- Path traversal or arbitrary file access through the local HTTP server.

## Out of scope

- Anything that requires an attacker to already have interactive access to the
  user's Windows account. Runtime data under `%LOCALAPPDATA%\PrivacyProtector\data`
  is protected by the operating system's user boundary and nothing more.
- The documented limits of DNS itself: it cannot see encrypted payloads, cannot
  prove which process made a request without USB or report evidence, and cannot
  observe traffic that bypasses the configured resolver. These are stated in
  **Known limitations** and are design boundaries, not vulnerabilities.
- Privacy properties of the upstream DNS-over-HTTPS providers, which are external
  dependencies with their own published policies.
- Deliberately exposing the application to the internet or placing it behind a
  reverse proxy. The README states this is unsupported without a separate
  security design.
- Missing wildcard blocking. Exact-domain matching is an intentional decision.
