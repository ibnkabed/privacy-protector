# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-03

A major update. It reads version 1's data folder, keeps your rules and apps, and asks once what you want
to protect before it changes anything.

### Added

- **Your choice of what is protected.** Settings has a switch for every part: phone protection, PC
  protection, device access (with a switch per kind: microphone, camera, location, contacts), Outlook mail,
  Windows Defender, temp cleanup and AI review. Each works at once and, when turned off, stops and undoes
  what it changed in Windows. A first-run wizard asks whether to protect the phone, the PC, both, or nothing.
- **PC protection.** The PC's own DNS goes through the engine; each domain is tied to the program that asked
  for it (Windows DNS client log and TCP table); a safety gate keeps what programs need open; a watchdog falls
  back to a public resolver within a minute if the engine stops.
- **Device access monitoring** from Windows' own access log and live microphone sessions, with a verdict per
  program and per kind of access.
- **Optional AI review** with providers you add (OpenAI-compatible or Anthropic) and your own keys: a writer
  reads, a jury decides, a judge confirms; daily limits per provider; built-in protection rules always win.
- **Trusted hosts, programs and apps** you list in Settings are never blocked or flagged.
- **Outlook mail checking**, **Windows Defender status** with download scans, and a **daily temp cleanup**,
  each off until you turn it on.
- **A new dashboard**: programs and apps as planets around the engine, coloured by whether anything intrusive
  still gets through; a tray light with the same state.
- **Arabic interface** with right-to-left layout, alongside English (the default).
- **Windows installer and `PrivacyProtector.exe`**, built on GitHub Actions from this repository, with
  checksums; the uninstaller undoes every Windows change, including version 1's firewall rules.
- `Uninstall-Privacy-Protector.ps1` for source checkouts.

### Changed

- The dashboard refuses requests naming another host (DNS rebinding) and needs a per-run session token for
  every change (CSRF).
- The DNS engine listens on the network only while phone protection is on, on this PC only while PC
  protection alone is on, and nowhere while both are off.
- The default DNS port is 53.

### Removed

- The classic dashboard, the Edge launcher, the VBS and CMD launchers, the desktop-shortcut script and
  `Prepare-iPhone-Connection.ps1`; Settings and the installer replace them.

## Before 2.0

Version 1 (September 2026) was a phone-only DNS monitor for an iPhone, with a classic dashboard. Version 2
replaced it and is the only supported version.
