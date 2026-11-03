"""Import an Apple App Privacy Report (NDJSON) into Privacy Protector.

Mirrors the dashboard import flow in web/orbit-panels.js (loadReport): it parses the
report's networkActivity rows, links every observed domain to every app
(bundleID) that contacted it — including domains shared by many apps — and
saves the result through the running backend (/api/apps/discovered) so the
attribution column keeps the full list of apps per domain.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

# Mirror of knownAppNames in web/orbit-panels.js — reports only carry bundle IDs.
KNOWN_APP_NAMES = {
    "com.google.chrome.ios": "Google Chrome",
    "com.apple.mobilesafari": "Safari",
    "com.apple.appstore": "App Store",
    "com.apple.preferences": "Settings",
    "com.apple.mobilemail": "Email",
    "com.apple.mobilesms": "Messages",
    "com.apple.maps": "Maps",
    "com.apple.camera": "Camera",
    "com.apple.mobileslideshow": "Pictures",
    "com.openai.chat": "ChatGPT",
    "com.whatsapp.whatsapp": "WhatsApp",
    "com.google.ios.youtube": "YouTube",
    "com.google.gmail": "Gmail",
    "com.apple.health": "Apple Health",
    "com.huawei.global.health": "HUAWEI Health",
    "kookybread.me": "ME",
    "com.iaugus.health": "Valens",
    "com.lean.tetamn": "Sehhaty",
}

# Same batching contract as web/orbit-panels.js (REPORT_APP_DOMAIN_CHUNK /
# REPORT_IMPORT_REQUEST_LIMIT) so requests stay below the server body limit.
REPORT_APP_DOMAIN_CHUNK = 100
REPORT_IMPORT_REQUEST_LIMIT = 96 * 1024


def normalize_domain(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def detected_name(bundle_id: str) -> str:
    return KNOWN_APP_NAMES.get(bundle_id.lower()) or bundle_id


def _parse_time(value: Any) -> float:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def parse_report(path: Path) -> dict[str, Any]:
    """Read the NDJSON report and link each domain to all apps that used it."""
    discovered: dict[str, dict[str, Any]] = {}
    attributions: dict[tuple[str, str], dict[str, Any]] = {}
    stats = {"rows": 0, "invalid": 0, "skipped": 0, "networkRows": 0}

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                stats["invalid"] += 1
                continue
            if not isinstance(row, dict):
                stats["invalid"] += 1
                continue
            stats["rows"] += 1
            if row.get("type") != "networkActivity":
                continue
            stats["networkRows"] += 1
            bundle_id = str(row.get("bundleID") or "").strip()
            domain = normalize_domain(row.get("domain"))
            if not bundle_id or not domain:
                stats["skipped"] += 1
                continue

            stamp = str(row.get("timeStamp") or "")
            stamp_ts = _parse_time(stamp)
            key = bundle_id.lower()

            app = discovered.setdefault(
                key,
                {
                    "bundleID": bundle_id,
                    "name": detected_name(bundle_id),
                    "domains": set(),
                    "lastSeen": stamp,
                    "_lastSeenTs": stamp_ts,
                },
            )
            app["domains"].add(domain)
            if stamp_ts >= app["_lastSeenTs"]:
                app["_lastSeenTs"] = stamp_ts
                app["lastSeen"] = stamp

            attribution_key = (key, domain)
            current = attributions.get(attribution_key)
            if current is None or stamp_ts >= current["_ts"]:
                attributions[attribution_key] = {
                    "domain": domain,
                    "bundleID": bundle_id,
                    "appName": detected_name(bundle_id),
                    "processName": "",
                    "observedAt": stamp,
                    "_ts": stamp_ts,
                }

    stats["domains"] = len({domain for _, domain in attributions})
    stats["apps"] = len(discovered)
    domain_apps: dict[str, set[str]] = {}
    for bundle_key, domain in attributions:
        domain_apps.setdefault(domain, set()).add(bundle_key)
    stats["sharedDomains"] = {
        domain: sorted(apps)
        for domain, apps in domain_apps.items()
        if len(apps) > 1
    }
    return {"discovered": discovered, "attributions": attributions, "stats": stats}
def build_discovered_batches(
    apps: list[dict[str, Any]], attributions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Chunk and size-limit payloads exactly like buildDiscoveredBatches()."""
    app_parts: list[dict[str, Any]] = []
    for app in apps:
        domains = app.get("domains", [])
        if not domains:
            app_parts.append({**app, "domains": []})
            continue
        for index in range(0, len(domains), REPORT_APP_DOMAIN_CHUNK):
            app_parts.append(
                {**app, "domains": domains[index : index + REPORT_APP_DOMAIN_CHUNK]}
            )
    return _sized_batches(app_parts, "apps") + _sized_batches(
        attributions, "attributions"
    )


def _utf8_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def _sized_batches(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    batches: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for item in items:
        candidate = current + [item]
        payload = {
            "apps": candidate if key == "apps" else [],
            "attributions": candidate if key == "attributions" else [],
        }
        if current and _utf8_size(payload) > REPORT_IMPORT_REQUEST_LIMIT:
            batches.append(
                {
                    "apps": current if key == "apps" else [],
                    "attributions": current if key == "attributions" else [],
                }
            )
            current = [item]
        else:
            current = candidate
    if current:
        batches.append(
            {
                "apps": current if key == "apps" else [],
                "attributions": current if key == "attributions" else [],
            }
        )
    return batches


def post_batch(server: str, batch: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(batch, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{server.rstrip('/')}/api/apps/discovered",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise SystemExit(f"Failed to save batch ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"Cannot connect to server {server}: {exc.reason}. Start the app first."
        ) from exc


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Path to Apple Privacy Report NDJSON file")
    parser.add_argument(
        "--server", default="http://127.0.0.1:8733", help="App server address"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze only without saving",
    )
    args = parser.parse_args()

    if not args.report.exists():
        print(f"File not found: {args.report}", file=sys.stderr)
        return 1

    parsed = parse_report(args.report)
    stats = parsed["stats"]
    discovered_apps = [
        {
            "bundleID": app["bundleID"],
            "name": app["name"],
            "domains": sorted(app["domains"]),
            "lastSeen": app["lastSeen"],
        }
        for app in parsed["discovered"].values()
    ]
    attribution_events = [
        {key: value for key, value in event.items() if key != "_ts"}
        for event in parsed["attributions"].values()
    ]

    print(f"File records: {stats['rows']} (network: {stats['networkRows']}, "
          f"skipped: {stats['skipped']}, invalid: {stats['invalid']})")
    print(f"Unique domains: {stats['domains']} • Apps: {stats['apps']} • "
          f"Attribution proofs (domain×app): {len(attribution_events)}")
    shared = stats["sharedDomains"]
    print(f"Domains shared across multiple apps: {len(shared)}")
    for domain, apps in sorted(shared.items(), key=lambda item: -len(item[1]))[:15]:
        names = [parsed["discovered"][key]["name"] for key in apps]
        print(f"  {domain} ← {', '.join(names)}")

    if args.dry_run:
        print("Dry-run mode — nothing saved.")
        return 0

    batches = build_discovered_batches(discovered_apps, attribution_events)
    saved = 0
    for index, batch in enumerate(batches, start=1):
        result = post_batch(args.server, batch)
        saved += int(result.get("savedAttributions") or 0)
        print(f"Batch {index}/{len(batches)}: "
              f"{len(batch['apps'])} apps, {len(batch['attributions'])} proofs — saved {saved}")
    print(f"Import complete: {saved} attribution proofs saved in the app column.")
    return 0
if __name__ == "__main__":
    sys.exit(main())
