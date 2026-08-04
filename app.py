from __future__ import annotations
import argparse
import json
import logging
import os
import re
import shutil
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from domain_classifier import DomainClassificationEngine
from dns_engine import DEFAULT_FALLBACK_UPSTREAM, DEFAULT_PRIMARY_UPSTREAM, MAX_DNS_MESSAGE, MAX_UDP_MESSAGE, DNSCache, Resolver, error_response, normalize_domain, question_details
from privacy_control import PrivacyControlStore, analyze_syslog
APP_ROOT = Path(__file__).resolve().parent
WEB_ROOT = APP_ROOT / 'web'
DATA_ROOT = Path(os.environ.get('PRIVACY_PROTECTOR_DATA_DIR', str(Path(os.environ.get('LOCALAPPDATA', APP_ROOT)) / 'PrivacyProtector' / 'data'))).expanduser().resolve()
POLICY_PATH = DATA_ROOT / 'policy.json'
APPS_PATH = DATA_ROOT / 'apps.json'
ACTIVITY_PATH = DATA_ROOT / 'dns-activity.ndjson'
ATTRIBUTION_PATH = DATA_ROOT / 'app-attribution.ndjson'
PRIVACY_CONTROLS_PATH = DATA_ROOT / 'privacy-controls.json'
CLASSIFICATIONS_PATH = DATA_ROOT / 'domain-classifications.json'
CAPTURES_ROOT = DATA_ROOT / 'captures' / 'privacy-sessions'
ALLOWED_ACTIONS = {'allow', 'monitor', 'block'}
DEFAULT_UPSTREAM = DEFAULT_PRIMARY_UPSTREAM
KNOWN_PROCESS_NAMES: dict[str, str] = {}
KNOWN_APP_DOMAINS: dict[str, set[str]] = {}
APP_PRIVACY_ENDPOINTS: dict[str, dict[str, str]] = {}
SYSTEM_PROTECTION_DOMAINS: dict[str, list[str]] = {}
APP_PURPOSE_PROFILES = {'com.example.fitness': {'purposeDisplayName': 'Example Fitness', 'purposeKind': 'optional_health_reader', 'purposeRisk': 'orange', 'purposeLabel': 'Optional health application', 'purposeReason': 'Health and fitness access is expected for the selected application purpose.', 'expectedDomainSuffixes': ['fitness.example']}}
BALANCED_PRIVACY_DOMAINS = {
    'ads.example.test': ('Advertising', 'Advertising and conversion measurement'),
    'attribution.example.test': ('Attribution analytics', 'Application installation attribution'),
    'analytics.example.test': ('Product analytics', 'Application event analytics'),
    'crash.example.test': ('Crash diagnostics', 'Crash and stability diagnostics'),
}

class PolicyStore:

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                with self.path.open('r', encoding='utf-8') as handle:
                    data = json.load(handle)
            else:
                data = {'version': 1, 'domains': {}}
            domains = data.setdefault('domains', {})
            normalized: dict[str, Any] = {}
            for domain, settings in domains.items():
                clean = normalize_domain(domain)
                if not clean or not isinstance(settings, dict):
                    continue
                action = settings.get('action', 'monitor')
                if action not in ALLOWED_ACTIONS:
                    action = 'monitor'
                normalized[clean] = {'action': action, 'label': settings.get('label', clean), 'note': settings.get('note', ''), 'source': settings.get('source', 'manual')}
            data['domains'] = normalized
            self.data = data
            if not self.path.exists():
                self.save()

    def save(self) -> None:
        with self.lock:
            temp = self.path.with_suffix('.tmp')
            with temp.open('w', encoding='utf-8', newline='\n') as handle:
                json.dump(self.data, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
            os.replace(temp, self.path)

    def action_for(self, domain: str) -> str:
        with self.lock:
            entry = self.data.get('domains', {}).get(normalize_domain(domain))
            return entry.get('action', 'monitor') if entry else 'monitor'

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.data, ensure_ascii=False))

    def update(self, domain: str, action: str, label: str | None=None, note: str | None=None, source: str | None=None) -> dict[str, Any]:
        clean = normalize_domain(domain)
        if not clean or '.' not in clean:
            raise ValueError('Invalid hostname')
        if action not in ALLOWED_ACTIONS:
            raise ValueError('Invalid action')
        with self.lock:
            domains = self.data.setdefault('domains', {})
            entry = domains.setdefault(clean, {'label': clean, 'note': 'Added from the interface', 'source': source or 'manual'})
            entry['action'] = action
            entry['source'] = source or 'manual'
            if label is not None:
                entry['label'] = str(label).strip()[:120] or clean
            if note is not None:
                entry['note'] = str(note).strip()[:300]
            self.save()
            return json.loads(json.dumps(entry, ensure_ascii=False))

    def activate_balanced_protection(self) -> dict[str, Any]:
        """Add missing exact telemetry rules without overwriting user choices."""
        with self.lock:
            domains = self.data.setdefault('domains', {})
            added = 0
            for domain, (label, note) in BALANCED_PRIVACY_DOMAINS.items():
                clean = normalize_domain(domain)
                if clean in domains:
                    continue
                domains[clean] = {'action': 'block', 'label': label, 'note': note, 'source': 'balanced'}
                added += 1
            balanced = {'enabled': True, 'exactRules': len(BALANCED_PRIVACY_DOMAINS), 'permissionDefaults': {'location': 'deny', 'motion': 'deny', 'tracking': 'deny'}}
            metadata_changed = self.data.get('mode') != 'balanced' or self.data.get('balancedProtection') != balanced
            self.data['mode'] = 'balanced'
            self.data['balancedProtection'] = balanced
            if added or metadata_changed:
                self.save()
            return {'added': added, **self.data['balancedProtection']}

    def delete(self, domain: str) -> bool:
        clean = normalize_domain(domain)
        with self.lock:
            domains = self.data.setdefault('domains', {})
            if clean not in domains:
                return False
            del domains[clean]
            self.save()
            return True

class AppProfileStore:

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {'version': 2, 'apps': [], 'detectedApps': []}
        self.load()

    @staticmethod
    def _clean_profile(profile: dict[str, Any]) -> dict[str, Any]:
        bundle_id = str(profile.get('bundleID') or '').strip()[:180]
        known_domains = KNOWN_APP_DOMAINS.get(bundle_id.lower(), set())
        return {'id': str(profile.get('id') or uuid.uuid4()), 'name': str(profile.get('name') or '').strip()[:80], 'bundleID': bundle_id, 'processName': str(profile.get('processName') or KNOWN_PROCESS_NAMES.get(bundle_id.lower(), '')).strip()[:120], 'confirmedDomains': sorted({normalize_domain(str(value)) for value in profile.get('confirmedDomains', []) if normalize_domain(str(value))}), 'observedDomains': sorted({normalize_domain(str(value)) for value in profile.get('observedDomains', []) if normalize_domain(str(value))} | known_domains), 'createdAt': str(profile.get('createdAt') or datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'))}

    @staticmethod
    def _clean_detected(app: dict[str, Any]) -> dict[str, Any]:
        bundle_id = str(app.get('bundleID') or '').strip()[:180]
        raw_sources = app.get('sources')
        if not isinstance(raw_sources, list):
            raw_sources = [app.get('source') or 'report']
        return {'bundleID': bundle_id, 'name': str(app.get('name') or bundle_id).strip()[:80], 'processName': str(app.get('processName') or KNOWN_PROCESS_NAMES.get(bundle_id.lower(), '')).strip()[:120], 'domains': sorted({normalize_domain(str(value)) for value in app.get('domains', [])[:2000] if normalize_domain(str(value))}), 'lastSeen': str(app.get('lastSeen') or datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')), 'sources': sorted({str(value).strip().lower() for value in raw_sources if str(value).strip().lower() in {'report', 'device'}} or {'report'})}

    def load(self) -> None:
        with self.lock:
            if self.path.exists():
                with self.path.open('r', encoding='utf-8') as handle:
                    raw = json.load(handle)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                raw = {'version': 2, 'apps': [], 'detectedApps': []}
            profiles = []
            seen_ids = set()
            for item in raw.get('apps', []):
                clean = self._clean_profile(item)
                if not clean['name'] or clean['id'] in seen_ids:
                    continue
                seen_ids.add(clean['id'])
                profiles.append(clean)
            detected = []
            seen_bundles = set()
            for item in raw.get('detectedApps', []):
                clean = self._clean_detected(item)
                bundle_key = clean['bundleID'].lower()
                if not bundle_key or bundle_key in seen_bundles:
                    continue
                seen_bundles.add(bundle_key)
                detected.append(clean)
            detected_by_bundle = {item['bundleID'].lower(): item for item in detected}
            for profile in profiles:
                detected_app = detected_by_bundle.get(profile['bundleID'].lower())
                if detected_app:
                    profile['confirmedDomains'] = sorted(set(profile['confirmedDomains']) | set(detected_app.get('domains', [])))
            self.data = {'version': 2, 'apps': profiles, 'detectedApps': detected}
            self.save()

    def save(self) -> None:
        with self.lock:
            temp = self.path.with_suffix('.tmp')
            with temp.open('w', encoding='utf-8', newline='\n') as handle:
                json.dump(self.data, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
            os.replace(temp, self.path)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            snapshot = json.loads(json.dumps(self.data, ensure_ascii=False))
        for collection in (snapshot.get('apps', []), snapshot.get('detectedApps', [])):
            for item in collection:
                purpose = APP_PURPOSE_PROFILES.get(str(item.get('bundleID') or '').lower())
                if purpose:
                    item.update(json.loads(json.dumps(purpose, ensure_ascii=False)))
        return snapshot

    def add(self, name: str, bundle_id: str='', process_name: str='') -> dict[str, Any]:
        clean_name = str(name).strip()[:80]
        clean_bundle = str(bundle_id).strip()[:180]
        if not clean_name:
            raise ValueError('Application name is required')
        with self.lock:
            detected_match = next((item for item in self.data.get('detectedApps', []) if clean_bundle and str(item.get('bundleID', '')).lower() == clean_bundle.lower()), None)
            if clean_bundle:
                for item in self.data['apps']:
                    if item.get('bundleID', '').lower() == clean_bundle.lower():
                        raise ValueError('The application identifier is already monitored')
            profile = self._clean_profile({'id': str(uuid.uuid4()), 'name': clean_name, 'bundleID': clean_bundle, 'processName': str(process_name or (detected_match or {}).get('processName', '') or KNOWN_PROCESS_NAMES.get(clean_bundle.lower(), '')).strip()[:120], 'confirmedDomains': (detected_match or {}).get('domains', []), 'observedDomains': []})
            self.data['apps'].append(profile)
            self.save()
            return json.loads(json.dumps(profile, ensure_ascii=False))

    def delete(self, profile_id: str) -> bool:
        with self.lock:
            before = len(self.data['apps'])
            self.data['apps'] = [item for item in self.data['apps'] if item.get('id') != profile_id]
            changed = len(self.data['apps']) != before
            if changed:
                self.save()
            return changed

    def get(self, profile_id: str) -> dict[str, Any] | None:
        with self.lock:
            for item in self.data['apps']:
                if item.get('id') == profile_id:
                    return json.loads(json.dumps(item, ensure_ascii=False))
        return None

    def get_by_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        clean_bundle = str(bundle_id).strip().lower()
        with self.lock:
            for item in self.data['apps']:
                if str(item.get('bundleID', '')).lower() == clean_bundle:
                    return json.loads(json.dumps(item, ensure_ascii=False))
        return None

    def resolve_process(self, process_name: str) -> dict[str, Any] | None:
        """Resolve exact iOS packet/syslog process metadata to one installed app."""
        clean = str(process_name or '').strip().lower()
        if not clean:
            return None

        def normalized(value: Any) -> str:
            return re.sub('[^a-z0-9]+', '', str(value or '').lower())
        with self.lock:
            candidates = list(self.data.get('detectedApps', [])) + list(self.data.get('apps', []))
            exact = [item for item in candidates if str(item.get('processName', '')).strip().lower() == clean]
            if len(exact) == 1:
                return json.loads(json.dumps(exact[0], ensure_ascii=False))
            compact = normalized(clean)
            inferred = []
            for item in candidates:
                bundle_tail = str(item.get('bundleID', '')).rsplit('.', 1)[-1]
                values = {normalized(item.get('name', '')), normalized(bundle_tail)}
                values.discard('')
                if compact in values:
                    inferred.append(item)
            unique = {str(item.get('bundleID', '')).lower(): item for item in inferred}
            if len(unique) == 1:
                return json.loads(json.dumps(next(iter(unique.values())), ensure_ascii=False))
        return None

    def add_domains(self, profile_id: str, domains: list[str], source: str) -> dict[str, Any]:
        if source not in {'confirmed', 'observed'}:
            raise ValueError('Invalid hostname source')
        field = 'confirmedDomains' if source == 'confirmed' else 'observedDomains'
        clean_domains = {normalize_domain(str(value)) for value in domains[:2000] if normalize_domain(str(value))}
        with self.lock:
            for item in self.data['apps']:
                if item.get('id') == profile_id:
                    item[field] = sorted(set(item.get(field, [])) | clean_domains)
                    self.save()
                    return json.loads(json.dumps(item, ensure_ascii=False))
        raise ValueError('Application not found')

    def merge_detected(self, apps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        with self.lock:
            indexed = {str(item.get('bundleID', '')).lower(): item for item in self.data.get('detectedApps', [])}
            for raw in apps[:500]:
                if not isinstance(raw, dict):
                    continue
                clean = self._clean_detected(raw)
                key = clean['bundleID'].lower()
                if not key:
                    continue
                current = indexed.get(key)
                if current:
                    current['domains'] = sorted(set(current.get('domains', [])) | set(clean['domains']))
                    if clean['name'] and clean['name'] != clean['bundleID']:
                        current['name'] = clean['name']
                    if clean['processName']:
                        current['processName'] = clean['processName']
                    current['lastSeen'] = clean['lastSeen']
                    current['sources'] = sorted(set(current.get('sources', [])) | set(clean['sources']))
                else:
                    self.data.setdefault('detectedApps', []).append(clean)
                    indexed[key] = clean
            self.data['detectedApps'].sort(key=lambda item: (str(item.get('name', '')).lower(), item['bundleID']))
            self.save()
            return json.loads(json.dumps(self.data['detectedApps'], ensure_ascii=False))

def scan_paired_iphone_apps() -> dict[str, Any]:
    tool = _mobiledevice_tool()
    if not tool:
        return {'ok': False, 'code': 'tool_missing', 'error': 'Install the local iPhone connector first.'}
    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        pair_record = _pair_record_path()
        if not pair_record:
            raise ValueError('The iPhone pairing record is unavailable')
        host = _discover_iphone_host(tool)
        interpreter = tool.parent / 'python.exe'
        if not interpreter.exists():
            interpreter = Path(sys.executable)
        result = subprocess.run([str(interpreter), str(APP_ROOT / 'tools' / 'list_ios_apps.py'), '--host', host, '--pair-record', str(pair_record)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=45, creationflags=creation_flags, check=False, cwd=str(APP_ROOT), env={**os.environ, 'PYTHONUTF8': '1'})
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
        return {'ok': False, 'code': 'device_unavailable', 'error': f'Unable to read applications from the paired iPhone: {exc}'}
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or '').strip().splitlines()
        return {'ok': False, 'code': 'device_unavailable', 'error': 'Unable to read applications from the paired iPhone.', 'detail': detail[-1][:300] if detail else ''}
    output = result.stdout.strip()
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        starts = [position for position in (output.find('{'), output.find('[')) if position >= 0]
        if not starts:
            return {'ok': False, 'code': 'invalid_output', 'error': 'The iPhone application inventory returned invalid output.'}
        try:
            payload = json.loads(output[min(starts):])
        except json.JSONDecodeError:
            return {'ok': False, 'code': 'invalid_output', 'error': 'The iPhone application inventory returned invalid output.'}
    apps = []
    for metadata in payload[:2000] if isinstance(payload, list) else []:
        if not isinstance(metadata, dict):
            continue
        bundle_id = str(metadata.get('bundleID') or '').strip()
        if not bundle_id:
            continue
        name = str(metadata.get('name') or bundle_id).strip()
        process_name = str(metadata.get('processName') or '').strip()
        apps.append({'bundleID': bundle_id, 'name': name, 'processName': process_name, 'domains': [], 'source': 'device'})
    return {'ok': True, 'apps': apps, 'count': len(apps)}

class ActivityLog:

    def __init__(self, limit: int=10000, path: Path | None=None, rotation_bytes: int=20 * 1024 * 1024):
        self.items: deque[dict[str, Any]] = deque(maxlen=limit)
        self.lock = threading.Lock()
        self.path = path
        self.rotation_bytes = max(1, int(rotation_bytes))
        self.sequence = 0
        self.counts = {'monitored': 0, 'allowed': 0, 'blocked': 0, 'error': 0}
        self.corrupt_lines = 0
        self.rotation_count = 0
        self._load()

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return
        for line_number, line in enumerate(lines[-self.items.maxlen:], start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError('Activity row is not an object')
                self.sequence = max(self.sequence, int(item.get('id', 0)), line_number)
                self.items.appendleft(item)
                action = str(item.get('action', ''))
                if action in self.counts:
                    self.counts[action] += 1
            except (ValueError, TypeError, json.JSONDecodeError):
                self.corrupt_lines += 1

    def add(self, **item: Any) -> None:
        item.setdefault('time', datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'))
        with self.lock:
            self.sequence += 1
            item['id'] = self.sequence
            self.items.appendleft(item)
            action = str(item.get('action', ''))
            if action in self.counts:
                self.counts[action] += 1
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.rotation_bytes:
                    rotated = self.path.with_suffix('.previous.ndjson')
                    os.replace(self.path, rotated)
                    self.rotation_count += 1
                with self.path.open('a', encoding='utf-8', newline='\n') as handle:
                    handle.write(json.dumps(item, ensure_ascii=False) + '\n')
                    handle.flush()

    def snapshot(self, limit: int=80, after_id: int | None=None) -> list[dict[str, Any]]:
        with self.lock:
            if after_id is not None:
                ordered = reversed(self.items)
                return [item for item in ordered if int(item.get('id', 0)) > after_id][:limit]
            return list(self.items)[:limit]

    def summary(self) -> dict[str, Any]:
        with self.lock:
            return {'lastEventId': self.sequence, 'storedEvents': len(self.items), 'counts': dict(self.counts), 'corruptLines': self.corrupt_lines, 'rotations': self.rotation_count}

    def domain_stats(self) -> dict[str, dict[str, Any]]:
        """Return durable per-domain observation and block timing for the UI."""
        with self.lock:
            stats: dict[str, dict[str, Any]] = {}
            for item in self.items:
                domain = normalize_domain(str(item.get('domain', '')))
                if not domain:
                    continue
                entry = stats.setdefault(domain, {'observedCount': 0, 'blockedCount': 0, 'lastObservedAt': '', 'lastBlockedAt': '', 'lastAction': ''})
                entry['observedCount'] += 1
                action = str(item.get('action', ''))
                observed_at = str(item.get('time', ''))
                if not entry['lastObservedAt']:
                    entry['lastObservedAt'] = observed_at
                    entry['lastAction'] = action
                if action == 'blocked':
                    entry['blockedCount'] += 1
                    if not entry['lastBlockedAt']:
                        entry['lastBlockedAt'] = observed_at
            return stats

    def clear(self) -> dict[str, Any]:
        with self.lock:
            removed = len(self.items)
            self.items.clear()
            self.counts = {'monitored': 0, 'allowed': 0, 'blocked': 0, 'error': 0}
            self.corrupt_lines = 0
            if self.path:
                candidates = [self.path, self.path.with_suffix('.previous.ndjson')]
                for candidate in candidates:
                    try:
                        candidate.unlink(missing_ok=True)
                    except OSError:
                        pass
            return {'removed': removed, 'lastEventId': self.sequence}

class AppAttributionLog:
    """Persistent evidence linking a DNS domain to an iOS process."""

    def __init__(self, path: Path, limit: int=10000):
        self.path = path
        self.items: deque[dict[str, Any]] = deque(maxlen=limit)
        self.lock = threading.RLock()
        self.sequence = 0
        self.last_signatures: dict[tuple[str, ...], float] = {}
        self._load()

    @staticmethod
    def _signature(event: dict[str, Any]) -> tuple[str, ...]:
        return (str(event.get('type') or ''), normalize_domain(str(event.get('domain') or '')), str(event.get('processName') or '').strip().lower(), str(event.get('bundleID') or '').strip().lower())

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return
        for line in lines[-self.items.maxlen:]:
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or item.get('type') != 'appDomain':
                    continue
                self.sequence = max(self.sequence, int(item.get('id', 0)))
                self.items.appendleft(item)
                observed_at = str(item.get('observedAt') or '')
                try:
                    event_time = datetime.fromisoformat(observed_at.replace('Z', '+00:00')).timestamp()
                except ValueError:
                    event_time = 0.0
                if event_time:
                    signature = self._signature(item)
                    self.last_signatures[signature] = max(event_time, self.last_signatures.get(signature, 0.0))
            except (ValueError, TypeError, json.JSONDecodeError):
                continue

    def add(self, event: dict[str, Any]) -> dict[str, Any] | None:
        kind = str(event.get('type') or '')
        if kind != 'appDomain':
            return None
        domain = normalize_domain(str(event.get('domain') or ''))
        process_name = str(event.get('processName') or '').strip()[:120]
        if not domain:
            return None
        observed_at = str(event.get('observedAt') or '').strip()
        if not observed_at:
            observed_at = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
        try:
            event_time = datetime.fromisoformat(observed_at.replace('Z', '+00:00')).timestamp()
        except ValueError:
            event_time = time.time()
            observed_at = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
        signature = self._signature({**event, 'type': kind, 'domain': domain, 'processName': process_name})
        with self.lock:
            previous = self.last_signatures.get(signature, 0.0)
            if abs(event_time - previous) < 1.0:
                return None
            self.last_signatures[signature] = event_time
            self.sequence += 1
            clean = {'id': self.sequence, 'type': kind, 'observedAt': observed_at, 'domain': domain, 'qtypeName': str(event.get('qtypeName') or '')[:16], 'transport': str(event.get('transport') or '')[:16], 'processName': process_name, 'pid': max(0, int(event.get('pid') or 0)), 'bundleID': str(event.get('bundleID') or '').strip()[:180], 'appName': str(event.get('appName') or '').strip()[:80], 'source': str(event.get('source') or 'local-evidence').strip()[:40], 'confidence': str(event.get('confidence') or 'evidence').strip()[:40]}
            self.items.appendleft(clean)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open('a', encoding='utf-8', newline='\n') as handle:
                handle.write(json.dumps(clean, ensure_ascii=False) + '\n')
            return json.loads(json.dumps(clean, ensure_ascii=False))

    def snapshot(self, limit: int=2000) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.items)[:max(1, min(int(limit), 5000))]

    def summary(self) -> dict[str, Any]:
        with self.lock:
            exact_apps = {str(item.get('bundleID') or item.get('processName') or '') for item in self.items if item.get('type') == 'appDomain' and (item.get('bundleID') or item.get('processName'))}
            return {'events': len(self.items), 'lastEventId': self.sequence, 'attributedApps': len(exact_apps)}

class UDPDNSHandler(socketserver.BaseRequestHandler):
    resolver: Resolver

    def handle(self) -> None:
        packet, connection = self.request
        if not packet or len(packet) > MAX_UDP_MESSAGE:
            answer = error_response(packet, 1)
        else:
            answer = self.resolver.resolve(packet, self.client_address[0], 'udp')
        connection.sendto(answer, self.client_address)

class TCPDNSHandler(socketserver.BaseRequestHandler):
    resolver: Resolver

    @staticmethod
    def _read_exact(connection: Any, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = connection.recv(size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)

    def handle(self) -> None:
        length_raw = self._read_exact(self.request, 2)
        if len(length_raw) != 2:
            return
        packet_size = struct.unpack('!H', length_raw)[0]
        if packet_size < 12 or packet_size > MAX_DNS_MESSAGE:
            return
        packet = self._read_exact(self.request, packet_size)
        if len(packet) != packet_size:
            return
        answer = self.resolver.resolve(packet, self.client_address[0], 'tcp')
        self.request.sendall(struct.pack('!H', len(answer)) + answer)

class ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = False
    daemon_threads = True
    request_queue_size = 128

class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

def _mobiledevice_tool() -> Path | None:
    candidate = APP_ROOT / '.venv' / 'Scripts' / 'pymobiledevice3.exe'
    if candidate.exists():
        return candidate
    found = shutil.which('pymobiledevice3')
    return Path(found) if found else None

def _pair_record_path() -> Path | None:
    folder = Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData')) / 'Apple' / 'Lockdown'
    records = [path for path in folder.glob('*.plist') if path.name.lower() != 'systemconfiguration.plist']
    return max(records, key=lambda path: path.stat().st_mtime) if records else None

def _discover_iphone_host(tool: Path) -> str:
    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    result = subprocess.run([str(tool), '--no-color', 'bonjour', 'mobdev2'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=10, creationflags=creation_flags, check=False, env={**os.environ, 'PYTHONUTF8': '1'})
    output = (result.stdout or '').strip()
    start = output.find('[')
    end = output.rfind(']')
    if start < 0 or end < start:
        raise ValueError('No paired iPhone service was discovered.')
    devices = json.loads(output[start:end + 1])
    for device in devices:
        host = str(device.get('ip') or device.get('Identifier') or '').strip()
        if host:
            return host
    raise ValueError('No reachable paired iPhone was discovered.')

def check_iphone_developer_mode() -> dict[str, Any]:
    """Read Developer Mode from the paired iPhone without changing it."""
    tool = _mobiledevice_tool()
    pair_record = _pair_record_path()
    if not tool or not pair_record:
        return {'ok': False, 'code': 'connector_unavailable', 'error': 'The required local component is unavailable.'}
    try:
        host = _discover_iphone_host(tool)
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError) as exc:
        return {'ok': False, 'code': 'device_unavailable', 'error': str(exc) or 'Unable to discover the paired iPhone.'}
    interpreter = tool.parent / 'python.exe'
    if not interpreter.exists():
        interpreter = Path(sys.executable)
    helper = APP_ROOT / 'tools' / 'check_ios_developer_mode.py'
    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        result = subprocess.run([str(interpreter), str(helper), '--host', host, '--pair-record', str(pair_record)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20, creationflags=creation_flags, check=False, cwd=str(APP_ROOT), env={**os.environ, 'PYTHONUTF8': '1'})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'ok': False, 'code': 'device_unavailable', 'error': f'Unable to read Developer Mode status: {exc}'}
    output = (result.stdout or '').strip()
    try:
        payload = json.loads(output.splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        payload = {'ok': False, 'code': 'invalid_output', 'error': 'The Developer Mode helper returned invalid output.'}
    if not isinstance(payload, dict):
        payload = {'ok': False, 'code': 'invalid_output', 'error': 'The Developer Mode helper returned invalid output.'}
    if not payload.get('ok') and (not payload.get('error')):
        detail = (result.stderr or '').strip().splitlines()
        payload['error'] = detail[-1][:300] if detail else 'Unable to read Developer Mode status.'
    return payload

def sync_system_protection(policy: PolicyStore, bundle_id: str, app_name: str, mode: str) -> list[dict[str, Any]]:
    clean_bundle = str(bundle_id).strip().lower()
    clean_mode = str(mode).strip().lower()
    if clean_mode not in {'monitor', 'block'}:
        clean_mode = 'monitor'
    domains = SYSTEM_PROTECTION_DOMAINS.get(clean_bundle, [])
    if clean_mode == 'block' and (not domains):
        raise ValueError('No reviewed system-protection hostnames are configured for this application.')
    rules = []
    for domain in domains:
        action = 'block' if clean_mode == 'block' else 'monitor'
        entry = policy.update(domain, action, label=f'System protection: {app_name}', note='Reviewed system-protection hostname selected by the user.')
        rules.append({'domain': domain, 'action': action, 'entry': entry})
    return rules

def enforce_privacy_containment(policy: PolicyStore, bundle_id: str, app_name: str, control: dict[str, Any], candidate_domains: list[str] | None=None) -> dict[str, Any]:
    desired = control.get('desired', {})
    evaluation = control.get('evaluation', {})
    violations = sorted((key for key, item in evaluation.items() if item.get('verdict') == 'violation'))
    requested_automatic = desired.get('containment', 'monitor') == 'auto_block'
    result = {'enabled': False, 'mode': 'manual', 'automaticRequested': requested_automatic, 'triggered': False, 'evidenceDetected': bool(violations), 'violations': violations, 'blockedDomains': [], 'allowedExceptions': [], 'recommendedDomains': [], 'limitedToNetwork': True}
    if not violations:
        return result
    endpoints = dict(APP_PRIVACY_ENDPOINTS.get(str(bundle_id).lower(), {}))
    for domain in candidate_domains or []:
        clean = normalize_domain(str(domain))
        if clean in BALANCED_PRIVACY_DOMAINS:
            endpoints.setdefault(clean, BALANCED_PRIVACY_DOMAINS[clean][1])
    result['recommendedDomains'] = sorted(endpoints)
    current_rules = policy.snapshot().get('domains', {})
    for domain in endpoints:
        current = current_rules.get(domain, {})
        if current.get('action') in {'allow', 'monitor'}:
            result['allowedExceptions'].append(domain)
        elif current.get('action') == 'block':
            result['blockedDomains'].append(domain)
    return result

def apply_stored_containment(policy: PolicyStore, controls: PrivacyControlStore, profiles: AppProfileStore) -> list[dict[str, Any]]:
    return []

class PrivacyCaptureManager:

    def __init__(self, controls: PrivacyControlStore):
        self.controls = controls
        self.lock = threading.RLock()
        self.processes: list[subprocess.Popen[str]] = []
        self.stderr_handles: list[Any] = []
        self.session: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            active = any((process.poll() is None for process in self.processes))
            if self.session is None:
                return {'active': False}
            return {**json.loads(json.dumps(self.session, ensure_ascii=False)), 'active': active}

    def start(self, profile: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            if any((process.poll() is None for process in self.processes)):
                raise ValueError('A privacy evidence capture is already running.')
            bundle_id = str(profile.get('bundleID') or '').strip()
            process_name = str(profile.get('processName') or KNOWN_PROCESS_NAMES.get(bundle_id.lower(), '')).strip()
            if not bundle_id:
                raise ValueError('An application identifier is required to start a capture.')
            if not process_name:
                raise ValueError('A process name is required to start a capture.')
            tool = _mobiledevice_tool()
            pair_record = _pair_record_path()
            if not tool or not pair_record:
                raise ValueError('The required local component is unavailable.')
            host = _discover_iphone_host(tool)
            interpreter = tool.parent / 'python.exe'
            if not interpreter.exists():
                interpreter = Path(sys.executable)
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            slug = re.sub('[^a-zA-Z0-9._-]+', '-', bundle_id).strip('-')[:80]
            session_dir = CAPTURES_ROOT / f'{timestamp}-{slug}'
            session_dir.mkdir(parents=True, exist_ok=True)
            log_path = session_dir / 'syslog.txt'
            system_log_path = session_dir / 'system-syslog.txt'
            helper = str(APP_ROOT / 'tools' / 'capture_ios_process_syslog_network.py')
            common = [str(interpreter), helper, '--host', host, '--pair-record', str(pair_record)]
            commands = [(common + ['--process-name', process_name, '--out', str(log_path)], session_dir / 'capture-stderr.txt'), (common + ['--all-processes', '--out', str(system_log_path)], session_dir / 'system-capture-stderr.txt')]
            self.processes = []
            self.stderr_handles = []
            try:
                for command, stderr_path in commands:
                    stderr_handle = stderr_path.open('w', encoding='utf-8')
                    self.stderr_handles.append(stderr_handle)
                    self.processes.append(subprocess.Popen(command, cwd=str(APP_ROOT), stdout=subprocess.DEVNULL, stderr=stderr_handle, text=True, encoding='utf-8', errors='replace', creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), env={**os.environ, 'PYTHONUTF8': '1'}))
                time.sleep(1.0)
                failed = [process for process in self.processes if process.poll() is not None]
                if failed:
                    details = []
                    for handle in self.stderr_handles:
                        handle.flush()
                        handle.close()
                    for _, stderr_path in commands:
                        details.append(stderr_path.read_text(encoding='utf-8', errors='replace').strip())
                    for process in self.processes:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=3)
                    self.processes = []
                    self.stderr_handles = []
                    raise ValueError(next((detail[-500:] for detail in details if detail), '') or 'The iPhone log capture stopped before it became ready.')
            except Exception:
                for process in self.processes:
                    if process.poll() is None:
                        process.terminate()
                for handle in self.stderr_handles:
                    if not handle.closed:
                        handle.close()
                self.stderr_handles = []
                raise
            self.session = {'bundleID': bundle_id, 'appName': str(profile.get('name') or bundle_id), 'processName': process_name, 'startedAt': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds'), 'logPath': str(log_path.resolve()), 'systemLogPath': str(system_log_path.resolve())}
            (session_dir / 'capture-meta.json').write_text(json.dumps({**self.session, 'host': host}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            return self.snapshot()

    def stop(self) -> dict[str, Any]:
        with self.lock:
            if not self.processes or self.session is None:
                raise ValueError('No privacy evidence capture is running.')
            for process in self.processes:
                if process.poll() is None:
                    process.terminate()
            for process in self.processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for handle in self.stderr_handles:
                if not handle.closed:
                    handle.close()
            log_path = Path(self.session['logPath'])
            result = analyze_syslog(log_path)
            system_result = analyze_syslog(Path(self.session['systemLogPath']))
            result['developerChecks'] = system_result['developerChecks']
            if not result['systemProtection']['detected'] and system_result['systemProtection']['detected']:
                result['systemProtection'] = system_result['systemProtection']
            entry = self.controls.record_result(self.session['bundleID'], self.session['appName'], result)
            response = {**self.session, 'active': False, 'result': result, 'control': entry}
            self.processes = []
            self.stderr_handles = []
            self.session = None
            return response

class IPhoneEvidenceMonitor:
    """Optionally collect exact app attribution for DNS packets over USB."""

    def __init__(self, profiles: AppProfileStore, attributions: AppAttributionLog, classifications: DomainClassificationEngine | None, *, enabled: bool=False):
        self.profiles = profiles
        self.attributions = attributions
        self.classifications = classifications
        self.enabled = bool(enabled)
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.processes: dict[str, subprocess.Popen[str]] = {}
        self.workers: list[threading.Thread] = []
        detail = 'USB packet attribution is waiting to start.' if self.enabled else 'USB packet attribution is disabled by default.'
        self.states: dict[str, dict[str, Any]] = {'packetAttribution': {'state': 'paused', 'detail': detail}}

    def _set_state(self, kind: str, state: str, detail: str='') -> None:
        with self.lock:
            self.states[kind] = {'state': state, 'detail': str(detail).strip()[:240], 'updatedAt': datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {'continuousEnabled': self.enabled, 'continuousKinds': ['packetAttribution'] if self.enabled else [], 'monitorCount': int(self.enabled), **json.loads(json.dumps(self.states, ensure_ascii=False)), 'summary': self.attributions.summary()}

    def start(self) -> None:
        if not self.enabled:
            return
        if self.workers:
            return
        worker = threading.Thread(target=self._worker_loop, name='iphone-packetAttribution', daemon=True)
        self.workers.append(worker)
        worker.start()

    def shutdown(self) -> None:
        self.stop_event.set()
        with self.lock:
            processes = list(self.processes.values())
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for worker in self.workers:
            worker.join(timeout=3)

    def _helper_command(self) -> list[str]:
        tool = _mobiledevice_tool()
        if not tool:
            raise ValueError('The required local component is unavailable.')
        base_executable = Path(getattr(sys, '_base_executable', sys.executable))
        interpreter = base_executable.parent / 'python.exe'
        if not interpreter.exists():
            interpreter = tool.parent / 'python.exe'
        return [str(interpreter), str(APP_ROOT / 'tools' / 'watch_ios_dns_attribution.py')]

    def _handle_event(self, payload: dict[str, Any]) -> None:
        if payload.get('type') == 'status':
            return
        process_name = str(payload.get('processName') or '').strip()
        app = self.profiles.resolve_process(process_name)
        if app:
            payload['bundleID'] = str(app.get('bundleID') or '')
            payload['appName'] = str(app.get('name') or process_name)
        elif process_name:
            payload['appName'] = process_name
            payload['confidence'] = 'exact-process-unmapped'
        saved = self.attributions.add(payload)
        if not saved or not self.classifications:
            return
        self.classifications.observe(saved['domain'], qtype=saved.get('qtypeName', ''), transport=f"ios-{saved.get('transport', '')}".strip('-'), app_context=saved.get('appName', ''), app_bundle=saved.get('bundleID', ''), observed_at=saved.get('observedAt', ''), schedule=False)

    def _worker_loop(self) -> None:
        kind = 'packetAttribution'
        retry_seconds = 30
        while not self.stop_event.is_set():
            try:
                command = self._helper_command()
                process = subprocess.Popen(command, cwd=str(APP_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), env={**os.environ, 'PYTHONUTF8': '1', 'PYTHONPATH': os.pathsep.join(filter(None, [str(APP_ROOT / '.venv' / 'Lib' / 'site-packages'), str(APP_ROOT / '.venv' / 'Lib' / 'site-packages' / 'win32'), str(APP_ROOT / '.venv' / 'Lib' / 'site-packages' / 'win32' / 'lib'), str(APP_ROOT / '.venv' / 'Lib' / 'site-packages' / 'pythonwin'), os.environ.get('PYTHONPATH', '')]))})
                with self.lock:
                    self.processes[kind] = process
                self._set_state(kind, 'connecting', 'Functional service evidence with no independent confirmed privacy violation.')
                assert process.stdout is not None
                last_helper_output = ''
                for line in process.stdout:
                    if self.stop_event.is_set():
                        break
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        last_helper_output = line.strip()[:180]
                        continue
                    if isinstance(payload, dict):
                        if payload.get('type') == 'status':
                            self._set_state(kind, str(payload.get('state') or 'listening'), str(payload.get('detail') or ''))
                            continue
                        self._handle_event(payload)
                return_code = process.wait(timeout=3)
                if self.stop_event.is_set():
                    break
                self._set_state(kind, 'waiting_for_usb', 'Waiting for an unlocked paired iPhone over USB.')
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self._set_state(kind, 'waiting_for_usb', str(exc))
            finally:
                with self.lock:
                    self.processes.pop(kind, None)
            self.stop_event.wait(retry_seconds)

class AppState:

    def __init__(self, policy: PolicyStore, profiles: AppProfileStore, activity: ActivityLog, controls: PrivacyControlStore, privacy_capture: PrivacyCaptureManager, resolver: Resolver, dns_host: str, dns_port: int, classifications: DomainClassificationEngine | None=None, attributions: AppAttributionLog | None=None, evidence_monitor: IPhoneEvidenceMonitor | None=None):
        self.policy = policy
        self.profiles = profiles
        self.activity = activity
        self.controls = controls
        self.privacy_capture = privacy_capture
        self.resolver = resolver
        self.dns_host = dns_host
        self.dns_port = dns_port
        self.classifications = classifications
        self.attributions = attributions
        self.evidence_monitor = evidence_monitor
        self.started_at = time.time()

class DashboardHandler(SimpleHTTPRequestHandler):
    state: AppState

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        logging.info('dashboard: ' + format, *args)

    def _json(self, payload: Any, status: HTTPStatus=HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(body)

    def _local_request(self) -> bool:
        host = self.headers.get('Host', '').split(':', 1)[0]
        return host in {'127.0.0.1', 'localhost', '[::1]'}

    def _request_path(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urllib.parse.urlparse(self.path)
        return (parsed.path, urllib.parse.parse_qs(parsed.query))

    def _read_json(self, maximum: int=131072) -> dict[str, Any]:
        size = int(self.headers.get('Content-Length', '0'))
        if size <= 0 or size > maximum:
            raise ValueError('Invalid request size')
        value = json.loads(self.rfile.read(size).decode('utf-8'))
        if not isinstance(value, dict):
            raise ValueError('Invalid request format')
        return value

    def do_GET(self) -> None:
        path, query = self._request_path()
        if path == '/':
            self.path = '/Privacy%20Protector.html'
            super().do_GET()
            return
        if path == '/api/health':
            self._json({'ok': True})
            return
        if path == '/api/status':
            policy = self.state.policy.snapshot()
            activity = self.state.activity.summary()
            self._json({'ok': True, 'dnsPort': self.state.dns_port, 'uptimeSeconds': round(time.time() - self.state.started_at), 'blockedDomains': sum((1 for item in policy.get('domains', {}).values() if item.get('action') == 'block')), 'events': activity['storedEvents'], 'lastEventId': activity['lastEventId'], 'eventCounts': activity['counts'], 'corruptLogLines': activity['corruptLines'], 'dnsEngine': self.state.resolver.coverage_snapshot(), 'classificationEngine': self.state.classifications.summary() if self.state.classifications else {'version': 2, 'total': 0}, 'appAttribution': self.state.evidence_monitor.snapshot() if self.state.evidence_monitor else {'packetAttribution': {'state': 'unavailable'}}})
            return
        if path == '/api/dns/coverage':
            self._json(self.state.resolver.coverage_snapshot())
            return
        if path == '/api/policy':
            self._json(self.state.policy.snapshot())
            return
        if path == '/api/classifications':
            if not self.state.classifications:
                self._json({'error': 'The V3 classification engine is unavailable'}, HTTPStatus.SERVICE_UNAVAILABLE)
                return
            domain = str(query.get('domain', [''])[0])
            if domain:
                entry = self.state.classifications.get(domain)
                if entry:
                    self._json({'ok': True, 'entry': entry})
                else:
                    self._json({'error': 'No classification exists for that hostname.'}, HTTPStatus.NOT_FOUND)
                return
            self._json(self.state.classifications.snapshot())
            return
        if path == '/api/apps':
            self._json(self.state.profiles.snapshot())
            return
        if path == '/api/privacy-controls':
            self._json({**self.state.controls.snapshot(), 'capture': self.state.privacy_capture.snapshot()})
            return
        if path == '/api/privacy-capture':
            self._json(self.state.privacy_capture.snapshot())
            return
        if path == '/api/developer-mode/status':
            status = check_iphone_developer_mode()
            self._json(status, HTTPStatus.OK if status.get('ok') else HTTPStatus.SERVICE_UNAVAILABLE)
            return
        if path == '/api/logs':
            try:
                limit = min(max(int(query.get('limit', ['80'])[0]), 1), 2000)
                after_raw = query.get('after', [None])[0]
                after = int(after_raw) if after_raw is not None else None
                requested = limit + 1 if after is not None else limit
                items = self.state.activity.snapshot(requested, after)
                has_more = after is not None and len(items) > limit
                items = items[:limit]
                summary = self.state.activity.summary()
                self._json({'items': items, 'lastEventId': summary['lastEventId'], 'hasMore': has_more, 'domainStats': self.state.activity.domain_stats(), 'attributions': self.state.attributions.snapshot(limit=2000) if self.state.attributions else []})
            except ValueError:
                self._json({'error': 'The supplied value is invalid.'}, HTTPStatus.BAD_REQUEST)
            return
        super().do_GET()

    def do_POST(self) -> None:
        if not self._local_request():
            self._json({'error': 'Local requests only'}, HTTPStatus.FORBIDDEN)
            return
        path, _ = self._request_path()
        try:
            payload = self._read_json()
            if path == '/api/policy':
                domain = str(payload.get('domain', ''))
                action = str(payload.get('action', ''))
                entry = self.state.policy.update(domain, action)
                self.state.resolver.cache.invalidate(domain)
                if self.state.classifications:
                    self.state.classifications.observe(domain, decision=action, label=str(entry.get('label', '')), note=str(entry.get('note', '')))
                self._json({'ok': True, 'entry': entry})
                return
            if path == '/api/classifications/analyze':
                if not self.state.classifications:
                    self._json({'error': 'The V3 classification engine is unavailable'}, HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                result = self.state.classifications.request_analysis(str(payload.get('domain', '')), force=bool(payload.get('force', False)))
                self._json({**result, 'summary': self.state.classifications.summary()})
                return
            if path == '/api/dns/self-test':
                result = self.state.resolver.run_self_test(self.state.dns_host, self.state.dns_port)
                status = HTTPStatus.OK if result.get('state') == 'passed' else HTTPStatus.SERVICE_UNAVAILABLE
                self._json(result, status)
                return
            if path == '/api/apps/discovered':
                apps = payload.get('apps', [])
                if not isinstance(apps, list):
                    raise ValueError('The detected-application list is invalid')
                detected = self.state.profiles.merge_detected(apps)
                attribution_events = payload.get('attributions', [])
                if not isinstance(attribution_events, list):
                    raise ValueError('Application-attribution evidence is invalid')
                saved_attributions = 0
                if self.state.attributions:
                    for event in attribution_events[:5000]:
                        if not isinstance(event, dict):
                            continue
                        saved = self.state.attributions.add({**event, 'type': 'appDomain', 'source': 'app-privacy-report', 'confidence': 'exact-bundle'})
                        if saved:
                            saved_attributions += 1
                if self.state.classifications:
                    for app in detected:
                        for domain in app.get('domains', []):
                            self.state.classifications.observe(domain, app_context=str(app.get('name') or app.get('bundleID') or ''), app_bundle=str(app.get('bundleID') or ''), observed_at=str(app.get('lastSeen') or ''))
                self._json({'ok': True, 'detectedApps': detected, 'savedAttributions': saved_attributions})
                return
            if path == '/api/device/apps/scan':
                scan = scan_paired_iphone_apps()
                if not scan.get('ok'):
                    self._json(scan, HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                detected = self.state.profiles.merge_detected(scan['apps'])
                self._json({'ok': True, 'count': scan['count'], 'detectedApps': detected})
                return
            if path == '/api/apps':
                profile = self.state.profiles.add(str(payload.get('name', '')), str(payload.get('bundleID', '')), str(payload.get('processName', '')))
                self._json({'ok': True, 'profile': profile}, HTTPStatus.CREATED)
                return
            if path == '/api/privacy-controls':
                desired = payload.get('desired', {})
                if not isinstance(desired, dict):
                    raise ValueError('Permission choices are invalid')
                bundle_id = str(payload.get('bundleID', ''))
                app_name = str(payload.get('appName', ''))
                rules = sync_system_protection(self.state.policy, bundle_id, app_name or bundle_id, str(desired.get('systemState', 'monitor')))
                entry = self.state.controls.update(bundle_id, app_name, desired)
                self._json({'ok': True, 'control': entry, 'rules': rules})
                return
            if path == '/api/privacy-capture/start':
                profile = self.state.profiles.get(str(payload.get('profileID', '')))
                if not profile:
                    raise ValueError('The application is not in the monitored list')
                session = self.state.privacy_capture.start(profile)
                self._json({'ok': True, 'capture': session}, HTTPStatus.CREATED)
                return
            if path == '/api/privacy-capture/stop':
                result = self.state.privacy_capture.stop()
                profile = self.state.profiles.get_by_bundle(result['bundleID']) or {}
                candidate_domains = sorted(set(profile.get('confirmedDomains', [])) | set(profile.get('observedDomains', [])))
                containment = enforce_privacy_containment(self.state.policy, result['bundleID'], result['appName'], result['control'], candidate_domains)
                result['result']['containment'] = containment
                result['control'] = self.state.controls.record_result(result['bundleID'], result['appName'], result['result'])
                result['containment'] = containment
                if self.state.classifications:
                    developer_check = bool(result.get('result', {}).get('developerChecks', {}).get('detected'))
                    violations = list(containment.get('violations', []) or [])
                    if violations:
                        self.state.classifications.mark_privacy_evidence(list(containment.get('recommendedDomains', []) or []), violations=violations, developer_check=False, app_context=result['appName'])
                    if developer_check:
                        self.state.classifications.mark_privacy_evidence(list(SYSTEM_PROTECTION_DOMAINS.get(result['bundleID'].lower(), [])), violations=[], developer_check=True, app_context=result['appName'])
                self._json({'ok': True, **result})
                return
            prefix = '/api/apps/'
            if path.startswith(prefix) and path.endswith('/domains'):
                profile_id = urllib.parse.unquote(path[len(prefix):-len('/domains')]).strip('/')
                domains = payload.get('domains', [])
                if not isinstance(domains, list):
                    raise ValueError('The hostname list is invalid')
                profile = self.state.profiles.add_domains(profile_id, domains, str(payload.get('source', 'observed')))
                if self.state.classifications:
                    for domain in domains:
                        self.state.classifications.observe(str(domain), app_context=str(profile.get('name') or profile.get('bundleID') or ''), app_bundle=str(profile.get('bundleID') or ''))
                self._json({'ok': True, 'profile': profile})
                return
            self._json({'error': 'Not found'}, HTTPStatus.NOT_FOUND)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({'error': str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:
        if not self._local_request():
            self._json({'error': 'Local requests only'}, HTTPStatus.FORBIDDEN)
            return
        path, query = self._request_path()
        if path == '/api/logs':
            result = self.state.activity.clear()
            self._json({'ok': True, **result})
            return
        if path == '/api/dns/cache':
            removed = self.state.resolver.cache.clear()
            self._json({'ok': True, 'removed': removed, 'preserved': ['policy', 'apps', 'activity', 'classifications']})
            return
        if path == '/api/policy':
            domain = str(query.get('domain', [''])[0])
            if self.state.policy.delete(domain):
                self.state.resolver.cache.invalidate(domain)
                self._json({'ok': True})
            else:
                self._json({'error': 'The operation was not found'}, HTTPStatus.NOT_FOUND)
            return
        prefix = '/api/apps/'
        if not path.startswith(prefix):
            self._json({'error': 'Not found'}, HTTPStatus.NOT_FOUND)
            return
        profile_id = urllib.parse.unquote(path[len(prefix):]).strip('/')
        if not profile_id or '/' in profile_id:
            self._json({'error': 'Not found'}, HTTPStatus.NOT_FOUND)
            return
        if self.state.profiles.delete(profile_id):
            self._json({'ok': True})
        else:
            self._json({'error': 'Application not found'}, HTTPStatus.NOT_FOUND)

    def end_headers(self) -> None:
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        super().end_headers()

def start_dns(resolver: Resolver, host: str, port: int) -> tuple[Any, Any]:
    UDPDNSHandler.resolver = resolver
    TCPDNSHandler.resolver = resolver
    udp = ThreadingUDPServer((host, port), UDPDNSHandler)
    bound_port = int(udp.server_address[1])
    try:
        tcp = ThreadingTCPServer((host, bound_port), TCPDNSHandler)
    except OSError:
        udp.server_close()
        raise
    threading.Thread(target=udp.serve_forever, name='dns-udp', daemon=True).start()
    threading.Thread(target=tcp.serve_forever, name='dns-tcp', daemon=True).start()
    return (udp, tcp)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Privacy Protector')
    parser.add_argument('--dns-host', default='0.0.0.0')
    parser.add_argument('--dns-port', type=int, default=53053)
    parser.add_argument('--web-host', default='127.0.0.1')
    parser.add_argument('--web-port', type=int, default=8733)
    parser.add_argument('--upstream', default=DEFAULT_UPSTREAM)
    parser.add_argument('--fallback-upstream', default=DEFAULT_FALLBACK_UPSTREAM)
    parser.add_argument('--upstream-timeout', type=float, default=3.0)
    parser.add_argument('--cache-size', type=int, default=2048)
    parser.add_argument('--iphone-client-ip', default='')
    parser.add_argument('--continuous-iphone-evidence', action='store_true', help='Enable optional USB packet attribution for advanced diagnostics')
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    policy = PolicyStore(POLICY_PATH)
    profiles = AppProfileStore(APPS_PATH)
    activity = ActivityLog(path=ACTIVITY_PATH)
    attributions = AppAttributionLog(ATTRIBUTION_PATH)
    controls = PrivacyControlStore(PRIVACY_CONTROLS_PATH)
    controls.activate_balanced_defaults()
    classifications = DomainClassificationEngine(CLASSIFICATIONS_PATH, active_analysis=True, app_purpose_profiles=APP_PURPOSE_PROFILES)
    classifications.bootstrap(policy.snapshot(), profiles.snapshot(), activity.snapshot(limit=10000), controls.snapshot(), privacy_domains_by_bundle=APP_PRIVACY_ENDPOINTS, developer_domains_by_bundle=SYSTEM_PROTECTION_DOMAINS)
    privacy_capture = PrivacyCaptureManager(controls)
    evidence_monitor = IPhoneEvidenceMonitor(profiles, attributions, classifications, enabled=args.continuous_iphone_evidence)
    resolver = Resolver(policy, activity, args.upstream, args.fallback_upstream, timeout=args.upstream_timeout, cache=DNSCache(maximum=args.cache_size), iphone_client_ip=args.iphone_client_ip, classifications=classifications)
    try:
        udp, tcp = start_dns(resolver, args.dns_host, args.dns_port)
    except OSError as exc:
        raise SystemExit(f'Unable to bind DNS listeners on port {args.dns_port}: {exc}. Choose a free test port or complete the documented Windows preparation.') from exc
    state = AppState(policy, profiles, activity, controls, privacy_capture, resolver, args.dns_host, args.dns_port, classifications, attributions, evidence_monitor)
    DashboardHandler.state = state
    dashboard = ThreadingHTTPServer((args.web_host, args.web_port), DashboardHandler)
    print(f'Privacy Protector: http://{args.web_host}:{args.web_port}')
    print(f'DNS: {args.dns_host}:{args.dns_port} -> {args.upstream} (fallback: {args.fallback_upstream})')
    classifications.start()
    evidence_monitor.start()
    try:
        dashboard.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.shutdown()
        udp.shutdown()
        tcp.shutdown()
        classifications.shutdown()
        evidence_monitor.shutdown()
        dashboard.server_close()
        udp.server_close()
        tcp.server_close()
if __name__ == '__main__':
    main()
