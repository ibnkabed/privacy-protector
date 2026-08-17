from __future__ import annotations
import hashlib
import html
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
ENGINE_VERSION = 3
CLASSIFICATION_RULESET_VERSION = 5
BACKGROUND_ANALYSIS_WORKERS = 2
STARTUP_CATCHUP_LIMIT = 32
RISK_ORDER = {'green': 0, 'orange': 1, 'red': 2}
RISK_LABELS = {'green': 'Green - functional with no identified privacy intrusion', 'orange': 'Orange - operational device data without a confirmed violation', 'red': 'Red - tracking or a confirmed privacy intrusion'}
STAGE_LABELS = {'preliminary': 'Preliminary', 'studied': 'Studied'}

def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')

def _observation_iso(value: Any) -> str:
    clean = str(value or '').strip()
    if not clean:
        return ''
    try:
        parsed = datetime.fromisoformat(clean.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone().isoformat(timespec='seconds')
    except ValueError:
        return ''

def _latest_observation(current: Any, candidate: Any) -> str:
    current_iso = _observation_iso(current)
    candidate_iso = _observation_iso(candidate)
    if not candidate_iso:
        return current_iso
    if not current_iso:
        return candidate_iso
    return max(current_iso, candidate_iso, key=lambda value: datetime.fromisoformat(value))

def _normalize_domain(value: str) -> str:
    clean = str(value or '').strip().lower().rstrip('.')
    if not clean or len(clean) > 253:
        return ''
    try:
        clean = clean.encode('idna').decode('ascii')
    except UnicodeError:
        return ''
    labels = clean.split('.')
    if len(labels) < 2 or any((not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or (not re.fullmatch('(?:[a-z0-9-]+|_[a-z0-9-]+)', label)) for label in labels)):
        return ''
    try:
        ipaddress.ip_address(clean)
        return ''
    except ValueError:
        return clean

def _bounded(value: Any, maximum: int=500) -> str:
    return re.sub('\\s+', ' ', str(value or '')).strip()[:maximum]

def _catalog_entry(risk: str, category: str, category_label: str, summary: str, reason: str, source: str='', *, developer_check: bool=False, device_data: bool=False) -> dict[str, Any]:
    return {'risk': risk, 'category': category, 'categoryLabel': category_label, 'summary': summary, 'reason': reason, 'source': source, 'developerModeCheck': developer_check, 'deviceDataAccess': device_data}
CURATED_DOMAIN_CATALOG: dict[str, dict[str, Any]] = {'integrity.example.test': _catalog_entry('red', 'device_integrity', 'Device integrity check', 'Synthetic fixture for a reviewed device-integrity endpoint.', 'Device-integrity checks can reveal device state and are classified as red.', 'https://example.com/privacy-protector-fixtures', developer_check=True, device_data=True), 'telemetry.example.test': _catalog_entry('orange', 'device_operational', 'Operational telemetry', 'Synthetic fixture for diagnostics and operational telemetry.', 'Operational diagnostics can include technical device data without proving a denied-permission violation.', 'https://example.com/privacy-protector-fixtures', device_data=True), 'api.example.test': _catalog_entry('green', 'core_service', 'Core service', 'Synthetic fixture for a functional application API.', 'A functional first-party service has no independent tracking indicator in this reviewed fixture.', 'https://example.com/privacy-protector-fixtures')}
RED_PATTERN = re.compile('(?:analytics|measurement|tracker|tracking|advertising|doubleclick|adsystem|appsflyer|adjust|rudderstack|clarity|demdex|tagmanager|attribution|devicecheck|appattest|developer.?mode|jailbreak|root.?check|integrity|location|motion|fitness|health)', re.IGNORECASE)
ORANGE_PATTERN = re.compile('(?:crash|logging|diagnostic|telemetry|performance|push|messaging|notification|device|installation|instance|sentry|appcenter|optimization|assistant)', re.IGNORECASE)
GREEN_PATTERN = re.compile('(?:auth|oauth|login|api|gateway|cdn|asset|static|font|image|privacy|relay|safebrowsing|cookie|account|update)', re.IGNORECASE)
CURATED_DOMAIN_FAMILIES: tuple[tuple[re.Pattern[str], dict[str, Any]], ...] = ((re.compile('(?:^|\\.)analytics(?:\\.|-|$)', re.IGNORECASE), _catalog_entry('red', 'behavior_analytics', 'Behavior analytics', 'A hostname explicitly identifies an analytics ingestion service.', 'Analytics endpoints can receive interaction, session, or device events.')), (re.compile('(?:^|\\.)(?:attribution|tracking|tracker)(?:\\.|-|$)', re.IGNORECASE), _catalog_entry('red', 'attribution', 'Attribution and tracking', 'A hostname explicitly identifies tracking or attribution.', 'Attribution links application activity to campaign or audience identifiers.')), (re.compile('(?:^|\\.)(?:ads|advertising)(?:\\.|-|$)', re.IGNORECASE), _catalog_entry('red', 'advertising_tracking', 'Advertising measurement', 'A hostname explicitly identifies an advertising service.', 'Advertising endpoints commonly measure impressions, conversions, or audiences.')), (re.compile('(?:^|\\.)(?:rum|telemetry|diagnostics?)(?:\\.|-|$)', re.IGNORECASE), _catalog_entry('orange', 'device_operational', 'Operational diagnostics', 'A hostname identifies diagnostics or real-user monitoring.', 'Operational telemetry may include performance and technical device attributes.', device_data=True)))

class SafeHTTPSStudy:
    """Fetch bounded public HTTPS metadata without cookies, redirects, or private IPs."""

    def __init__(self, timeout: float=3.5, maximum_bytes: int=65536):
        self.timeout = max(0.5, float(timeout))
        self.maximum_bytes = min(max(int(maximum_bytes), 4096), 131072)

    @staticmethod
    def _targets(domain: str) -> list[tuple[int, tuple[Any, ...], str]]:
        targets: list[tuple[int, tuple[Any, ...], str]] = []
        seen: set[str] = set()
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP):
            if socktype != socket.SOCK_STREAM:
                continue
            address = str(sockaddr[0])
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if not parsed.is_global or address in seen:
                continue
            seen.add(address)
            targets.append((family, sockaddr, address))
        return targets[:4]

    @staticmethod
    def _certificate_name(values: Any) -> str:
        parts = []
        for group in values or []:
            for key, value in group:
                if key in {'organizationName', 'commonName'}:
                    parts.append(_bounded(value, 120))
        return ' / '.join(dict.fromkeys((part for part in parts if part)))[:240]

    @staticmethod
    def _html_meta(body: str) -> tuple[str, str]:
        title_match = re.search('<title[^>]*>(.*?)</title>', body, re.I | re.S)
        description_match = re.search('<meta[^>]+(?:name|property)=[\\"\'](?:description|og:description)[\\"\'][^>]+content=[\\"\'](.*?)[\\"\']', body, re.I | re.S) or re.search('<meta[^>]+content=[\\"\'](.*?)[\\"\'][^>]+(?:name|property)=[\\"\'](?:description|og:description)[\\"\']', body, re.I | re.S)
        title = _bounded(html.unescape(re.sub('<[^>]+>', ' ', title_match.group(1))), 200) if title_match else ''
        description = _bounded(html.unescape(re.sub('<[^>]+>', ' ', description_match.group(1))), 320) if description_match else ''
        return (title, description)

    def study(self, domain: str) -> dict[str, Any]:
        clean = _normalize_domain(domain)
        if not clean:
            return {'ok': False, 'error': 'Invalid hostname'}
        try:
            targets = self._targets(clean)
        except OSError as exc:
            return {'ok': False, 'error': _bounded(exc, 180)}
        if not targets:
            return {'ok': False, 'error': 'No safe public internet address was available for study'}
        last_error = 'The public HTTPS request failed'
        context = ssl.create_default_context()
        request = f'GET / HTTP/1.1\r\nHost: {clean}\r\nUser-Agent: PrivacyProtector-DomainStudy/3.0\r\nAccept: text/html,application/json;q=0.7,*/*;q=0.2\r\nAccept-Encoding: identity\r\nRange: bytes=0-32767\r\nConnection: close\r\n\r\n'.encode('ascii')
        for family, sockaddr, address in targets:
            raw: socket.socket | None = None
            tls: ssl.SSLSocket | None = None
            try:
                raw = socket.socket(family, socket.SOCK_STREAM)
                raw.settimeout(self.timeout)
                raw.connect(sockaddr)
                tls = context.wrap_socket(raw, server_hostname=clean)
                tls.settimeout(self.timeout)
                certificate = tls.getpeercert()
                tls.sendall(request)
                chunks = bytearray()
                while len(chunks) < self.maximum_bytes:
                    part = tls.recv(min(8192, self.maximum_bytes - len(chunks)))
                    if not part:
                        break
                    chunks.extend(part)
                raw_response = bytes(chunks)
                head, _, body_bytes = raw_response.partition(b'\r\n\r\n')
                head_text = head.decode('iso-8859-1', errors='replace')
                lines = head_text.split('\r\n')
                status_match = re.match('HTTP/\\S+\\s+(\\d{3})', lines[0] if lines else '')
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    if ':' not in line:
                        continue
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    if key in {'content-type', 'server', 'location', 'via', 'x-powered-by'}:
                        headers[key] = _bounded(value, 240)
                body = body_bytes.decode('utf-8', errors='replace')
                title, description = self._html_meta(body)
                redirect_host = ''
                if headers.get('location'):
                    redirect_host = _normalize_domain(urlsplit(headers['location']).hostname or '')
                return {'ok': True, 'studiedAt': _now_iso(), 'addressHash': hashlib.sha256(address.encode('ascii')).hexdigest()[:12], 'httpStatus': int(status_match.group(1)) if status_match else 0, 'contentType': headers.get('content-type', ''), 'server': headers.get('server', ''), 'poweredBy': headers.get('x-powered-by', ''), 'via': headers.get('via', ''), 'redirectHost': redirect_host, 'title': title, 'description': description, 'certificateSubject': self._certificate_name(certificate.get('subject')), 'certificateIssuer': self._certificate_name(certificate.get('issuer')), 'bytesRead': len(raw_response), 'privacy': 'Operational device or diagnostic evidence.'}
            except (OSError, ssl.SSLError, ValueError) as exc:
                last_error = _bounded(exc, 180)
            finally:
                if tls:
                    try:
                        tls.close()
                    except OSError:
                        pass
                elif raw:
                    try:
                        raw.close()
                    except OSError:
                        pass
        return {'ok': False, 'studiedAt': _now_iso(), 'error': last_error}

def _catalog_for_domain(domain: str) -> dict[str, Any] | None:
    catalog = CURATED_DOMAIN_CATALOG.get(domain)
    if catalog:
        return catalog
    for pattern, family_catalog in CURATED_DOMAIN_FAMILIES:
        if pattern.search(domain):
            return family_catalog
    if domain == '_dns.resolver.arpa' or (domain.startswith('lb._dns-sd._udp.') and domain.endswith('.in-addr.arpa')):
        return _catalog_entry('green', 'dns_service_discovery', 'Local DNS service discovery', 'Operational DNS record for resolver or local-service discovery.', 'The hostname and query type identify DNS discovery rather than application data collection.')
    return None

class DomainClassificationEngine:

    def __init__(self, path: Path, *, active_analysis: bool=True, probe: SafeHTTPSStudy | None=None, app_purpose_profiles: dict[str, dict[str, Any]] | None=None):
        self.path = path
        self.active_analysis = bool(active_analysis)
        self.probe = probe or SafeHTTPSStudy()
        self.app_purpose_profiles = {str(bundle).lower(): dict(settings) for bundle, settings in (app_purpose_profiles or {}).items()}
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {'version': ENGINE_VERSION, 'engine': 'DNS Engine V3', 'domains': {}}
        self.jobs: queue.Queue[str | None] = queue.Queue()
        self.pending: set[str] = set()
        self.workers: list[threading.Thread] = []
        self.stopping = threading.Event()
        self._load()

    @staticmethod
    def _refresh_catalog_entry(domain: str, entry: dict[str, Any]) -> bool:
        catalog = _catalog_for_domain(domain)
        if not catalog:
            return False
        fresh = DomainClassificationEngine._base_entry(domain)
        previous_risk = str(entry.get('risk') or '')
        local_evidence = any((str(item).startswith('Evidence-based privacy classification.') for item in entry.get('evidence', [])))
        preserve_local_red = local_evidence and previous_risk == 'red' and (RISK_ORDER.get(fresh['risk'], 0) < RISK_ORDER['red'])
        changed = False
        for key in ('risk', 'riskLabel', 'category', 'categoryLabel', 'stage', 'stageLabel', 'confidence', 'confidenceLabel', 'summary', 'reason', 'privacyRelevant', 'deviceDataAccess', 'developerModeCheck', 'analyzedAt'):
            if preserve_local_red and key in {'risk', 'riskLabel', 'category', 'categoryLabel', 'stage', 'stageLabel', 'confidence', 'confidenceLabel', 'summary', 'reason', 'privacyRelevant', 'deviceDataAccess', 'developerModeCheck', 'analyzedAt'}:
                continue
            if entry.get(key) != fresh.get(key):
                entry[key] = fresh.get(key)
                changed = True
        evidence = list(entry.get('evidence', []))
        if 'Reviewed V3 catalogue match' not in evidence:
            evidence.append('Reviewed V3 catalogue match')
            entry['evidence'] = evidence[-30:]
            changed = True
        sources = list(entry.get('researchSources', []))
        for source in fresh.get('researchSources', []):
            if source not in sources:
                sources.append(source)
                changed = True
        entry['researchSources'] = sources[-12:]
        if preserve_local_red:
            history = entry.get('classificationHistory', [])
            if isinstance(history, list):
                cleaned_history = [item for item in history if not (isinstance(item, dict) and item.get('ruleset') == CLASSIFICATION_RULESET_VERSION and (item.get('from') == 'red') and (item.get('to') != 'red'))]
                if cleaned_history != history:
                    entry['classificationHistory'] = cleaned_history
                    entry['reclassifiedAt'] = str(cleaned_history[-1].get('at', '')) if cleaned_history else ''
                    changed = True
        elif previous_risk in RISK_ORDER and RISK_ORDER[fresh['risk']] > RISK_ORDER[previous_risk]:
            history = entry.get('classificationHistory', [])
            if not isinstance(history, list):
                history = []
            history.append({'from': previous_risk, 'to': fresh['risk'], 'at': _now_iso(), 'ruleset': CLASSIFICATION_RULESET_VERSION, 'reason': 'Classification confidence'})
            entry['classificationHistory'] = history[-20:]
            entry['reclassifiedAt'] = history[-1]['at']
            changed = True
        return changed

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding='utf-8'))
            if isinstance(loaded, dict):
                self.data['domains'] = loaded.get('domains', {}) if isinstance(loaded.get('domains'), dict) else {}
                changed = 'functions' in loaded
                for domain, entry in self.data['domains'].items():
                    if isinstance(entry, dict):
                        if 'lastObservedAt' not in entry:
                            entry['lastObservedAt'] = ''
                            changed = True
                        changed = self._refresh_catalog_entry(domain, entry) or changed
                        for bundle in list(entry.get('appBundles', []) or []):
                            changed = self._apply_app_purpose_locked(domain, entry, str(bundle)) or changed
                if changed:
                    self._save_locked()
        except (OSError, ValueError, json.JSONDecodeError):
            corrupt = self.path.with_suffix('.corrupt.json')
            try:
                os.replace(self.path, corrupt)
            except OSError:
                pass

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix('.tmp')
        payload = {'version': ENGINE_VERSION, 'engine': 'DNS Engine V3', 'classificationRuleset': CLASSIFICATION_RULESET_VERSION, 'updatedAt': _now_iso(), 'definitions': {'green': RISK_LABELS['green'], 'orange': RISK_LABELS['orange'], 'red': RISK_LABELS['red'], 'preliminary': 'Evidence-based privacy classification.', 'studied': 'Classification confidence'}, 'domains': self.data['domains']}
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        os.replace(temp, self.path)

    @staticmethod
    def _base_entry(domain: str, hint_text: str='') -> dict[str, Any]:
        stamp = _now_iso()
        catalog = _catalog_for_domain(domain)
        if catalog:
            risk = catalog['risk']
            source = catalog.get('source', '')
            return {'domain': domain, 'risk': risk, 'riskLabel': RISK_LABELS[risk], 'category': catalog['category'], 'categoryLabel': catalog['categoryLabel'], 'stage': 'studied', 'stageLabel': STAGE_LABELS['studied'], 'confidence': 92, 'confidenceLabel': 'High confidence', 'summary': catalog['summary'], 'reason': catalog['reason'], 'privacyRelevant': risk == 'red', 'deviceDataAccess': bool(catalog.get('deviceDataAccess')), 'developerModeCheck': bool(catalog.get('developerModeCheck')), 'firstSeen': stamp, 'lastSeen': stamp, 'lastObservedAt': '', 'analyzedAt': stamp, 'lastProbeAt': '', 'hits': 0, 'qtypes': [], 'transports': [], 'decisions': [], 'cnameChain': [], 'appContexts': [], 'evidence': ['Reviewed V3 catalogue match'], 'researchSources': [source] if source else [], 'networkStudy': {}}
        text = f'{domain} {hint_text}'.lower()
        if RED_PATTERN.search(text):
            risk, category, label, confidence = ('red', 'privacy_signal', 'Tracking, advertising, or behavior-analytics evidence.', 64)
            summary = 'Tracking, advertising, or behavior-analytics evidence.'
        elif ORANGE_PATTERN.search(text):
            risk, category, label, confidence = ('orange', 'device_telemetry', 'Operational device or diagnostic evidence.', 56)
            summary = 'Operational device or diagnostic evidence.'
        elif GREEN_PATTERN.search(text):
            risk, category, label, confidence = ('green', 'functional_service', 'Operational device or diagnostic evidence.', 52)
            summary = 'Functional service evidence with no independent confirmed privacy violation.'
        else:
            risk, category, label, confidence = ('green', 'general_network', 'Functional service evidence with no independent confirmed privacy violation.', 35)
            summary = 'Privacy evidence associated with the saved application context.'
        return {'domain': domain, 'risk': risk, 'riskLabel': RISK_LABELS[risk], 'category': category, 'categoryLabel': label, 'stage': 'preliminary', 'stageLabel': STAGE_LABELS['preliminary'], 'confidence': confidence, 'confidenceLabel': 'Medium confidence' if confidence >= 50 else 'Preliminary confidence', 'summary': summary, 'reason': 'Tracking, advertising, or behavior-analytics evidence.', 'privacyRelevant': risk == 'red', 'deviceDataAccess': risk in {'orange', 'red'}, 'developerModeCheck': bool(re.search('developer.?mode|jailbreak|root.?check|integrity', text)), 'firstSeen': stamp, 'lastSeen': stamp, 'lastObservedAt': '', 'analyzedAt': '', 'lastProbeAt': '', 'hits': 0, 'qtypes': [], 'transports': [], 'decisions': [], 'cnameChain': [], 'appContexts': [], 'evidence': ['Preliminary hostname classification'], 'researchSources': [], 'networkStudy': {}}

    @staticmethod
    def _append_unique(entry: dict[str, Any], key: str, values: list[str], maximum: int) -> bool:
        current = list(entry.get(key, []))
        changed = False
        for value in values:
            clean = _bounded(value, 240)
            if clean and clean not in current:
                current.append(clean)
                changed = True
        if len(current) > maximum:
            current = current[-maximum:]
            changed = True
        entry[key] = current
        return changed

    @staticmethod
    def _matches_domain_suffix(domain: str, suffix: str) -> bool:
        clean_suffix = _normalize_domain(suffix)
        return bool(clean_suffix and (domain == clean_suffix or domain.endswith(f'.{clean_suffix}')))

    def _apply_app_purpose_locked(self, domain: str, entry: dict[str, Any], app_bundle: str) -> bool:
        bundle = str(app_bundle or '').strip().lower()
        purpose = self.app_purpose_profiles.get(bundle)
        if not bundle or not purpose:
            return False
        expected = any((self._matches_domain_suffix(domain, suffix) for suffix in purpose.get('expectedDomainSuffixes', [])))
        contexts = entry.get('appPurposeContexts', {})
        if not isinstance(contexts, dict):
            contexts = {}
        context = {'bundleID': bundle, 'kind': _bounded(purpose.get('purposeKind'), 80), 'risk': _bounded(purpose.get('purposeRisk'), 16), 'label': _bounded(purpose.get('purposeLabel'), 120), 'reason': _bounded(purpose.get('purposeReason'), 400), 'expectedForDomain': expected}
        changed = contexts.get(bundle) != context
        contexts[bundle] = context
        entry['appPurposeContexts'] = contexts
        changed |= self._append_unique(entry, 'appBundles', [bundle], 30)
        local_evidence = any((str(item).startswith('Evidence-based privacy classification.') for item in entry.get('evidence', [])))
        can_cap_health_access = purpose.get('purposeRisk') == 'orange' and expected and (entry.get('risk') == 'red') and (entry.get('category') in {'privacy_signal', 'expected_health_data'}) and (not local_evidence) and (_catalog_for_domain(domain) is None)
        if not can_cap_health_access:
            return changed
        previous_risk = str(entry.get('risk') or 'red')
        entry.update({'risk': 'orange', 'riskLabel': RISK_LABELS['orange'], 'category': 'expected_health_data', 'categoryLabel': 'Expected health-data access', 'stage': 'studied', 'stageLabel': STAGE_LABELS['studied'], 'confidence': max(94, int(entry.get('confidence', 0))), 'confidenceLabel': 'High confidence from application context', 'summary': 'The hostname handles health data expected for the selected application purpose.', 'reason': str(purpose.get('purposeReason') or '')[:400], 'privacyRelevant': False, 'deviceDataAccess': True, 'analyzedAt': _now_iso()})
        self._append_unique(entry, 'evidence', [f"Optional health-application context: {purpose.get('purposeLabel', '')}"], 30)
        history = entry.get('classificationHistory', [])
        if not isinstance(history, list):
            history = []
        if not history or not (history[-1].get('from') == previous_risk and history[-1].get('to') == 'orange' and (history[-1].get('ruleset') == CLASSIFICATION_RULESET_VERSION)):
            history.append({'from': previous_risk, 'to': 'orange', 'at': _now_iso(), 'ruleset': CLASSIFICATION_RULESET_VERSION, 'reason': 'Purpose-aware adjustment for an expected first-party health hostname'})
        entry['classificationHistory'] = history[-20:]
        entry['reclassifiedAt'] = history[-1]['at']
        return True

    def observe(self, domain: str, *, qtype: str='', transport: str='', decision: str='', cname_chain: list[str] | None=None, app_context: str='', app_bundle: str='', label: str='', note: str='', observed_at: str='', schedule: bool=True, persist: bool=True) -> dict[str, Any] | None:
        clean = _normalize_domain(domain)
        if not clean:
            return None
        hint = f'{label} {note}'
        with self.lock:
            entry = self.data['domains'].get(clean)
            created = entry is None
            if created:
                entry = self._base_entry(clean, hint)
                self.data['domains'][clean] = entry
            else:
                changed = self._refresh_catalog_entry(clean, entry)
            entry['lastSeen'] = _now_iso()
            latest_observation = _latest_observation(entry.get('lastObservedAt', ''), observed_at)
            if latest_observation != entry.get('lastObservedAt', ''):
                entry['lastObservedAt'] = latest_observation
                changed = True
            entry['hits'] = int(entry.get('hits', 0)) + (1 if qtype or transport or decision else 0)
            changed = created or changed
            changed |= self._append_unique(entry, 'qtypes', [qtype], 24)
            changed |= self._append_unique(entry, 'transports', [transport], 8)
            changed |= self._append_unique(entry, 'decisions', [decision], 8)
            changed |= self._append_unique(entry, 'cnameChain', list(cname_chain or []), 30)
            changed |= self._append_unique(entry, 'appContexts', [app_context], 20)
            changed |= self._append_unique(entry, 'appBundles', [app_bundle], 30)
            if hint and entry.get('stage') == 'preliminary':
                preliminary = self._base_entry(clean, hint)
                if RISK_ORDER[preliminary['risk']] > RISK_ORDER[entry['risk']]:
                    for key in ('risk', 'riskLabel', 'category', 'categoryLabel', 'summary', 'reason', 'privacyRelevant', 'deviceDataAccess', 'developerModeCheck', 'confidence', 'confidenceLabel'):
                        entry[key] = preliminary[key]
                    changed = True
            changed = self._apply_app_purpose_locked(clean, entry, app_bundle) or changed
            if persist and (changed or int(entry.get('hits', 0)) % 25 == 0):
                self._save_locked()
            snapshot = json.loads(json.dumps(entry, ensure_ascii=False))
        if schedule and self.active_analysis and (snapshot.get('stage') == 'preliminary'):
            self.schedule(clean)
        return snapshot

    def mark_privacy_evidence(self, domains: list[str], *, violations: list[str] | None=None, developer_check: bool=False, app_context: str='', persist: bool=True) -> None:
        clean_domains = [_normalize_domain(value) for value in domains]
        with self.lock:
            changed = False
            for clean in clean_domains:
                if not clean:
                    continue
                entry = self.data['domains'].get(clean) or self._base_entry(clean)
                self.data['domains'][clean] = entry
                entry.update({'risk': 'red', 'riskLabel': RISK_LABELS['red'], 'category': 'developer_mode_check' if developer_check else 'confirmed_privacy_violation', 'categoryLabel': 'Developer Mode check' if developer_check else 'Locally confirmed privacy violation', 'stage': 'studied', 'stageLabel': STAGE_LABELS['studied'], 'confidence': 99, 'confidenceLabel': 'Locally confirmed confidence', 'privacyRelevant': True, 'deviceDataAccess': True, 'developerModeCheck': bool(developer_check or entry.get('developerModeCheck')), 'analyzedAt': _now_iso(), 'summary': 'The hostname is linked to local evidence of a Developer Mode check.' if developer_check else 'The hostname is linked to a saved privacy-choice violation.', 'reason': 'Evidence reviewed for the hostname classification.'})
                self._append_unique(entry, 'evidence', ['Evidence reviewed for the hostname classification.' if developer_check else f"Evidence-based privacy classification.{', '.join(violations or [])}"], 30)
                self._append_unique(entry, 'appContexts', [app_context], 20)
                changed = True
            if changed and persist:
                self._save_locked()

    def bootstrap(self, policy: dict[str, Any], profiles: dict[str, Any], activity: list[dict[str, Any]], controls: dict[str, Any] | None=None, privacy_domains_by_bundle: dict[str, dict[str, str] | list[str] | set[str]] | None=None, developer_domains_by_bundle: dict[str, list[str] | set[str]] | None=None) -> None:
        app_domains_by_bundle: dict[str, set[str]] = {}
        for domain, settings in policy.get('domains', {}).items():
            self.observe(domain, decision=str(settings.get('action', '')), label=str(settings.get('label', '')), note=str(settings.get('note', '')), schedule=False, persist=False)
        for app in list(profiles.get('apps', [])) + list(profiles.get('detectedApps', [])):
            context = str(app.get('name') or app.get('bundleID') or '')
            observed_at = str(app.get('lastSeen') or '')
            domains = set(app.get('confirmedDomains', [])) | set(app.get('observedDomains', [])) | set(app.get('domains', []))
            bundle = str(app.get('bundleID') or '').lower()
            if bundle:
                app_domains_by_bundle.setdefault(bundle, set()).update((_normalize_domain(domain) for domain in domains if _normalize_domain(domain)))
            for domain in domains:
                self.observe(domain, app_context=context, app_bundle=bundle, observed_at=observed_at, schedule=False, persist=False)
        for item in activity:
            self.observe(str(item.get('domain', '')), qtype=str(item.get('qtypeName', '')), transport=str(item.get('transport', '')), decision=str(item.get('decision', '')), cname_chain=list(item.get('cnameChain', []) or []), observed_at=str(item.get('time', '')), schedule=False, persist=False)
        for bundle_id, control in (controls or {}).get('apps', {}).items():
            bundle_key = str(bundle_id).lower()
            result = control.get('lastResult', {})
            containment = result.get('containment', {})
            blocked = list(containment.get('blockedDomains', []) or [])
            violations = list(containment.get('violations', []) or [])
            if not violations:
                violations = [key for key, value in (control.get('evaluation', {}) or {}).items() if isinstance(value, dict) and value.get('verdict') == 'violation']
            developer = bool(result.get('developerChecks', {}).get('detected'))
            mapped_privacy = (privacy_domains_by_bundle or {}).get(bundle_key, {})
            if isinstance(mapped_privacy, dict):
                mapped_privacy = list(mapped_privacy)
            privacy_domains = blocked or list(mapped_privacy or [])
            if not privacy_domains and violations:
                privacy_domains = [domain for domain in app_domains_by_bundle.get(bundle_key, set()) if (_catalog_for_domain(domain) or {}).get('risk') == 'red']
            if privacy_domains and violations:
                self.mark_privacy_evidence(privacy_domains, violations=violations, developer_check=False, app_context=str(control.get('appName') or bundle_id), persist=False)
            developer_domains = list((developer_domains_by_bundle or {}).get(bundle_key, []) or [])
            if not developer_domains and developer:
                developer_domains = [domain for domain in app_domains_by_bundle.get(bundle_key, set()) if (_catalog_for_domain(domain) or {}).get('developerModeCheck')]
            if developer and developer_domains:
                self.mark_privacy_evidence(developer_domains, violations=[], developer_check=True, app_context=str(control.get('appName') or bundle_id), persist=False)
        with self.lock:
            self._save_locked()

    def start(self) -> None:
        if not self.active_analysis or any((worker.is_alive() for worker in self.workers)):
            return
        self.workers = [threading.Thread(target=self._worker_loop, name=f'domain-study-v3-{index}', daemon=True) for index in range(1, BACKGROUND_ANALYSIS_WORKERS + 1)]
        for worker in self.workers:
            worker.start()
        self.request_analysis(limit=STARTUP_CATCHUP_LIMIT)

    def shutdown(self) -> None:
        self.stopping.set()
        for _ in self.workers:
            self.jobs.put(None)
        for worker in self.workers:
            worker.join(timeout=2)

    def schedule(self, domain: str, force: bool=False) -> bool:
        clean = _normalize_domain(domain)
        if not clean:
            return False
        with self.lock:
            entry = self.data['domains'].get(clean)
            if not entry:
                entry = self._base_entry(clean)
                self.data['domains'][clean] = entry
                self._save_locked()
            if not force and entry.get('stage') == 'studied':
                return False
            if clean in self.pending:
                return False
            self.pending.add(clean)
        self.jobs.put(clean)
        return True

    def request_analysis(self, domain: str='', force: bool=False, limit: int | None=None) -> dict[str, Any]:
        if domain:
            queued = 1 if self.schedule(domain, force=force) else 0
        else:
            with self.lock:
                candidates = list(self.data['domains'].items())
            if not force:
                candidates = [item for item in candidates if item[1].get('stage') != 'studied']
            candidates.sort(key=lambda item: (bool(item[1].get('lastProbeAt')), -RISK_ORDER.get(str(item[1].get('risk')), 0), -int(item[1].get('hits', 0)), str(item[1].get('lastProbeAt', '')), item[0]))
            domains = [item[0] for item in candidates]
            if limit is not None:
                domains = domains[:max(0, int(limit))]
            queued = sum((1 for item in domains if self.schedule(item, force=force)))
        return {'ok': True, 'queued': queued, 'pending': self.jobs.qsize()}

    def _worker_loop(self) -> None:
        while not self.stopping.is_set():
            domain = self.jobs.get()
            if domain is None:
                break
            try:
                self.analyze(domain)
            except Exception:
                pass
            finally:
                with self.lock:
                    self.pending.discard(domain)
                self.jobs.task_done()
            time.sleep(0.15)

    def analyze(self, domain: str) -> dict[str, Any] | None:
        clean = _normalize_domain(domain)
        if not clean:
            return None
        study = self.probe.study(clean)
        with self.lock:
            entry = self.data['domains'].get(clean) or self._base_entry(clean)
            self.data['domains'][clean] = entry
            entry['lastProbeAt'] = _now_iso()
            entry['networkStudy'] = study
            catalog = _catalog_for_domain(clean)
            text = ' '.join((str(study.get(key, '')) for key in ('title', 'description', 'certificateSubject', 'server', 'redirectHost')))
            inferred = self._base_entry(clean, text)
            if not catalog and RISK_ORDER[inferred['risk']] > RISK_ORDER[entry['risk']]:
                for key in ('risk', 'riskLabel', 'category', 'categoryLabel', 'summary', 'privacyRelevant', 'deviceDataAccess', 'developerModeCheck'):
                    entry[key] = inferred[key]
                self._append_unique(entry, 'evidence', ['Evidence-based privacy classification.'], 30)
            if study.get('ok'):
                entry['stage'] = 'studied'
                entry['stageLabel'] = STAGE_LABELS['studied']
                entry['analyzedAt'] = _now_iso()
                if catalog:
                    entry['confidence'] = max(92, int(entry.get('confidence', 0)))
                    entry['confidenceLabel'] = 'High confidence'
                else:
                    entry['confidence'] = max(58, int(entry.get('confidence', 0)))
                    entry['confidenceLabel'] = 'Medium confidence'
                    entry['reason'] = 'Evidence reviewed for the hostname classification.'
                self._append_unique(entry, 'evidence', ['Safe public HTTPS root study'], 30)
                redirect = study.get('redirectHost')
                if redirect:
                    self._append_unique(entry, 'cnameChain', [redirect], 30)
            else:
                self._append_unique(entry, 'evidence', [f"HTTPS study failed: {_bounded(study.get('error'), 120)}"], 30)
            for bundle in list(entry.get('appBundles', []) or []):
                self._apply_app_purpose_locked(clean, entry, str(bundle))
            self._save_locked()
            return json.loads(json.dumps(entry, ensure_ascii=False))

    def get(self, domain: str) -> dict[str, Any] | None:
        clean = _normalize_domain(domain)
        with self.lock:
            entry = self.data['domains'].get(clean)
            return json.loads(json.dumps(entry, ensure_ascii=False)) if entry else None

    def summary(self) -> dict[str, Any]:
        with self.lock:
            entries = list(self.data['domains'].values())
            colors = {risk: sum((1 for item in entries if item.get('risk') == risk)) for risk in RISK_ORDER}
            stages = {stage: sum((1 for item in entries if item.get('stage') == stage)) for stage in STAGE_LABELS}
            return {'version': ENGINE_VERSION, 'engine': 'DNS Engine V3', 'classificationRuleset': CLASSIFICATION_RULESET_VERSION, 'total': len(entries), 'colors': colors, 'stages': stages, 'pending': len(self.pending), 'activeAnalysis': self.active_analysis}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {'version': ENGINE_VERSION, 'engine': 'DNS Engine V3', 'definitions': {'green': RISK_LABELS['green'], 'orange': RISK_LABELS['orange'], 'red': RISK_LABELS['red']}, 'summary': self.summary(), 'domains': json.loads(json.dumps(self.data['domains'], ensure_ascii=False))}
