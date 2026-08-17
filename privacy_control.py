from __future__ import annotations
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
PERMISSION_KEYS = ('location', 'motion', 'tracking')
DESIRED_STATES = {'allow', 'monitor', 'deny'}
SYSTEM_PROTECTION_STATES = {'monitor', 'block'}
CONTAINMENT_STATES = {'monitor', 'auto_block'}
PRIVACY_CATEGORIES = {'location': 'Location', 'motion': 'Motion and sensors', 'tracking': 'Tracking'}
PRIVACY_ACTIVITIES = {'location': 'Uses location', 'motion': 'Accesses motion and sensors', 'tracking': 'Checks or uses tracking permission'}

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')

def _desired(value: Any) -> str:
    clean = str(value or 'monitor').strip().lower()
    return clean if clean in DESIRED_STATES else 'monitor'

def _system_protection(value: Any) -> str:
    clean = str(value or 'monitor').strip().lower()
    return clean if clean in SYSTEM_PROTECTION_STATES else 'monitor'

def _containment(value: Any) -> str:
    clean = str(value or 'monitor').strip().lower()
    return clean if clean in CONTAINMENT_STATES else 'monitor'

def _empty_result() -> dict[str, Any]:
    return {'capturedAt': '', 'logPath': '', 'location': {'state': 'not_seen', 'requests': 0, 'updates': 0}, 'motion': {'state': 'not_seen', 'sessions': 0, 'samples': 0}, 'tracking': {'state': 'not_seen', 'checks': 0, 'authorizationStatus': None}, 'systemProtection': {'detected': False, 'requests': 0, 'bytesSent': 0, 'bytesReceived': 0}, 'developerChecks': {'detected': False, 'signals': []}}

def evaluate_result(desired: dict[str, str], result: dict[str, Any]) -> dict[str, dict[str, str]]:
    evaluation: dict[str, dict[str, str]] = {}
    for key in PERMISSION_KEYS:
        wanted = _desired(desired.get(key))
        observed = str(result.get(key, {}).get('state') or 'not_seen')
        if wanted == 'deny':
            if observed in {'used', 'authorized'}:
                verdict = 'violation'
            elif observed in {'denied', 'restricted', 'requested'}:
                verdict = 'protected'
            else:
                verdict = 'not_verified'
        elif wanted == 'allow':
            verdict = 'allowed' if observed in {'used', 'authorized'} else 'not_observed'
        else:
            verdict = 'observed' if observed != 'not_seen' else 'not_observed'
        evaluation[key] = {'desired': wanted, 'observed': observed, 'verdict': verdict, 'category': PRIVACY_CATEGORIES[key], 'activity': PRIVACY_ACTIVITIES[key], 'classification': {'violation': 'Privacy choice violation', 'protected': 'Blocked by iOS', 'allowed': 'Allowed by your choice', 'observed': 'Monitored', 'not_observed': 'No use observed', 'not_verified': 'Not verified'}[verdict]}
    return evaluation

def build_privacy_incident(bundle_id: str, app_name: str, result: dict[str, Any], evaluation: dict[str, dict[str, str]], desired: dict[str, str] | None=None) -> dict[str, Any] | None:
    violations = []
    for key in PERMISSION_KEYS:
        item = evaluation.get(key, {})
        if item.get('verdict') != 'violation':
            continue
        violations.append({'key': key, 'category': item.get('category', PRIVACY_CATEGORIES[key]), 'activity': item.get('activity', PRIVACY_ACTIVITIES[key]), 'classification': 'Privacy choice violation', 'evidence': result.get(key, {})})
    if not violations:
        return None
    captured_at = str(result.get('capturedAt') or now_iso())
    keys = '-'.join((item['key'] for item in violations))
    return {'id': f'{captured_at}|{bundle_id}|{keys}', 'capturedAt': captured_at, 'bundleID': bundle_id, 'appName': app_name, 'severity': 'high', 'title': 'Privacy choice violation', 'violations': violations, 'protectionMode': _containment((desired or {}).get('containment')), 'containment': result.get('containment', {})}

def analyze_syslog(path: Path) -> dict[str, Any]:
    result = _empty_result()
    result['capturedAt'] = now_iso()
    result['logPath'] = str(path.resolve())
    if not path.exists():
        return result
    tracking_status: int | None = None
    developer_signals: set[str] = set()
    sent_pattern = re.compile('Sent\\s+(\\d+)\\s+bytes,\\s+received\\s+(\\d+)\\s+bytes', re.IGNORECASE)
    tracking_pattern = re.compile('(?:Returning from trackingAuthorizationStatus(?:\\s+-)?|Returning)\\s+(?:-|status\\s*)?([0-3])\\b', re.IGNORECASE)
    with path.open('r', encoding='utf-8', errors='replace') as handle:
        for line in handle:
            if '"_cmd":"startUpdatingLocation"' in line:
                result['location']['requests'] += 1
            if 'locationManager:didUpdateLocations:' in line:
                result['location']['updates'] += 1
            if 'FastPath opened' in line and 'CoreMotion' in line:
                result['motion']['sessions'] += 1
            if 'CMDeviceMotion:' in line:
                result['motion']['samples'] += 1
            if 'trackingAuthorizationStatus API call invoked' in line:
                result['tracking']['checks'] += 1
            if 'trackingAuthorizationStatus' in line and (match := tracking_pattern.search(line)):
                tracking_status = int(match.group(1))
            lower = line.lower()
            protection_markers = ('devicecheck', 'appattest', 'developer mode', 'jailbreak', 'root check', 'integrity check')
            if any((marker in lower for marker in protection_markers)):
                result['systemProtection']['detected'] = True
                if (match := sent_pattern.search(line)):
                    result['systemProtection']['requests'] += 1
                    result['systemProtection']['bytesSent'] += int(match.group(1))
                    result['systemProtection']['bytesReceived'] += int(match.group(2))
            for label, marker in (('kern.bootargs', 'kern.bootargs'), ('gdb', '/sbin/gdb'), ('lldb', '/sbin/lldb'), ('jailbreak-files', '/private/etc/apt'), ('ssh-port', 'port 22'), ('process-fork', 'process-fork')):
                if marker in lower:
                    developer_signals.add(label)
    if result['location']['updates']:
        result['location']['state'] = 'used'
    elif result['location']['requests']:
        result['location']['state'] = 'requested'
    if result['motion']['samples']:
        result['motion']['state'] = 'used'
    elif result['motion']['sessions']:
        result['motion']['state'] = 'requested'
    result['tracking']['authorizationStatus'] = tracking_status
    tracking_states = {0: 'not_determined', 1: 'restricted', 2: 'denied', 3: 'authorized'}
    if tracking_status is not None:
        result['tracking']['state'] = tracking_states[tracking_status]
    elif result['tracking']['checks']:
        result['tracking']['state'] = 'requested'
    result['developerChecks']['signals'] = sorted(developer_signals)
    result['developerChecks']['detected'] = bool(developer_signals)
    return result

class PrivacyControlStore:

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {'version': 4, 'mode': 'balanced', 'defaults': {'location': 'deny', 'motion': 'deny', 'tracking': 'deny', 'systemState': 'monitor', 'containment': 'monitor'}, 'apps': {}, 'incidents': []}
        self.load()

    def load(self) -> None:
        with self.lock:
            if self.path.exists():
                with self.path.open('r', encoding='utf-8') as handle:
                    raw = json.load(handle)
            else:
                raw = {'apps': {}}
            raw_defaults = raw.get('defaults', {})
            defaults = {key: _desired(raw_defaults.get(key, 'deny')) for key in PERMISSION_KEYS}
            defaults['systemState'] = _system_protection(raw_defaults.get('systemState', 'monitor'))
            defaults['containment'] = _containment(raw_defaults.get('containment', 'monitor'))
            apps: dict[str, Any] = {}
            for bundle_id, item in raw.get('apps', {}).items():
                clean_bundle = str(bundle_id).strip()[:180]
                if not clean_bundle or not isinstance(item, dict):
                    continue
                desired_raw = item.get('desired', {})
                desired = {key: _desired(desired_raw.get(key)) for key in PERMISSION_KEYS}
                desired['systemState'] = _system_protection(desired_raw.get('systemState'))
                desired['containment'] = _containment(desired_raw.get('containment', defaults['containment']))
                result = item.get('lastResult')
                if not isinstance(result, dict):
                    result = _empty_result()
                apps[clean_bundle] = {'bundleID': clean_bundle, 'appName': str(item.get('appName') or clean_bundle).strip()[:80], 'desired': desired, 'updatedAt': str(item.get('updatedAt') or now_iso()), 'lastResult': result, 'evaluation': evaluate_result(desired, result)}
            incidents = [item for item in raw.get('incidents', []) if isinstance(item, dict) and item.get('id')][-200:]
            known_incident_ids = {str(item['id']) for item in incidents}
            for item in incidents:
                related = apps.get(str(item.get('bundleID', '')), {})
                item.setdefault('protectionMode', _containment(related.get('desired', {}).get('containment')))
            for bundle_id, entry in apps.items():
                incident = build_privacy_incident(bundle_id, entry['appName'], entry['lastResult'], entry['evaluation'], entry['desired'])
                if incident and incident['id'] not in known_incident_ids:
                    incidents.append(incident)
                    known_incident_ids.add(incident['id'])
            incidents.sort(key=lambda item: str(item.get('capturedAt', '')), reverse=True)
            self.data = {'version': 4, 'mode': 'balanced', 'defaults': defaults, 'balancedDefaultsApplied': bool(raw.get('balancedDefaultsApplied', False)), 'manualEnforcementApplied': bool(raw.get('manualEnforcementApplied', False)), 'apps': apps, 'incidents': incidents[:200]}
            self.save()

    def save(self) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_suffix('.tmp')
            with temp.open('w', encoding='utf-8', newline='\n') as handle:
                json.dump(self.data, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
            os.replace(temp, self.path)

    def activate_balanced_defaults(self) -> dict[str, Any]:
        """Apply privacy-first defaults once, preserving explicit allow/deny choices."""
        with self.lock:
            defaults = self.data.setdefault('defaults', {})
            defaults.update({'location': 'deny', 'motion': 'deny', 'tracking': 'deny', 'systemState': 'monitor', 'containment': 'monitor'})
            changed = 0
            if not self.data.get('balancedDefaultsApplied'):
                for entry in self.data.setdefault('apps', {}).values():
                    desired = entry.setdefault('desired', {})
                    for key in PERMISSION_KEYS:
                        if _desired(desired.get(key)) == 'monitor':
                            desired[key] = 'deny'
                            changed += 1
                    result = entry.get('lastResult')
                    if not isinstance(result, dict):
                        result = _empty_result()
                    entry['evaluation'] = evaluate_result(desired, result)
                    entry['updatedAt'] = now_iso()
                self.data['balancedDefaultsApplied'] = True
            if not self.data.get('manualEnforcementApplied'):
                for entry in self.data.setdefault('apps', {}).values():
                    entry.setdefault('desired', {})['containment'] = 'monitor'
                self.data['manualEnforcementApplied'] = True
            self.data['version'] = 4
            self.data['mode'] = 'balanced'
            self.save()
            return {'changed': changed, 'defaults': dict(defaults)}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.data, ensure_ascii=False))

    def update(self, bundle_id: str, app_name: str, desired: dict[str, Any]) -> dict[str, Any]:
        clean_bundle = str(bundle_id).strip()[:180]
        if not clean_bundle or '.' not in clean_bundle:
            raise ValueError('An application identifier is required to save permissions')
        with self.lock:
            apps = self.data.setdefault('apps', {})
            current = apps.get(clean_bundle, {})
            defaults = self.data.get('defaults', {})
            clean_desired = {key: _desired(desired.get(key, current.get('desired', {}).get(key, defaults.get(key, 'deny')))) for key in PERMISSION_KEYS}
            clean_desired['systemState'] = _system_protection(desired.get('systemState', current.get('desired', {}).get('systemState')))
            clean_desired['containment'] = _containment(desired.get('containment', current.get('desired', {}).get('containment', defaults.get('containment', 'monitor'))))
            result = current.get('lastResult')
            if not isinstance(result, dict):
                result = _empty_result()
            entry = {'bundleID': clean_bundle, 'appName': str(app_name or clean_bundle).strip()[:80], 'desired': clean_desired, 'updatedAt': now_iso(), 'lastResult': result, 'evaluation': evaluate_result(clean_desired, result)}
            apps[clean_bundle] = entry
            self.save()
            return json.loads(json.dumps(entry, ensure_ascii=False))

    def record_result(self, bundle_id: str, app_name: str, result: dict[str, Any]) -> dict[str, Any]:
        clean_bundle = str(bundle_id).strip()[:180]
        if not clean_bundle:
            raise ValueError('The application identifier is missing')
        with self.lock:
            current = self.data.setdefault('apps', {}).get(clean_bundle, {})
            defaults = self.data.get('defaults', {})
            desired = {key: _desired(current.get('desired', {}).get(key, defaults.get(key, 'deny'))) for key in PERMISSION_KEYS}
            desired['systemState'] = _system_protection(current.get('desired', {}).get('systemState'))
            desired['containment'] = _containment(current.get('desired', {}).get('containment', defaults.get('containment', 'monitor')))
            evaluation = evaluate_result(desired, result)
            entry = {'bundleID': clean_bundle, 'appName': str(app_name or current.get('appName') or clean_bundle).strip()[:80], 'desired': desired, 'updatedAt': now_iso(), 'lastResult': result, 'evaluation': evaluation}
            self.data['apps'][clean_bundle] = entry
            incident = build_privacy_incident(clean_bundle, entry['appName'], result, evaluation, desired)
            if incident:
                incidents = self.data.setdefault('incidents', [])
                incidents[:] = [item for item in incidents if item.get('id') != incident['id']]
                incidents.insert(0, incident)
                del incidents[200:]
            self.save()
            return json.loads(json.dumps(entry, ensure_ascii=False))
