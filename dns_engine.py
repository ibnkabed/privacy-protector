from __future__ import annotations
import hashlib
import ipaddress
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
DEFAULT_PRIMARY_UPSTREAM = 'https://cloudflare-dns.com/dns-query'
DEFAULT_FALLBACK_UPSTREAM = 'https://dns.google/dns-query'
MAX_DNS_MESSAGE = 65535
MAX_UDP_MESSAGE = 4096
QTYPE_NAMES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS'}

def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')

def _safe_error(value: Any, limit: int=240) -> str:
    text = ' '.join(str(value).split())
    return text[:limit]

def _provider_display(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            return 'configured-provider'
        host = parsed.hostname
        if ':' in host and (not host.startswith('[')):
            host = f'[{host}]'
        if parsed.port:
            host = f'{host}:{parsed.port}'
        return urllib.parse.urlunsplit((parsed.scheme, host, parsed.path or '/', '', ''))
    except (TypeError, ValueError):
        return 'configured-provider'

def normalize_domain(value: str) -> str:
    raw = str(value or '').strip().rstrip('.')
    if not raw or len(raw) > 253 or '\x00' in raw:
        return ''
    normalized: list[str] = []
    for label in raw.split('.'):
        if not label or len(label) > 63:
            return ''
        try:
            encoded = label.encode('idna').decode('ascii').lower()
        except (UnicodeError, ValueError):
            return ''
        if len(encoded) > 63 or encoded.startswith('-') or encoded.endswith('-'):
            return ''
        if any((not (char.isalnum() or char in {'-', '_'}) for char in encoded)):
            return ''
        normalized.append(encoded)
    result = '.'.join(normalized)
    return result if len(result) <= 253 else ''

def _read_name(packet: bytes, offset: int, visited: set[int] | None=None) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    seen = set() if visited is None else set(visited)
    jumps = 0
    while True:
        if cursor >= len(packet):
            raise ValueError('Invalid DNS name')
        length = packet[cursor]
        if length == 0:
            cursor += 1
            if next_offset is None:
                next_offset = cursor
            break
        if length & 192 == 192:
            if cursor + 1 >= len(packet):
                raise ValueError('Invalid DNS compression pointer')
            pointer = (length & 63) << 8 | packet[cursor + 1]
            if pointer >= len(packet) or pointer in seen:
                raise ValueError('Invalid DNS compression pointer')
            seen.add(pointer)
            jumps += 1
            if jumps > 32:
                raise ValueError('DNS compression chain is too deep')
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 192:
            raise ValueError('Unsupported DNS label type')
        cursor += 1
        if length > 63 or cursor + length > len(packet):
            raise ValueError('Invalid DNS label')
        try:
            labels.append(packet[cursor:cursor + length].decode('ascii'))
        except UnicodeDecodeError as exc:
            raise ValueError('DNS label is not ASCII/IDNA') from exc
        cursor += length
    return ('.'.join(labels), int(next_offset))

@dataclass(frozen=True)
class DNSQuestion:
    domain: str
    qtype: int
    qclass: int
    question_end: int
    flags: int
    dnssec_requested: bool

def parse_question(packet: bytes) -> DNSQuestion:
    if len(packet) < 17 or len(packet) > MAX_DNS_MESSAGE:
        raise ValueError('DNS packet size is invalid')
    _, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', packet[:12])
    if flags & 32768:
        raise ValueError('Expected a DNS query, received a response')
    if qdcount != 1:
        raise ValueError('Exactly one DNS question is required')
    raw_name, offset = _read_name(packet, 12)
    domain = normalize_domain(raw_name)
    if not domain:
        raise ValueError('DNS question name is invalid')
    if offset + 4 > len(packet):
        raise ValueError('DNS question has no type/class')
    qtype, qclass = struct.unpack('!HH', packet[offset:offset + 4])
    question_end = offset + 4
    dnssec_requested = False
    cursor = question_end
    for count in (ancount, nscount):
        for _ in range(count):
            _, cursor = _read_name(packet, cursor)
            if cursor + 10 > len(packet):
                raise ValueError('Truncated DNS record')
            rdlength = struct.unpack('!H', packet[cursor + 8:cursor + 10])[0]
            cursor += 10 + rdlength
            if cursor > len(packet):
                raise ValueError('Truncated DNS record data')
    for _ in range(arcount):
        _, cursor = _read_name(packet, cursor)
        if cursor + 10 > len(packet):
            raise ValueError('Truncated DNS additional record')
        rtype, _, ttl, rdlength = struct.unpack('!HHIH', packet[cursor:cursor + 10])
        if rtype == 41:
            dnssec_requested = bool(ttl & 32768)
        cursor += 10 + rdlength
        if cursor > len(packet):
            raise ValueError('Truncated DNS additional data')
    return DNSQuestion(domain, qtype, qclass, question_end, flags, dnssec_requested)

def question_details(packet: bytes) -> tuple[str, int, int]:
    question = parse_question(packet)
    return (question.domain, question.qtype, question.question_end)

def error_response(query: bytes, rcode: int) -> bytes:
    try:
        question_end = parse_question(query).question_end
    except ValueError:
        question_end = min(len(query), 12)
    query_id = query[:2] if len(query) >= 2 else b'\x00\x00'
    original_flags = struct.unpack('!H', query[2:4])[0] if len(query) >= 4 else 0
    flags = 32768 | 128 | original_flags & 272 | rcode & 15
    qdcount = query[4:6] if len(query) >= 6 else b'\x00\x00'
    header = query_id + struct.pack('!H', flags) + qdcount + b'\x00\x00\x00\x00\x00\x00'
    return header + query[12:question_end]

@dataclass
class ResponseAnalysis:
    rcode: int
    truncated: bool
    cache_ttl: int
    ttl_fields: list[tuple[int, int]]
    cname_chain: list[str]
    negative: bool

def analyze_response(packet: bytes) -> ResponseAnalysis:
    if len(packet) < 12 or len(packet) > MAX_DNS_MESSAGE:
        raise ValueError('DNS response size is invalid')
    _, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', packet[:12])
    if not flags & 32768:
        raise ValueError('Upstream payload is not a DNS response')
    rcode = flags & 15
    cursor = 12
    for _ in range(qdcount):
        _, cursor = _read_name(packet, cursor)
        cursor += 4
        if cursor > len(packet):
            raise ValueError('Truncated DNS response question')
    ttl_fields: list[tuple[int, int]] = []
    answer_ttls: list[int] = []
    authority_soa_ttls: list[int] = []
    cname_chain: list[str] = []
    total_records = ancount + nscount + arcount
    for index in range(total_records):
        _, cursor = _read_name(packet, cursor)
        if cursor + 10 > len(packet):
            raise ValueError('Truncated DNS response record')
        rtype, _, ttl, rdlength = struct.unpack('!HHIH', packet[cursor:cursor + 10])
        ttl_offset = cursor + 4
        rdata_offset = cursor + 10
        rdata_end = rdata_offset + rdlength
        if rdata_end > len(packet):
            raise ValueError('Truncated DNS response data')
        ttl_fields.append((ttl_offset, ttl))
        in_answer = index < ancount
        in_authority = ancount <= index < ancount + nscount
        if in_answer and rtype != 41:
            answer_ttls.append(ttl)
        if in_answer and rtype == 5:
            try:
                target, _ = _read_name(packet, rdata_offset)
                clean_target = normalize_domain(target)
                if clean_target and clean_target not in cname_chain:
                    cname_chain.append(clean_target)
            except ValueError:
                pass
        if in_authority and rtype == 6:
            try:
                _, soa_cursor = _read_name(packet, rdata_offset)
                _, soa_cursor = _read_name(packet, soa_cursor)
                if soa_cursor + 20 <= rdata_end:
                    minimum = struct.unpack('!I', packet[soa_cursor + 16:soa_cursor + 20])[0]
                    authority_soa_ttls.append(min(ttl, minimum))
            except ValueError:
                pass
        cursor = rdata_end
    negative = rcode == 3 or (rcode == 0 and ancount == 0)
    if negative:
        cache_ttl = min(authority_soa_ttls) if authority_soa_ttls else 0
    else:
        cache_ttl = min(answer_ttls) if answer_ttls else 0
    return ResponseAnalysis(rcode=rcode, truncated=bool(flags & 512), cache_ttl=max(0, int(cache_ttl)), ttl_fields=ttl_fields, cname_chain=cname_chain, negative=negative)

def response_code(packet: bytes) -> int:
    return struct.unpack('!H', packet[2:4])[0] & 15 if len(packet) >= 4 else 1

def build_query(domain: str, qtype: int=1, query_id: int=20560, edns: bool=True) -> bytes:
    clean = normalize_domain(domain)
    if not clean:
        raise ValueError('Invalid DNS query name')
    labels = b''.join((bytes([len(part)]) + part.encode('ascii') for part in clean.split('.')))
    additional = b''
    arcount = 0
    if edns:
        additional = b'\x00' + struct.pack('!HHIH', 41, 1232, 0, 0)
        arcount = 1
    return struct.pack('!HHHHHH', query_id & 65535, 256, 1, 0, 0, arcount) + labels + b'\x00' + struct.pack('!HH', qtype, 1) + additional

@dataclass
class CacheEntry:
    response: bytes
    stored_at: float
    expires_at: float
    ttl_fields: list[tuple[int, int]]
    cname_chain: list[str]
    negative: bool

class DNSCache:

    def __init__(self, maximum: int=2048, positive_ttl_cap: int=86400, negative_ttl_cap: int=300):
        self.maximum = max(1, maximum)
        self.positive_ttl_cap = max(1, positive_ttl_cap)
        self.negative_ttl_cap = max(1, negative_ttl_cap)
        self.items: OrderedDict[tuple[Any, ...], CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    @staticmethod
    def key(query: bytes, question: DNSQuestion) -> tuple[Any, ...]:
        signature = hashlib.sha256(query[2:]).digest()
        return (question.domain, question.qtype, question.qclass, bool(question.flags & 256), bool(question.flags & 16), question.dnssec_requested, signature)

    def get(self, key: tuple[Any, ...], query_id: bytes) -> tuple[bytes, CacheEntry] | None:
        now = time.monotonic()
        with self.lock:
            entry = self.items.get(key)
            if not entry or entry.expires_at <= now:
                if entry:
                    self.items.pop(key, None)
                self.misses += 1
                return None
            self.items.move_to_end(key)
            self.hits += 1
            elapsed = max(0, int(now - entry.stored_at))
            answer = bytearray(entry.response)
            answer[:2] = query_id
            for offset, original_ttl in entry.ttl_fields:
                if offset + 4 <= len(answer):
                    answer[offset:offset + 4] = struct.pack('!I', max(0, original_ttl - elapsed))
            return (bytes(answer), entry)

    def put(self, key: tuple[Any, ...], response: bytes, analysis: ResponseAnalysis) -> bool:
        if analysis.rcode not in {0, 3} or analysis.cache_ttl <= 0 or analysis.truncated:
            return False
        cap = self.negative_ttl_cap if analysis.negative else self.positive_ttl_cap
        ttl = min(analysis.cache_ttl, cap)
        now = time.monotonic()
        entry = CacheEntry(response=bytes(response), stored_at=now, expires_at=now + ttl, ttl_fields=list(analysis.ttl_fields), cname_chain=list(analysis.cname_chain), negative=analysis.negative)
        with self.lock:
            self.items[key] = entry
            self.items.move_to_end(key)
            while len(self.items) > self.maximum:
                self.items.popitem(last=False)
                self.evictions += 1
        return True

    def invalidate(self, domain: str) -> int:
        clean = normalize_domain(domain)
        with self.lock:
            keys = [key for key in self.items if key[0] == clean]
            for key in keys:
                self.items.pop(key, None)
            return len(keys)

    def clear(self) -> int:
        with self.lock:
            removed = len(self.items)
            self.items.clear()
            return removed

    def summary(self) -> dict[str, int]:
        with self.lock:
            return {'entries': len(self.items), 'maximum': self.maximum, 'hits': self.hits, 'misses': self.misses, 'evictions': self.evictions}

@dataclass
class UpstreamResult:
    response: bytes
    provider: str
    latency_ms: float
    failover_reason: str
    truncated_retry: bool

class Resolver:

    def __init__(self, policy: Any, activity: Any, upstream: str=DEFAULT_PRIMARY_UPSTREAM, fallback_upstream: str=DEFAULT_FALLBACK_UPSTREAM, timeout: float=3.0, cache: DNSCache | None=None, maximum_concurrent: int=128, iphone_client_ip: str='', urlopen: Callable[..., Any] | None=None, classifications: Any | None=None):
        self.policy = policy
        self.activity = activity
        self.upstream = upstream
        self.fallback_upstream = fallback_upstream
        self.timeout = max(0.2, float(timeout))
        self.cache = cache or DNSCache()
        self.capacity = threading.BoundedSemaphore(max(1, maximum_concurrent))
        self._urlopen = urlopen or urllib.request.urlopen
        self.classifications = classifications
        self.lock = threading.RLock()
        self.started_at = time.time()
        self.transport_counts = {'udp': 0, 'tcp': 0}
        self.last_transport_at = {'udp': '', 'tcp': ''}
        self.last_query_at = ''
        self.last_non_loopback_at = ''
        self.last_non_loopback_client = ''
        self.iphone_client_ip = iphone_client_ip.strip()
        self.provider_health = {upstream: self._new_provider_state('primary'), fallback_upstream: self._new_provider_state('fallback')}
        self.recent_errors: deque[dict[str, str]] = deque(maxlen=20)
        self.self_test_lock = threading.RLock()
        self.self_test_actions: dict[str, str] = {}
        self.last_self_test: dict[str, Any] | None = None

    @staticmethod
    def _new_provider_state(role: str) -> dict[str, Any]:
        return {'role': role, 'state': 'notTested', 'lastSuccessAt': '', 'lastFailureAt': '', 'lastLatencyMs': None, 'consecutiveFailures': 0, 'cooldownUntil': 0.0, 'lastError': ''}

    def _record_transport(self, transport: str, client_ip: str) -> None:
        stamp = _now_iso()
        transport = transport if transport in self.transport_counts else 'unknown'
        with self.lock:
            if transport in self.transport_counts:
                self.transport_counts[transport] += 1
                self.last_transport_at[transport] = stamp
            self.last_query_at = stamp
            try:
                address = ipaddress.ip_address(client_ip)
                if not address.is_loopback:
                    self.last_non_loopback_at = stamp
                    self.last_non_loopback_client = client_ip
            except ValueError:
                pass

    def _provider_success(self, url: str, latency_ms: float) -> None:
        with self.lock:
            state = self.provider_health[url]
            state.update(state='healthy', lastSuccessAt=_now_iso(), lastLatencyMs=round(latency_ms, 2), consecutiveFailures=0, cooldownUntil=0.0, lastError='')

    def _provider_failure(self, url: str, error: Any) -> None:
        message = _safe_error(str(error).replace(url, _provider_display(url)))
        with self.lock:
            state = self.provider_health[url]
            failures = int(state['consecutiveFailures']) + 1
            state.update(state='unavailable', lastFailureAt=_now_iso(), consecutiveFailures=failures, lastError=message)
            if failures >= 2:
                state['cooldownUntil'] = time.monotonic() + min(30.0, 5.0 * failures)
            self.recent_errors.append({'time': _now_iso(), 'provider': _provider_display(url), 'error': message})

    def _provider_order(self) -> tuple[list[str], str]:
        now = time.monotonic()
        primary = self.provider_health[self.upstream]
        if primary['cooldownUntil'] > now:
            return ([self.fallback_upstream, self.upstream], 'primary provider cooldown')
        return ([self.upstream, self.fallback_upstream], '')

    def _doh_request(self, url: str, query: bytes) -> bytes:
        request = urllib.request.Request(url, data=query, headers={'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message', 'User-Agent': 'Privacy-Protector/2.0'}, method='POST')
        with self._urlopen(request, timeout=self.timeout) as response:
            answer = response.read(MAX_DNS_MESSAGE + 1)
        if len(answer) > MAX_DNS_MESSAGE:
            raise ValueError('Upstream DNS response exceeds 65535 bytes')
        if len(answer) < 12:
            raise ValueError('Upstream DNS response is too short')
        return answer

    def _forward(self, query: bytes) -> UpstreamResult:
        providers, failover_reason = self._provider_order()
        failures: list[str] = []
        for index, provider in enumerate(providers):
            started = time.perf_counter()
            try:
                answer = self._doh_request(provider, query)
                if answer[:2] != query[:2]:
                    raise ValueError('Upstream DNS transaction ID mismatch')
                analysis = analyze_response(answer)
                retried = False
                if analysis.truncated:
                    retried = True
                    answer = self._doh_request(provider, query)
                    if answer[:2] != query[:2]:
                        raise ValueError('Upstream DNS transaction ID mismatch after retry')
                    analysis = analyze_response(answer)
                    if analysis.truncated:
                        raise ValueError('Upstream DNS response remained truncated')
                latency_ms = (time.perf_counter() - started) * 1000
                self._provider_success(provider, latency_ms)
                if index > 0 and (not failover_reason):
                    failover_reason = failures[-1] if failures else 'primary provider failed'
                return UpstreamResult(answer, _provider_display(provider), latency_ms, failover_reason, retried)
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                self._provider_failure(provider, exc)
                failures.append(f"{self.provider_health[provider]['role']}: {_safe_error(exc)}")
        raise RuntimeError('; '.join(failures) or 'No DNS-over-HTTPS provider is configured')

    def _action_for(self, domain: str) -> str:
        with self.self_test_lock:
            if domain in self.self_test_actions:
                return self.self_test_actions[domain]
        return self.policy.action_for(domain)

    def _log(self, started: float, question: DNSQuestion | None, client_ip: str, transport: str, **fields: Any) -> None:
        duration = round((time.perf_counter() - started) * 1000, 2)
        observed_at = datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
        payload = {'time': observed_at, 'client': client_ip, 'domain': question.domain if question else 'invalid-request', 'qtype': question.qtype if question else 0, 'qtypeName': QTYPE_NAMES.get(question.qtype, f'TYPE{question.qtype}') if question else 'UNKNOWN', 'transport': transport, 'latencyMs': duration, **fields}
        self.activity.add(**payload)
        if self.classifications and question:
            try:
                self.classifications.observe(question.domain, qtype=payload['qtypeName'], transport=transport, decision=str(fields.get('decision', '')), cname_chain=list(fields.get('cnameChain', []) or []), observed_at=observed_at)
            except Exception:
                pass

    def resolve(self, query: bytes, client_ip: str, transport: str='udp') -> bytes:
        started = time.perf_counter()
        self._record_transport(transport, client_ip)
        try:
            question = parse_question(query)
        except (ValueError, UnicodeError) as exc:
            self._log(started, None, client_ip, transport, action='error', decision='error', rcode=1, upstream='', cache='bypass', error=_safe_error(exc), detail=_safe_error(exc))
            return error_response(query, 1)
        action = self._action_for(question.domain)
        if action == 'block':
            answer = error_response(query, 3)
            self._log(started, question, client_ip, transport, action='blocked', decision='block', rcode=3, upstream='', cache='bypass', error='', detail='Exact-hostname block')
            return answer
        key = self.cache.key(query, question)
        cached = self.cache.get(key, query[:2])
        if cached:
            answer, entry = cached
            self._log(started, question, client_ip, transport, action='allowed' if action == 'allow' else 'monitored', decision=action, rcode=response_code(answer), upstream='cache', cache='hit', error='', cnameChain=entry.cname_chain, detail='DNS cache response')
            return answer
        if not self.capacity.acquire(timeout=0.25):
            answer = error_response(query, 2)
            self._log(started, question, client_ip, transport, action='error', decision=action, rcode=2, upstream='', cache='miss', error='DNS engine concurrency limit reached', detail='The resolver is temporarily busy')
            return answer
        try:
            result = self._forward(query)
            analysis = analyze_response(result.response)
            self.cache.put(key, result.response, analysis)
            detail = 'Encrypted forwarding over DoH'
            if result.failover_reason:
                detail += 'Evidence-based privacy classification.'
            if result.truncated_retry:
                detail += 'Evidence-based privacy classification.'
            self._log(started, question, client_ip, transport, action='allowed' if action == 'allow' else 'monitored', decision=action, rcode=analysis.rcode, upstream=result.provider, upstreamLatencyMs=round(result.latency_ms, 2), failoverReason=result.failover_reason, cache='miss', error='', cnameChain=analysis.cname_chain, truncatedRetry=result.truncated_retry, detail=detail)
            return result.response
        except (RuntimeError, ValueError, OSError) as exc:
            answer = error_response(query, 2)
            self._log(started, question, client_ip, transport, action='error', decision=action, rcode=2, upstream='', cache='miss', error=_safe_error(exc), detail='Encrypted DNS providers are unreachable')
            return answer
        finally:
            self.capacity.release()

    def provider_snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            result = []
            for url in (self.upstream, self.fallback_upstream):
                state = dict(self.provider_health[url])
                state.pop('cooldownUntil', None)
                state['url'] = _provider_display(url)
                result.append(state)
            return result

    def coverage_snapshot(self, recent_seconds: int=300) -> dict[str, Any]:
        with self.lock:
            now = datetime.now(timezone.utc).astimezone()

            def recent(stamp: str) -> bool:
                if not stamp:
                    return False
                try:
                    return (now - datetime.fromisoformat(stamp)).total_seconds() <= recent_seconds
                except ValueError:
                    return False
            if self.iphone_client_ip and self.last_non_loopback_client == self.iphone_client_ip:
                iphone_state = 'confirmed'
            elif self.last_non_loopback_client:
                iphone_state = 'possibleClient'
            else:
                iphone_state = 'notSeen'
            return {'state': 'measured', 'windowSeconds': recent_seconds, 'recentQueries': recent(self.last_query_at), 'lastQueryAt': self.last_query_at, 'iphoneClient': {'state': iphone_state, 'configuredAddress': bool(self.iphone_client_ip), 'lastSeenAt': self.last_non_loopback_at}, 'transports': {name: {'received': self.transport_counts[name] > 0, 'recent': recent(self.last_transport_at[name]), 'count': self.transport_counts[name], 'lastSeenAt': self.last_transport_at[name]} for name in ('udp', 'tcp')}, 'providers': self.provider_snapshot(), 'cache': self.cache.summary(), 'recentErrors': list(self.recent_errors), 'lastSelfTest': self.last_self_test, 'blindSpots': ['cellular traffic that does not traverse this computer', 'encrypted DNS implemented inside an application', 'direct IP connections', 'DNS answers cached before the observation window', 'VPN or another DNS/profile path', 'Wi-Fi or computer connectivity interruptions', 'HTTPS paths, encrypted contents, and application function names']}

    @staticmethod
    def _udp_exchange(host: str, port: int, query: bytes, timeout: float) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            connection.sendto(query, (host, port))
            return connection.recvfrom(MAX_UDP_MESSAGE)[0]

    @staticmethod
    def _tcp_exchange(host: str, port: int, query: bytes, timeout: float) -> bytes:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(struct.pack('!H', len(query)) + query)
            size_raw = Resolver._read_exact(connection, 2)
            if len(size_raw) != 2:
                raise OSError('DNS TCP response has no length prefix')
            size = struct.unpack('!H', size_raw)[0]
            answer = Resolver._read_exact(connection, size)
            if len(answer) != size:
                raise OSError('DNS TCP response is incomplete')
            return answer

    @staticmethod
    def _read_exact(connection: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    @staticmethod
    def _check(name: str, function: Callable[[], Any]) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            detail = function()
            return {'name': name, 'state': 'passed', 'durationMs': round((time.perf_counter() - started) * 1000, 2), 'detail': detail if isinstance(detail, str) else 'ok'}
        except Exception as exc:
            return {'name': name, 'state': 'failed', 'durationMs': round((time.perf_counter() - started) * 1000, 2), 'detail': _safe_error(exc)}

    def run_self_test(self, host: str, port: int) -> dict[str, Any]:
        target = '127.0.0.1' if host in {'', '0.0.0.0', '::'} else host
        block_query = build_query('block.dns-selftest.invalid', 1, 20737)
        monitor_query = build_query('monitor.dns-selftest.invalid', 28, 20738)
        allow_query = build_query('allow.dns-selftest.invalid', 65, 20739)
        provider_query = build_query('example.com', 1, 20740)
        before_id = int(self.activity.summary().get('lastEventId', 0))
        with self.self_test_lock:
            self.self_test_actions = {'block.dns-selftest.invalid': 'block', 'monitor.dns-selftest.invalid': 'monitor', 'allow.dns-selftest.invalid': 'allow'}
        try:
            checks = [self._check('udp', lambda: 'NXDOMAIN block response received' if response_code(self._udp_exchange(target, port, block_query, self.timeout)) == 3 else (_ for _ in ()).throw(RuntimeError('unexpected UDP response'))), self._check('tcp', lambda: 'NXDOMAIN block response received' if response_code(self._tcp_exchange(target, port, block_query, self.timeout)) == 3 else (_ for _ in ()).throw(RuntimeError('unexpected TCP response'))), self._check('monitor', lambda: f'rcode={response_code(self._udp_exchange(target, port, monitor_query, self.timeout))}'), self._check('allow', lambda: f'rcode={response_code(self._tcp_exchange(target, port, allow_query, self.timeout))}')]
            after_id = int(self.activity.summary().get('lastEventId', 0))
            checks.append({'name': 'logging', 'state': 'passed' if after_id >= before_id + 4 else 'failed', 'durationMs': 0.0, 'detail': f'{after_id - before_id} DNS events recorded'})
        finally:
            with self.self_test_lock:
                self.self_test_actions = {}

        def test_provider(provider: str) -> str:
            started = time.perf_counter()
            try:
                answer = self._doh_request(provider, provider_query)
                if answer[:2] != provider_query[:2]:
                    raise ValueError('Upstream DNS transaction ID mismatch')
                analysis = analyze_response(answer)
                if analysis.truncated:
                    raise ValueError('Provider returned a truncated DoH response')
                latency_ms = (time.perf_counter() - started) * 1000
                self._provider_success(provider, latency_ms)
                return f'rcode={analysis.rcode}'
            except Exception as exc:
                self._provider_failure(provider, exc)
                raise
        checks.extend((self._check(f"doh-{self.provider_health[provider]['role']}", lambda provider=provider: test_provider(provider)) for provider in (self.upstream, self.fallback_upstream)))
        states = {item['state'] for item in checks}
        overall = 'passed' if states == {'passed'} else 'failed'
        result = {'state': overall, 'testedAt': _now_iso(), 'checks': checks}
        with self.lock:
            self.last_self_test = result
        return result
