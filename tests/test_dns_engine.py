import json
import socket
import struct
import tempfile
import threading
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import app
from app import (
    ActivityLog,
    AppProfileStore,
    AppState,
    DashboardHandler,
    PolicyStore,
    PrivacyCaptureManager,
    start_dns,
)
from dns_engine import (
    DNSCache,
    Resolver,
    analyze_response,
    build_query,
    normalize_domain,
    parse_question,
    raw_question_name,
    response_code,
    _provider_display,
)
from privacy_control import PrivacyControlStore


def answer_a(query: bytes, ttl: int = 30) -> bytes:
    question = parse_question(query)
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + b"\x7f\x00\x00\x01"
    return header + query[12 : question.question_end] + record


def answer_cname(query: bytes, target: str = "target.example", ttl: int = 60) -> bytes:
    question = parse_question(query)
    target_wire = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in target.split(".")
    ) + b"\x00"
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    record = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 5, 1, ttl, len(target_wire))
        + target_wire
    )
    return header + query[12 : question.question_end] + record


def answer_dangling(query: bytes, cname_ttl: int = 3600, soa_ttl: int = 30) -> bytes:
    """A CNAME with no record of the requested type, plus a short SOA."""
    base = answer_cname(query, ttl=cname_ttl)
    mname = b"\x02ns\x07example\x00"
    rname = b"\x04host\x07example\x00"
    soa = mname + rname + struct.pack("!IIIII", 1, 60, 60, 60, soa_ttl)
    authority = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, soa_ttl, len(soa)) + soa
    return base[:8] + struct.pack("!H", 1) + base[10:] + authority


def answer_truncated(query: bytes) -> bytes:
    question = parse_question(query)
    return (
        query[:2]
        + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0)
        + query[12 : question.question_end]
    )


def answer_nxdomain(query: bytes, ttl: int = 30, minimum: int = 20) -> bytes:
    question = parse_question(query)
    mname = b"\x02ns\x07example\x00"
    rname = b"\x04host\x07example\x00"
    soa = mname + rname + struct.pack("!IIIII", 1, 60, 60, 60, minimum)
    header = query[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 1, 0)
    authority = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, ttl, len(soa)) + soa
    return header + query[12 : question.question_end] + authority


class LocalDoHHandler(BaseHTTPRequestHandler):
    requests = []
    primary_failures = 0
    truncated_once = False

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        query = self.rfile.read(size)
        type(self).requests.append((self.path, query))
        if self.path == "/primary" and type(self).primary_failures > 0:
            type(self).primary_failures -= 1
            self.send_response(503)
            self.end_headers()
            return
        if self.path == "/truncated" and not type(self).truncated_once:
            type(self).truncated_once = True
            payload = answer_truncated(query)
        elif self.path == "/cname":
            payload = answer_cname(query)
        elif self.path == "/dangling":
            payload = answer_dangling(query)
        else:
            payload = answer_a(query)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


class LocalDoHServer:
    def __enter__(self):
        LocalDoHHandler.requests = []
        LocalDoHHandler.primary_failures = 0
        LocalDoHHandler.truncated_once = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalDoHHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class DNSEngineTests(unittest.TestCase):
    def make_policy(self, folder: str, domains=None) -> PolicyStore:
        path = Path(folder) / "policy.json"
        path.write_text(json.dumps({"domains": domains or {}}), encoding="utf-8")
        return PolicyStore(path)

    def test_dangling_cname_is_a_short_negative(self):
        query = build_query("schools.example", 1)
        analysis = analyze_response(answer_dangling(query))
        self.assertTrue(analysis.dangling)
        self.assertTrue(analysis.negative)
        self.assertEqual(analysis.cache_ttl, 30)
        self.assertFalse(analyze_response(answer_a(query)).dangling)
        self.assertFalse(analyze_response(answer_dangling(build_query("x.example", 5))).dangling)

    def test_dangling_a_answer_tries_the_other_provider(self):
        query = build_query("schools.example", 1)
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as server:
            resolver = Resolver(
                self.make_policy(folder), ActivityLog(),
                server.base + "/dangling", server.base + "/fallback", timeout=1,
            )
            answer = resolver.resolve(query, "127.0.0.1")
            self.assertFalse(analyze_response(answer).dangling)
            self.assertEqual([path for path, _ in LocalDoHHandler.requests], ["/dangling", "/fallback"])

    def test_dangling_from_both_providers_is_returned_not_an_error(self):
        query = build_query("schools.example", 1)
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as server:
            resolver = Resolver(
                self.make_policy(folder), ActivityLog(),
                server.base + "/dangling", server.base + "/dangling", timeout=1,
            )
            self.assertEqual(response_code(resolver.resolve(query, "127.0.0.1")), 0)

    def test_normalization_idna_and_invalid_names(self):
        self.assertEqual(normalize_domain(" BÜCHER.DE. "), "xn--bcher-kva.de")
        self.assertEqual(normalize_domain("_sip._tcp.EXAMPLE.COM."), "_sip._tcp.example.com")
        for invalid in ("", ".", "*.example.com", "has space.example", "-bad.example"):
            self.assertEqual(normalize_domain(invalid), "")

    def test_rejected_question_name_is_described(self):
        label = "مرحبا".encode("utf-8")
        packet = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + bytes([len(label)]) + label + bytes([3]) + b"com" + bytes([0]) + struct.pack("!HH", 1, 1)
        with self.assertRaises(ValueError):
            parse_question(packet)
        self.assertEqual(raw_question_name(packet), "مرحبا.com")

    def test_provider_display_redacts_credentials_and_query_parameters(self):
        self.assertEqual(
            _provider_display("https://user:secret@example.test/dns-query?token=private#fragment"),
            "https://example.test/dns-query",
        )

    def test_common_query_types_and_edns_dnssec_are_parsed(self):
        for qtype in (1, 2, 12, 15, 16, 28, 33, 64, 65):
            question = parse_question(build_query("example.com", qtype, edns=True))
            self.assertEqual(question.qtype, qtype)
            self.assertEqual(question.domain, "example.com")
        query = bytearray(build_query("example.com", 1, edns=True))
        query[-6:-2] = struct.pack("!I", 0x8000)
        self.assertTrue(parse_question(bytes(query)).dnssec_requested)

    def test_positive_and_negative_cache_respect_ttl_and_query_id(self):
        cache = DNSCache(maximum=2)
        query = build_query("cache.example", 1, 0x1001)
        question = parse_question(query)
        analysis = analyze_response(answer_a(query, ttl=30))
        key = cache.key(query, question)
        self.assertTrue(cache.put(key, answer_a(query, ttl=30), analysis))
        entry = cache.items[key]
        entry.stored_at -= 5
        cached, _ = cache.get(key, b"\x20\x02")
        self.assertEqual(cached[:2], b"\x20\x02")
        ttl_offset = analysis.ttl_fields[0][0]
        self.assertEqual(struct.unpack("!I", cached[ttl_offset : ttl_offset + 4])[0], 25)

        nx_query = build_query("missing.example", 1, 0x1002)
        nx_analysis = analyze_response(answer_nxdomain(nx_query))
        self.assertTrue(nx_analysis.negative)
        self.assertEqual(nx_analysis.cache_ttl, 20)
        self.assertTrue(cache.put(cache.key(nx_query, parse_question(nx_query)), answer_nxdomain(nx_query), nx_analysis))
        self.assertLessEqual(cache.summary()["entries"], 2)

    def test_exact_policy_block_and_enriched_log_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            policy = self.make_policy(
                folder,
                {"blocked.example": {"action": "block", "label": "blocked"}},
            )
            activity = ActivityLog()
            resolver = Resolver(policy, activity)
            query = build_query("blocked.example", 65, 0x2201)
            answer = resolver.resolve(query, "127.0.0.1", "udp")
            self.assertEqual(response_code(answer), 3)
            row = activity.snapshot(1)[0]
            for field in (
                "id",
                "time",
                "client",
                "domain",
                "qtype",
                "qtypeName",
                "decision",
                "rcode",
                "latencyMs",
                "upstream",
                "cache",
                "error",
                "transport",
            ):
                self.assertIn(field, row)
            self.assertEqual(row["decision"], "block")
            self.assertEqual(policy.action_for("sub.blocked.example"), "monitor")

    def test_doh_failover_primary_recovery_and_cname_evidence(self):
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as upstream:
            policy = self.make_policy(folder)
            activity = ActivityLog()
            LocalDoHHandler.primary_failures = 1
            resolver = Resolver(
                policy,
                activity,
                upstream.base + "/primary",
                upstream.base + "/cname",
                timeout=1,
            )
            first = resolver.resolve(build_query("one.example", 1, 0x3001), "127.0.0.1")
            self.assertEqual(response_code(first), 0)
            first_row = activity.snapshot(1)[0]
            self.assertEqual(first_row["upstream"], upstream.base + "/cname")
            self.assertTrue(first_row["failoverReason"])
            self.assertEqual(first_row["cnameChain"], ["target.example"])

            second = resolver.resolve(build_query("two.example", 1, 0x3002), "127.0.0.1")
            self.assertEqual(response_code(second), 0)
            self.assertEqual(activity.snapshot(1)[0]["upstream"], upstream.base + "/primary")
            providers = resolver.provider_snapshot()
            self.assertEqual(providers[0]["state"], "healthy")
            self.assertEqual(providers[1]["state"], "healthy")

    def test_truncated_doh_response_is_retried(self):
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as upstream:
            resolver = Resolver(
                self.make_policy(folder),
                ActivityLog(),
                upstream.base + "/truncated",
                upstream.base + "/fallback",
                timeout=1,
            )
            answer = resolver.resolve(build_query("retry.example", 1), "127.0.0.1")
            self.assertEqual(response_code(answer), 0)
            self.assertTrue(resolver.activity.snapshot(1)[0]["truncatedRetry"])
            truncated_requests = [item for item in LocalDoHHandler.requests if item[0] == "/truncated"]
            self.assertEqual(len(truncated_requests), 2)

    def test_cache_hit_avoids_second_upstream_call(self):
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as upstream:
            activity = ActivityLog()
            resolver = Resolver(
                self.make_policy(folder),
                activity,
                upstream.base + "/primary",
                upstream.base + "/fallback",
                timeout=1,
            )
            query = build_query("cached.example", 1, 0x4001)
            resolver.resolve(query, "127.0.0.1")
            resolver.resolve(query[:2].replace(b"\x40\x01", b"\x40\x02") + query[2:], "127.0.0.1")
            self.assertEqual(len(LocalDoHHandler.requests), 1)
            self.assertEqual(activity.snapshot(1)[0]["cache"], "hit")

    def test_udp_tcp_concurrency_edns_and_self_test_use_local_upstream(self):
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as upstream:
            activity = ActivityLog()
            resolver = Resolver(
                self.make_policy(folder),
                activity,
                upstream.base + "/primary",
                upstream.base + "/fallback",
                timeout=1,
            )
            udp = tcp = None
            try:
                udp, tcp = start_dns(resolver, "127.0.0.1", 0)
                port = udp.server_address[1]
                query = build_query("transport.example", 28, 0x5001, edns=True)
                udp_answer = Resolver._udp_exchange("127.0.0.1", port, query, 1)
                tcp_answer = Resolver._tcp_exchange("127.0.0.1", port, query, 1)
                self.assertEqual(udp_answer[:2], query[:2])
                self.assertEqual(tcp_answer[:2], query[:2])
                self.assertIn(query, [item[1] for item in LocalDoHHandler.requests])

                def exchange(index):
                    item = build_query(f"concurrent-{index}.example", 1, 0x6000 + index)
                    answer = Resolver._udp_exchange("127.0.0.1", port, item, 2)
                    return item[:2], answer[:2]

                with ThreadPoolExecutor(max_workers=12) as pool:
                    pairs = list(pool.map(exchange, range(24)))
                self.assertTrue(all(expected == actual for expected, actual in pairs))

                result = resolver.run_self_test("127.0.0.1", port)
                self.assertEqual(result["state"], "passed")
                self.assertTrue(all(item["state"] == "passed" for item in result["checks"]))
                coverage = resolver.coverage_snapshot()
                self.assertTrue(coverage["transports"]["udp"]["received"])
                self.assertTrue(coverage["transports"]["tcp"]["received"])
            finally:
                for server in (udp, tcp):
                    if server:
                        server.shutdown()
                        server.server_close()

    def test_malformed_request_returns_format_error_without_crash(self):
        with tempfile.TemporaryDirectory() as folder:
            activity = ActivityLog()
            resolver = Resolver(self.make_policy(folder), activity)
            answer = resolver.resolve(b"\x12\x34bad", "127.0.0.1", "tcp")
            self.assertEqual(response_code(answer), 1)
            self.assertEqual(activity.snapshot(1)[0]["action"], "error")

    def test_dns_coverage_self_test_and_cache_apis(self):
        with tempfile.TemporaryDirectory() as folder, LocalDoHServer() as upstream:
            root = Path(folder)
            policy = self.make_policy(folder)
            profiles = AppProfileStore(root / "apps.json")
            controls = PrivacyControlStore(root / "privacy-controls.json")
            activity = ActivityLog(path=root / "activity.ndjson")
            resolver = Resolver(
                policy,
                activity,
                upstream.base + "/primary",
                upstream.base + "/fallback",
                timeout=1,
            )
            udp = tcp = dashboard = None
            dashboard_thread = None
            try:
                udp, tcp = start_dns(resolver, "127.0.0.1", 0)
                dns_port = udp.server_address[1]
                state = AppState(
                    policy,
                    profiles,
                    activity,
                    controls,
                    PrivacyCaptureManager(controls),
                    resolver,
                    "127.0.0.1",
                    dns_port,
                )
                DashboardHandler.state = state
                dashboard = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
                dashboard_thread = threading.Thread(target=dashboard.serve_forever, daemon=True)
                dashboard_thread.start()
                base = f"http://127.0.0.1:{dashboard.server_address[1]}"

                coverage = json.loads(urllib.request.urlopen(base + "/api/dns/coverage").read())
                self.assertIn("blindSpots", coverage)
                request = urllib.request.Request(
                    base + "/api/dns/self-test",
                    data=b"{}",
                    headers={"Content-Type": "application/json", app.TOKEN_HEADER: app.SESSION_TOKEN},
                    method="POST",
                )
                self_test = json.loads(urllib.request.urlopen(request, timeout=5).read())
                self.assertEqual(self_test["state"], "passed")

                resolver.resolve(build_query("cached-api.example", 1), "127.0.0.1")
                logs = json.loads(urllib.request.urlopen(base + "/api/logs?limit=1").read())
                self.assertIn("domainStats", logs)
                self.assertEqual(
                    logs["domainStats"]["cached-api.example"]["lastAction"],
                    "monitored",
                )
                self.assertTrue(
                    logs["domainStats"]["cached-api.example"]["lastObservedAt"]
                )
                before_policy = policy.snapshot()
                clear_request = urllib.request.Request(base + "/api/dns/cache", method="DELETE",
                                                       headers={app.TOKEN_HEADER: app.SESSION_TOKEN})
                cleared = json.loads(urllib.request.urlopen(clear_request).read())
                self.assertTrue(cleared["ok"])
                self.assertGreaterEqual(cleared["removed"], 1)
                self.assertEqual(policy.snapshot(), before_policy)
                self.assertGreater(len(activity.snapshot()), 0)
            finally:
                if dashboard:
                    dashboard.shutdown()
                    dashboard.server_close()
                if dashboard_thread:
                    dashboard_thread.join(timeout=2)
                for server in (udp, tcp):
                    if server:
                        server.shutdown()
                        server.server_close()

    def test_corrupt_activity_line_is_isolated_and_rotation_is_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "activity.ndjson"
            path.write_text(
                '{"id":1,"domain":"one.example","action":"monitored"}\nnot-json\n'
                '{"id":3,"domain":"three.example","action":"blocked"}\n',
                encoding="utf-8",
            )
            activity = ActivityLog(limit=10, path=path, rotation_bytes=1)
            self.assertEqual(activity.summary()["corruptLines"], 1)
            self.assertEqual(len(activity.snapshot()), 2)
            activity.add(domain="four.example", action="monitored", client="127.0.0.1")
            self.assertTrue(path.with_suffix(".previous.ndjson").exists())
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
