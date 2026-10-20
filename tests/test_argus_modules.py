"""Tests for the active web modules: takeover, reflected-XSS and path discovery.

Runs with the standard library only:
    python3 -m unittest discover -s tests -v

Active checks run against a local HTTP server started by the tests, so the
assertions exercise real request/response behaviour, including the false-positive
controls (soft-404 pages, encoded reflections) and redaction.
"""
import html
import http.server
import pathlib
import sys
import threading
import unittest
from urllib.parse import parse_qs, urlparse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from t4wf1q.scanners import paths, takeover, xss  # noqa: E402
from t4wf1q.scanners.base import ScanContext  # noqa: E402
from t4wf1q.scanners.netutil import Resp  # noqa: E402
from t4wf1q.scope import ScopeGuard  # noqa: E402

SOFT_404 = "<html><body><h1>Welcome</h1><p>Generic landing page for this site.</p></body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html") -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/reflect":
            return self._send(200, f"<html><body>Hello {q.get('q', [''])[0]}</body></html>")
        if u.path == "/escaped":
            return self._send(200, f"<html><body>Hello {html.escape(q.get('q', [''])[0])}</body></html>")
        if u.path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if u.path == "/.env":
            return self._send(200, "DB_PASSWORD=hunter2\nAPI_SECRET=topsecret\n", "text/plain")
        if u.path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /private-area\n", "text/plain")
        if u.path == "/private-area":
            return self._send(200, "<html><body>" + ("Internal content. " * 40) + "</body></html>")
        if u.path == "/admin/":
            return self._send(403, "Forbidden")
        # Everything else is a soft-404: 200 with a generic page.
        return self._send(200, SOFT_404)


class LocalServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def ctx(self) -> ScanContext:
        return ScanContext(asset={"id": "t", "target": self.base}, scan_id="s", cfg=None,
                           log=lambda level, msg: None,
                           scanners_cfg={"request_delay": 0, "request_timeout": 5, "concurrency": 4})

    def allow_local(self) -> ScopeGuard:
        return ScopeGuard(enforce=True, allow=["127.0.0.1"], deny=[])


class TakeoverTests(unittest.TestCase):
    def test_dangling_github_pages_is_high_confidence(self):
        f = takeover.check_host(
            "blog.example.com",
            resolve_cname=lambda h: "acme-old.github.io",
            name_exists=lambda n: False,  # NXDOMAIN
            fetch_fn=lambda u: Resp(u, 404, {}, "<html>There isn't a GitHub Pages site here.</html>", 40),
        )
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "high")
        self.assertEqual(f.source, "argus-takeover")
        self.assertIn("UNVERIFIED", f.description)  # never auto-confirmed

    def test_live_third_party_cname_is_not_flagged(self):
        f = takeover.check_host(
            "www.example.com",
            resolve_cname=lambda h: "cdn.example.net",
            name_exists=lambda n: True,
            fetch_fn=lambda u: Resp(u, 200, {}, "<html>real site</html>", 20),
        )
        self.assertIsNone(f)

    def test_nxdomain_only_is_low_confidence(self):
        f = takeover.check_host(
            "old.example.com",
            resolve_cname=lambda h: "gone.unknown-provider.test",
            name_exists=lambda n: False,
            fetch_fn=lambda u: None,
        )
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "low")

    def test_provider_classification(self):
        self.assertEqual(takeover.classify("app.herokuapp.com")[0], "Heroku")
        self.assertEqual(takeover.classify("bucket.s3-website-us-east-1.amazonaws.com")[0], "AWS S3")
        self.assertIsNone(takeover.classify("cdn.example.net"))

    def test_no_cname_means_no_finding(self):
        f = takeover.check_host("plain.example.com", resolve_cname=lambda h: None,
                                name_exists=lambda n: False, fetch_fn=lambda u: None)
        self.assertIsNone(f)


class XssTests(LocalServerTestCase):
    def test_unescaped_reflection_is_a_candidate(self):
        findings = xss.probe_url(f"{self.base}/reflect?q=test", delay=0, timeout=5)
        self.assertEqual(len(findings), 1)
        self.assertIn("reflected XSS", findings[0].title)
        self.assertEqual(findings[0].confidence, "medium")
        self.assertEqual(findings[0].cwe, "CWE-79")

    def test_encoded_reflection_is_not_flagged(self):
        self.assertEqual(xss.probe_url(f"{self.base}/escaped?q=test", delay=0, timeout=5), [])

    def test_urls_without_parameters_are_skipped(self):
        self.assertEqual(xss.probe_url(f"{self.base}/reflect", delay=0, timeout=5), [])

    def test_scope_guard_blocks_out_of_scope_urls(self):
        guard = ScopeGuard(enforce=True, allow=["example.org"], deny=[])
        self.assertEqual(xss.scan(self.ctx(), [f"{self.base}/reflect?q=x"], guard=guard), [])


class PathTests(LocalServerTestCase):
    def test_finds_real_exposures_and_ignores_soft_404s(self):
        findings = paths.scan(self.ctx(), [self.base], guard=self.allow_local())
        titles = {f.title for f in findings}
        self.assertIn("Exposed .git repository", titles)
        self.assertIn("Exposed .env file", titles)
        self.assertIn("Path disclosed in robots.txt: /private-area", titles)
        # the soft-404 server answers every unknown path with 200 HTML:
        # none of these should be reported.
        self.assertFalse(any("phpinfo" in t.lower() or "adminer" in t.lower() for t in titles))

    def test_secret_values_are_never_in_findings(self):
        findings = paths.scan(self.ctx(), [self.base], guard=self.allow_local())
        blob = " ".join(f"{f.evidence} {f.description} {f.remediation}" for f in findings)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("topsecret", blob)

    def test_restricted_admin_is_reported_as_info(self):
        findings = paths.scan(self.ctx(), [self.base], categories={"admin"}, guard=self.allow_local())
        self.assertTrue(any(f.severity == "info" and "Restricted admin surface" in f.title for f in findings))

    def test_out_of_scope_origin_is_never_probed(self):
        guard = ScopeGuard(enforce=True, allow=["example.org"], deny=[])
        self.assertEqual(paths.scan(self.ctx(), [self.base], guard=guard), [])

    def test_non_http_targets_are_ignored(self):
        self.assertEqual(paths.scan(self.ctx(), ["file:///etc/passwd"], guard=self.allow_local()), [])


if __name__ == "__main__":
    unittest.main()
