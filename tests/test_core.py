"""Core controls: SSRF/scope guard, finding lifecycle, rate limiter, and the
parsers for the Amass / ZAP / Dependency-Check / SQLMap adapters.

Everything here runs without the external tools or third-party packages.
"""
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import t4wf1q.db as db  # noqa: E402
from t4wf1q.ratelimit import RateLimiter  # noqa: E402
from t4wf1q.scanners import extra_tools  # noqa: E402
from t4wf1q.scanners.base import Finding, ScanContext  # noqa: E402
from t4wf1q.scope import ScopeGuard  # noqa: E402


class ScopeGuardTests(unittest.TestCase):
    def test_metadata_endpoint_blocked_even_when_allowlisted(self):
        g = ScopeGuard(enforce=True, allow=["169.254.169.254"], deny=[], allow_private=True)
        ok, reason = g.check("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(ok)
        self.assertIn("metadata", reason)

    def test_metadata_blocked_even_when_enforcement_is_off(self):
        g = ScopeGuard(enforce=False, allow=[], deny=[], allow_private=True)
        self.assertFalse(g.check("http://169.254.169.254/")[0])

    def test_loopback_refused_by_default(self):
        g = ScopeGuard(enforce=True, allow=["127.0.0.1"], deny=[])
        ok, reason = g.check("http://127.0.0.1:8080/")
        self.assertFalse(ok)
        self.assertIn("private", reason)

    def test_loopback_allowed_in_lab_mode(self):
        g = ScopeGuard(enforce=True, allow=["127.0.0.1"], deny=[], allow_private=True)
        self.assertTrue(g.check("http://127.0.0.1:8080/")[0])

    def test_rfc1918_refused_by_default(self):
        g = ScopeGuard(enforce=True, allow=["10.0.0.5"], deny=[])
        self.assertFalse(g.check("http://10.0.0.5/")[0])

    def test_public_ip_on_allowlist_passes(self):
        g = ScopeGuard(enforce=True, allow=["93.184.216.34"], deny=[])
        self.assertTrue(g.check("http://93.184.216.34/")[0])

    def test_unlisted_host_rejected(self):
        g = ScopeGuard(enforce=True, allow=["example.org"], deny=[])
        self.assertFalse(g.check("http://example.com/")[0])

    def test_wildcard_target_is_the_root_domain(self):
        from t4wf1q.scope import extract_host
        self.assertEqual(extract_host("*.ezviz.com"), "ezviz.com")
        self.assertEqual(extract_host("https://*.ezviz.com/x"), "ezviz.com")

    def test_wildcard_allow_rule_covers_root_and_subdomains(self):
        g = ScopeGuard(enforce=True, allow=["*.ezviz.com"], deny=[])
        self.assertTrue(g.check("*.ezviz.com")[0])
        self.assertTrue(g.check("https://www.ezviz.com/")[0])
        self.assertFalse(g.check("https://ezviz.org/")[0])

    def test_deny_rule_wins_over_allow(self):
        g = ScopeGuard(enforce=True, allow=["example.org"], deny=["admin.example.org"])
        self.assertFalse(g.check("https://admin.example.org/")[0])


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit_then_recovers_after_window(self):
        rl = RateLimiter(limit_per_min=3, window_seconds=10)
        t = 1000.0
        self.assertEqual([rl.allow("ip", t) for _ in range(4)], [True, True, True, False])
        self.assertTrue(rl.allow("ip", t + 11))

    def test_clients_are_limited_independently(self):
        rl = RateLimiter(limit_per_min=1, window_seconds=60)
        self.assertTrue(rl.allow("a", 0.0))
        self.assertFalse(rl.allow("a", 1.0))
        self.assertTrue(rl.allow("b", 1.0))


class StatusLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        db.init(self.tmp / "t.db")
        self.asset = db.add_asset("Demo", "https://demo.test", "web")
        self.scan = db.create_scan(self.asset["id"], "web")

    def _finding(self, title="Missing security header"):
        return Finding(title=title, severity="low", source="argus-http",
                       host="demo.test", location="https://demo.test/").to_dict()

    def _upsert(self, title="Missing security header"):
        return db.upsert_finding(self.asset["id"], self.scan["id"], self._finding(title))

    def test_new_scanner_finding_is_new_and_unverified(self):
        f, is_new = self._upsert()
        self.assertTrue(is_new)
        self.assertEqual(f["status"], "new")
        self.assertEqual(f["verification"], "unverified")

    def test_rescan_never_auto_confirms(self):
        self._upsert()
        f, is_new = self._upsert()
        self.assertFalse(is_new)
        self.assertEqual(f["status"], "new")
        self.assertEqual(f["seen_count"], 2)

    def test_fixed_finding_that_reappears_is_reopened(self):
        f, _ = self._upsert()
        db.set_finding_status(f["id"], "fixed")
        again, _ = self._upsert()
        self.assertEqual(again["status"], "reopened")
        self.assertEqual(again["verification"], "unverified")

    def test_confirming_records_manual_verification(self):
        f, _ = self._upsert()
        confirmed = db.set_finding_status(f["id"], "confirmed")
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["verification"], "manually_verified")

    def test_unknown_status_is_rejected(self):
        f, _ = self._upsert()
        with self.assertRaises(ValueError):
            db.set_finding_status(f["id"], "open")

    def test_false_positive_is_excluded_from_active_counts(self):
        f, _ = self._upsert()
        self.assertEqual(db.severity_counts(self.asset["id"])["low"], 1)
        db.set_finding_status(f["id"], "false_positive")
        self.assertEqual(db.severity_counts(self.asset["id"])["low"], 0)

    def test_accepted_risk_stays_in_active_counts(self):
        f, _ = self._upsert()
        db.set_finding_status(f["id"], "accepted_risk")
        self.assertEqual(db.severity_counts(self.asset["id"])["low"], 1)

    def test_legacy_status_values_are_remapped_on_init(self):
        f, _ = self._upsert()
        with db.conn() as c:
            c.execute("UPDATE findings SET status='in_progress' WHERE id=?", (f["id"],))
        db.init(self.tmp / "t.db")   # re-running migration must be safe and remap
        self.assertEqual(db.get_finding(f["id"])["status"], "confirmed")

    def test_audit_log_records_actions(self):
        db.audit("scope.add", "demo.test", "kind=allow", "127.0.0.1")
        rows = db.list_audit(10)
        self.assertEqual(rows[0]["action"], "scope.add")
        self.assertEqual(rows[0]["ip"], "127.0.0.1")


class AdapterParserTests(unittest.TestCase):
    def test_zap_maps_risk_strips_html_and_skips_false_positives(self):
        data = {"site": [{"alerts": [
            {"name": "Missing Anti-clickjacking Header", "riskcode": "2", "confidence": "2",
             "cweid": "1021", "desc": "<p>Clickjacking</p>", "solution": "<p>Add header</p>",
             "instances": [{"uri": "https://demo.test/"}]},
            {"name": "Noise", "riskcode": "1", "confidence": "0", "cweid": "0",
             "desc": "x", "instances": [{"uri": "https://demo.test/x"}]},
        ]}]}
        out = extra_tools.parse_zap(data, "demo.test", "https://demo.test/")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "medium")
        self.assertEqual(out[0].cwe, "CWE-1021")
        self.assertEqual(out[0].description, "Clickjacking")
        self.assertEqual(out[0].source, "zap")

    def test_zap_daemon_alerts_convert_and_group(self):
        """core.alerts() output (API shape) must become the same findings as the report shape."""
        alerts = [
            {"alert": "X-Frame-Options Header Not Set", "riskcode": "2", "confidence": "Medium",
             "cweid": "1021", "description": "<p>Clickjacking</p>", "solution": "<p>Set it</p>",
             "url": "https://demo.test/a"},
            {"alert": "X-Frame-Options Header Not Set", "riskcode": "2", "confidence": "Medium",
             "cweid": "1021", "description": "<p>Clickjacking</p>", "solution": "<p>Set it</p>",
             "url": "https://demo.test/b"},
            {"alert": "Suspicious comment", "riskcode": "0", "confidence": "False Positive",
             "cweid": "200", "description": "x", "solution": "", "url": "https://demo.test/c"},
        ]
        report = extra_tools.zap_alerts_to_report(alerts)
        out = extra_tools.parse_zap(report, "demo.test", "https://demo.test/")
        self.assertEqual(len(out), 1)                       # the false positive is dropped
        self.assertEqual(out[0].title, "ZAP: X-Frame-Options Header Not Set")
        self.assertEqual(out[0].severity, "medium")
        self.assertEqual(out[0].confidence, "medium")
        self.assertEqual(out[0].cwe, "CWE-1021")
        self.assertIn("2 instance(s)", out[0].evidence)     # both URLs grouped under one rule

    def test_depcheck_extracts_cve_cvss_and_severity(self):
        data = {"dependencies": [{"fileName": "lodash-4.17.4.js", "vulnerabilities": [
            {"name": "CVE-2019-10744", "severity": "Critical",
             "cvssv3": {"baseScore": 9.1}, "cwes": ["CWE-1321"],
             "description": "prototype pollution"}]}]}
        out = extra_tools.parse_depcheck(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "critical")
        self.assertEqual(out[0].cve, "CVE-2019-10744")
        self.assertEqual(out[0].cvss, 9.1)
        self.assertEqual(out[0].owasp, "A06")

    def test_sqlmap_reports_only_confirmed_injection(self):
        url = "https://demo.test/item?id=1"
        self.assertEqual(extra_tools.parse_sqlmap("[WARNING] no injection found", url), [])
        out = extra_tools.parse_sqlmap(
            "Parameter: id (GET)\n  Type: boolean-based blind\n"
            "sqlmap identified the following injection point(s)", url)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].cwe, "CWE-89")
        self.assertIn("id", out[0].evidence)
        self.assertIn("No data was extracted", out[0].description)

    def test_sqlmap_is_off_unless_explicitly_allowed(self):
        logs = []
        ctx = ScanContext(asset={"id": "t", "target": "https://demo.test"}, scan_id="s", cfg=None,
                          log=lambda lvl, msg: logs.append(msg), scanners_cfg={})
        self.assertEqual(extra_tools.sqlmap(ctx, ["https://demo.test/?id=1"], allow_intrusive=False), [])
        self.assertTrue(any("intrusive" in m for m in logs))


class DalfoxAdapterTests(unittest.TestCase):
    """dalfox PoCs are candidates: never 'confirmed', and the parameter is recovered from the URL."""

    def test_poc_is_candidate_with_recovered_parameter(self):
        import json as _json
        from t4wf1q.scanners import web_extra

        poc = [{"data": "http://www.example.test/?h5debug=%3Cscript%3E"}]   # no 'param' key, like the bug
        orig_run, orig_avail = web_extra.run, web_extra.tool_available
        web_extra.run = lambda cmd, timeout=600: (0, _json.dumps(poc), "")
        web_extra.tool_available = lambda binary: True
        try:
            ctx = ScanContext(asset={"id": "t", "target": "www.example.test"}, scan_id="s",
                              cfg=None, log=lambda lvl, msg: None, scanners_cfg={})
            out = web_extra.dalfox(ctx, ["http://www.example.test/?h5debug=1"])
        finally:
            web_extra.run, web_extra.tool_available = orig_run, orig_avail

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].confidence, "medium")
        self.assertIn("candidate", out[0].title)
        self.assertIn("'h5debug'", out[0].description)
        self.assertNotIn("'?'", out[0].description)


class ParamHintTests(unittest.TestCase):
    """Parameter-name leads: passive, deduplicated, and never storing values."""

    def test_classifies_known_parameter_names(self):
        from t4wf1q.scanners import param_hints

        leads = param_hints.classify_url("https://app.example.test/view?file=a.txt&ID=7&q=x&other=1")
        self.assertEqual({(l["param"], l["class"]) for l in leads},
                         {("file", "LFI/RFI"), ("id", "IDOR"), ("q", "XSS/SSTI/SQLi")})

    def test_leads_are_deduplicated_and_never_contain_values(self):
        from t4wf1q.scanners import param_hints

        urls = ["https://a.test/x?redirect=https://evil.test&next=1",
                "https://a.test/x?redirect=other"]
        leads = param_hints.leads_for_urls(urls)
        self.assertEqual(len(leads), 2)                    # redirect + next, each once
        for lead in leads:
            f = param_hints.lead_to_finding(lead)
            self.assertEqual(f.severity, "info")
            self.assertEqual(f.confidence, "low")
            self.assertNotIn("evil.test", f.evidence)
            self.assertNotIn("other", f.evidence)
            self.assertIn("Manual check", f.description)

    def test_non_http_and_credentials_are_handled(self):
        from t4wf1q.scanners import param_hints

        self.assertEqual(param_hints.classify_url("file:///etc/passwd?file=x"), [])
        leads = param_hints.classify_url("https://user:secret@a.test/p?cmd=1")
        self.assertEqual(leads[0]["base"], "https://a.test/p")   # userinfo stripped


if __name__ == "__main__":
    unittest.main()
