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


class ChainTests(unittest.TestCase):
    """Lead-driven chaining: focus real URLs first, corroborate agreeing checks. Pure logic."""

    def _xss_finding(self, url_with_param):
        return Finding(title="x", severity="medium", source="argus-xss", host="a.test",
                       location=url_with_param)

    def test_reflection_keys_extracted_from_xss_findings_only(self):
        from t4wf1q.scanners import chain
        fs = [self._xss_finding("https://a.test/s?q="),
              Finding(title="y", severity="low", source="nuclei", host="a.test", location="https://a.test/x?z=")]
        self.assertEqual(chain.reflection_keys(fs), {("a.test", "/s", "q")})

    def test_prioritize_puts_focused_params_first_without_inventing_urls(self):
        from t4wf1q.scanners import chain
        urls = ["https://a.test/p?safe=1", "https://a.test/s?q=1", "https://a.test/r?other=2"]
        focus = {("a.test", "/s", "q")}
        ordered, n = chain.prioritize(urls, focus, cap=10)
        self.assertEqual(ordered[0], "https://a.test/s?q=1")   # focused one first
        self.assertEqual(n, 1)
        self.assertEqual(set(ordered), set(urls))              # same set, only reordered

    def test_prioritize_respects_cap(self):
        from t4wf1q.scanners import chain
        urls = [f"https://a.test/p{i}?x={i}" for i in range(30)]
        ordered, _ = chain.prioritize(urls, set(), cap=20)
        self.assertEqual(len(ordered), 20)

    def test_lead_keys_filter_by_class(self):
        from t4wf1q.scanners import chain
        leads = [{"host": "a.test", "base": "https://a.test/s", "param": "q", "class": "XSS/SSTI/SQLi"},
                 {"host": "a.test", "base": "https://a.test/g", "param": "next", "class": "Open Redirect"}]
        self.assertEqual(chain.lead_keys(leads, chain.XSS_CLASSES), {("a.test", "/s", "q")})

    def test_corroboration_raises_confidence_and_notes(self):
        from t4wf1q.scanners import chain
        dalfox = Finding(title="XSS candidate", severity="high", source="dalfox", host="a.test",
                         location="https://a.test/s?q=%3Cscript%3E", confidence="medium")
        out, n = chain.annotate_corroboration([dalfox], {("a.test", "/s", "q")})
        self.assertEqual(n, 1)
        self.assertEqual(out[0].confidence, "high")
        self.assertIn("Corroborated", out[0].description or "")

    def test_corroboration_leaves_unmatched_findings_untouched(self):
        from t4wf1q.scanners import chain
        dalfox = Finding(title="XSS candidate", severity="high", source="dalfox", host="a.test",
                         location="https://a.test/other?z=1", confidence="medium")
        out, n = chain.annotate_corroboration([dalfox], {("a.test", "/s", "q")})
        self.assertEqual(n, 0)
        self.assertEqual(out[0].confidence, "medium")


class ResearchAndChecklistTests(unittest.TestCase):
    def test_enrich_adds_pinpoint_steps_and_research_links(self):
        from t4wf1q import research
        f = {"title": "Potential reflected XSS in parameter 'q'", "owasp": "A03", "cwe": "CWE-79",
             "source": "argus-xss", "host": "a.test", "location": "https://a.test/s?q=",
             "reference": []}
        research.enrich(f)
        self.assertIn("Pinpoint:", f["verify"])
        self.assertIn("parameter 'q'", f["verify"])
        self.assertIn("Verify by hand", f["verify"])
        self.assertTrue(any("cwe.mitre.org/data/definitions/79" in r for r in f["reference"]))
        self.assertTrue(any("cheatsheetseries.owasp.org" in r for r in f["reference"]))

    def test_verification_text_stops_at_proof(self):
        from t4wf1q import research
        for owasp in research._OWASP:
            steps, _ = research._OWASP[owasp]
            joined = " ".join(steps).lower()
            self.assertNotIn("exfiltrat", joined)
            self.assertNotIn("dump the database", joined)

    def test_checklist_catalog_is_complete_and_unique(self):
        from t4wf1q.checklist import CATALOG
        keys = [i["key"] for i in CATALOG]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreaterEqual(len(CATALOG), 30)
        for i in CATALOG:
            self.assertIn(i["severity"], {"critical", "high", "medium", "low"})
            self.assertTrue(i["how"].strip())
            self.assertTrue(i["owasp"].startswith("A"))


class ArjunParsingTests(unittest.TestCase):
    """arjun's JSON report shape varies by version; the parser must handle both."""

    def test_dict_of_list_shape(self):
        from t4wf1q.scanners import recon_extra
        data = {"https://a.test/s": ["debug", "token"]}
        self.assertEqual(recon_extra._parse_arjun_json(data), {"https://a.test/s": ["debug", "token"]})

    def test_dict_of_dict_with_param_objects(self):
        from t4wf1q.scanners import recon_extra
        data = {"https://a.test/s": {"params": [{"name": "debug"}, {"name": "token"}]}}
        self.assertEqual(recon_extra._parse_arjun_json(data)["https://a.test/s"], ["debug", "token"])

    def test_list_of_entries_shape(self):
        from t4wf1q.scanners import recon_extra
        data = [{"url": "https://a.test/s", "params": ["debug"]}]
        self.assertEqual(recon_extra._parse_arjun_json(data), {"https://a.test/s": ["debug"]})

    def test_garbage_shape_returns_empty(self):
        from t4wf1q.scanners import recon_extra
        self.assertEqual(recon_extra._parse_arjun_json("not json structure"), {})
        self.assertEqual(recon_extra._parse_arjun_json(None), {})

    def test_findings_are_info_level_and_never_store_real_values(self):
        from t4wf1q.scanners import recon_extra
        out = recon_extra.arjun_findings({"https://a.test/s?id=1": ["debug"]})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "info")
        self.assertEqual(out[0].source, "arjun")
        self.assertIn("'debug'", out[0].title)


class JsluiceParsingTests(unittest.TestCase):
    def test_parses_jsonl_and_ignores_bad_lines(self):
        from t4wf1q.scanners import recon_extra
        out = recon_extra._parse_jsluice_urls(
            '{"url": "/api/v1/users"}\nnot json\n{"url": "https://cdn.a.test/x"}\n{"nope": 1}\n')
        self.assertEqual(out, ["/api/v1/users", "https://cdn.a.test/x"])

    def test_resolve_relative_and_absolute_and_protocol_relative(self):
        from t4wf1q.scanners import recon_extra
        js = "https://a.test/static/app.js"
        self.assertEqual(recon_extra._resolve_js_url("https://b.test/x", js), "https://b.test/x")
        self.assertEqual(recon_extra._resolve_js_url("/api/v1/users", js), "https://a.test/api/v1/users")
        self.assertEqual(recon_extra._resolve_js_url("//cdn.test/x", js), "https://cdn.test/x")

    def test_ignores_unsafe_or_ambiguous_schemes(self):
        from t4wf1q.scanners import recon_extra
        js = "https://a.test/app.js"
        for bad in ("javascript:alert(1)", "data:text/html,x", "mailto:a@b.test", "", "relative/path"):
            self.assertIsNone(recon_extra._resolve_js_url(bad, js))


def _stub_httpx():
    import sys, types
    if "httpx" not in sys.modules:
        httpx = types.ModuleType("httpx")
        class _C:
            def __init__(self, *a, **k): pass
        httpx.Client = _C; httpx.AsyncClient = _C; httpx.Response = object
        httpx.RequestError = Exception; httpx.HTTPError = Exception; httpx.TimeoutException = Exception
        sys.modules["httpx"] = httpx


class PipelineChainStageTests(unittest.TestCase):
    """jsluice/arjun/evidence stages: what they write into the shared scan state."""

    def setUp(self):
        _stub_httpx()
        from t4wf1q import pipeline
        from t4wf1q.scanners import evidence, recon_extra
        self.pipeline, self.evidence, self.recon_extra = pipeline, evidence, recon_extra
        self.ctx = ScanContext(asset={"id": "t", "target": "a.test"}, scan_id="s", cfg=None,
                               log=lambda l, m: None, scanners_cfg={})

        class G:
            def check(self, u):
                return (True, "ok")
        self.guard = G()

    def _st(self, **over):
        base = {"root": "a.test", "hosts": ["a.test"], "tech": {}, "errors": [], "live": [],
                "discovered": [], "leads": [], "findings": [], "screenshots": []}
        base.update(over)
        return base

    def test_jsluice_endpoints_feed_discovered_urls(self):
        self.recon_extra.jsluice_scan = lambda ctx, urls: ["https://a.test/api/v1/secret"]
        st = self._st(live=["https://a.test/app.js"])
        self.pipeline._s_jsluice(self.ctx, st, self.guard, {})
        self.assertIn("https://a.test/api/v1/secret", st["discovered"])

    def test_arjun_only_adds_leads_for_the_newly_discovered_parameter(self):
        """Regression: classifying the merged URL (old + new params) used to re-add the
        URL's EXISTING parameter as if it were new. Only the genuinely new one should land."""
        def fake_scan(ctx, urls):
            f = Finding(title="Hidden parameter discovered: 'url'", severity="info",
                       source="arjun", host="a.test", location="https://a.test/s?url=")
            return [f], {"https://a.test/s?q=1": ["url", "debug"]}   # 'url'=SSRF-prone, 'debug'=not
        self.recon_extra.arjun_scan = fake_scan
        st = self._st(live=["https://a.test/s?q=1"],
                     leads=[{"host": "a.test", "base": "https://a.test/s", "param": "q",
                            "class": "XSS/SSTI/SQLi"}])
        self.pipeline._s_arjun(self.ctx, st, self.guard, {})

        new = [l for l in st["leads"] if l["param"] == "url"]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["class"], "SSRF")
        # the pre-existing 'q' lead must not be duplicated
        q_leads = [l for l in st["leads"] if l["param"] == "q"]
        self.assertEqual(len(q_leads), 1)
        # 'debug' matches no known pattern, so it gets no lead (only the arjun finding itself)
        self.assertFalse(any(l["param"] == "debug" for l in st["leads"]))
        self.assertEqual(len([f for f in st["findings"] if f.source == "arjun"]), 1)

    def test_evidence_stage_stores_the_capture_manifest(self):
        self.evidence.capture = lambda ctx, urls, out_dir: [{"file": "a.png", "host": None, "url": None}]
        import pathlib
        class FakeCfg:
            evidence_dir = pathlib.Path("/tmp/argus-test-evidence")
        self.ctx.cfg = FakeCfg()
        st = self._st(live=["https://a.test/"])
        self.pipeline._s_evidence(self.ctx, st, self.guard, {})
        self.assertEqual(st["screenshots"], [{"file": "a.png", "host": None, "url": None}])


class SingleToolProfileTests(unittest.TestCase):
    """Every stage gets a runnable single-tool profile; web stages get a probe first."""

    def _profiles(self):
        import sys, types
        if "httpx" not in sys.modules:
            httpx = types.ModuleType("httpx")
            class _C:
                def __init__(self, *a, **k): pass
            httpx.Client = _C; httpx.AsyncClient = _C; httpx.Response = object
            httpx.RequestError = Exception; httpx.HTTPError = Exception; httpx.TimeoutException = Exception
            sys.modules["httpx"] = httpx
        from t4wf1q import pipeline
        return pipeline

    def test_one_profile_per_stage(self):
        pipeline = self._profiles()
        single = {k: v for k, v in pipeline.PROFILES.items() if k.startswith("tool:")}
        self.assertEqual(len(single), len(pipeline.STAGE_ORDER))
        for stage in pipeline.STAGE_ORDER:
            self.assertIn(f"tool:{stage}", single)

    def test_web_stage_profiles_probe_first(self):
        pipeline = self._profiles()
        self.assertEqual(pipeline.PROFILES["tool:dalfox"]["stages"], ["probe", "dalfox"])
        self.assertEqual(pipeline.PROFILES["tool:nuclei"]["stages"], ["probe", "nuclei"])

    def test_standalone_stage_profiles_skip_probe(self):
        pipeline = self._profiles()
        self.assertEqual(pipeline.PROFILES["tool:recon"]["stages"], ["recon"])
        self.assertEqual(pipeline.PROFILES["tool:nmap"]["stages"], ["nmap"])
        self.assertEqual(pipeline.PROFILES["tool:gitleaks"]["stages"], ["gitleaks"])


class ToolJobsTests(unittest.TestCase):
    """Background install/uninstall jobs: one at a time, real exit codes, no real subprocess."""

    def setUp(self):
        from t4wf1q import jobs
        self.jobs = jobs
        # Fresh in-memory state per test, and never touch the real db/events.
        jobs._jobs.clear()
        jobs._order.clear()
        if jobs._lock.locked():
            jobs._lock.release()
        self._patches = []
        for mod, name, replacement in [
            (jobs.db, "audit", lambda *a, **k: None),
            (jobs.events, "publish", lambda *a, **k: None),
        ]:
            original = getattr(mod, name)
            setattr(mod, name, replacement)
            self._patches.append((mod, name, original))

    def tearDown(self):
        for mod, name, original in self._patches:
            setattr(mod, name, original)

    def _fake_popen(self, rc, delay=0.0):
        import subprocess

        class _Proc:
            pid = 4242

            def wait(self, timeout=None):
                import time as _t
                if delay:
                    _t.sleep(delay)
                return rc

            def kill(self):
                pass

        return lambda *a, **k: _Proc()

    def test_unknown_tool_is_rejected(self):
        with self.assertRaises(self.jobs.UnknownTool):
            self.jobs.start_install("not-a-real-tool")

    def test_install_runs_the_script_with_the_tool_key_and_reports_done(self):
        import subprocess
        real_popen = subprocess.Popen
        subprocess.Popen = self._fake_popen(0)
        try:
            job = self.jobs.start_install("nuclei")
            self.assertEqual(job["tool"], "nuclei")
            self.assertEqual(job["action"], "install")
            for _ in range(50):
                if self.jobs.get(job["id"])["status"] != "running":
                    break
                __import__("time").sleep(0.02)
        finally:
            subprocess.Popen = real_popen
        self.assertEqual(self.jobs.get(job["id"])["status"], "done")

    def test_uninstall_refused_exit_code_is_surfaced_distinctly(self):
        import subprocess
        real_popen = subprocess.Popen
        subprocess.Popen = self._fake_popen(2)
        try:
            job = self.jobs.start_uninstall("whatweb")
            for _ in range(50):
                if self.jobs.get(job["id"])["status"] != "running":
                    break
                __import__("time").sleep(0.02)
        finally:
            subprocess.Popen = real_popen
        self.assertEqual(self.jobs.get(job["id"])["status"], "refused")

    def test_failed_install_is_distinguished_from_refused(self):
        import subprocess
        real_popen = subprocess.Popen
        subprocess.Popen = self._fake_popen(1)
        try:
            job = self.jobs.start_install("semgrep")
            for _ in range(50):
                if self.jobs.get(job["id"])["status"] != "running":
                    break
                __import__("time").sleep(0.02)
        finally:
            subprocess.Popen = real_popen
        self.assertEqual(self.jobs.get(job["id"])["status"], "failed")

    def test_a_second_job_is_refused_while_one_is_running(self):
        import subprocess
        real_popen = subprocess.Popen
        subprocess.Popen = self._fake_popen(0, delay=0.2)
        try:
            self.jobs.start_install("nuclei")
            with self.assertRaises(self.jobs.AlreadyRunning):
                self.jobs.start_install("trivy")
            # let the first job finish so it doesn't leak into later tests
            for _ in range(50):
                if self.jobs.current() is None:
                    break
                __import__("time").sleep(0.02)
        finally:
            subprocess.Popen = real_popen

    def test_public_view_never_includes_the_log_path(self):
        import subprocess
        real_popen = subprocess.Popen
        subprocess.Popen = self._fake_popen(0)
        try:
            job = self.jobs.start_install("nuclei")
            for _ in range(50):
                if self.jobs.get(job["id"])["status"] != "running":
                    break
                __import__("time").sleep(0.02)
            view = self.jobs.public_view(self.jobs.get(job["id"]))
        finally:
            subprocess.Popen = real_popen
        self.assertNotIn("log_path", view)
        self.assertNotIn("pid", view)
        self.assertEqual(view["tool"], "nuclei")


class RoutePathParamNameTests(unittest.TestCase):
    """A route's {path_param} can never be named 'key' or 'x_api_key'.

    Regression: @app.post("/api/tools/{key}/install") with
    def tool_install(key: str, ..., _=Depends(require_key)) crashed FastAPI at
    import time with "Cannot use Query for path param 'key'" — require_key's
    own `key: str | None = Query(...)` (the API key passed as ?key=...) and the
    route's path param share the name "key", and FastAPI merges dependency
    parameters with route parameters by name, so it tried to treat one path
    param as both Path and Query. Caught by a user running the real app,
    since fastapi isn't importable in this sandbox to catch it directly.
    """

    def test_no_route_path_param_collides_with_require_key(self):
        import ast
        import re

        main_src = (pathlib.Path(__file__).resolve().parent.parent / "t4wf1q" / "main.py").read_text()
        tree = ast.parse(main_src)
        banned = {"key", "x_api_key"}
        checked = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            route_paths = []
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in ("get", "post", "put", "delete", "patch")
                        and dec.args and isinstance(dec.args[0], ast.Constant)):
                    route_paths.append(dec.args[0].value)
            if not route_paths:
                continue
            uses_require_key = "require_key" in ast.dump(node)
            if not uses_require_key:
                continue
            checked += 1
            path_params = {m for p in route_paths for m in re.findall(r"\{(\w+)\}", p)}
            collision = path_params & banned
            self.assertFalse(
                collision,
                f"{node.name}: path param(s) {collision} collide with require_key's own "
                f"'key'/'x_api_key' params — rename the route's path param")
        self.assertGreater(checked, 0, "no require_key-protected route found — test is not exercising anything")


class ToolsScriptConsistencyTests(unittest.TestCase):
    """Every key in tools.TOOLS has a matching install/uninstall case in the shell script."""

    def test_every_tool_key_has_a_dispatch_case(self):
        from t4wf1q import tools
        script = (pathlib.Path(__file__).resolve().parent.parent
                  / "scripts" / "install-tools.sh").read_text()
        for key, *_ in tools.TOOLS:
            needle = f'"{key}")' if key in ("testssl.sh", "dependency-check") else f"{key})"
            self.assertIn(needle, script, f"{key} has no dispatch_install case in install-tools.sh")

    def test_every_tool_key_has_a_binary_lookup_case(self):
        from t4wf1q import tools
        script = (pathlib.Path(__file__).resolve().parent.parent
                  / "scripts" / "install-tools.sh").read_text()
        binary_fn = script.split("_binary_for() {", 1)[1].split("\n}", 1)[0]
        for key, *_ in tools.TOOLS:
            needle = f'"{key}")' if key in ("testssl.sh", "dependency-check") else f"{key})"
            self.assertIn(needle, binary_fn, f"{key} has no _binary_for case in install-tools.sh")


if __name__ == "__main__":
    unittest.main()
