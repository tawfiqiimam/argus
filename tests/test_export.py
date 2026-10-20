"""Tests for JSON/CSV export: redaction and CSV formula-injection protection."""
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import t4wf1q.db as db  # noqa: E402
from t4wf1q import report  # noqa: E402
from t4wf1q.config import Config  # noqa: E402
from t4wf1q.scanners.base import Finding  # noqa: E402


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        db.init(self.tmp / "t.db")
        self.asset = db.add_asset("Demo", "http://127.0.0.1:9", "web")
        scan = db.create_scan(self.asset["id"], "web")
        db.upsert_finding(self.asset["id"], scan["id"], Finding(
            title="=HYPERLINK(\"http://evil.test\")", severity="medium", owasp="A05",
            source="argus-paths", location="http://127.0.0.1:9/.env",
            evidence="password=hunter2 AKIAABCDEFGHIJKLMNOP", cwe="CWE-79",
            confidence="high").to_dict())
        self.cfg = Config.load(ROOT / "config.yaml.example")
        self.cfg._data["reports"]["dir"] = str(self.tmp / "reports")

    def test_json_export_is_redacted(self):
        path = report.export(self.cfg, self.asset["id"], "json")
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("hunter2", text)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", text)
        self.assertIn("[REDACTED]", text)
        doc = json.loads(text)
        self.assertEqual(doc["summary"]["total"], 1)

    def test_csv_export_neutralises_formula_injection(self):
        path = report.export(self.cfg, self.asset["id"], "csv")
        text = path.read_text(encoding="utf-8")
        self.assertIn("'=HYPERLINK", text)          # prefixed, not a live formula
        self.assertNotIn("hunter2", text)
        header = text.splitlines()[0].split(",")
        self.assertIn("cwe", header)
        self.assertIn("confidence", header)

    def test_unknown_format_rejected(self):
        with self.assertRaises(ValueError):
            report.export(self.cfg, self.asset["id"], "xml")


if __name__ == "__main__":
    unittest.main()
