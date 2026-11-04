import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("evaluate.py")
SPEC = importlib.util.spec_from_file_location("research_evaluate", MODULE_PATH)
evaluate_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluate_module)


class ReportParserTests(unittest.TestCase):
    def test_docx_style_severity_precedes_endpoint(self):
        units = [
            "Security Audit Report",
            "Severity: CRITICAL",
            "Endpoint: GET:/api/admin/audit-logs",
            "Type: AUTHORIZATION_MISSING",
            "--------------------",
            "Severity: HIGH",
            "Endpoint: POST:/api/admin/backup",
            "Type: MISSING_POLICY",
            "--------------------",
        ]
        parsed = evaluate_module.parse_labelled_units(units)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["severity"], "CRITICAL")
        self.assertEqual(parsed[1]["severity"], "HIGH")

    def test_csv_uses_named_columns(self):
        csv_text = "Endpoint,Severity,Type,Message\nGET:/api/private,HIGH,MISSING_POLICY,No policy\n"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.csv"
            path.write_text(csv_text, encoding="utf-8")
            parsed = evaluate_module.parse_csv(str(path))
        self.assertEqual(parsed[0]["endpoint"], "GET:/api/private")
        self.assertEqual(parsed[0]["severity"], "HIGH")
        self.assertEqual(parsed[0]["violationType"], "MISSING_POLICY")


if __name__ == "__main__":
    unittest.main()
