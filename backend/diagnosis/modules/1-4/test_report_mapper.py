import unittest
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[3]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from module import _dedupe_session_results
from report_mapper import build_findings


class SessionResultMergeTests(unittest.TestCase):
    def test_dedupes_findings_and_preserves_roles(self):
        base = {
            "method": "POST",
            "url": "http://target/report",
            "param": "logoUrl",
            "vuln_type": "Server-Side Request Forgery",
            "confidence": "HIGH",
            "evidence": "timing",
        }
        merged = _dedupe_session_results(
            [
                {**base, "confirmed_by_roles": ["USER"]},
                {**base, "confirmed_by_roles": ["SELLER"]},
                {**base, "confirmed_by_roles": ["SUPER_ADMIN"]},
            ]
        )
        self.assertEqual(len(merged), 1)
        finding = build_findings(merged)[0]
        self.assertEqual(
            finding.evidence["confirmed_by_roles"],
            ["SELLER", "SUPER_ADMIN", "USER"],
        )


if __name__ == "__main__":
    unittest.main()
