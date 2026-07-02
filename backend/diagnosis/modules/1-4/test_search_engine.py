import unittest
from models import ParamLocation, ScanParam, ScanTarget, InputSource, VulnType
from search_engine import search_targets

class SearchRegressionTests(unittest.TestCase):
    def target(self, name, path="/api/items"):
        return ScanTarget(method="POST", path=path, base_url="http://example.test",
            params=[ScanParam(name=name, location=ParamLocation.BODY, schema={"type": "string"})],
            source=InputSource.SWAGGER)

    def test_plural_image_urls_uses_contains_fallback(self):
        hits = search_targets([self.target("imageUrls")])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].vuln_type, VulnType.SSRF)

    def test_report_template_special_case_remains_detected(self):
        target = self.target("template", "/api/reports")
        target.params[0].schema["x-argus-sibling-names"] = ["logoUrl"]
        hits = search_targets([target])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].vuln_type, VulnType.SSRF)

if __name__ == "__main__":
    unittest.main()
