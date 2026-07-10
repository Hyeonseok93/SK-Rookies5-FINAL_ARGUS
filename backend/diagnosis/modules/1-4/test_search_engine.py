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

    def test_template_is_detected_as_file_inclusion_candidate(self):
        hits = search_targets([self.target("template", "/api/reports")])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].vuln_type, VulnType.LFI)

    def test_logo_url_is_detected_independently_as_ssrf_candidate(self):
        hits = search_targets([self.target("logoUrl", "/api/reports")])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].vuln_type, VulnType.SSRF)

    def test_temporal_return_field_is_a_soft_constrained_ssrf_candidate(self):
        hits = search_targets([self.target("returnTime", "/api/cars/search")])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].vuln_type, VulnType.SSRF)
        self.assertTrue(hits[0].is_soft_constrained)

    def test_return_url_remains_an_ssrf_candidate(self):
        hits = search_targets([self.target("returnUrl", "/api/auth")])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].vuln_type, VulnType.SSRF)
        self.assertFalse(hits[0].is_soft_constrained)

if __name__ == "__main__":
    unittest.main()
