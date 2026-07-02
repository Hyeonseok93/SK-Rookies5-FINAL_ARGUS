import unittest
from types import SimpleNamespace
from unittest.mock import patch

import requests

from payload_injector import InjectionResult, PayloadInjector
from search_engine import VulnType


def response(status, body):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode()
    result.headers["Content-Type"] = "application/json"
    return result


class SsrfBaselineDiffTests(unittest.TestCase):
    def setUp(self):
        self.injector = PayloadInjector(delay_between_requests=0)
        self.hit = SimpleNamespace(
            vuln_type=VulnType.SSRF,
            param=SimpleNamespace(name="link", schema={}),
        )

    def test_conflict_status_change_alone_is_not_confirmed(self):
        confirmed, _, method = self.injector._analyze_response(
            self.hit,
            "http://127.0.0.1:22",
            response(409, "x" * 157),
            1,
            response(200, "x" * 156),
        )
        self.assertFalse(confirmed)
        self.assertEqual(method, "")

    def test_uniform_conflict_responses_are_downgraded(self):
        baseline = response(200, "ok")
        results = [
            InjectionResult(
                hit=self.hit,
                payload=f"http://127.0.0.1:{port}",
                confirmed=True,
                evidence="baseline differs",
                response_status=409,
                payload_response_length=156 + index % 2,
                detection_method="BASELINE_DIFF",
                confidence="MEDIUM",
            )
            for index, port in enumerate(range(20, 33))
        ]

        self.injector._apply_uniform_response_check(results, baseline)

        self.assertTrue(all(not result.confirmed for result in results))
        self.assertTrue(all(result.confidence == "LOW" for result in results))

    def test_non_uniform_baseline_diffs_remain_confirmed(self):
        baseline = response(200, "ok")
        results = [
            InjectionResult(
                hit=self.hit,
                payload=f"http://127.0.0.1:{port}",
                confirmed=True,
                evidence="baseline differs",
                response_status=status,
                payload_response_length=length,
                detection_method="BASELINE_DIFF",
                confidence="MEDIUM",
            )
            for port, status, length in (
                (22, 502, 100), (80, 200, 800), (3306, 504, 40), (6379, 500, 220)
            )
        ]

        self.injector._apply_uniform_response_check(results, baseline)

        self.assertTrue(all(result.confirmed for result in results))
        self.assertTrue(all(result.confidence == "MEDIUM" for result in results))

    def test_4xx_baseline_status_is_preserved_in_result(self):
        target = SimpleNamespace(method="POST", full_url="http://example.test", content_type="")
        hit = SimpleNamespace(
            target=target, param=SimpleNamespace(name="link"), vuln_type=VulnType.SSRF
        )
        baseline = response(409, "conflict")
        with (
            patch.object(self.injector, "_build_url", return_value=target.full_url),
            patch.object(self.injector, "_build_request_kwargs", return_value={}),
            patch.object(self.injector, "_analyze_response", return_value=(False, "", "")),
            patch.object(self.injector.session, "request", return_value=response(409, "conflict")),
        ):
            result = self.injector._inject_single(hit, "http://127.0.0.1", baseline)

        self.assertEqual(result.baseline_status, 409)

    def test_polluted_conflict_baseline_is_skipped_and_reported(self):
        target = SimpleNamespace(
            method="POST", full_url="http://example.test/applications/1", content_type="application/json"
        )
        hit = SimpleNamespace(
            target=target,
            param=SimpleNamespace(name="link"),
            to_dict=lambda: {"method": "POST", "url": target.full_url, "param": "link"},
        )
        with patch.object(self.injector, "_get_baseline", return_value=response(409, "duplicate")):
            results = self.injector.inject_all([hit])

        self.assertEqual(results, [])
        detail = self.injector.skipped_failed_baseline_details[0]
        self.assertEqual(detail["baseline_status"], 409)
        self.assertTrue(detail["baseline_polluted"])
        self.assertIn("정리한 후 재스캔 권장", detail["skip_reason"])

    def test_baseline_401_refreshes_token_and_retries_once(self):
        injector = PayloadInjector(
            delay_between_requests=0,
            auth_refresh_callback=lambda: {"Authorization": "Bearer fresh-token"},
        )
        target = SimpleNamespace(
            method="GET", full_url="http://example.test/private", content_type="", params=[]
        )
        with (
            patch.object(injector, "_build_safe_request", return_value=(target.full_url, {})),
            patch.object(injector.session, "request", side_effect=[
                response(401, "expired"), response(200, "ok")
            ]) as request,
        ):
            probe = injector.probe_target_access(target)

        self.assertEqual(request.call_count, 2)
        self.assertEqual(probe.response.status_code, 200)
        self.assertEqual(injector.session.headers["Authorization"], "Bearer fresh-token")

    def test_stored_probe_uses_separate_swagger_get_endpoint(self):
        write = SimpleNamespace(method="POST", path="/api/reports", full_url="http://x/api/reports")
        read = SimpleNamespace(method="GET", path="/api/reports/{id}", full_url="http://x/api/reports/1")
        injector = PayloadInjector(delay_between_requests=0, scan_targets=[write, read])
        self.assertIs(injector._find_stored_read_target(write), read)

    def test_stored_probe_is_skipped_without_swagger_get_endpoint(self):
        write = SimpleNamespace(method="POST", path="/api/reports", full_url="http://x/api/reports")
        injector = PayloadInjector(delay_between_requests=0, scan_targets=[write])
        self.assertIsNone(injector._find_stored_read_target(write))

    def test_stored_probe_prefers_collection_get_over_detail_get(self):
        write = SimpleNamespace(method="POST", path="/api/reports", full_url="http://x/api/reports")
        detail = SimpleNamespace(method="GET", path="/api/reports/{id}", full_url="http://x/api/reports/{id}")
        collection = SimpleNamespace(method="GET", path="/api/reports", full_url="http://x/api/reports")
        injector = PayloadInjector(delay_between_requests=0, scan_targets=[write, detail, collection])
        self.assertIs(injector._find_stored_read_target(write), collection)

    def test_stored_probe_rejects_unrelated_common_api_prefix(self):
        write = SimpleNamespace(method="POST", path="/api/v1/report/integrated", full_url="http://x/api/v1/report/integrated")
        unrelated = SimpleNamespace(method="GET", path="/api/v1/seller/insurances", full_url="http://x/api/v1/seller/insurances")
        injector = PayloadInjector(delay_between_requests=0, scan_targets=[write, unrelated])
        self.assertIsNone(injector._find_stored_read_target(write))


if __name__ == "__main__":
    unittest.main()
