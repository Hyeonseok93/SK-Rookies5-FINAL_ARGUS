import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from zap_engine import ZapEngine


class SwaggerImportTests(unittest.TestCase):
    def setUp(self):
        self.engine = ZapEngine()

    @patch("zap_engine.time.sleep")
    def test_local_swagger_uses_import_file_with_absolute_path(self, _sleep):
        with patch.object(self.engine, "_get", return_value={}) as get:
            self.engine.import_swagger("swagger.json", "http://localhost:8080")

        get.assert_called_once_with(
            "/JSON/openapi/action/importFile/",
            {
                "file": str(Path("swagger.json").resolve()),
                "target": "http://localhost:8080",
            },
        )

    @patch("zap_engine.time.sleep")
    def test_remote_swagger_uses_import_url(self, _sleep):
        url = "https://example.test/swagger.json"
        with patch.object(self.engine, "_get", return_value={}) as get:
            self.engine.import_swagger(url, "http://localhost:8080")

        get.assert_called_once_with(
            "/JSON/openapi/action/importUrl/",
            {"url": url, "hostOverride": "http://localhost:8080"},
        )


class ContextSetupTests(unittest.TestCase):
    def setUp(self):
        self.engine = ZapEngine()

    def test_existing_context_is_reused_and_scope_is_updated(self):
        with patch.object(self.engine, "_get", side_effect=[
            {"context": {"id": "7", "name": self.engine.context_name}},
            {},
        ]) as get:
            context_id = self.engine.setup_context(
                "http://example.test", ["http://example.test/api/{id}"]
            )

        self.assertEqual(context_id, "7")
        endpoints = [call.args[0] for call in get.call_args_list]
        self.assertEqual(endpoints, [
            "/JSON/context/view/context/",
            "/JSON/context/action/includeInContext/",
        ])

    def test_missing_context_is_created_then_scoped(self):
        missing_response = requests.Response()
        missing_response.status_code = 404
        missing_response._content = b"not found"
        missing = requests.HTTPError(response=missing_response)
        with patch.object(self.engine, "_get", side_effect=[
            missing,
            {"contextId": "8"},
            {},
        ]) as get:
            context_id = self.engine.setup_context("http://example.test")

        self.assertEqual(context_id, "8")
        endpoints = [call.args[0] for call in get.call_args_list]
        self.assertEqual(endpoints, [
            "/JSON/context/view/context/",
            "/JSON/context/action/newContext/",
            "/JSON/context/action/includeInContext/",
        ])


class ZapDiagnosticsAndPolicyTests(unittest.TestCase):
    def setUp(self):
        self.engine = ZapEngine()

    def test_get_includes_zap_error_body_and_preserves_response(self):
        response = requests.Response()
        response.status_code = 400
        response.url = "http://localhost:8090/JSON/ascan/action/scan/"
        response._content = b'{"code":"bad_policy","message":"missing policy"}'
        response.request = requests.Request("GET", response.url).prepare()
        with patch("zap_engine.requests.get", return_value=response):
            with self.assertRaises(requests.HTTPError) as raised:
                self.engine._get("/JSON/ascan/action/scan/", {})
        self.assertIn("missing policy", str(raised.exception))
        self.assertIs(raised.exception.response, response)

    def test_policy_uses_dynamically_discovered_ssrf_scanner(self):
        calls = []

        def fake_get(endpoint, params):
            calls.append((endpoint, params))
            if endpoint == "/JSON/ascan/view/scanners/":
                return {"scanners": [
                    {"id": "12345", "name": "Server Side Request Forgery"},
                    {"id": "999", "name": "Something Else"},
                ]}
            return {}

        with patch.object(self.engine, "_get", side_effect=fake_get):
            self.engine.configure_ssrf_lfi_policy()
        configured_ids = {
            str(params["id"]) for endpoint, params in calls
            if endpoint == "/JSON/ascan/action/setScannerAlertThreshold/"
        }
        self.assertIn("12345", configured_ids)
        self.assertNotIn("40046", configured_ids)

    def test_active_scan_starts_from_first_scoped_url(self):
        calls = []

        def fake_get(endpoint, params):
            calls.append((endpoint, params))
            return {"scan": "3"} if endpoint.endswith("/scan/") else {"status": "100"}

        with patch.object(self.engine, "_get", side_effect=fake_get):
            scan_id = self.engine.active_scan(
                "http://example.test",
                scoped_urls=["http://example.test/api/applications/1"],
                poll_interval=0,
            )

        self.assertEqual(scan_id, "3")
        self.assertEqual(calls[0][1]["url"], "http://example.test/api/applications/1")

if __name__ == "__main__":
    unittest.main()
