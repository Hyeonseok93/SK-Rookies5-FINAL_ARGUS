import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import requests

from main import build_credential_auth_sessions, login_and_get_token


def response(status, body):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode()
    return result


class LoginDiagnosticsTests(unittest.TestCase):
    def test_both_login_failures_log_status_and_body(self):
        output = io.StringIO()
        with (
            patch("requests.post", side_effect=[
                response(401, "email credentials rejected"),
                response(429, "rate limited"),
            ]),
            redirect_stdout(output),
        ):
            token = login_and_get_token(
                "http://example.test/login", "user@example.test", "bad-password"
            )

        log = output.getvalue()
        self.assertIsNone(token)
        self.assertIn("status=401", log)
        self.assertIn("email credentials rejected", log)
        self.assertIn("status=429", log)
        self.assertIn("rate limited", log)

    def test_failed_explicit_credentials_do_not_fall_back_to_anonymous_scan(self):
        with patch("main.login_and_get_token", return_value=None):
            sessions = build_credential_auth_sessions(
                [{"email": "admin@travel.com", "password": "bad"}],
                {},
                "http://example.test",
                login_url_override="http://example.test/login",
            )
        self.assertEqual(sessions, [])


if __name__ == "__main__":
    unittest.main()
