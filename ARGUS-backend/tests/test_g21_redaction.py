"""Tests for 2-1 evidence redaction, including presigned/signed-URL masking."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_redaction():
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "2-1" / "redaction.py"
    module_dir = path.parent
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    mod_name = "g21_redaction_test"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_auth_headers_are_masked_but_others_untouched():
    redaction = _load_redaction()
    headers = redaction.redact_headers(
        {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
            "Cookie": "accessToken=tok-123; Path=/",
            "Content-Type": "multipart/form-data; boundary=x",
        }
    )
    assert headers["Authorization"] == "***REDACTED***"
    assert headers["Cookie"] == "***REDACTED***"
    assert headers["Content-Type"] == "multipart/form-data; boundary=x"


def test_json_secret_fields_are_masked():
    redaction = _load_redaction()
    body = redaction.redact_text('{"password":"secret","accessToken":"tok-abc"}')
    assert '"password":"***REDACTED***"' in body
    assert '"accessToken":"***REDACTED***"' in body


def test_presigned_s3_url_signature_is_masked_in_text():
    redaction = _load_redaction()
    url = (
        "https://bucket.s3.amazonaws.com/uploads/argus-shell.php"
        "?X-Amz-Credential=AKIAEXAMPLE%2F20260101&X-Amz-Signature=deadbeef1234"
    )
    redacted = redaction.redact_text(f'{{"fileUrl":"{url}"}}')
    assert "AKIAEXAMPLE" not in redacted
    assert "deadbeef1234" not in redacted
    assert "X-Amz-Credential=***REDACTED***" in redacted
    assert "X-Amz-Signature=***REDACTED***" in redacted
    # Non-secret parts of the URL stay readable for the evidence screenshot.
    assert "bucket.s3.amazonaws.com/uploads/argus-shell.php" in redacted


def test_presigned_url_signature_is_masked_in_header_value():
    redaction = _load_redaction()
    headers = redaction.redact_headers(
        {
            "Location": (
                "https://storage.googleapis.com/bucket/obj"
                "?X-Goog-Signature=abcdef0123456789"
            )
        }
    )
    assert "abcdef0123456789" not in headers["Location"]
    assert "X-Goog-Signature=***REDACTED***" in headers["Location"]


def test_generic_token_query_param_is_masked():
    redaction = _load_redaction()
    redacted = redaction.redact_text("https://cdn.example.test/f?token=super-secret-value&size=100")
    assert "super-secret-value" not in redacted
    assert "token=***REDACTED***" in redacted
    assert "size=100" in redacted
