from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_redaction():
    path = Path(__file__).resolve().parents[1] / "screenshot" / "modules" / "2-2" / "redaction.py"
    module_dir = path.parent
    if str(module_dir) not in sys.path:
        sys.path.insert(0, str(module_dir))
    mod_name = "g22_redaction_test"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_auth_headers_and_tokens_are_kept():
    redaction = _load_redaction()
    headers = redaction.redact_headers(
        {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
            "Cookie": "accessToken=tok-123; Path=/",
            "Content-Type": "application/json",
        }
    )
    assert headers["Authorization"] == "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def"
    assert headers["Cookie"] == "accessToken=tok-123; Path=/"
    body = redaction.redact_text(
        '{"accessToken":"tok-abc","refreshToken":"ref-xyz","password":"secret"}'
    )
    assert '"accessToken":"tok-abc"' in body
    assert '"refreshToken":"ref-xyz"' in body
    assert '"password":"***"' in body
