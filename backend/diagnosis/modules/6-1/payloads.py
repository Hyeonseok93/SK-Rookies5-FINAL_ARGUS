"""Fuzz payload catalog for 6-1 error-page probes (type-agnostic)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class PayloadSpec:
    payload_id: str
    value: str
    category: str


def utf8_encodable(value: str) -> bool:
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _long(n: int) -> str:
    return "A" * n


def build_payload_suite(
    long_lengths: Iterable[int] | None = None,
    *,
    include_long: bool = True,
) -> list[PayloadSpec]:
    """Return a broad payload set; ignores declared OpenAPI types."""
    lengths = list(long_lengths or (256, 1000, 5000))
    specs: list[PayloadSpec] = [
        PayloadSpec("empty", "", "empty"),
        PayloadSpec("space", " ", "whitespace"),
        PayloadSpec("ascii_alpha", "abcXYZargusProbe", "alphabet"),
        PayloadSpec("korean", "한글가나다라마바사테스트", "korean"),
        PayloadSpec("digits", "123456789012345", "numeric"),
        PayloadSpec("negative", "-1", "numeric"),
        PayloadSpec("max_int", "99999999999999999999", "numeric"),
        PayloadSpec("special", "!@#$%^&*()_+-=[]{}|;':\",./<>?", "special"),
        PayloadSpec("quotes_sql", "'\"\\;--", "special"),
        PayloadSpec("single_quote", "'", "special"),
        PayloadSpec("backslash", "\\\\..\\\\", "special"),
        PayloadSpec("null_literal", "null", "literal"),
        PayloadSpec("true_literal", "true", "literal"),
        PayloadSpec("false_literal", "false", "literal"),
        PayloadSpec("json_array", "[1,2,3]", "structure"),
        PayloadSpec("json_object", '{"a":1}', "structure"),
        PayloadSpec("float_str", "3.14", "numeric"),
        PayloadSpec("nan_str", "NaN", "numeric"),
        PayloadSpec("scientific", "1e308", "numeric"),
        PayloadSpec("newline", "line1\nline2", "whitespace"),
        PayloadSpec("tab", "a\tb", "whitespace"),
        PayloadSpec("emoji", "🔥argus🧪", "unicode"),
        PayloadSpec("path_traversal", "../../../etc/passwd", "traversal"),
        PayloadSpec("percent_null", "%00%41%42", "encoding"),
        # Literal percent-escape (valid UTF-8 string) — exercises non-UTF-8 byte handling server-side.
        PayloadSpec("invalid_utf8_percent", "%FF%FE%FD%00", "encoding"),
        PayloadSpec("xml_fragment", "<xml><a>1</a></xml>", "structure"),
        PayloadSpec("format_string", "%s%s%s%n", "special"),
        PayloadSpec("unicode_escape", "\\u0041\\u0042", "encoding"),
        PayloadSpec("zero_width", "a\u200bb", "unicode"),
    ]
    if include_long:
        for n in lengths:
            specs.append(PayloadSpec(f"long_{n}", _long(n), "length"))
    return specs
