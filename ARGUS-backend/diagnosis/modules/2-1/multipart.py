"""Minimal multipart/form-data body encoder.

Both transports in this module (httpx-direct and ZAP ``sendRequest``) take a
raw ``bytes`` body + header dict rather than a high-level ``files=`` kwarg
(see ``diagnosis.probe_transport.ProbeTransport``), so the multipart body is
built by hand here. This also gives byte-exact control over the filename —
needed for techniques like the null-byte bypass, which a high-level HTTP
client's own multipart encoder may reject or mangle before it ever reaches
the wire.
"""

from __future__ import annotations

import os


def _boundary() -> str:
    return f"ArgusBoundary{os.urandom(12).hex()}"


def encode_multipart(
    *,
    file_field: str,
    filename: str,
    file_content: bytes,
    file_content_type: str,
    fields: dict[str, str] | None = None,
) -> tuple[bytes, str]:
    """Return (body_bytes, content_type_header)."""
    boundary = _boundary()
    chunks: list[bytes] = []

    for name, value in (fields or {}).items():
        chunks.append(
            (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8", errors="replace")
        )

    chunks.append(
        (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
            f"Content-Type: {file_content_type}\r\n\r\n"
        ).encode("utf-8", errors="replace")
    )
    chunks.append(file_content)
    chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))

    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
