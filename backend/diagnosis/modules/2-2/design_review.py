"""Static design review for guideline 2-2 (path/filename direct parameters)."""

from __future__ import annotations

import re

from diagnosis.result import DiagnosisFinding
from inventory.net import probe_base_url
from inventory.schema import Endpoint

# Guideline 2-2: prefer opaque fileId over direct path/filename composition
DIRECT_PATH_PARAM = re.compile(
    r"^(path|filename|filepath|file_path|filePath|dir|directory|folder|savepath|save_path)$",
    re.IGNORECASE,
)
RISKY_PARAM = re.compile(
    r"(path|file|filename|filepath|template|dir|folder|export|download|attach|storage|uri|location)",
    re.IGNORECASE,
)


def review_design(candidates: list[Endpoint]) -> list[DiagnosisFinding]:
    findings: list[DiagnosisFinding] = []
    seen: set[tuple[str, str, str]] = set()

    for ep in candidates:
        for inp in ep.request_params:
            if inp.in_ not in ("query", "body", "form", "path"):
                continue
            name = inp.name
            if not RISKY_PARAM.search(name):
                continue
            key = (ep.endpoint_id, inp.in_, name)
            if key in seen:
                continue
            seen.add(key)

            severity = "info"
            message = f"File-related parameter `{name}` ({inp.in_}) on {ep.method} {ep.path}"
            if DIRECT_PATH_PARAM.match(name):
                severity = "medium"
                message = (
                    f"Direct path/filename parameter `{name}` ({inp.in_}) on "
                    f"{ep.method} {ep.path} — prefer opaque fileId (guideline 2-2 design)"
                )

            findings.append(
                DiagnosisFinding(
                    severity=severity,
                    message=message,
                    evidence={
                        "rule_id": "2-2-design",
                        "trigger": "design_review",
                        "trigger_label": (
                            "Direct path/filename parameter (guideline 2-2 design)"
                            if DIRECT_PATH_PARAM.match(name)
                            else "File-related parameter name (design review)"
                        ),
                        "endpoint_id": ep.endpoint_id,
                        "method": ep.method,
                        "path": ep.path,
                        "base_url": probe_base_url(ep.base_url or ""),
                        "param_in": inp.in_,
                        "param_name": name,
                    },
                )
            )
    return findings
