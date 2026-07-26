"""Static design review for guideline 1-3 — hidden-field candidates (SCOPE.md §5 item 7).

A body/form parameter that (a) classifies as sensitive by name and (b) is not
required per the api-tree schema is flagged as an info-level "hidden candidate":
UI likely never renders/edits it, so a client can add or change it freely.
"""

from __future__ import annotations

from typing import Any, Callable

from diagnosis.result import DiagnosisFinding
from inventory.schema import Endpoint


def review_design(
    candidates: list[Endpoint],
    *,
    sensitive_params_fn: Callable[[Endpoint], list[tuple[Any, str, str]]],
) -> list[DiagnosisFinding]:
    findings: list[DiagnosisFinding] = []
    seen: set[tuple[str, str, str]] = set()

    for ep in candidates:
        for inp, category, reason in sensitive_params_fn(ep):
            if inp.in_ not in ("body", "form") or inp.required:
                continue
            key = (ep.endpoint_id, inp.in_, inp.name)
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                DiagnosisFinding(
                    severity="info",
                    message=(
                        f"Hidden-field candidate `{inp.name}` ({category}) on "
                        f"{ep.method} {ep.path} — not required, client can add/omit freely"
                    ),
                    evidence={
                        "rule_id": "1-3-hidden-candidate",
                        "engine": "design",
                        "trigger": "design_review",
                        "endpoint_id": ep.endpoint_id,
                        "method": ep.method,
                        "path": ep.path,
                        "base_url": ep.base_url,
                        "param_in": inp.in_,
                        "param_name": inp.name,
                        "category": category,
                        "reason": reason,
                    },
                )
            )
    return findings
