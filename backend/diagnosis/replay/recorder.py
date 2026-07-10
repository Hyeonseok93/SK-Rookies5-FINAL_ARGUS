"""Record replay steps at vulnerability detection time."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from diagnosis.replay.artifacts import body_fingerprint, save_response_artifact
from diagnosis.replay.normalize import auth_config_from_raw, normalize_url, resolve_public_base_url
from diagnosis.replay.schema import (
    HttpExpectSpec,
    HttpRequestSpec,
    ReplayAuthConfig,
    ReplayEnv,
    ReplayPlan,
    ReplayStep,
)
from diagnosis.result import DiagnosisFinding


def make_finding_id(section_id: str, rule_id: str, path: str, trigger: str = "") -> str:
    seed = f"{section_id}|{rule_id}|{path}|{trigger}|{uuid.uuid4().hex[:8]}"
    digest = hashlib.sha256(seed.encode()).hexdigest()[:10]
    safe_section = section_id.replace("/", "-")
    return f"{safe_section}-{digest}"


def _sanitize_headers(headers: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        key = str(k)
        lower = key.lower()
        if lower in ("host", "content-length", "connection"):
            continue
        out[key] = str(v)
    return out


def _body_as_str(body: str | bytes | None) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    return body


class ReplayRecorder:
    """Accumulates replay steps for one finding."""

    def __init__(
        self,
        *,
        section_id: str,
        rule_id: str,
        artifacts_root: Path,
        raw_config: dict[str, Any] | None = None,
        account_auth: dict[str, Any] | None = None,
        finding_id: str | None = None,
        trigger: str = "",
        path: str = "",
    ) -> None:
        self.section_id = section_id
        self.rule_id = rule_id
        self.raw_config = raw_config or {}
        self.public_base = resolve_public_base_url(self.raw_config)
        self.finding_id = finding_id or make_finding_id(section_id, rule_id, path, trigger)
        self.artifacts_dir = artifacts_root / self.finding_id
        self.steps: list[ReplayStep] = []
        auth_cfg = auth_config_from_raw(self.raw_config, account_auth)
        self.auth = ReplayAuthConfig(
            login_url=auth_cfg["login_url"],
            account_email=auth_cfg["account_email"],
            delivery=auth_cfg["delivery"],
            cookie_name=auth_cfg["cookie_name"],
            id_field=auth_cfg["id_field"],
            pw_field=auth_cfg["pw_field"],
        )
        self._step_index = 0

    def _next_id(self, prefix: str) -> str:
        self._step_index += 1
        return f"s{self._step_index:02d}_{prefix}"

    def set_auth(self, auth_mode: str, *, account_email: str | None = None) -> str:
        step_id = self._next_id(f"auth_{auth_mode}")
        self.steps.append(
            ReplayStep(
                id=step_id,
                action="set_auth",
                label=f"Auth: {auth_mode}",
                auth=auth_mode,  # type: ignore[arg-type]
                account_email=account_email,
            )
        )
        return step_id

    def _capture_modes(self, *modes: str) -> list[str]:
        return list(modes)

    def append_ui_flow(self, *, method: str, path: str) -> bool:
        return False

    def prepend_ui_flow(self, *, method: str, path: str) -> bool:
        return False

    def record_http(
        self,
        prefix: str,
        *,
        label: str,
        method: str,
        url: str,
        headers: dict[str, Any],
        body: str | bytes | None,
        response_status: int | None,
        response_headers: dict[str, Any],
        response_body: bytes,
        auth_mode: str = "anonymous",
        account_email: str | None = None,
        body_contains: list[str] | None = None,
        manipulated_param: str | None = None,
    ) -> str:
        step_id = self._next_id(prefix)
        norm_url = normalize_url(url, public_base_url=self.public_base, raw_config=self.raw_config)
        body_str = _body_as_str(body)
        hdrs = _sanitize_headers(headers)
        fp = body_fingerprint(response_body)
        ctype = str(
            response_headers.get("content-type") or response_headers.get("Content-Type") or ""
        )

        artifact_name = save_response_artifact(
            self.artifacts_dir,
            step_id,
            response_body,
            content_type=ctype,
        )

        expect = HttpExpectSpec(
            status=response_status,
            sha256=fp["sha256"],
            body_contains=list(body_contains or []),
            min_size=fp["size"] if fp["size"] else None,
        )

        self.steps.append(
            ReplayStep(
                id=step_id,
                action="http",
                label=label,
                auth=auth_mode,  # type: ignore[arg-type]
                account_email=account_email,
                request=HttpRequestSpec(method=method, url=norm_url, headers=hdrs, body=body_str),
                expect=expect,
                capture=self._capture_modes("response_file", "evidence_screenshot"),
                artifact_refs={"response_file": artifact_name},
                manipulated_param=manipulated_param,
            )
        )
        return step_id

    def record_http_from_probe(
        self,
        prefix: str,
        *,
        label: str,
        probe: dict[str, Any],
        response_status: int | None,
        response_headers: dict[str, Any],
        response_body: bytes,
        auth_mode: str = "anonymous",
        account_email: str | None = None,
        body_contains: list[str] | None = None,
        manipulated_param: str | None = None,
    ) -> str:
        return self.record_http(
            prefix,
            label=label,
            method=str(probe.get("method") or "GET"),
            url=str(probe.get("url") or ""),
            headers=dict(probe.get("headers") or {}),
            body=probe.get("body"),
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            auth_mode=auth_mode,
            account_email=account_email,
            body_contains=body_contains,
            manipulated_param=manipulated_param,
        )

    def record_compare(self, left_id: str, right_id: str, *, label: str) -> str:
        step_id = self._next_id("compare")
        self.steps.append(
            ReplayStep(
                id=step_id,
                action="compare",
                label=label,
                left=left_id,
                right=right_id,
                capture=self._capture_modes("evidence_screenshot"),
            )
        )
        return step_id

    def record_annotate(self, text: str, *, label: str = "") -> str:
        step_id = self._next_id("note")
        self.steps.append(
            ReplayStep(
                id=step_id,
                action="annotate",
                label=label or "Note",
                text=text,
                capture=self._capture_modes("evidence_screenshot"),
            )
        )
        return step_id

    def finalize(self, *, replayable: bool = True) -> dict[str, Any]:
        rel_dir = self.finding_id
        plan = ReplayPlan(
            finding_id=self.finding_id,
            replayable=replayable and bool(self.steps),
            rule_id=self.rule_id,
            env=ReplayEnv(public_base_url=self.public_base, section_id=self.section_id),
            auth=self.auth,
            artifacts_dir=rel_dir,
            steps=self.steps,
        )
        manifest = {
            "finding_id": self.finding_id,
            "section_id": self.section_id,
            "rule_id": self.rule_id,
            "replay": plan.to_dict(),
        }
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        (self.artifacts_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return plan.to_dict()

    def attach_to(self, finding: DiagnosisFinding) -> DiagnosisFinding:
        replay = self.finalize()
        finding.evidence["replay"] = replay
        finding.evidence["replayable"] = replay.get("replayable", False)
        finding.evidence["finding_id"] = self.finding_id
        return finding


class ReplaySession:
    """Per-scan session — creates recorders sharing artifacts root and config."""

    def __init__(
        self,
        *,
        section_id: str,
        artifacts_root: Path,
        raw_config: dict[str, Any] | None = None,
        account_auth: dict[str, Any] | None = None,
    ) -> None:
        self.section_id = section_id
        self.artifacts_root = artifacts_root
        self.raw_config = raw_config or {}
        self.account_auth = account_auth
        artifacts_root.mkdir(parents=True, exist_ok=True)

    def recorder(
        self,
        *,
        rule_id: str,
        path: str = "",
        trigger: str = "",
    ) -> ReplayRecorder:
        return ReplayRecorder(
            section_id=self.section_id,
            rule_id=rule_id,
            artifacts_root=self.artifacts_root,
            raw_config=self.raw_config,
            account_auth=self.account_auth,
            trigger=trigger,
            path=path,
        )
