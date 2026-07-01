"""ReplayPlan v1 — machine-readable steps for evidence capture."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

REPLAY_VERSION = 1

ReplayAction = Literal[
    "set_auth",
    "http",
    "compare",
    "annotate",
    "capture",
    "navigate",
    "click",
    "scroll",
    "screenshot",
]

AuthMode = Literal["anonymous", "authenticated"]


@dataclass
class ReplayEnv:
    public_base_url: str = ""
    section_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class ReplayAuthConfig:
    login_url: str = ""
    account_email: str = ""
    delivery: str = "cookie"
    cookie_name: str = "accessToken"
    id_field: str = "email"
    pw_field: str = "password"

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class HttpRequestSpec:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "method": self.method.upper(),
            "url": self.url,
        }
        if self.headers:
            out["headers"] = dict(self.headers)
        if self.body:
            out["body"] = self.body
        return out


@dataclass
class HttpExpectSpec:
    status: int | None = None
    sha256: str = ""
    body_contains: list[str] = field(default_factory=list)
    min_size: int | None = None
    verify_sha256: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.status is not None:
            out["status"] = self.status
        if self.sha256:
            out["sha256"] = self.sha256
        if self.body_contains:
            out["body_contains"] = list(self.body_contains)
        if self.min_size is not None:
            out["min_size"] = self.min_size
        if self.verify_sha256:
            out["verify_sha256"] = True
        return out


@dataclass
class ReplayStep:
    id: str
    action: ReplayAction
    label: str = ""
    auth: AuthMode | None = None
    account_email: str | None = None
    request: HttpRequestSpec | None = None
    expect: HttpExpectSpec | None = None
    capture: list[str] = field(default_factory=list)
    left: str | None = None
    right: str | None = None
    text: str | None = None
    url: str | None = None
    selector: str | None = None
    artifact_refs: dict[str, str] = field(default_factory=dict)
    manipulated_param: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "action": self.action}
        if self.label:
            out["label"] = self.label
        if self.auth is not None:
            out["auth"] = self.auth
        if self.account_email:
            out["account_email"] = self.account_email
        if self.request is not None:
            out["request"] = self.request.to_dict()
        if self.expect is not None:
            expect = self.expect.to_dict()
            if expect:
                out["expect"] = expect
        if self.capture:
            out["capture"] = list(self.capture)
        if self.left:
            out["left"] = self.left
        if self.right:
            out["right"] = self.right
        if self.text:
            out["text"] = self.text
        if self.url:
            out["url"] = self.url
        if self.selector:
            out["selector"] = self.selector
        if self.manipulated_param:
            out["manipulated_param"] = self.manipulated_param
        if self.artifact_refs:
            out["artifact_refs"] = dict(self.artifact_refs)
        return out


@dataclass
class ReplayPlan:
    version: int = REPLAY_VERSION
    finding_id: str = ""
    replayable: bool = True
    rule_id: str = ""
    env: ReplayEnv = field(default_factory=ReplayEnv)
    auth: ReplayAuthConfig = field(default_factory=ReplayAuthConfig)
    artifacts_dir: str = ""
    steps: list[ReplayStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "finding_id": self.finding_id,
            "replayable": self.replayable,
            "rule_id": self.rule_id,
            "env": self.env.to_dict(),
            "auth": self.auth.to_dict(),
            "artifacts_dir": self.artifacts_dir,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ReplayPlan:
        env_raw = raw.get("env") or {}
        auth_raw = raw.get("auth") or {}
        steps: list[ReplayStep] = []
        for s in raw.get("steps") or []:
            if not isinstance(s, dict):
                continue
            req_raw = s.get("request") or {}
            exp_raw = s.get("expect") or {}
            steps.append(
                ReplayStep(
                    id=str(s.get("id", "")),
                    action=s.get("action", "http"),  # type: ignore[arg-type]
                    label=str(s.get("label", "")),
                    auth=s.get("auth"),  # type: ignore[arg-type]
                    account_email=s.get("account_email"),
                    request=HttpRequestSpec(
                        method=str(req_raw.get("method", "GET")),
                        url=str(req_raw.get("url", "")),
                        headers=dict(req_raw.get("headers") or {}),
                        body=str(req_raw.get("body", "")),
                    )
                    if req_raw
                    else None,
                    expect=HttpExpectSpec(
                        status=exp_raw.get("status"),
                        sha256=str(exp_raw.get("sha256", "")),
                        body_contains=list(exp_raw.get("body_contains") or []),
                        min_size=exp_raw.get("min_size"),
                        verify_sha256=bool(exp_raw.get("verify_sha256", False)),
                    )
                    if exp_raw
                    else None,
                    capture=list(s.get("capture") or []),
                    left=s.get("left"),
                    right=s.get("right"),
                    text=s.get("text"),
                    url=s.get("url"),
                    selector=s.get("selector"),
                    artifact_refs=dict(s.get("artifact_refs") or {}),
                    manipulated_param=s.get("manipulated_param"),
                )
            )
        return cls(
            version=int(raw.get("version", REPLAY_VERSION)),
            finding_id=str(raw.get("finding_id", "")),
            replayable=bool(raw.get("replayable", True)),
            rule_id=str(raw.get("rule_id", "")),
            env=ReplayEnv(
                public_base_url=str(env_raw.get("public_base_url", "")),
                section_id=str(env_raw.get("section_id", "")),
            ),
            auth=ReplayAuthConfig(
                login_url=str(auth_raw.get("login_url", "")),
                account_email=str(auth_raw.get("account_email", "")),
                delivery=str(auth_raw.get("delivery", "cookie")),
                cookie_name=str(auth_raw.get("cookie_name", "accessToken")),
                id_field=str(auth_raw.get("id_field", "email")),
                pw_field=str(auth_raw.get("pw_field", "password")),
            ),
            artifacts_dir=str(raw.get("artifacts_dir", "")),
            steps=steps,
        )
