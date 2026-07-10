"""Execute ReplayPlan — httpx replay + optional Playwright screenshots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from diagnosis.replay.artifacts import body_fingerprint, guess_extension, save_response_artifact
from diagnosis.g22_replay import perform_login
from diagnosis.replay.evidence_panel import render_evidence_panel
from diagnosis.replay.normalize import normalize_url, resolve_public_base_url
from diagnosis.replay.schema import ReplayPlan, ReplayStep


@dataclass
class StepResult:
    step_id: str
    action: str
    ok: bool
    message: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)


@dataclass
class ReplayRunResult:
    finding_id: str
    ok: bool
    steps: list[StepResult] = field(default_factory=list)
    output_dir: str = ""
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "ok": self.ok,
            "output_dir": self.output_dir,
            "message": self.message,
            "steps": [
                {
                    "step_id": s.step_id,
                    "action": s.action,
                    "ok": s.ok,
                    "message": s.message,
                    "artifacts": s.artifacts,
                }
                for s in self.steps
            ],
        }


def _text_preview(body: bytes, limit: int = 1200) -> str:
    if body.startswith(b"%PDF"):
        try:
            from io import BytesIO

            from pypdf import PdfReader

            reader = PdfReader(BytesIO(body))
            parts: list[str] = []
            for page in reader.pages[:2]:
                parts.append(page.extract_text() or "")
            text = "\n".join(parts).strip()
            if text:
                return text[:limit]
        except Exception:
            pass
        return "(PDF binary)"
    try:
        return body.decode("utf-8", errors="replace")[:limit]
    except Exception:
        return "(binary)"


class _AuthState:
    def __init__(self, plan: ReplayPlan, raw_config: dict[str, Any] | None, test_accounts: list[dict]) -> None:
        self.plan = plan
        self.raw_config = raw_config or {}
        self.test_accounts = test_accounts
        self.mode = "anonymous"
        self.account_email = plan.auth.account_email
        self._auth_headers: dict[str, str] = {}
        self._browser_cookies: list[dict[str, Any]] = []
        self._browser_bootstrapped = False

    def apply_set_auth(self, step: ReplayStep) -> None:
        self.mode = step.auth or "anonymous"
        if step.account_email:
            self.account_email = step.account_email
        if self.mode != "authenticated":
            self._browser_bootstrapped = False

    def headers_for_request(self, client: httpx.Client, base_headers: dict[str, str]) -> dict[str, str]:
        hdrs = dict(base_headers)
        if self.mode != "authenticated":
            hdrs.pop("Cookie", None)
            hdrs.pop("Authorization", None)
            return hdrs

        if self._auth_headers:
            hdrs.update(self._auth_headers)
            return hdrs

        auth = self.plan.auth
        acct = next(
            (a for a in self.test_accounts if a.get("email") == self.account_email),
            self.test_accounts[0] if self.test_accounts else None,
        )
        if not acct:
            return hdrs

        token_field = str((self.raw_config.get("auth") or {}).get("token_field") or "cookie.accessToken")
        self._auth_headers, self._browser_cookies = perform_login(
            client,
            login_url=auth.login_url,
            email=str(acct.get("email") or ""),
            password=str(acct.get("password") or ""),
            id_field=auth.id_field,
            pw_field=auth.pw_field,
            delivery=auth.delivery,
            cookie_name=auth.cookie_name,
            token_field=token_field,
            raw_config=self.raw_config,
            frontend_base_url=self.plan.env.public_base_url,
        )
        hdrs.update(self._auth_headers)
        return hdrs

    def browser_cookies_for_ui(self, public_base: str) -> list[dict[str, Any]]:
        if not self._browser_cookies:
            return []
        domain = urlparse(public_base).hostname or "localhost"
        out: list[dict[str, Any]] = []
        for c in self._browser_cookies:
            cookie = dict(c)
            cookie["domain"] = domain
            out.append(cookie)
        return out


def _verify_expect(body: bytes, status: int, expect: dict[str, Any]) -> tuple[bool, str]:
    if expect.get("status") is not None and int(expect["status"]) != status:
        return False, f"status {status} != expected {expect['status']}"
    fp = body_fingerprint(body)
    if expect.get("verify_sha256") and expect.get("sha256") and expect["sha256"] != fp["sha256"]:
        return False, f"sha256 mismatch (got {fp['sha256'][:16]}…)"
    if expect.get("min_size") is not None and fp["size"] < int(expect["min_size"]):
        return False, f"body too small ({fp['size']})"
    text = body.decode("utf-8", errors="replace").lower()
    for needle in expect.get("body_contains") or []:
        if str(needle).lower() not in text:
            preview = _text_preview(body, 400).lower()
            if str(needle).lower() not in preview:
                return False, f"missing body marker: {needle}"
    return True, "ok"


def _screenshot_html(html_path: Path, png_path: Path) -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.goto(html_path.resolve().as_uri(), wait_until="networkidle")
            page.screenshot(path=str(png_path), full_page=True)
            browser.close()
        return True
    except Exception:
        return False


class _BrowserSession:
    """Reusable Playwright session for UI navigation steps."""

    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self._pw = None
        self._browser = None
        self._context = None
        self.page = None
        self._auth_bootstrapped = False

    def __enter__(self) -> _BrowserSession:
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._context = self._browser.new_context(viewport={"width": 1280, "height": 900})
        self.page = self._context.new_page()
        return self

    def __exit__(self, *args: object) -> None:
        if self._browser:
            self._browser.close()
        if self._pw:
            self._pw.stop()

    def apply_cookies(self, cookies: list[dict[str, Any]]) -> None:
        if not cookies or not self._context:
            return
        self._context.add_cookies(cookies)

    def bootstrap_auth_session(self, public_base: str) -> None:
        """Load SPA once so cookie-based session restore runs before protected routes."""
        if self._auth_bootstrapped or not self.page:
            return
        self.page.goto(public_base.rstrip("/") + "/", wait_until="domcontentloaded", timeout=30000)
        self._auth_bootstrapped = True

    def reset_session(self) -> None:
        if self._context:
            self._context.clear_cookies()
        self._auth_bootstrapped = False

    def run_ui_step(self, step: ReplayStep, *, auth_state: _AuthState, public_base: str) -> StepResult:
        assert self.page is not None
        artifacts: dict[str, str] = {}
        try:
            if step.action == "navigate" and step.url:
                self.page.goto(step.url, wait_until="networkidle", timeout=30000)
            elif step.action == "scroll" and step.selector:
                loc = self.page.locator(step.selector)
                loc.scroll_into_view_if_needed(timeout=10000)
            elif step.action == "click" and step.selector:
                self.page.locator(step.selector).click(timeout=10000)
            elif step.action == "screenshot":
                pass
            else:
                return StepResult(step_id=step.id, action=step.action, ok=False, message="unsupported ui step")

            wants_shot = "screenshot" in step.capture or step.action == "screenshot"
            if wants_shot:
                png_path = self.out_dir / f"{step.id}_screenshot.png"
                self.page.screenshot(path=str(png_path), full_page=True)
                artifacts["screenshot"] = png_path.name
            return StepResult(step_id=step.id, action=step.action, ok=True, artifacts=artifacts)
        except Exception as exc:
            return StepResult(step_id=step.id, action=step.action, ok=False, message=str(exc)[:200])


def run_replay_plan(
    plan: ReplayPlan | dict[str, Any],
    *,
    artifacts_root: Path,
    output_subdir: str = "replay",
    raw_config: dict[str, Any] | None = None,
    test_accounts: list[dict[str, Any]] | None = None,
    use_playwright: bool = True,
) -> ReplayRunResult:
    """Re-run recorded steps and capture evidence artifacts."""
    if isinstance(plan, dict):
        parsed = ReplayPlan.from_dict(plan)
    else:
        parsed = plan

    finding_id = parsed.finding_id
    if not parsed.replayable or not parsed.steps:
        return ReplayRunResult(
            finding_id=finding_id,
            ok=False,
            message="not replayable",
        )

    base_dir = artifacts_root / parsed.artifacts_dir
    out_dir = base_dir / output_subdir
    out_dir.mkdir(parents=True, exist_ok=True)

    public_base = parsed.env.public_base_url or resolve_public_base_url(raw_config)
    accounts = list(test_accounts or [])
    auth_state = _AuthState(parsed, raw_config, accounts)

    step_results: list[StepResult] = []
    http_cache: dict[str, dict[str, Any]] = {}
    all_ok = True
    ui_actions = frozenset({"navigate", "click", "scroll", "screenshot"})
    has_ui = any(s.action in ui_actions for s in parsed.steps)

    browser_ctx: _BrowserSession | None = None
    if use_playwright and has_ui:
        try:
            browser_ctx = _BrowserSession(out_dir)
            browser_ctx.__enter__()
        except Exception:
            browser_ctx = None

    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        for step in parsed.steps:
            if step.action in ui_actions:
                if browser_ctx is None:
                    step_results.append(
                        StepResult(step_id=step.id, action=step.action, ok=False, message="playwright unavailable")
                    )
                    all_ok = False
                    continue
                if auth_state.mode == "authenticated":
                    auth_state.headers_for_request(client, {})
                    cookies = auth_state.browser_cookies_for_ui(public_base)
                    if cookies:
                        browser_ctx.apply_cookies(cookies)
                        browser_ctx.bootstrap_auth_session(public_base)
                elif auth_state.mode == "anonymous":
                    browser_ctx.reset_session()
                result = browser_ctx.run_ui_step(step, auth_state=auth_state, public_base=public_base)
                step_results.append(result)
                if not result.ok:
                    all_ok = False
                continue

            if step.action == "set_auth":
                auth_state.apply_set_auth(step)
                step_results.append(StepResult(step_id=step.id, action=step.action, ok=True))
                continue

            if step.action == "annotate":
                if "evidence_screenshot" in step.capture and use_playwright:
                    html_path = out_dir / f"{step.id}_panel.html"
                    png_path = out_dir / f"{step.id}_screenshot.png"
                    html_path.write_text(
                        render_evidence_panel(
                            title="ARGUS Evidence",
                            section_id=parsed.env.section_id,
                            finding_id=finding_id,
                            step_label=step.label or step.id,
                            note=step.text or "",
                        ),
                        encoding="utf-8",
                    )
                    shot_ok = _screenshot_html(html_path, png_path)
                    step_results.append(
                        StepResult(
                            step_id=step.id,
                            action=step.action,
                            ok=True,
                            artifacts={
                                "panel_html": str(html_path.name),
                                **({"screenshot": str(png_path.name)} if shot_ok else {}),
                            },
                        )
                    )
                else:
                    step_results.append(StepResult(step_id=step.id, action=step.action, ok=True))
                continue

            if step.action == "compare":
                left = http_cache.get(step.left or "", {})
                right = http_cache.get(step.right or "", {})
                artifacts: dict[str, str] = {}
                if "evidence_screenshot" in step.capture and use_playwright:
                    html_path = out_dir / f"{step.id}_panel.html"
                    png_path = out_dir / f"{step.id}_screenshot.png"
                    html_path.write_text(
                        render_evidence_panel(
                            title="ARGUS Evidence — Compare",
                            section_id=parsed.env.section_id,
                            finding_id=finding_id,
                            step_label=step.label or step.id,
                            compare={
                                "left_label": left.get("label", step.left),
                                "left_summary": left.get("summary", ""),
                                "right_label": right.get("label", step.right),
                                "right_summary": right.get("summary", ""),
                            },
                        ),
                        encoding="utf-8",
                    )
                    if _screenshot_html(html_path, png_path):
                        artifacts["screenshot"] = png_path.name
                    artifacts["panel_html"] = html_path.name
                step_results.append(
                    StepResult(step_id=step.id, action=step.action, ok=True, artifacts=artifacts)
                )
                continue

            if step.action != "http" or step.request is None:
                step_results.append(
                    StepResult(step_id=step.id, action=step.action, ok=False, message="unsupported step")
                )
                all_ok = False
                continue

            req = step.request
            url = normalize_url(req.url, public_base_url=public_base, raw_config=raw_config)
            hdrs = auth_state.headers_for_request(client, dict(req.headers))
            body_bytes = req.body.encode("utf-8") if req.body else None

            try:
                resp = client.request(req.method, url, headers=hdrs, content=body_bytes)
                resp_body = bytes(resp.content or b"")
                resp_status = resp.status_code
            except httpx.HTTPError as exc:
                step_results.append(
                    StepResult(step_id=step.id, action=step.action, ok=False, message=str(exc)[:200])
                )
                all_ok = False
                continue

            expect_dict = step.expect.to_dict() if step.expect else {}
            ok, msg = _verify_expect(resp_body, resp_status, expect_dict)

            ctype = resp.headers.get("content-type", "")
            replay_artifact = save_response_artifact(out_dir, step.id, resp_body, content_type=ctype)
            fp = body_fingerprint(resp_body)
            preview = _text_preview(resp_body)

            http_cache[step.id] = {
                "label": step.label,
                "summary": f"HTTP {resp_status} sha256={fp['sha256'][:16]}…\n{preview[:300]}",
            }

            artifacts = {"response_file": replay_artifact}
            if "evidence_screenshot" in step.capture and use_playwright:
                html_path = out_dir / f"{step.id}_panel.html"
                png_path = out_dir / f"{step.id}_screenshot.png"
                html_path.write_text(
                    render_evidence_panel(
                        title="ARGUS Evidence",
                        section_id=parsed.env.section_id,
                        finding_id=finding_id,
                        step_label=step.label or step.id,
                        request={"method": req.method, "url": url, "headers": hdrs, "body": req.body},
                        response={
                            "status": resp_status,
                            "content_type": ctype,
                            "sha256": fp["sha256"],
                            "body_preview": preview,
                        },
                        expect=expect_dict,
                    ),
                    encoding="utf-8",
                )
                if _screenshot_html(html_path, png_path):
                    artifacts["screenshot"] = png_path.name
                artifacts["panel_html"] = html_path.name

            step_results.append(
                StepResult(
                    step_id=step.id,
                    action=step.action,
                    ok=ok,
                    message=msg,
                    artifacts=artifacts,
                )
            )
            if not ok:
                all_ok = False

    if browser_ctx is not None:
        browser_ctx.__exit__(None, None, None)

    run_manifest = {
        "finding_id": finding_id,
        "ok": all_ok,
        "result": ReplayRunResult(
            finding_id=finding_id, ok=all_ok, steps=step_results, output_dir=str(out_dir)
        ).to_dict(),
    }
    (out_dir / "run_manifest.json").write_text(
        json.dumps(run_manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return ReplayRunResult(
        finding_id=finding_id,
        ok=all_ok,
        steps=step_results,
        output_dir=str(out_dir),
        message="replay complete" if all_ok else "replay completed with verification failures",
    )
