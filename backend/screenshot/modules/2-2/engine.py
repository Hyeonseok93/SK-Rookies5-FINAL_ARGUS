"""Playwright screenshot engine for 2-2 evidence boards / UI overlays."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from credentials import load_replay_credentials
from models import CaptureArtifact, EvidenceCase
from renderer import (
    render_comparison_overlay,
    render_evidence_overlay,
    render_file_compare_overlay,
)
from ui_flow import resolve_ui_flow

UI_PROBE_RULES = frozenset(
    {
        "2-2-path-traversal",
        "2-2-input-validation",
        "2-2-forced-browse",
        "2-2-idor",
    }
)

PROBE_CAPTURES = (
    ("main_site", "01_main_site.png"),
    ("logged_in_main", "02_logged_in_main.png"),
    ("feature_page", "03_feature_page.png"),
    ("baseline_evidence", "04_baseline_evidence.png"),
    ("attack_evidence", "05_attack_evidence.png"),
    ("ui_result", "06_ui_result.png"),
)

UNAUTH_CAPTURES = (
    ("main_site", "01_main_site.png"),
    ("feature_page", "02_feature_page.png"),
    ("auth_evidence", "03_auth_evidence.png"),
    ("anon_evidence", "04_anon_evidence.png"),
    ("ui_result", "05_ui_result.png"),
)

FILE_COMPARE_CAPTURE = ("file_compare", "07_file_compare.png")
UNAUTH_FILE_COMPARE_CAPTURE = FILE_COMPARE_CAPTURE
PROBE_FILE_COMPARE_CAPTURE = FILE_COMPARE_CAPTURE


def _playwright_resolver_args() -> list[str]:
    try:
        host_gateway = socket.gethostbyname("host.docker.internal")
        return [f"--host-resolver-rules=MAP localhost {host_gateway}"]
    except OSError:
        return []


def _launch_browser(playwright):
    return playwright.chromium.launch(
        headless=not bool(os.environ.get("DISPLAY")),
        args=[
            *_playwright_resolver_args(),
            "--window-position=0,0",
            "--window-size=1280,720",
            "--force-device-scale-factor=1",
        ],
    )


def _shot_page(page, path: Path) -> None:
    page.emulate_media(reduced_motion="reduce")
    try:
        page.evaluate("document.fonts.ready")
    except Exception:
        page.wait_for_timeout(500)
    _take_window_shot(page, path)


def _inject_overlay(page, css: str, markup: str) -> None:
    last_error = None
    for _ in range(3):
        try:
            page.wait_for_load_state("domcontentloaded", timeout=5_000)
            page.evaluate(
                """({css, markup}) => {
                  document.getElementById('argus-evidence-root')?.remove();
                  const root = document.createElement('div');
                  root.id = 'argus-evidence-root';
                  const style = document.createElement('style');
                  style.textContent = css;
                  root.appendChild(style);
                  const body = document.createElement('div');
                  body.innerHTML = markup;
                  while (body.firstChild) root.appendChild(body.firstChild);
                  document.documentElement.appendChild(root);
                }""",
                {"css": css, "markup": markup},
            )
            return
        except Exception as exc:
            last_error = exc
            page.wait_for_timeout(500)
    raise RuntimeError(f"Overlay injection failed after SPA navigation: {last_error}")


def _authenticate_browser_context(context, case: EvidenceCase) -> None:
    """Login via API and seed SPA browser cookies when configured."""
    import httpx

    from diagnosis.g22_replay import perform_login, spa_browser_session_mod

    SpaBrowserSessionConfig = spa_browser_session_mod().SpaBrowserSessionConfig

    login = dict(case.metadata.get("login") or {})
    if not login.get("ok"):
        case.metadata["browser_login"] = {"ok": False, "reason": "Replay login unavailable"}
        return

    account_id = str(login.get("account_id") or "")
    email = str(login.get("email") or "")
    credentials = load_replay_credentials(Path(__file__).resolve().parents[3] / "data")
    credential = next(
        (
            item
            for item in credentials
            if item.account_id == account_id or item.identifier == email
        ),
        None,
    )
    if credential is None and credentials:
        credential = credentials[0]
    if credential is None:
        case.metadata["browser_login"] = {"ok": False, "reason": "Replay account unavailable"}
        return

    source = dict(case.metadata.get("source_evidence") or {})
    replay_auth = dict((source.get("replay") or {}).get("auth") or {})
    login_url = str(login.get("runtime_login_url") or login.get("login_url") or "")
    frontend_url = str(case.metadata.get("main_url") or case.metadata.get("ui_url") or "")
    if not login_url or not frontend_url:
        case.metadata["browser_login"] = {"ok": False, "reason": "Login or frontend URL missing"}
        return

    delivery = str(replay_auth.get("delivery") or "cookie")
    cookie_name = str(replay_auth.get("cookie_name") or "accessToken")
    spa = SpaBrowserSessionConfig.from_dict(case.metadata.get("spa_browser_session"))
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            _, browser_cookies = perform_login(
                client,
                login_url=login_url,
                email=credential.identifier,
                password=credential.password,
                id_field=str(case.metadata.get("id_field") or replay_auth.get("id_field") or "email"),
                pw_field=str(case.metadata.get("password_field") or replay_auth.get("pw_field") or "password"),
                delivery=delivery,
                cookie_name=cookie_name,
                spa=spa,
                frontend_base_url=frontend_url,
            )
    except Exception as exc:
        case.metadata["browser_login"] = {"ok": False, "reason": f"Login request failed: {exc}"}
        return

    if not browser_cookies:
        case.metadata["browser_login"] = {
            "ok": False,
            "reason": "Login succeeded but SPA session cookies were not produced (check auth.spa_browser_session in config)",
        }
        return

    domain = urlsplit(frontend_url).hostname or "localhost"
    context.add_cookies(
        [{**cookie, "domain": domain} for cookie in browser_cookies]
    )

    bootstrap = context.new_page()
    try:
        bootstrap.goto(frontend_url.rstrip("/") + "/", wait_until="domcontentloaded", timeout=20_000)
        bootstrap.wait_for_timeout(800)
    finally:
        bootstrap.close()

    case.metadata["browser_login"] = {
        "ok": True,
        "account_id": credential.account_id,
        "email": credential.identifier,
        "cookie_count": len(browser_cookies),
    }


def _target_api_path(case: EvidenceCase) -> str:
    return urlsplit(case.baseline.url or case.attack.url or "").path.rstrip("/")


def _resolve_ui_pages(case: EvidenceCase, *, main_url: str) -> tuple[str, str]:
    """Prefer replay/ui_flow navigation; fall back to network discovery."""
    flow = resolve_ui_flow(case)
    if flow:
        case.metadata.update(flow)
        return str(flow["main_url"]), str(flow["feature_url"])

    case.metadata["ui_route_source"] = "network-discovery-fallback"
    return main_url, main_url


resolve_unauth_pages = _resolve_ui_pages


def _run_ui_prep_steps(page, prep_steps: list[dict]) -> None:
    """Best-effort scroll/click before comparison (skipped on auth-gated pages)."""
    for step in prep_steps:
        action = str(step.get("action") or "")
        selector = str(step.get("selector") or "")
        try:
            if action == "scroll" and selector:
                page.locator(selector).scroll_into_view_if_needed(timeout=5_000)
            elif action == "click" and selector:
                page.locator(selector).click(timeout=5_000)
            page.wait_for_timeout(400)
        except Exception:
            break


def _discover_related_page(context, case: EvidenceCase) -> str:
    """Find a frontend route that issues the finding's API call (generic, no hardcoded paths)."""
    frontend_base = str(case.metadata.get("main_url") or case.metadata.get("ui_url") or "")
    if not frontend_base:
        return ""
    routes = list(case.metadata.get("frontend_routes") or ["/"])
    target_path = _target_api_path(case)
    matches: list[tuple[int, str, str]] = []
    probe = context.new_page()
    try:
        for route_path in routes:
            requested_paths: set[str] = set()

            def remember_request(request) -> None:
                requested_paths.add(urlsplit(request.url).path.rstrip("/"))

            probe.on("request", remember_request)
            candidate = urljoin(frontend_base.rstrip("/") + "/", str(route_path).lstrip("/"))
            try:
                probe.goto(candidate, wait_until="domcontentloaded", timeout=8_000)
                probe.wait_for_timeout(900)
            except Exception:
                probe.remove_listener("request", remember_request)
                continue
            probe.remove_listener("request", remember_request)
            if target_path and target_path in requested_paths:
                # Prefer non-root, deeper routes that actually hit the API.
                score = (0 if str(route_path).rstrip("/") in {"", "/"} else 10) + str(route_path).count("/")
                matches.append((score, str(route_path), candidate))
    finally:
        probe.close()

    if matches:
        matches.sort(key=lambda item: (-item[0], item[1]))
        best_route, best_url = matches[0][1], matches[0][2]
        case.metadata["feature_route"] = best_route
        case.metadata["ui_route_source"] = "network-discovery"
        return best_url

    case.metadata["feature_route"] = "/"
    case.metadata["ui_route_source"] = "frontend-base-fallback"
    return frontend_base


def _settle_page(page) -> None:
    page.wait_for_timeout(1_200)
    try:
        page.wait_for_load_state("networkidle", timeout=5_000)
    except Exception:
        pass
    _focus_page_content(page)


def _focus_page_content(page) -> None:
    page.evaluate(
        """() => {
          const main = document.querySelector('main');
          if (!main) return;
          const children = Array.from(main.children)
            .filter((element) => element.getBoundingClientRect().height > 20);
          const target = children.length > 1 ? children[1] : main;
          const top = target.getBoundingClientRect().top + window.scrollY;
          if (top > 120) {
            window.scrollTo({top: Math.max(0, top - 90), behavior: 'instant'});
          }
        }"""
    )
    page.wait_for_timeout(400)


def _take_window_shot(page, path: Path) -> None:
    page.bring_to_front()
    page.wait_for_timeout(250)
    if os.environ.get("DISPLAY"):
        subprocess.run(["scrot", "--overwrite", str(path)], check=True)
    else:
        page.screenshot(path=str(path), full_page=False)


def _route_attack_api(page, case: EvidenceCase) -> None:
    """Route in-browser API calls to the replayed exploit exchange."""
    target_path = urlsplit(case.baseline.url or case.attack.url).path.rstrip("/")
    attack_url = case.attack.url

    def handler(route) -> None:
        request = route.request
        if (
            request.method.upper() == (case.baseline.method or case.attack.method or "GET").upper()
            and urlsplit(request.url).path.rstrip("/") == target_path
        ):
            route.continue_(url=attack_url)
        else:
            route.continue_()

    page.route("**/*", handler)


def _route_anon_api(page, case: EvidenceCase) -> None:
    """Force the download API call to the unauthenticated exchange URL."""
    target_path = urlsplit(case.baseline.url or case.attack.url).path.rstrip("/")
    attack_url = case.attack.url

    def handler(route) -> None:
        request = route.request
        if (
            request.method.upper() == (case.baseline.method or case.attack.method or "GET").upper()
            and urlsplit(request.url).path.rstrip("/") == target_path
        ):
            # Strip auth headers so the browser-side call behaves as anonymous.
            headers = {
                key: value
                for key, value in request.headers.items()
                if key.lower() not in {"cookie", "authorization"}
            }
            route.continue_(url=attack_url, headers=headers)
        else:
            route.continue_()

    page.route("**/*", handler)


def _page_url_for_kind(kind: str, *, main_url: str, feature_url: str) -> str:
    if kind in {"main_site", "logged_in_main"}:
        return main_url
    return feature_url


def _apply_overlay(page, case: EvidenceCase, kind: str) -> None:
    if kind in {"auth_evidence", "baseline_evidence"}:
        css, markup = render_evidence_overlay(case, "baseline")
        _inject_overlay(page, css, markup)
    elif kind in {"anon_evidence", "attack_evidence"}:
        css, markup = render_evidence_overlay(case, "attack")
        _inject_overlay(page, css, markup)
    elif kind == "ui_result":
        page.wait_for_timeout(800)
        css, markup = render_comparison_overlay(case)
        _inject_overlay(page, css, markup)
    elif kind == "file_compare":
        css, markup = render_file_compare_overlay(case)
        _inject_overlay(page, css, markup)


def _capture_probe_ui_case(case: EvidenceCase, output_dir: Path) -> list[CaptureArtifact]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is required for 2-2 UI evidence capture. "
            "Install dependencies and run `playwright install chromium`."
        ) from exc

    main_url = str(case.metadata.get("main_url") or case.metadata.get("ui_url") or "")
    if not main_url:
        raise RuntimeError("Frontend URL unavailable for 2-2 UI capture")

    artifacts: list[CaptureArtifact] = []
    with sync_playwright() as playwright:
        browser = _launch_browser(playwright)

        anon_context = browser.new_context(no_viewport=True, locale="ko-KR")
        auth_context = browser.new_context(no_viewport=True, locale="ko-KR")
        _authenticate_browser_context(auth_context, case)

        flow_main, feature_url = _resolve_ui_pages(case, main_url=main_url)
        if case.metadata.get("ui_route_source") == "network-discovery-fallback":
            discovered = _discover_related_page(auth_context, case)
            if case.metadata.get("ui_route_source") != "frontend-base-fallback":
                feature_url = discovered
            elif discovered and discovered != main_url:
                feature_url = discovered

        main_url = flow_main or main_url
        feature_url = feature_url or main_url
        prep_steps = list(case.metadata.get("prep_steps") or [])
        case.metadata["browser_session"] = "authenticated"

        probe_shots = list(PROBE_CAPTURES)
        if case.metadata.get("file_compare_detail"):
            probe_shots.append(PROBE_FILE_COMPARE_CAPTURE)

        for kind, filename in probe_shots:
            context = anon_context if kind == "main_site" else auth_context
            page = context.new_page()
            if kind == "ui_result":
                _route_attack_api(page, case)
            page.goto(
                _page_url_for_kind(kind, main_url=main_url, feature_url=feature_url),
                wait_until="domcontentloaded",
                timeout=20_000,
            )
            _settle_page(page)
            if kind in {"baseline_evidence", "attack_evidence", "ui_result"} and prep_steps:
                _run_ui_prep_steps(page, prep_steps)
            _apply_overlay(page, case, kind)
            path = output_dir / filename
            _shot_page(page, path)
            artifacts.append(CaptureArtifact(kind=kind, path=str(path)))
            page.close()

        anon_context.close()
        auth_context.close()
        browser.close()
    return artifacts


def _capture_unauth_case(case: EvidenceCase, output_dir: Path) -> list[CaptureArtifact]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is required for unauth-download UI capture. "
            "Install dependencies and run `playwright install chromium`."
        ) from exc

    artifacts: list[CaptureArtifact] = []
    with sync_playwright() as playwright:
        browser = _launch_browser(playwright)

        main_url = str(case.metadata.get("main_url") or case.metadata.get("ui_url") or "")
        if not main_url:
            browser.close()
            raise RuntimeError("Frontend URL unavailable for unauth-download UI capture")

        anon_context = browser.new_context(no_viewport=True, locale="ko-KR")
        flow_main, feature_url = _resolve_ui_pages(case, main_url=main_url)
        if case.metadata.get("ui_route_source") == "network-discovery-fallback":
            discovered = _discover_related_page(anon_context, case)
            if case.metadata.get("ui_route_source") != "frontend-base-fallback":
                feature_url = discovered
            elif discovered and discovered != main_url:
                feature_url = discovered

        main_url = flow_main or main_url
        feature_url = feature_url or main_url
        case.metadata["main_url"] = main_url
        case.metadata["main_display_url"] = main_url.replace("host.docker.internal", "localhost")
        case.metadata["feature_url"] = feature_url
        case.metadata["ui_url"] = feature_url
        case.metadata["ui_display_url"] = feature_url.replace("host.docker.internal", "localhost")
        case.metadata["browser_session"] = "anonymous"
        prep_steps = list(case.metadata.get("prep_steps") or [])

        shots = list(UNAUTH_CAPTURES)
        if case.metadata.get("file_compare_detail"):
            shots.append(FILE_COMPARE_CAPTURE)

        for kind, filename in shots:
            page = anon_context.new_page()
            if kind == "ui_result":
                _route_anon_api(page, case)
            page.goto(
                _page_url_for_kind(kind, main_url=main_url, feature_url=feature_url),
                wait_until="domcontentloaded",
                timeout=20_000,
            )
            _settle_page(page)
            if kind == "ui_result" and prep_steps:
                _run_ui_prep_steps(page, prep_steps)
            _apply_overlay(page, case, kind)
            path = output_dir / filename
            _shot_page(page, path)
            artifacts.append(CaptureArtifact(kind=kind, path=str(path)))
            page.close()

        anon_context.close()
        browser.close()
    return artifacts


def capture_case(case: EvidenceCase, output_dir: Path) -> list[CaptureArtifact]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for previous in output_dir.glob("*.png"):
        previous.unlink()

    if case.rule_id == "2-2-unauth-download":
        return _capture_unauth_case(case, output_dir)
    return _capture_probe_ui_case(case, output_dir)
