#!/usr/bin/env python3
"""CLI: capture report-driven REAL screenshots for guideline 6-1.

GET findings are captured by opening a real, visible Chrome window and
grabbing the actual OS-level window (address bar included) — this needs an
accessible display and will not work in headless Docker/CI. POST/PUT/PATCH/
DELETE findings are captured by making a genuine live request (same method +
Content-Type the scanner used) and rendering the real response plainly.

Usage:
    python screenshot/modules/6-1/run.py
    python screenshot/modules/6-1/run.py --severities high,medium --max-per-group 2
    python screenshot/modules/6-1/run.py --base-url http://192.168.0.55
    # 아무 인증 옵션도 안 주면 report(latest.yaml)에서 스캐너가 실제로 쓴 계정을
    # 자동으로 읽어 그 계정으로 로그인한다. 다른 계정을 쓰거나 로그인을 끄려면:
    python screenshot/modules/6-1/run.py --auth-account admin@travel.com
    python screenshot/modules/6-1/run.py --no-auth
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

_MODULE_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _MODULE_DIR.parents[2]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))


def _load_capture_module():
    spec = importlib.util.spec_from_file_location("screenshot_module_6_1_capture", _MODULE_DIR / "capture.py")
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load screenshot/modules/6-1/capture.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclass() needs cls.__module__ resolvable in sys.modules
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    # Windows 콘솔은 로케일에 따라 stdout이 cp949 등 non-UTF-8로 열려 있어, 결과 JSON 안의
    # 한글/특수문자(em dash 등)를 만나면 UnicodeEncodeError로 죽는다 — 캡처 자체는 이미 끝난
    # 뒤인데 마지막 출력에서만 실패하는 걸 막기 위해 stdout을 UTF-8로 강제한다.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(description="ARGUS 6-1 report-driven REAL screenshot capture")
    parser.add_argument("--report", type=Path, help="6-1 report yaml (default: data/report/6-1/latest.yaml)")
    parser.add_argument("--data-dir", type=Path, help="data dir root (default: backend/data)")
    parser.add_argument("--output-dir", type=Path, help="output dir (default: data/report/6-1/evidence/webcapture)")
    parser.add_argument("--severities", help="comma-separated severities to include, e.g. high,medium")
    parser.add_argument("--max-per-group", type=int, default=3, help="captures per rule group (default: 3)")
    parser.add_argument(
        "--base-url",
        help="report의 host.docker.internal 주소를 치환할 실제 접속 가능한 API 서버 주소 (기본: http://192.168.0.55)",
    )
    parser.add_argument(
        "--frontend-url",
        help="STEP1(공격 전 홈 화면)/STEP2(non-GET 대기 화면)에 띄울 실제 프론트엔드 주소 "
        "(생략 시 --base-url과 동일 — API 서버와 프론트가 다른 포트일 때 지정, 예: http://localhost:5173)",
    )

    # 인증 옵션 — 아무것도 지정하지 않으면 report(latest.yaml)에 남은
    # "authenticated:<email>:login" 표기에서 스캐너가 실제로 쓴 계정 이메일을 자동으로
    # 읽어 그 계정으로 로그인한다(data/test-accounts.json + data/login-endpoints.json +
    # config.yaml의 auth: 블록 재사용, method="config"와 동일). 다른 계정/방식을 쓰려면
    # 아래 옵션으로 직접 지정하고, 로그인 자체를 끄려면 --no-auth를 준다.
    parser.add_argument("--auth-method", choices=["config", "api", "form"], default=None)
    parser.add_argument("--auth-account", help="method=config일 때 사용할 계정 이메일 (생략 시 report에서 자동 감지)")
    parser.add_argument("--no-auth", action="store_true", help="로그인 자동 감지를 끄고 비로그인 상태로 캡처")
    parser.add_argument("--login-url", help="method=api/form일 때 필요")
    parser.add_argument("--id-field", default="username")
    parser.add_argument("--pw-field", default="password")
    parser.add_argument("--test-id", help="method=api/form일 때 필요")
    parser.add_argument("--test-pw", help="method=api/form일 때 필요")
    parser.add_argument("--token-json-key", default="accessToken")

    args = parser.parse_args()

    capture = _load_capture_module()
    severities = {s.strip().lower() for s in args.severities.split(",") if s.strip()} if args.severities else None

    auth_config = None
    if args.no_auth:
        auth_config = {"enabled": False}
    elif args.auth_method == "config" or (args.auth_method is None and args.auth_account):
        auth_config = {"enabled": True, "method": "config", "account_email": args.auth_account}
    elif args.auth_method:
        auth_config = {
            "enabled": True,
            "method": args.auth_method,
            "login_url": args.login_url,
            "id_field": args.id_field,
            "pw_field": args.pw_field,
            "test_id": args.test_id,
            "test_pw": args.test_pw,
            "token_json_key": args.token_json_key,
        }

    results = capture.run_capture(
        report_path=args.report,
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        severities=severities,
        max_per_group=args.max_per_group,
        public_base_url=args.base_url,
        frontend_base_url=args.frontend_url,
        auth_config=auth_config,
    )
    print(json.dumps({"count": len(results), "captures": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
