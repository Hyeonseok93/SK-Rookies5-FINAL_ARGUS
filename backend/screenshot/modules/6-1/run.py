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
    # 로그인이 필요한 대상: 스캐너가 이미 쓴 계정(data/test-accounts.json)을 그대로 재사용
    python screenshot/modules/6-1/run.py --auth-method config
    python screenshot/modules/6-1/run.py --auth-method config --auth-account admin@travel.com
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
        help="report의 host.docker.internal 주소를 치환할 실제 접속 가능한 주소 (기본: http://192.168.0.55)",
    )

    # 인증 옵션 (선택 입력) — 로그인 후에만 볼 수 있는 대상을 캡처할 때 사용.
    # "config"(권장)는 report를 만든 6-1 스캐너가 이미 쓴 계정/로그인 설정
    # (data/test-accounts.json, data/login-endpoints.json, config.yaml의 auth: 블록)을
    # 그대로 재사용하므로 --login-url/--test-id/--test-pw를 다시 줄 필요가 없다.
    parser.add_argument("--auth-method", choices=["config", "api", "form"], default=None)
    parser.add_argument("--auth-account", help="method=config일 때 사용할 계정 이메일 (생략 시 첫 로그인 성공 계정)")
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
    if args.auth_method == "config":
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
        auth_config=auth_config,
    )
    print(json.dumps({"count": len(results), "captures": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
