#!/usr/bin/env python3
"""
엔드포인트 정의서(Markdown 테이블)에서 HTTP Method + API URL 추출.

사용:
  python parse_endpoints.py --input ../2단계...md --output ./generated/urls.txt
  python parse_endpoints.py --input ../2단계...md --filter download,export --json ./generated/seeds.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROW_RE = re.compile(
    r"^\|\s*`(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)`\s*\|\s*"
    r"`(?P<url>[^`]+)`\s*\|",
    re.IGNORECASE,
)

FRONT_ROW_RE = re.compile(
    r"^\|\s*`(?P<url>/[^`]+)`\s*\|",
)


def parse_markdown_tables(text: str) -> list[dict]:
    endpoints: list[dict] = []
    for line in text.splitlines():
        m = ROW_RE.match(line.strip())
        if m:
            endpoints.append(
                {"method": m.group("method").upper(), "url": m.group("url").strip(), "kind": "api"}
            )
            continue
        fm = FRONT_ROW_RE.match(line.strip())
        if fm:
            endpoints.append({"method": "GET", "url": fm.group("url").strip(), "kind": "frontend"})
    return endpoints


def to_frontend_seeds(endpoints: list[dict], frontend_base: str) -> list[dict]:
    base = frontend_base.rstrip("/")
    seeds: list[dict] = []
    for ep in endpoints:
        if ep.get("kind") != "frontend":
            continue
        path = ep["url"]
        if not path.startswith("/"):
            path = "/" + path
        seeds.append(
            {
                "name": f"fe-{path.strip('/').replace('/', '-') or 'root'}",
                "method": "GET",
                "url": f"{base}{path}",
            }
        )
    return seeds


def filter_by_keywords(items: list[dict], keywords: list[str]) -> list[dict]:
    if not keywords:
        return items
    lowered = [k.lower() for k in keywords]
    return [e for e in items if any(k in e["url"].lower() for k in lowered)]


PATH_PARAM_RE = re.compile(r"\{[a-zA-Z0-9_]+\}")

DEFAULT_PATH_PARAMS: dict[str, str] = {
    "id": "1",
    "scheduleId": "1",
    "bookingId": "1",
    "policyId": "1",
    "paymentId": "1",
    "commentId": "1",
    "postId": "1",
    "roomId": "1",
    "settlementId": "1",
    "reservationId": "1",
    "requestId": "1",
    "booking_code": "TEST001",
}


def materialize_path_params(path: str, defaults: dict[str, str] | None = None) -> str:
    """Replace {param} placeholders with concrete values for ZAP requestor URLs."""
    params = defaults or DEFAULT_PATH_PARAMS

    def replace(match: re.Match[str]) -> str:
        key = match.group(0)[1:-1]
        return params.get(key, "1")

    return PATH_PARAM_RE.sub(replace, path)


def to_requestor_seeds(
    endpoints: list[dict],
    base_urls: list[str],
    name_prefix: str = "ep",
    materialize_params: bool = True,
    path_param_defaults: dict[str, str] | None = None,
) -> list[dict]:
    seeds: list[dict] = []
    for base in base_urls:
        base = base.rstrip("/")
        for i, ep in enumerate(endpoints):
            path = ep["url"]
            if not path.startswith("/"):
                path = "/" + path
            if materialize_params and "{" in path:
                path = materialize_path_params(path, path_param_defaults)
            seeds.append(
                {
                    "name": f"{name_prefix}-{i}-{ep['method']}",
                    "method": ep["method"],
                    "url": f"{base}{path}",
                }
            )
    return seeds


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse endpoint MD → URL list")
    parser.add_argument("--input", "-i", required=True, help="Markdown file path")
    parser.add_argument("--output", "-o", help="Plain URL list (one per line)")
    parser.add_argument("--json", help="Requestor seeds JSON output")
    parser.add_argument(
        "--base-url",
        action="append",
        default=[],
        help="Base URL prefix (repeatable). Example: http://localhost:8080",
    )
    parser.add_argument(
        "--filter",
        help="Comma-separated keywords (download,file,export,...)",
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")
    endpoints = parse_markdown_tables(text)

    if args.filter:
        keywords = [k.strip() for k in args.filter.split(",") if k.strip()]
        endpoints = filter_by_keywords(endpoints, keywords)

    print(f"Parsed {len(endpoints)} endpoint(s)")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if args.base_url:
            for seed in to_requestor_seeds(endpoints, args.base_url):
                lines.append(seed["url"])
        else:
            lines = [e["url"] for e in endpoints]
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote {out}")

    if args.json:
        if not args.base_url:
            print("--json requires at least one --base-url", file=sys.stderr)
            return 1
        seeds = to_requestor_seeds(endpoints, args.base_url)
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(seeds, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
