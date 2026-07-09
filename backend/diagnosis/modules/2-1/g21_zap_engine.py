"""
ARGUS 2-1 - Malicious File Upload ZAP Engine.

ZAP 플러그인 대신 ZAP을 HTTP 프록시로 활용하여
httpx 파일 업로드 요청을 ZAP을 통과시키고
passive / active 스캔 결과(파일 업로드 관련)를 수집합니다.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from zapv2 import ZAPv2

from g21_models import DetectionResult, InjectionType, VerificationStatus


# ZAP 파일 업로드 관련 플러그인 ID
# 90034: Reflected XSS via File Upload
# 10045: Source Code Disclosure (SVN/GIT)
# 40012: Cross Site Scripting (Reflected)
# 40014: Cross Site Scripting (Persistent)
# 10095: Backup File Disclosure
# 10104: User Agent Fuzzer (파일타입 우회 검증)
# 0: 직접 수집(httpx probe 결과를 ZAP 알림으로 변환)
FILE_UPLOAD_PLUGIN_IDS = {
    "90034",  # Reflected XSS via File Upload
    "40012",  # Cross Site Scripting (Reflected)
    "40014",  # Cross Site Scripting (Persistent)
    "40018",  # SQL Injection
    "10095",  # Backup File Disclosure
    "10045",  # Source Code Disclosure
    "10104",  # User Agent Fuzzer
    "90017",  # XML External Entity Attack
    "20019",  # External Redirect
}


class ZapEngine:
    """ZAP을 프록시로 활용하여 파일 업로드 취약점을 진단한다."""

    FILE_UPLOAD_PLUGIN_IDS = FILE_UPLOAD_PLUGIN_IDS

    def __init__(self, proxy_address: str = "127.0.0.1:8090", api_key: str = "argus_secret_key"):
        self.proxy_address = proxy_address
        self.api_key = api_key
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={"http": f"http://{proxy_address}", "https": f"http://{proxy_address}"},
        )
        self.policy_name = "Argus_FileUpload_Policy"

    def log(self, message: str) -> None:
        print(f"[ZAP-FileUpload] {message}")

    def _is_alive(self) -> bool:
        try:
            self.zap.core.version()
            return True
        except Exception:
            return False

    def _openapi_import(self, swagger_url: str, target_url: str) -> None:
        action = "importUrl" if swagger_url.startswith(("http://", "https://")) else "importFile"
        spec_key = "url" if action == "importUrl" else "file"
        spec_value = swagger_url if action == "importUrl" else os.path.abspath(swagger_url)
        endpoint = f"http://{self.proxy_address}/JSON/openapi/action/{action}/"
        params = {
            "apikey": self.api_key,
            spec_key: spec_value,
            "target": target_url,
        }
        for attempt in range(1, 3):
            try:
                session = requests.Session()
                session.trust_env = False
                response = session.get(endpoint, params=params, timeout=60)
                response.raise_for_status()
                payload = response.json()
                if payload.get("Result") == "OK":
                    return
                self.log(f"OpenAPI import response: {payload}")
                return
            except requests.RequestException as exc:
                self.log(f"OpenAPI import attempt {attempt}/2 failed: {exc}")
                time.sleep(2)

    def configure_scan(
        self,
        target_url: str,
        swagger_url: str = "",
        jwt_token: str = "",
        session_headers: Dict[str, str] | None = None,
    ) -> None:
        """파일 업로드 전용 스캔 정책 설정 및 인증 헤더 등록."""
        if not self._is_alive():
            raise RuntimeError("ZAP proxy is not reachable")

        self.log("File upload scan policy init...")
        try:
            self.zap.ascan.remove_scan_policy(scanpolicyname=self.policy_name)
        except Exception:
            pass

        # 파일 업로드 전용 스캔 정책 생성
        self.zap.ascan.add_scan_policy(
            scanpolicyname=self.policy_name,
            alertthreshold="LOW",
            attackstrength="HIGH",
        )
        self.zap.ascan.disable_all_scanners(scanpolicyname=self.policy_name)

        for pid in sorted(self.FILE_UPLOAD_PLUGIN_IDS):
            try:
                self.zap.ascan.enable_scanners(ids=pid, scanpolicyname=self.policy_name)
                self.zap.ascan.set_scanner_attack_strength(
                    id=pid, attackstrength="HIGH", scanpolicyname=self.policy_name
                )
                self.zap.ascan.set_scanner_alert_threshold(
                    id=pid, alertthreshold="LOW", scanpolicyname=self.policy_name
                )
            except Exception:
                pass

        # 기존 알림 초기화
        try:
            self.zap.core.delete_all_alerts()
            self.log("Cleared existing ZAP alerts.")
        except Exception:
            self.log("Could not clear alerts; continuing.")

        # 인증 헤더 등록 (Replacer)
        for desc in ("Auth_JWT_21", "Auth_Cookie_21"):
            try:
                self.zap.replacer.remove_rule(description=desc)
            except Exception:
                pass

        headers = session_headers or {}
        cookie_val = headers.get("Cookie") or headers.get("cookie")
        if cookie_val:
            self.log("Registering Cookie with ZAP Replacer.")
            self.zap.replacer.add_rule(
                description="Auth_Cookie_21",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=str(cookie_val),
            )
        if jwt_token:
            self.log("Registering JWT with ZAP Replacer.")
            auth_value = jwt_token if jwt_token.lower().startswith("bearer") else f"Bearer {jwt_token}"
            self.zap.replacer.add_rule(
                description="Auth_JWT_21",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Authorization",
                replacement=auth_value,
            )

        if swagger_url:
            self.log(f"Importing OpenAPI spec: {swagger_url}")
            try:
                self._openapi_import(swagger_url, target_url)
                time.sleep(2)
            except Exception as exc:
                self.log(f"OpenAPI import failed (non-fatal): {exc}")

    def run_active_scan(
        self,
        target_url: str,
        *,
        max_minutes: int = 15,
        progress_cb=None,
    ) -> List[DetectionResult]:
        """파일 업로드 엔드포인트 대상 ZAP 액티브 스캔 실행."""
        self.log(f"Active Scan (File Upload) start: {target_url}")
        scan_id = self.zap.ascan.scan(url=target_url, recurse=True, scanpolicyname=self.policy_name)
        self.log(f"Active Scan id: {scan_id}")

        deadline = time.time() + max(1, max_minutes) * 60
        last_status = -1
        unavailable_reads = 0

        while True:
            raw_status = self.zap.ascan.status(scan_id)
            try:
                status = int(raw_status)
            except (TypeError, ValueError):
                unavailable_reads += 1
                self.log(f"Scan status unavailable: {raw_status}")
                if unavailable_reads >= 5:
                    self.log("Status stayed unavailable; proceeding with collected alerts.")
                    break
                time.sleep(2)
                continue
            unavailable_reads = 0

            if status != last_status and progress_cb:
                progress_cb(status, target_url)
                last_status = status
            if status >= 100:
                break
            if time.time() >= deadline:
                self.log(f"Scan deadline ({max_minutes}m) reached.")
                break
            time.sleep(2)

        if progress_cb:
            progress_cb(100, target_url)
        self.log("Active Scan complete. Collecting results.")
        return self._collect_results(target_url)

    def collect_passive_results(self, target_url: str) -> List[DetectionResult]:
        """ZAP passive scan 결과만 수집 (액티브 스캔 없이)."""
        self.log(f"Collecting passive scan results for: {target_url}")
        return self._collect_results(target_url, passive_only=True)

    def _parse_request_header(self, request_header: str, fallback_url: str) -> Tuple[str, Dict[str, str]]:
        raw_request_url = fallback_url
        headers: Dict[str, str] = {}
        if not request_header:
            return raw_request_url, headers

        lines = request_header.split("\n")
        if lines:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                raw_request_url = parts[1]

        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.lower() in {"host", "content-length"}:
                continue
            headers[key.strip()] = value.strip()
        return raw_request_url, headers

    def _absolute_request_url(self, request_url: str, alert_url: str) -> str:
        if request_url.startswith("http://") or request_url.startswith("https://"):
            return request_url
        parsed = urlparse(alert_url)
        if request_url.startswith("/"):
            return f"{parsed.scheme}://{parsed.netloc}{request_url}"
        return alert_url

    def _collect_results(
        self,
        target_url: str,
        *,
        passive_only: bool = False,
    ) -> List[DetectionResult]:
        """ZAP alerts 에서 파일 업로드 관련 항목만 추출."""
        try:
            alerts = self.zap.core.alerts(baseurl=target_url)
        except Exception as exc:
            self.log(f"Failed to collect alerts: {exc}")
            return []

        results: List[DetectionResult] = []
        seen: set = set()

        for alert in alerts:
            plugin_id = str(alert.get("pluginId", ""))
            # 파일 업로드 관련 플러그인만 수집
            if plugin_id not in self.FILE_UPLOAD_PLUGIN_IDS:
                continue
            risk = alert.get("risk", "")
            if risk not in ("High", "Medium"):
                continue

            method = alert.get("method", "GET")
            url = alert.get("url", "")
            param = alert.get("param", "")
            attack = alert.get("attack", "")
            message_id = alert.get("messageId", "")
            raw_request_body = ""
            raw_request_url = url
            raw_request_headers: Dict[str, str] = {}

            if message_id:
                try:
                    msg = self.zap.core.message(message_id)
                    raw_request_body = msg.get("requestBody", "")
                    parsed_url, parsed_headers = self._parse_request_header(
                        msg.get("requestHeader", ""), url
                    )
                    raw_request_url = self._absolute_request_url(parsed_url, url)
                    raw_request_headers = parsed_headers
                except Exception as exc:
                    self.log(f"Failed to collect message {message_id}: {exc}")

            # multipart 요청이 아닌 경우 파일 업로드와 무관 → 스킵
            content_type = raw_request_headers.get("Content-Type", "")
            if not passive_only and "multipart" not in content_type.lower():
                # passive_only 모드에서는 필터 없이 수집
                pass

            dedupe_key = (plugin_id, method, url, param, attack)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            results.append(
                DetectionResult(
                    method=method,
                    url=url,
                    param=param,
                    risk=risk.upper(),
                    plugin_id=plugin_id,
                    plugin_name=alert.get("alert", "File Upload Issue"),
                    injection_type=InjectionType.GENERIC,
                    has_zap=True,
                    zap_payload=attack,
                    verification_status=VerificationStatus.SUSPECTED,
                    evidence=alert.get("evidence", ""),
                    description=alert.get("description", ""),
                    solution=alert.get("solution", ""),
                    raw_request_body=raw_request_body,
                    raw_request_url=raw_request_url,
                    raw_request_headers=raw_request_headers,
                )
            )

        self.log(f"Collected {len(results)} file-upload-related ZAP alerts.")
        return results
