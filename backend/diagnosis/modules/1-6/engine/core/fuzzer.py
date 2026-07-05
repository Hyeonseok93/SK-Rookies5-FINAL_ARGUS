# =============================================================================
# core/fuzzer.py  -  ARGUS W-1-6 fuzzer v6.1
#
# 변경사항 (v4→v5):
#   - ThreadPoolExecutor 기반 병렬 실행 (워커 5개)
#   - findings thread-safe lock 추가
#   - 나머지 로직 전부 기존 v4 유지
#
# 변경사항 (v5→v6):
#   - threading.local()로 스레드별 독립 세션 캐시 (공유 세션 race condition 해결)
#   - _run_payload_set: session 사전 생성 제거 → _do_request 내부에서 발급
#   - _do_request: JWT 동기화 블록 제거 (→ _get_session 내부로 이동)
#   - _get_session: thread-local 세션 + 매 호출마다 토큰 동기화
# =============================================================================

import os
import gc
import json
import logging
import re
import threading
import time
import copy
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse
import requests
import uuid

from config import Config
from payloads.sk_shielders.payload_generator import SKPayloadGenerator
from payloads.kisa.payload_generator import KISAPayloadGenerator
from payloads.cwe.payload_generator import CWEPayloadGenerator
from payloads.owasp.payload_generator import OWASPPayloadGenerator
from core.false_positive_rules import is_suppressed_leak

logger = logging.getLogger(__name__)
FUZZER_VERSION = "v6.1"


class MassiveDataFuzzer:
    """
    ARGUS W-1-6 large-input fuzzer v6.1.

    SK Shielders와 KISA 페이로드를 각각 독립적으로 실행하고
    결과에 source 태그를 붙여 구분합니다.
    ThreadPoolExecutor 기반 병렬 실행.
    """

    def __init__(self, cfg: Config, role_manager=None, zap_engine=None):
        self.cfg = cfg
        self.role_manager = role_manager
        self.zap_engine = zap_engine
        self.findings: list = []
        self.sk_pg = SKPayloadGenerator()
        self.kisa_pg  = KISAPayloadGenerator()
        self.cwe_pg   = CWEPayloadGenerator()
        self.owasp_pg = OWASPPayloadGenerator()
        self._auth_error_counts: dict = {}
        self._findings_lock = threading.Lock()          # findings append 보호
        self._auth_lock     = threading.Lock()          # refresh_token 호출 보호 (드문 이벤트)
        self._thread_local  = threading.local()         # 스레드별 독립 세션 저장소
        # 토큰 문자열 캐시 — 읽기는 GIL로 원자적, 쓰기는 _auth_lock 하에서만
        self._current_tokens: dict = {}
        self._last_refresh_time: dict = {}              # 토큰 중복 갱신 방지용 타임스탬프
        self._request_count = 0
        self._request_lock = threading.Lock()
        self._endpoint_failures: dict = {}
        self._endpoint_blocked_until: dict = {}
        self._stop_event = threading.Event()
        # baseline(정상값) 검증 캐시 — key: (role, method, path_shape)
        # value: {"ok": bool, "status_code", "elapsed_sec", "body_snippet",
        #         "response_size", "verified": bool}
        # verified=False 는 "실제로 baseline 요청을 쏘지 않고 통과시켰다"는 뜻
        # (mutating method 부작용 방지, 아래 _baseline_ok 참고)
        self._baseline_cache: dict = {}
        self._baseline_lock = threading.Lock()
        self._request_templates = self._load_request_templates()
        # 초기 토큰 로드
        if role_manager:
            try:
                for r in role_manager.get_all_roles():
                    base = role_manager.get_session(r)
                    if base and "Authorization" in base.headers:
                        self._current_tokens[r] = base.headers["Authorization"]
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # ZAP 캡처 요청 템플릿 로딩 + "경로 모양(shape)" 정규화
    #
    # 문제였던 것: ZAP이 실제로 캡처한 경로는 사람이 클릭한 실제 값을 담고
    # 있음 (/api/users/57). 퍼저가 attack 요청을 만들 때는 스키마 샘플값을
    # 넣음 (/api/users/1). 두 문자열을 그대로 비교하면 절대 안 맞아서,
    # 파라미터가 있는 엔드포인트에서는 템플릿이 100% 매칭 실패했었다.
    # → 숫자/UUID/ObjectId처럼 "값처럼 보이는" 경로 세그먼트와 swagger의
    #   {param} 표기를 전부 동일한 '*' 로 정규화한 뒤 그 모양으로 매칭한다.
    # -------------------------------------------------------------------------
    _ID_SEGMENT_RE = re.compile(
        r'^\d+$'                      # 순수 숫자 ID
        r'|^[0-9a-fA-F-]{8,}$'        # UUID / hex 계열
        r'|^[0-9a-fA-F]{24}$'         # Mongo ObjectId
    )

    def _path_shape(self, url_or_path: str) -> str:
        text = str(url_or_path or "")
        if text.startswith("http://") or text.startswith("https://"):
            text = urlparse(text).path or "/"
        text = text.split("?", 1)[0] or "/"
        text = re.sub(r'\{[^/]+\}', '*', text)          # swagger {id} → *
        segments = text.split('/')
        normalized = ['*' if seg and self._ID_SEGMENT_RE.match(seg) else seg
                      for seg in segments]
        return '/'.join(normalized)

    def _load_request_templates(self) -> dict:
        path = getattr(self.cfg, "REQUEST_TEMPLATES", "") or ""
        if not path or not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            logger.warning(f"[Fuzzer] request template load failed: {e}")
            return {}

        templates = raw.get("templates", raw if isinstance(raw, list) else [])
        indexed = {}
        for item in templates:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or "GET").lower()
            shape = self._path_shape(item.get("path") or item.get("url") or "")
            if shape:
                # 같은 shape가 여러 개면 가장 최근 것으로 덮어씀 (ZAP history는
                # 시간순으로 오므로 마지막 것이 보통 더 최신 세션 값)
                indexed[(method, shape)] = item
        logger.info(f"[Fuzzer] request templates loaded: {len(indexed)} (path-shape 매칭 기준)")
        return indexed

    def _template_for(self, url: str, method: str) -> dict:
        return self._request_templates.get(
            (str(method or "get").lower(), self._path_shape(url)), {}
        )

    def _template_query(self, url: str, method: str) -> dict:
        query = self._template_for(url, method).get("query")
        return dict(query) if isinstance(query, dict) else {}

    def _template_body(self, url: str, method: str):
        body = self._template_for(url, method).get("body")
        if isinstance(body, (dict, list)):
            return copy.deepcopy(body)
        return None

    def _method_supports_body(self, method: str) -> bool:
        return str(method or "get").lower() not in ("get", "delete", "head", "options")

    def _request_snapshot(self, url: str, method: str, headers: dict = None,
                          query_params: dict = None, json_body=None, raw_data: bytes = None) -> dict:
        snapshot = {
            "method": str(method or "get").upper(),
            "url": url,
            "headers": dict(headers or {}),
        }
        if query_params:
            snapshot["query"] = copy.deepcopy(query_params)
        if json_body is not None:
            snapshot["json"] = copy.deepcopy(json_body)
        elif raw_data is not None:
            snapshot["body_text"] = raw_data[:4000].decode("utf-8", errors="replace")
        return snapshot

    # -------------------------------------------------------------------------
    # Baseline(정상값) 검증
    #
    # 판단 기준 (v6.2, 통일됨):
    #   - ZAP 템플릿 수집 시 "유효한 응답"으로 인정하는 기준과 동일하게
    #     200 <= status < 400 만 baseline_valid=True. (기존엔 fuzzer가
    #     status<500이면 통과시켜서, 401/403/404처럼 애초에 정상값 자체가
    #     틀린 경우도 "정상"으로 오인하고 그 위에 공격 payload를 쌓는
    #     문제가 있었음 — 여기서 그 불일치를 없앰)
    #   - GET/HEAD/OPTIONS 등 상태를 바꾸지 않는 메소드만 실제로 probe
    #     요청을 쏜다. POST/PUT/PATCH/DELETE 같은 mutating 메소드는
    #     "검증용으로 실제 데이터를 하나 더 만들어내는" 부작용이 있으므로,
    #     ZAP 템플릿(사람이 실제로 성공시킨 트랜잭션)이 있을 때만 그 값을
    #     신뢰하고, 템플릿이 없으면 probe를 쏘지 않고 baseline_valid=False,
    #     verified=False로 표시한 채 그대로 진행한다.
    #     → 이 남은 케이스가 여전히 malformed-seed 문제에 노출돼 있다는
    #       뜻이며, 아래 답변의 "남은 한계"에서 그대로 설명한다.
    # -------------------------------------------------------------------------
    def _baseline_ok(self, url: str, method: str, session: requests.Session, role: str,
                     params_schema: dict = None, body_schema: dict = None) -> bool:
        method_name = str(method or "get").lower()
        key = (role, method_name, self._path_shape(url))
        with self._baseline_lock:
            cached = self._baseline_cache.get(key)
        if cached is not None:
            return cached["ok"]

        has_template = bool(self._template_for(url, method_name))
        is_idempotent = method_name in ("get", "head", "options")

        if not is_idempotent and not has_template:
            # mutating + 검증 근거(템플릿) 없음 → 실측 안 하고 "미검증"으로 표시,
            # 차단은 하지 않음 (커버리지 유지, 대신 정확도 저하는 finding 쪽에 남김)
            result = {"ok": True, "verified": False, "status_code": None,
                      "elapsed_sec": None, "body_snippet": "", "response_size": None}
            with self._baseline_lock:
                self._baseline_cache[key] = result
            return True

        template_query = self._template_query(url, method_name)
        kwargs = {
            "query_params": template_query or self._normal_query(params_schema or {}),
            "payload_name": "__baseline__",
            "session": session,
            "role": role,
            "source": "baseline",
            "record_finding": False,
            "write_progress": False,
            "return_response": True,
        }
        normal_body = self._template_body(url, method_name)
        if normal_body is None:
            normal_body = self._normal_body(body_schema or {})
        if normal_body is not None and self._method_supports_body(method_name):
            kwargs["json_body"] = normal_body

        resp = self._do_request(url, method_name, **kwargs)
        status = int(getattr(resp, "status_code", 0)) if resp is not None else 0
        ok = bool(resp is not None and self.cfg.BASELINE_VALID_STATUS_MIN <= status < self.cfg.BASELINE_VALID_STATUS_MAX)
        result = {
            "ok": ok,
            "verified": True,
            "status_code": status,
            "elapsed_sec": getattr(resp, "elapsed", None).total_seconds() if resp is not None and getattr(resp, "elapsed", None) else None,
            "body_snippet": (resp.text[:500] if resp is not None else ""),
            "response_size": len(resp.content) if resp is not None else None,
        }
        with self._baseline_lock:
            self._baseline_cache[key] = result
        return ok

    def _baseline_snapshot(self, url: str, method: str, role: str) -> dict:
        """finding에 실어 collector.py가 diff 판정에 쓸 수 있게 baseline 정보를 반환."""
        key = (role, str(method or "get").lower(), self._path_shape(url))
        with self._baseline_lock:
            return dict(self._baseline_cache.get(key) or {})

    def _sample_value(self, field_name: str = "", field_type: str = "string"):
        name = str(field_name or "").lower()
        ftype = str(field_type or "string").lower()
        if "email" in name:
            return "test@example.com"
        if "date" in name and "time" not in name:
            return "2026-07-03"
        if "time" in name:
            return "2026-07-03T00:00:00"
        if "phone" in name or "tel" in name:
            return "01012345678"
        if "url" in name or "uri" in name:
            return "http://localhost"
        if "id" in name or ftype in ("integer", "int", "long"):
            return 1
        if ftype in ("number", "float", "double"):
            return 1.0
        if ftype == "boolean":
            return True
        if ftype == "array":
            return ["test"]
        if ftype == "object":
            return {}
        return "test"

    def _normal_query(self, params_schema: dict) -> dict:
        query_params = (params_schema or {}).get("query", {})
        return {name: self._sample_value(name, ftype) for name, ftype in query_params.items()}

    def _normal_body(self, body_schema: dict):
        if not body_schema:
            return None
        return {name: self._sample_value(name, ftype) for name, ftype in body_schema.items()}

    def _normal_path(self, path: str, params_schema: dict) -> str:
        path_params = (params_schema or {}).get("path", {})
        normalized = path
        for name in re.findall(r'\{(\w+)\}', path):
            normalized = normalized.replace(f"{{{name}}}", str(self._sample_value(name, path_params.get(name, "string"))))
        return normalized

    # -------------------------------------------------------------------------
    # 메인 실행
    # -------------------------------------------------------------------------
    def run_all(self, target: str, fuzz_targets: list) -> list:
        """
        SK Shielders + KISA 페이로드를 순서대로 실행합니다.

        Args:
            target:       대상 베이스 URL
            fuzz_targets: SwaggerParser.get_fuzz_targets() 반환값

        Returns:
            발견된 취약점 딕셔너리 목록 (source 필드로 SK/KISA 구분)
        """
        roles = self.role_manager.get_all_roles() if self.role_manager else ["anonymous"]
        logger.info(f"[Fuzzer {FUZZER_VERSION}] start - roles: {roles}, endpoints: {len(fuzz_targets)}")

        logger.info("=" * 60)
        logger.info(f"[Fuzzer {FUZZER_VERSION}] KISA payloads start")
        logger.info("=" * 60)
        self._run_payload_set(target, fuzz_targets, roles,
                              self.kisa_pg.get_all_payloads(), "kisa")
        if self._stop_event.is_set():
            logger.warning(f"[Fuzzer {FUZZER_VERSION}] safety stop triggered; skipping remaining payload sets.")
            return self.findings

        logger.info("=" * 60)
        logger.info(f"[Fuzzer {FUZZER_VERSION}] SK Shielders payloads start")
        logger.info("=" * 60)
        self._run_payload_set(target, fuzz_targets, roles,
                              self.sk_pg.get_all_payloads(), "sk_shielders")
        if self._stop_event.is_set():
            logger.warning(f"[Fuzzer {FUZZER_VERSION}] safety stop triggered; skipping remaining payload sets.")
            return self.findings

        logger.info("=" * 60)
        logger.info(f"[Fuzzer {FUZZER_VERSION}] CWE v4.20 payloads start")
        logger.info("=" * 60)
        self._run_payload_set(target, fuzz_targets, roles,
                              self.cwe_pg.get_all_payloads(), "cwe")
        if self._stop_event.is_set():
            logger.warning(f"[Fuzzer {FUZZER_VERSION}] safety stop triggered; skipping remaining payload sets.")
            return self.findings

        logger.info("=" * 60)
        logger.info(f"[Fuzzer {FUZZER_VERSION}] OWASP Top 10 2021 payloads start")
        logger.info("=" * 60)
        self._run_payload_set(target, fuzz_targets, roles,
                              self.owasp_pg.get_all_payloads(), "owasp")

        logger.info(f"[Fuzzer {FUZZER_VERSION}] complete - total findings: {len(self.findings)}")
        return self.findings

    # -------------------------------------------------------------------------
    # ← CHANGED: ThreadPoolExecutor 기반 병렬 실행 + 진행도 이어하기(Task Resume)
    # -------------------------------------------------------------------------
    def _run_payload_set(self, target: str, fuzz_targets: list,
                         roles: list, payloads: list, source_tag: str):
        """
        단일 페이로드 셋을 ThreadPoolExecutor(5 workers)로 병렬 실행.
        Task Resume 시스템을 활용해 이미 검사 완료된 항목은 스킵합니다.
        """
        # 완료된 작업 기록 로드
        progress_path = os.path.join(self.cfg.OUTPUT_DIR, "temp_progress.txt")
        findings_path = os.path.join(self.cfg.OUTPUT_DIR, "temp_findings.jsonl")
        completed_keys = set()
        
        # 1) temp_progress.txt (성공/실패 여부 관계없이 완수한 전체 이력) 로드
        if os.path.exists(progress_path):
            try:
                with open(progress_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            completed_keys.add(line.strip())
            except Exception as e:
                logger.error(f"[Fuzzer] 진행률 복구 실패: {e}")
                
        # 2) temp_findings.jsonl (이전 세션에서 검출했던 취약점 이력) 로드 및 역매핑
        if os.path.exists(findings_path):
            try:
                with open(findings_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            finding = json.loads(line)
                            f_role = finding.get("role", "")
                            f_pname = finding.get("payload_name", "")
                            f_source = finding.get("source", "")
                            f_url = finding.get("url", "")
                            
                            # url에서 path 유추 (http://localhost:8080/api/v1/xxx -> /api/v1/xxx)
                            f_path = ""
                            if "http://" in f_url or "https://" in f_url:
                                parts = f_url.split("/", 3)
                                if len(parts) >= 4:
                                    f_path = "/" + parts[3].split("?")[0]
                                    
                            # path_traversal의 경우 URL 경로 파라미터가 뭉개져 있으므로, 
                            # '/etc/passwd'나 '..'가 들어간 경로에서 API 원본 path를 역매핑 시도
                            if ".." in f_path:
                                # fuzzer 내 스킵 편의상 /api/v1/seller/flights/calendar/../../../etc/passwd -> /api/v1/seller/flights/calendar 로 복원
                                f_path = f_path.split("/..")[0]
                                    
                            # GET/POST 등의 메소드는 findings에 없으므로, 해당 조합의 GET과 POST를 둘 다 스킵 맵에 추가
                            if f_role and f_path and f_pname and f_source:
                                completed_keys.add(f"{f_role}|get|{f_path}|{f_pname}|{f_source}")
                                completed_keys.add(f"{f_role}|post|{f_path}|{f_pname}|{f_source}")
                                completed_keys.add(f"{f_role}|put|{f_path}|{f_pname}|{f_source}")
                                completed_keys.add(f"{f_role}|delete|{f_path}|{f_pname}|{f_source}")
            except Exception as e:
                logger.error(f"[Fuzzer] 취약점 이력 기반 스킵 맵 생성 실패: {e}")

        chunks = [payloads[i: i + self.cfg.CHUNK_SIZE]
                  for i in range(0, len(payloads), self.cfg.CHUNK_SIZE)]

        # 전체 작업 목록 수집
        tasks = []
        skipped_count = 0
        limited_count = 0
        per_endpoint_counts = {}
        scheduling_limit_hit = False
        max_total_requests = max(0, int(getattr(self.cfg, "MAX_TOTAL_REQUESTS", 0)))
        max_per_endpoint = max(0, int(getattr(self.cfg, "MAX_REQUESTS_PER_ENDPOINT", 0)))
        with self._request_lock:
            remaining_total = (
                max_total_requests - self._request_count
                if max_total_requests > 0 else None
            )
        if remaining_total is not None and remaining_total <= 0:
            logger.warning(f"[{source_tag}] global request limit reached; skipping payload set.")
            self._stop_event.set()
            return
        
        for role in roles:
            for target_info in fuzz_targets:
                if scheduling_limit_hit:
                    break
                path          = target_info["path"]
                method        = target_info.get("method", "post")
                body_schema   = target_info.get("body_schema", {})
                params_schema = target_info.get("params", {})
                path_params   = target_info.get("path_params", [])

                if not target_info.get("requires_auth", True) and role != roles[0]:
                    continue

                # target_info에 base_url이 있으면 그걸 우선 사용
                # (admin 전용 스펙처럼 endpoint마다 서버가 다른 경우 지원).
                # 없으면 기존처럼 run_all()에 넘어온 전역 target을 그대로 씀.
                endpoint_base = target_info.get("base_url") or target
                base_url = f"{endpoint_base.rstrip('/')}{path}"

                for chunk in chunks:
                    if scheduling_limit_hit:
                        break
                    for payload in chunk:
                        if remaining_total is not None and len(tasks) >= remaining_total:
                            scheduling_limit_hit = True
                            break
                        p_name = payload.get("name", "")
                        # 고유 태스크 키 생성
                        task_key = f"{role}|{method}|{path}|{p_name}|{source_tag}"
                        
                        if task_key in completed_keys:
                            skipped_count += 1
                            continue

                        endpoint_key = f"{role}|{method}|{path}|{source_tag}"
                        if max_per_endpoint > 0:
                            endpoint_count = per_endpoint_counts.get(endpoint_key, 0)
                            if endpoint_count >= max_per_endpoint:
                                limited_count += 1
                                continue
                            per_endpoint_counts[endpoint_key] = endpoint_count + 1
                            
                        tasks.append((
                            base_url, path, method, body_schema,
                            params_schema, path_params,
                            payload, None, role, endpoint_base, task_key   # endpoint_base 전파 (base_target 파라미터로 들어감)
                        ))

        if skipped_count > 0:
            logger.info(f"[{source_tag}] 이어하기 활성화 ─ 이미 완료된 {skipped_count}개 작업을 스킵했습니다.")
        if limited_count > 0:
            logger.info(f"[{source_tag}] safety limits skipped {limited_count} tasks.")
        if scheduling_limit_hit:
            logger.warning(f"[{source_tag}] global request limit allows only {len(tasks)} more tasks.")

        if not tasks:
            logger.info(f"[{source_tag}] 추가로 진행할 새 작업이 없습니다. 스킵합니다.")
            return

        workers = max(1, int(getattr(self.cfg, "MAX_WORKERS", 2)))
        logger.info(f"[{source_tag}] starting {len(tasks)} tasks with {workers} workers")

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._dispatch_payload, *task): task
                for task in tasks
            }
            done = 0
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for pending in futures:
                        pending.cancel()
                    logger.warning(f"[{source_tag}] safety stop triggered; cancelling pending tasks.")
                    break
                done += 1
                if done % 100 == 0:
                    logger.info(f"[{source_tag}] 진행: {done}/{len(tasks)} "
                                f"| 발견: {len(self.findings)}건")
                    # gc.collect() 제거 — 10GB 힙 전체 스캔으로 GIL 점유 유발
                try:
                    future.result()
                except Exception as e:
                    logger.debug(f"[{source_tag}] Worker 예외: {e}")

    # -------------------------------------------------------------------------
    # 페이로드 dispatch: attack_vector 별 처리
    # -------------------------------------------------------------------------
    def _dispatch_payload(self, url: str, path: str, method: str,
                          body_schema: dict, params_schema: dict, path_params: list,
                          payload: dict, session: requests.Session, role: str,
                          base_target: str, task_key: str = ""):
        """
        attack_vector 값에 따라 적절한 전송 메서드로 dispatch.

        attack_vector 값:
            body   : JSON/Raw 바디에 삽입 (기존 방식)
            query  : GET 쿼리 파라미터에 삽입
            path   : URL 경로 파라미터에 삽입
            header : HTTP 헤더에 삽입
            cookie : 쿠키에 삽입
            url    : URL 직접 프로브
        """
        # thread_local 에 현재 고유 태스크 키 저장하여 _do_request 내부에서 접근 가능케 함 (린트 에러 차단)
        setattr(self._thread_local, "current_task_key", task_key)

        # None으로 넘어온 경우 스레드별 로컬 세션으로 복구
        if session is None:
            session = self._get_session(role)

        try:
            vector = payload.get("attack_vector", "body")
            ptype = payload.get("type", "")

            if vector == "query":
                self._fuzz_query_params(url, method, payload, session, role, params_schema, body_schema)

            elif vector == "path":
                self._fuzz_path_params(path, method, payload, session, role, base_target, params_schema, body_schema)

            elif vector == "header":
                self._fuzz_headers(url, method, payload, session, role)

            elif vector == "cookie":
                self._fuzz_cookies(url, method, payload, session, role)

            elif vector == "url":
                self._probe_url(payload, session, role, base_target)

            else:
                # body (기본값)
                if ptype == "multipart" or payload.get("boundary"):
                    self._send_multipart(url, payload, session, role)
                elif ptype == "large_json_array" and payload.get("raw_string"):
                    self._send_raw(url, method, payload, session, role)
                else:
                    self._send_dynamic(url, method, body_schema, payload, session, role)

        except MemoryError:
            gc.collect()
            logger.error(f"[Fuzzer] MemoryError ─ {payload.get('name')}")
        except Exception as e:
            logger.debug(f"[Fuzzer] 예외: {payload.get('name')} ─ {e}")

    # =========================================================================
    # GET 쿼리 파라미터 퍼징
    # =========================================================================
    def _fuzz_query_params(self, url: str, method: str, payload: dict,
                           session: requests.Session, role: str, params_schema: dict,
                           body_schema: dict = None):
        value = payload.get("value", payload.get("body", ""))
        param_name_hint = payload.get("param_name")

        query_params = params_schema.get("query", {}) if params_schema else {}
        if param_name_hint:
            param_names = [param_name_hint]
        elif query_params:
            param_names = list(query_params.keys())
        else:
            param_names = [
                "q", "search", "query", "id", "name", "file",
                "page", "url", "redirect", "path", "input",
                "keyword", "text", "data", "value", "token",
                "username", "password", "email", "phone",
            ]

        # baseline이 그 자체로 실패하는 엔드포인트는 스킵 (malformed seed 위에
        # 공격 페이로드를 쌓아서 나오는 가짜 findings 방지)
        if not self._baseline_ok(url, method, session, role, params_schema, body_schema):
            return

        for param_name in param_names[:1]:
            params = self._template_query(url, method) or self._normal_query(params_schema)
            params[param_name] = str(value)
            kwargs = {"query_params": params}
            normal_body = self._template_body(url, method)
            if normal_body is None:
                normal_body = self._normal_body(body_schema or {})
            if normal_body is not None and self._method_supports_body(method):
                kwargs["json_body"] = normal_body
            # ← 원래 메소드를 그대로 보존 (예전엔 무조건 "get"으로 하드코딩되어
            #   있어서 POST 엔드포인트인데 실제로는 GET으로 쏘고 있었음)
            self._do_request(url, method or "get",
                             payload_name=payload.get("name", ""),
                             session=session, role=role,
                             source=payload.get("source", ""),
                             kisa_code=payload.get("kisa_code", ""),
                             attack_vector=payload.get("attack_vector", ""),
                             baseline_valid=True,
                             **kwargs)

    # =========================================================================
    # URL 경로 파라미터 퍼징
    # =========================================================================
    def _fuzz_path_params(self, path: str, method: str, payload: dict,
                          session: requests.Session, role: str, base_target: str,
                          params_schema: dict = None, body_schema: dict = None):
        value = payload.get("value", payload.get("body", ""))

        normal_path = self._normal_path(path, params_schema or {})
        baseline_url = f"{base_target.rstrip('/')}{normal_path}"
        if not self._baseline_ok(baseline_url, method, session, role, params_schema, body_schema):
            return

        placeholders = re.findall(r'\{(\w+)\}', path)
        if not placeholders:
            test_url = f"{base_target.rstrip('/')}{path}/{value}"
        else:
            # 참고: placeholder가 2개 이상인 경로(/a/{x}/{y})는 첫 번째만
            # 공격값으로 바뀌고 나머지는 스키마 샘플값으로 채워진다.
            # 여러 파라미터를 동시에 공격하는 조합 케이스는 다루지 않음 —
            # 아래 "남은 한계"에 명시.
            test_path = path
            path_params = (params_schema or {}).get("path", {})
            for idx, ph in enumerate(placeholders):
                replacement = value if idx == 0 else self._sample_value(ph, path_params.get(ph, "string"))
                test_path = test_path.replace(f"{{{ph}}}", str(replacement))
            test_url = f"{base_target.rstrip('/')}{test_path}"

        kwargs = {"query_params": self._template_query(baseline_url, method) or self._normal_query(params_schema)}
        normal_body = self._template_body(baseline_url, method)
        if normal_body is None:
            normal_body = self._normal_body(body_schema or {})
        if normal_body is not None and self._method_supports_body(method):
            kwargs["json_body"] = normal_body

        self._do_request(test_url, method or "get",
                         payload_name=payload.get("name", ""),
                         session=session, role=role,
                         source=payload.get("source", ""),
                         kisa_code=payload.get("kisa_code", ""),
                         attack_vector=payload.get("attack_vector", ""),
                         baseline_valid=True,
                         **kwargs)

    # =========================================================================
    # HTTP 헤더 퍼징
    # =========================================================================
    def _fuzz_headers(self, url: str, method: str, payload: dict,
                      session: requests.Session, role: str):
        extra_headers = dict(payload.get("headers", {}))
        remove_auth = payload.get("remove_auth", False)

        temp_session = requests.Session()
        temp_session.proxies = session.proxies
        temp_session.verify = session.verify
        temp_headers = dict(session.headers)
        if remove_auth:
            temp_headers.pop("Authorization", None)
            temp_headers.pop("authorization", None)
        temp_headers.update(extra_headers)

        self._do_request(url, method or "get",
                         extra_headers=temp_headers,
                         payload_name=payload.get("name", ""),
                         session=temp_session, role=role,
                         source=payload.get("source", ""),
                         kisa_code=payload.get("kisa_code", ""),
                         attack_vector=payload.get("attack_vector", ""))

    # =========================================================================
    # 쿠키 퍼징
    # =========================================================================
    def _fuzz_cookies(self, url: str, method: str, payload: dict,
                      session: requests.Session, role: str):
        cookie_overrides = payload.get("cookie", {})

        temp_session = requests.Session()
        temp_session.proxies = session.proxies
        temp_session.verify = session.verify
        temp_session.headers.update(session.headers)
        temp_session.cookies.update(cookie_overrides)

        check_session_change = payload.get("check_session_change", False)

        resp = self._do_request(url, method or "get",
                                payload_name=payload.get("name", ""),
                                session=temp_session, role=role,
                                source=payload.get("source", ""),
                                kisa_code=payload.get("kisa_code", ""),
                                return_response=True)

        if resp and check_session_change:
            new_cookies = dict(resp.cookies)
            for cname, cval in cookie_overrides.items():
                if new_cookies.get(cname) == cval:
                    with self._findings_lock:
                        self.findings.append({
                            "source": payload.get("source", ""),
                            "kisa_code": payload.get("kisa_code", ""),
                            "role": role, "url": url,
                            "payload_name": payload.get("name", ""),
                            "vuln_name": "세션 고정 취약점 (SF)",
                            "status_code": resp.status_code,
                            "risk": "HIGH",
                            "elapsed_sec": 0,
                            "response_size_bytes": 0,
                            "response_text_snippet": "세션 ID 로그인 후 변경 안 됨",
                            "response_json": None,
                        })

    # =========================================================================
    # URL 경로 직접 프로브
    # =========================================================================
    def _probe_url(self, payload: dict, session: requests.Session,
                   role: str, base_target: str):
        url_path = payload.get("url_path", "/")
        probe_url = f"{base_target.rstrip('/')}{url_path}"

        self._do_request(probe_url, "get",
                         payload_name=payload.get("name", ""),
                         session=session, role=role,
                         source=payload.get("source", ""),
                         kisa_code=payload.get("kisa_code", ""))

    # =========================================================================
    # 동적 바디 페이로드 전송
    # =========================================================================
    def _send_dynamic(self, url: str, method: str, body_schema: dict,
                      payload: dict, session: requests.Session, role: str):
        p_body = payload.get("body", payload.get("value", ""))
        p_name = payload.get("name", "")

        # ← 기존엔 body_schema의 "모든" 필드를 p_body(공격값)로 덮어썼음.
        #   required 필드가 여러 개인 엔드포인트는 이 시점에 이미 baseline이
        #   깨져있던 것과 같은 문제 — 정상 필드까지 공격값으로 오염됨.
        #   이제는 template/schema로 "정상 바디"를 먼저 채우고, 공격 대상
        #   필드 1개만 덮어쓴다.
        if not self._baseline_ok(url, method, session, role, {}, body_schema or {}):
            return

        if body_schema:
            send_body = self._template_body(url, method) or self._normal_body(body_schema) or {}
            target_field = payload.get("field_name") or next(iter(body_schema.keys()), "data")
            send_body[target_field] = p_body
        else:
            if isinstance(p_body, (dict, list)):
                send_body = p_body
            else:
                send_body = {"data": p_body}

        self._do_request(url, method, json_body=send_body,
                         payload_name=p_name, session=session, role=role,
                         source=payload.get("source", ""),
                         kisa_code=payload.get("kisa_code", ""),
                         attack_vector=payload.get("attack_vector", "body"),
                         baseline_valid=True)

    def _send_raw(self, url: str, method: str, payload: dict,
                  session: requests.Session, role: str):
        raw = payload.get("body", payload.get("value", ""))
        data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else str(raw).encode()
        self._do_request(url, method, raw_data=data,
                         payload_name=payload.get("name", ""),
                         session=session, role=role,
                         source=payload.get("source", ""),
                         kisa_code=payload.get("kisa_code", ""))

    def _send_multipart(self, url: str, payload: dict,
                        session: requests.Session, role: str):
        boundary = payload.get("boundary", "----ARGUSBoundary")
        content_type = payload.get("content_type", f"multipart/form-data; boundary={boundary}")
        body_bytes = payload.get("body_bytes")
        if body_bytes:
            data = body_bytes
        else:
            raw = payload.get("body", "")
            data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw

        headers = dict(session.headers)
        headers["Content-Type"] = content_type
        self._do_request(url, "post", raw_data=data, extra_headers=headers,
                         payload_name=payload.get("name", ""),
                         session=session, role=role,
                         source=payload.get("source", ""),
                         kisa_code=payload.get("kisa_code", ""))

    def _endpoint_key_from_url(self, url: str) -> str:
        from urllib.parse import urlsplit

        try:
            parsed = urlsplit(url)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return url.split("?", 1)[0]

    def _reserve_request(self, url: str) -> bool:
        if self._stop_event.is_set():
            return False

        endpoint_key = self._endpoint_key_from_url(url)
        now = time.time()
        blocked_until = self._endpoint_blocked_until.get(endpoint_key, 0)
        if blocked_until > now:
            return False

        max_total = max(0, int(getattr(self.cfg, "MAX_TOTAL_REQUESTS", 0)))
        with self._request_lock:
            if max_total > 0 and self._request_count >= max_total:
                self._stop_event.set()
                logger.warning(f"[Fuzzer] global request limit reached ({max_total}); stopping.")
                return False
            self._request_count += 1
        return True

    def _note_request_result(self, url: str, status_code=None, failed: bool = False):
        endpoint_key = self._endpoint_key_from_url(url)
        is_server_failure = failed or status_code in (429, 500, 502, 503, 504)

        if not is_server_failure:
            self._endpoint_failures[endpoint_key] = 0
            return

        failures = self._endpoint_failures.get(endpoint_key, 0) + 1
        self._endpoint_failures[endpoint_key] = failures
        threshold = max(1, int(getattr(self.cfg, "CIRCUIT_BREAKER_FAILURES", 3)))
        if failures < threshold:
            return

        cooldown = max(0.0, float(getattr(self.cfg, "CIRCUIT_BREAKER_COOLDOWN_SEC", 30)))
        self._endpoint_blocked_until[endpoint_key] = time.time() + cooldown
        logger.warning(
            f"[Fuzzer] circuit breaker opened for {endpoint_key} "
            f"after {failures} failures; cooldown={cooldown}s"
        )
        if getattr(self.cfg, "STOP_ON_SERVER_DOWN", True):
            self._stop_event.set()
            logger.warning("[Fuzzer] safety stop enabled; stopping scan to protect the server.")

    # =========================================================================
    # 실제 HTTP 요청
    # =========================================================================
    def _do_request(self, url: str, method: str,
                    json_body=None, raw_data: Optional[bytes] = None,
                    query_params: Optional[dict] = None,
                    extra_headers: Optional[dict] = None,
                    payload_name: str = "",
                    session: requests.Session = None,
                    role: str = "",
                    source: str = "",
                    kisa_code: str = "",
                    attack_vector: str = "",
                    return_response: bool = False,
                    record_finding: bool = True,
                    write_progress: bool = True,
                    baseline_valid: bool = False):
        if not self._reserve_request(url):
            return None

        if self.cfg.DELAY_BETWEEN_REQUESTS > 0:
            time.sleep(self.cfg.DELAY_BETWEEN_REQUESTS)

        # thread-local 세션 발급 (토큰 동기화 포함, _get_session 내부 처리)
        if session is None:
            session = self._get_session(role)

        headers = extra_headers or {}
        start = time.time()

        try:
            req_method = getattr(session, method.lower(), session.get)
            kwargs = {"headers": headers, "timeout": self.cfg.REQUEST_TIMEOUT}
            if query_params:
                kwargs["params"] = query_params
            if json_body is not None:
                kwargs["json"] = json_body
            elif raw_data is not None:
                kwargs["data"] = raw_data

            resp = req_method(url, **kwargs)
            elapsed = time.time() - start
            self._note_request_result(url, resp.status_code)


            if resp.status_code == 401:
                # 토큰 만료 → JWT 갱신 필요
                with self._auth_lock:
                    self._handle_auth_error(url, resp.status_code, role)
            elif resp.status_code == 403:
                # 권한 없음 → 토큰 문제 아님, 갱신 불필요 (정상적인 접근 거부)
                pass
            else:
                with self._auth_lock:
                    self._auth_error_counts[role] = 0

            request_snapshot = self._request_snapshot(
                url, method, headers=headers, query_params=query_params,
                json_body=json_body, raw_data=raw_data,
            )
            if record_finding and self._judge_vulnerable(resp, elapsed, kisa_code, url):
                self._record(url, payload_name, resp, elapsed, role, source, kisa_code,
                             attack_vector, baseline_valid, method=method,
                             request_snapshot=request_snapshot)

            # 진행도 기록 (Task Resume용) — baseline probe는 기록하지 않음
            if write_progress:
                self._write_progress_key()

            if return_response:
                return resp

        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            self._note_request_result(url, "TIMEOUT", failed=True)
            if record_finding:
                self._record_timeout(url, payload_name, elapsed, role, source, kisa_code,
                                     attack_vector, baseline_valid)
            if write_progress:
                self._write_progress_key()
        except requests.exceptions.RequestException as e:
            logger.debug(f"[Fuzzer] request failed: {e}")
            self._note_request_result(url, None, failed=True)
            if write_progress:
                self._write_progress_key()
        except Exception as e:
            logger.debug(f"[Fuzzer] request handling failed: {e}")
            if write_progress:
                self._write_progress_key()

        return None

    def _write_progress_key(self):
        """현재 스레드에서 완료한 태스크 키를 temp_progress.txt 에 안전하게 기록"""
        task_key = getattr(self._thread_local, "current_task_key", None)
        if task_key:
            with self._findings_lock:  # 락 획득하여 동시 쓰기 경쟁 방지
                try:
                    os.makedirs(self.cfg.OUTPUT_DIR, exist_ok=True)
                    progress_path = os.path.join(self.cfg.OUTPUT_DIR, "temp_progress.txt")
                    with open(progress_path, "a", encoding="utf-8") as f:
                        f.write(task_key + "\n")
                except Exception as e:
                    logger.error(f"[Fuzzer] 진행률 키 저장 실패: {e}")

    # =========================================================================
    # 세션 / 인증 관리
    # =========================================================================
    def _get_session(self, role: str) -> requests.Session:
        """
        스레드별 독립 세션 반환 (threading.local 캐시).

        - 각 스레드가 자신만의 Session을 가지므로 headers 동시 쓰기 충돌 없음
        - 스레드 내에서는 동일 Session을 재사용 → TCP 연결 재사용 유지
        - 호출마다 최신 Authorization 토큰 동기화
        """
        key = f"session_{role}"
        s = getattr(self._thread_local, key, None)

        if s is None:
            # 이 스레드에 아직 세션이 없으면 새로 생성
            s = requests.Session()
            s.proxies = self.cfg.PROXIES  # 원래 정석대로 ZAP 프록시 경유
            s.verify = False
            s.headers.update({"Content-Type": "application/json",
                               "User-Agent": "ARGUS-W16-Fuzzer/5.0"})
            setattr(self._thread_local, key, s)

        # [v8 패치] CPython 딕셔너리 동시성 버그 방지
        # 쓰기(_handle_auth_error)와 읽기(_get_session)가 찰나에 겹치면
        # CPython 해시 버킷 탐색이 무한 루프에 빠지는 현상 → 읽기에도 락 적용
        # get() 연산은 1μs 미만이므로 스레드 대기 시간 영향 없음
        with self._auth_lock:
            token = self._current_tokens.get(role)
        if token:
            s.headers["Authorization"] = token

        return s

    def _handle_auth_error(self, url: str, status: int, role: str):
        # 이 메서드는 항상 _auth_lock 하에서 호출됨
        now = time.time()
        # 최근 5초 이내에 토큰이 이미 갱신되었다면 과거의 누적 401 에러는 무시
        if now - self._last_refresh_time.get(role, 0) < 5.0:
            self._auth_error_counts[role] = 0
            return

        self._auth_error_counts[role] = self._auth_error_counts.get(role, 0) + 1
        logger.debug(f"[Fuzzer] [{role}] 인증 오류 {status} "
                     f"(연속 {self._auth_error_counts[role]}회)")
        if self._auth_error_counts[role] >= self.cfg.JWT_REFRESH_THRESHOLD:
            if self.role_manager:
                password = self.cfg.ROLE_PASSWORDS.get(role, "")
                success = self.role_manager.refresh_token(role, password)
                if success:
                    # 갱신된 토큰을 캐시에 저장 → 다른 스레드들이 다음 요청부터 즉시 반영
                    base = self.role_manager.get_session(role)
                    if base and "Authorization" in base.headers:
                        self._current_tokens[role] = base.headers["Authorization"]
                    if self.zap_engine:
                        self.zap_engine.update_auth(self.role_manager.get_token(role))
                    self._last_refresh_time[role] = now
            self._auth_error_counts[role] = 0

    # =========================================================================
    # 취약 판정 (KISA 항목별 특화 판정 포함)
    # =========================================================================
    def _judge_vulnerable(self, resp, elapsed: float, kisa_code: str = "", url: str = "") -> bool:
        if resp.status_code >= 500:
            return True
        if elapsed >= self.cfg.SLOW_RESPONSE_THRESHOLD:
            return True

        body_lower = resp.text.lower()

        if 400 <= resp.status_code < 500:
            return self._has_real_sensitive_leak(body_lower)

        if resp.status_code in (200, 201):
            if self._has_real_sensitive_leak(body_lower):
                return True

        if kisa_code == "SI":
            sql_errors = ["sql syntax", "mysql_fetch", "ora-", "odbc driver",
                          "unclosed quotation", "quoted string not properly terminated",
                          "syntax error", "postgresql", "microsoft ole db"]
            if any(e in body_lower for e in sql_errors):
                return True

        elif kisa_code == "DI":
            if ("index of /" in body_lower or "directory listing" in body_lower
                    or "<title>index of" in body_lower):
                return True

        elif kisa_code == "AE":
            if resp.status_code in (200, 201) and self._has_real_sensitive_leak(body_lower):
                return True

        elif kisa_code == "IL":
            info_leak_indicators = [
                "stack trace", "at sun.reflect", "exception in thread",
                "traceback (most recent", "warning: mysql",
                "server: apache", "x-powered-by", "php/", "asp.net",
            ]
            if any(i in body_lower for i in info_leak_indicators):
                return True

        elif kisa_code == "XS":
            if "<script>alert" in body_lower or "onerror=alert" in body_lower:
                return True

        elif kisa_code == "PL":
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    return True

        elif kisa_code == "SN":
            if not resp.url.startswith("https://"):
                return True

        elif kisa_code == "IA":
            if resp.status_code in (200, 201) and self._has_real_sensitive_leak(body_lower):
                return True

        elif kisa_code == "FU":
            upload_url_hint = any(
                part in url.lower()
                for part in ("upload", "file", "image", "attachment", "document")
            )
            if resp.status_code in (200, 201) and upload_url_hint and "error" not in body_lower:
                return True

        elif kisa_code == "PT":
            if "root:x:" in resp.text or "[boot loader]" in resp.text:
                return True

        elif kisa_code == "FD":
            if "root:x:" in resp.text or "[extensions]" in resp.text:
                return True

        return False

    # =========================================================================
    # ← CHANGED: findings.append에 lock 적용
    # =========================================================================
    def _record(self, url: str, payload_name: str, resp,
                elapsed: float, role: str, source: str = "", kisa_code: str = "",
                attack_vector: str = "", baseline_valid: bool = False,
                method: str = "", request_snapshot: dict = None):
        body_lower = resp.text.lower()
        has_sensitive = self._has_real_sensitive_leak(body_lower)

        if resp.status_code >= 500 and has_sensitive:
            risk = "CRITICAL"
        elif resp.status_code >= 500 or elapsed >= self.cfg.SLOW_RESPONSE_THRESHOLD:
            risk = "HIGH"
        else:
            risk = "MEDIUM"

        try:
            response_json = resp.json()
        except Exception:
            response_json = None

        baseline = self._baseline_snapshot(url, method, role)

        finding = {
            "id": str(uuid.uuid4()),
            "source": source,
            "kisa_code": kisa_code,
            "attack_vector": attack_vector,
            "role": role,
            "method": str(method or "").upper(),
            "url": url,
            "request": request_snapshot or {},
            "payload_name": payload_name,
            "status_code": resp.status_code,
            "elapsed_sec": round(elapsed, 3),
            "risk": risk,
            "response_size_bytes": len(resp.content),
            "response_text_snippet": resp.text[:500],
            "response_json": response_json,
            # collector.py의 _classify_finding() 200/201 분기가 여기 있는
            # baseline_* 값들로 실제 diff를 할 수 있음 (payload_echoed /
            # body_similarity / timing_anomaly). baseline.verified=False면
            # 이 endpoint에 대해 실측 baseline이 없었다는 뜻이므로 diff에
            # 쓰지 말고 기존 고정 문자열 판정으로 폴백해야 함.
            "request_context": {
                "baseline_valid": bool(baseline_valid),
                "baseline_verified": bool(baseline.get("verified")),
                "baseline_status_code": baseline.get("status_code"),
                "baseline_elapsed_sec": baseline.get("elapsed_sec"),
                "baseline_body_snippet": baseline.get("body_snippet", ""),
                "baseline_response_size": baseline.get("response_size"),
                "method_preserved": True,
                "zap_template_used": bool(self._template_for(url, method)),
            },
        }

        with self._findings_lock:
            self.findings.append(finding)
            # 실시간 중간 결과 저장 (체크포인트)
            try:
                os.makedirs(self.cfg.OUTPUT_DIR, exist_ok=True)
                findings_path = os.path.join(self.cfg.OUTPUT_DIR, "temp_findings.jsonl")
                with open(findings_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(finding, ensure_ascii=False) + "\n")
            except Exception as e:
                logger.error(f"[Fuzzer] 임시 결과 저장 실패: {e}")

        logger.info(f"[{source}|{kisa_code}] [{role}] 취약점! "
                    f"[{risk}] {url} ─ {payload_name}")

    def _has_real_sensitive_leak(self, body_lower: str) -> bool:
        # 오탐 억제 규칙은 core/false_positive_rules.py 테이블에서 관리.
        # (collector.py의 _classify_finding과 동일한 테이블을 공유)
        if is_suppressed_leak(body_lower):
            return False

        sensitive_terms = [kw.lower() for kw in self.cfg.SENSITIVE_KEYWORDS]
        sensitive_terms.extend([
            "authorization: bearer",
            "access_token",
            "refresh_token",
            "api_key",
            "secret_key",
            "root:x:",
            "stacktrace",
            "traceback (most recent call last)",
            "exception in thread",
            "sqlstate",
            "sql exception",
            "syntax error at or near",
            "select * from",
            "insert into",
            "update ",
            "delete from",
        ])
        return any(term in body_lower for term in sensitive_terms)

    def _record_timeout(self, url: str, payload_name: str, elapsed: float,
                        role: str, source: str = "", kisa_code: str = "",
                        attack_vector: str = "", baseline_valid: bool = False):
        finding = {
            "id": str(uuid.uuid4()),
            "source": source,
            "kisa_code": kisa_code,
            "attack_vector": attack_vector,
            "role": role,
            "url": url,
            "payload_name": payload_name,
            "status_code": "TIMEOUT",
            "elapsed_sec": round(elapsed, 3),
            "risk": "HIGH",
            "vuln_name": "잠재적 DoS (타임아웃)",
            "response_size_bytes": 0,
            "response_text_snippet": "",
            "response_json": None,
            "request_context": {
                "baseline_valid": bool(baseline_valid),
                "method_preserved": True,
            },
        }

        with self._findings_lock:
            self.findings.append(finding)
            # 실시간 중간 결과 저장 (체크포인트)
            try:
                os.makedirs(self.cfg.OUTPUT_DIR, exist_ok=True)
                findings_path = os.path.join(self.cfg.OUTPUT_DIR, "temp_findings.jsonl")
                with open(findings_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(finding, ensure_ascii=False) + "\n")
            except Exception as e:
                logger.error(f"[Fuzzer] 임시 결과 저장 실패: {e}")