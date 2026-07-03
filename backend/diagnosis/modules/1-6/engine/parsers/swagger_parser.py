# =============================================================================
# swagger_parser.py  ─  Swagger/OpenAPI 명세서 파서
# Swagger JSON 파일을 읽어서 엔드포인트, 파라미터, 인증 방식을 자동으로 추출합니다.
# 이 모듈 덕분에 어떤 사이트든 swagger.json 하나만 주면 퍼징 대상이 자동 결정됩니다.
# =============================================================================

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SwaggerParser:
    """
    Swagger/OpenAPI 2.0 및 3.0 명세서를 파싱합니다.

    사용 방법:
        parser = SwaggerParser("swagger.json")
        endpoints  = parser.get_endpoints()       # 퍼징 대상 엔드포인트 목록
        login_info = parser.get_login_info()      # 로그인 엔드포인트 + 파라미터
        auth_type  = parser.get_auth_type()       # 인증 방식 (bearer, apikey, basic)
    """

    def __init__(self, spec_path: str):
        """
        Args:
            spec_path: swagger.json 파일 경로 또는 URL
        """
        self.spec_path = spec_path
        self.spec: dict = {}
        self._load()

    # -------------------------------------------------------------------------
    # 명세서 로드
    # -------------------------------------------------------------------------
    def _load(self):
        """Swagger JSON 파일을 읽어서 메모리에 올립니다."""
        if self.spec_path.startswith("http"):
            # URL로 제공된 경우 HTTP로 가져오기
            import requests
            try:
                resp = requests.get(self.spec_path, timeout=15, verify=False)
                self.spec = resp.json()
                logger.info(f"[Parser] Swagger URL 로드 완료: {self.spec_path}")
            except Exception as e:
                raise ValueError(f"Swagger URL 로드 실패: {e}")
        else:
            # 로컬 파일
            try:
                with open(self.spec_path, "r", encoding="utf-8") as f:
                    self.spec = json.load(f)
                logger.info(f"[Parser] Swagger 파일 로드 완료: {self.spec_path}")
            except Exception as e:
                raise ValueError(f"Swagger 파일 로드 실패: {e}")

        # OpenAPI 버전 감지
        if "openapi" in self.spec:
            self._version = 3
        elif "swagger" in self.spec:
            self._version = 2
        else:
            raise ValueError("Swagger/OpenAPI 형식이 아닙니다.")

        logger.info(f"[Parser] OpenAPI 버전: {self._version}")

    # -------------------------------------------------------------------------
    # 베이스 URL 추출
    # -------------------------------------------------------------------------
    def get_base_url(self, override_host: str = "") -> str:
        """
        명세서에서 베이스 URL을 추출합니다.
        override_host 가 주어지면 명세서의 host 대신 사용합니다.

        Args:
            override_host: CLI 로 넘어온 --target URL (우선 적용)

        Returns:
            베이스 URL 문자열
        """
        if override_host:
            return override_host.rstrip("/")

        if self._version == 3:
            servers = self.spec.get("servers", [{}])
            url = servers[0].get("url", "") if servers else ""
            return url.rstrip("/")
        else:
            # OpenAPI 2.0
            host = self.spec.get("host", "localhost")
            base = self.spec.get("basePath", "/")
            schemes = self.spec.get("schemes", ["http"])
            scheme = "https" if "https" in schemes else schemes[0]
            return f"{scheme}://{host}{base}".rstrip("/")

    # -------------------------------------------------------------------------
    # 엔드포인트 목록 추출
    # -------------------------------------------------------------------------
    def get_endpoints(self) -> list:
        """
        명세서의 모든 엔드포인트를 추출합니다.

        Returns:
            엔드포인트 딕셔너리 목록:
            [
                {
                    "path":    "/api/v1/users",
                    "method":  "post",
                    "params":  {...},   # 파라미터 구조 (동적 페이로드 주입용)
                    "requires_auth": True,
                    "summary": "사용자 생성",
                }
            ]
        """
        endpoints = []
        paths = self.spec.get("paths", {})

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete"]:
                operation = path_item.get(method)
                if operation is None:
                    continue

                # 파라미터 구조 파악
                params = self._extract_params(operation, path_item)

                # 인증 필요 여부 확인
                requires_auth = self._requires_auth(operation)

                endpoints.append({
                    "path":          path,
                    "method":        method,
                    "params":        params,
                    "requires_auth": requires_auth,
                    "summary":       operation.get("summary", ""),
                    "tags":          operation.get("tags", []),
                    "operation_id":  operation.get("operationId", ""),
                })

        logger.info(f"[Parser] 엔드포인트 추출 완료: {len(endpoints)} 개")
        return endpoints

    def _extract_params(self, operation: dict, path_item: dict) -> dict:
        """
        하나의 operation 에서 파라미터 구조를 추출합니다.

        Returns:
            {
                "body":   {"username": "string", "password": "string"},
                "query":  {"page": "integer"},
                "path":   {"id": "integer"},
                "header": {"X-Custom": "string"},
            }
        """
        result = {"body": {}, "query": {}, "path": {}, "header": {}}

        # parameters 배열 처리 (path/query/header 파라미터)
        all_params = path_item.get("parameters", []) + operation.get("parameters", [])
        for p in all_params:
            if "$ref" in p:
                p = self._resolve_ref(p["$ref"])
            location = p.get("in", "query")
            name = p.get("name", "")
            ptype = self._get_type(p.get("schema", p))
            if location in result and name:
                result[location][name] = ptype

        # requestBody 처리 (OpenAPI 3.0)
        req_body = operation.get("requestBody", {})
        if req_body:
            content = req_body.get("content", {})
            schema = None
            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
            elif "multipart/form-data" in content:
                schema = content["multipart/form-data"].get("schema", {})
            if schema:
                if "$ref" in schema:
                    schema = self._resolve_ref(schema["$ref"])
                props = schema.get("properties", {})
                for name, prop in props.items():
                    result["body"][name] = self._get_type(prop)

        # body 파라미터 처리 (OpenAPI 2.0)
        for p in all_params:
            if p.get("in") == "body":
                schema = p.get("schema", {})
                if "$ref" in schema:
                    schema = self._resolve_ref(schema["$ref"])
                props = schema.get("properties", {})
                for name, prop in props.items():
                    result["body"][name] = self._get_type(prop)

        return result

    def _get_type(self, schema: dict) -> str:
        """스키마에서 타입 문자열을 추출합니다."""
        if not schema:
            return "string"
        t = schema.get("type", "string")
        fmt = schema.get("format", "")
        if t == "integer" or t == "number":
            return "integer"
        if t == "boolean":
            return "boolean"
        if t == "array":
            return "array"
        if t == "object":
            return "object"
        return "string"

    def _requires_auth(self, operation: dict) -> bool:
        """해당 operation 에 인증이 필요한지 판단합니다."""
        # security 필드가 명시적으로 빈 배열이면 인증 불필요
        security = operation.get("security")
        if security is not None:
            return len(security) > 0
        # 전역 security 확인
        global_security = self.spec.get("security", [])
        return len(global_security) > 0

    # -------------------------------------------------------------------------
    # 로그인 엔드포인트 추출
    # -------------------------------------------------------------------------
    def get_login_info(self) -> dict:
        """
        로그인 엔드포인트를 자동으로 찾습니다.
        /auth/login, /login, /api/login, /token 등 패턴으로 탐지합니다.

        Returns:
            {
                "path":     "/auth/login",
                "method":   "post",
                "id_field": "username",   # 아이디 파라미터명
                "pw_field": "password",   # 비밀번호 파라미터명
                "token_path": ["data", "access_token"],  # 응답에서 토큰 위치
            }
        """
        # 더 명확한 로그인 의미의 키워드
        login_priority = ["login", "signin", "sign-in", "authenticate"]
        fallback_keywords = ["token", "auth", "session"]
        # 회원가입, 인증확인, 갱신 등은 로그인 엔드포인트가 아님
        exclude_keywords = ["signup", "sign-up", "register", "join", "check", "verify", "send", "refresh", "logout"]
        
        id_keywords = ["username", "email", "id", "user", "login_id", "account"]
        pw_keywords = ["password", "passwd", "pw", "pass", "secret"]

        paths = self.spec.get("paths", {})
        
        # 헬퍼 함수: 로그인 딕셔너리 생성
        def _build_info(path, method, operation, path_item):
            params = self._extract_params(operation, path_item)
            body_params = params.get("body", {})
            id_field = next((k for k in body_params if any(kw in k.lower() for kw in id_keywords)), "username")
            pw_field = next((k for k in body_params if any(kw in k.lower() for kw in pw_keywords)), "password")
            token_path = self._find_token_path(operation)
            logger.info(f"[Parser] 로그인 엔드포인트 발견: {method.upper()} {path}")
            return {
                "path":       path,
                "method":     method,
                "id_field":   id_field,
                "pw_field":   pw_field,
                "token_path": token_path,
            }

        # 1순위: 로그인 전용 키워드 매칭
        for path, path_item in paths.items():
            path_lower = path.lower()
            if any(ek in path_lower for ek in exclude_keywords):
                continue
            if any(lk in path_lower for lk in login_priority):
                for method in ["post", "put"]:
                    operation = path_item.get(method)
                    if not operation:
                        continue
                    return _build_info(path, method, operation, path_item)

        # 2순위: 일반적인 인증/토큰 키워드 매칭
        for path, path_item in paths.items():
            path_lower = path.lower()
            if any(ek in path_lower for ek in exclude_keywords):
                continue
            if any(fk in path_lower for fk in fallback_keywords):
                for method in ["post", "put"]:
                    operation = path_item.get(method)
                    if not operation:
                        continue
                    return _build_info(path, method, operation, path_item)

        # 못 찾으면 기본값
        logger.warning("[Parser] 로그인 엔드포인트를 자동으로 찾지 못했습니다. 기본값 사용.")
        return {
            "path":       "/login",
            "method":     "post",
            "id_field":   "username",
            "pw_field":   "password",
            "token_path": ["access_token"],
        }

    def _find_token_path(self, operation: dict) -> list:
        """
        응답 스키마에서 토큰 필드 경로를 추론합니다.
        예: {"data": {"access_token": "..."}} → ["data", "access_token"]
        """
        token_keywords = ["token", "access_token", "jwt", "auth_token", "bearer"]

        responses = operation.get("responses", {})
        ok_resp = responses.get("200", responses.get("201", {}))
        content = ok_resp.get("content", {})

        schema = None
        if "application/json" in content:
            schema = content["application/json"].get("schema", {})
        if not schema:
            return ["access_token"]

        if "$ref" in schema:
            schema = self._resolve_ref(schema["$ref"])

        # 재귀적으로 토큰 필드 찾기
        path = self._search_token_field(schema, token_keywords, [])
        return path if path else ["access_token"]

    def _search_token_field(self, schema: dict, keywords: list, current_path: list) -> list:
        """스키마를 재귀적으로 탐색해서 토큰 필드 경로를 반환합니다."""
        if not isinstance(schema, dict):
            return []
        props = schema.get("properties", {})
        for key, val in props.items():
            if any(kw in key.lower() for kw in keywords):
                return current_path + [key]
            if isinstance(val, dict) and val.get("type") == "object":
                result = self._search_token_field(val, keywords, current_path + [key])
                if result:
                    return result
        return []

    # -------------------------------------------------------------------------
    # 인증 방식 추출
    # -------------------------------------------------------------------------
    def get_auth_type(self) -> str:
        """
        명세서에서 인증 방식을 추출합니다.

        Returns:
            "bearer" | "apikey" | "basic" | "none"
        """
        if self._version == 3:
            components = self.spec.get("components", {})
            schemes = components.get("securitySchemes", {})
        else:
            schemes = self.spec.get("securityDefinitions", {})

        for name, scheme in schemes.items():
            t = scheme.get("type", "").lower()
            scheme_lower = scheme.get("scheme", "").lower()
            if t == "http" and scheme_lower == "bearer":
                return "bearer"
            if t == "apikey":
                return "apikey"
            if t == "http" and scheme_lower == "basic":
                return "basic"
            if t == "oauth2":
                return "bearer"

        return "bearer"  # 기본값

    # -------------------------------------------------------------------------
    # 퍼징에 바로 쓸 수 있는 형태로 정리
    # -------------------------------------------------------------------------
    def get_fuzz_targets(self) -> list:
        """
        퍼저가 바로 사용할 수 있는 형태로 엔드포인트 + 파라미터를 정리합니다.
        인증이 필요한 엔드포인트와 POST/PUT/PATCH 위주로 반환합니다.

        Returns:
            [{"path": "/api/v1/users", "method": "post", "body_schema": {...}}, ...]
        """
        targets = []
        for ep in self.get_endpoints():
            # W-1-6 은 데이터 주입이 목적이므로 body 가 있는 엔드포인트 우선
            body = ep["params"].get("body", {})
            targets.append({
                "path":         ep["path"],
                "method":       ep["method"],
                "body_schema":  body,
                "params":       ep["params"],
                "path_params":  list(ep["params"].get("path", {}).keys()),
                "requires_auth": ep["requires_auth"],
                "summary":      ep["summary"],
            })
        logger.info(f"[Parser] 퍼징 대상 정리 완료: {len(targets)} 개")
        return targets

    # -------------------------------------------------------------------------
    # $ref 해석
    # -------------------------------------------------------------------------
    def _resolve_ref(self, ref: str) -> dict:
        """
        $ref 경로를 따라가서 실제 스키마를 반환합니다.
        예: "#/components/schemas/User" → spec["components"]["schemas"]["User"]
        """
        if not ref.startswith("#/"):
            return {}
        parts = ref.lstrip("#/").split("/")
        schema = self.spec
        for part in parts:
            part = part.replace("~1", "/").replace("~0", "~")
            schema = schema.get(part, {})
        return schema
