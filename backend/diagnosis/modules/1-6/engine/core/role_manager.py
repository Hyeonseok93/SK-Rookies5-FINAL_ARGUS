# =============================================================================
# role_manager.py  ─  역할별 세션 관리 모듈
# user / seller / admin 등 여러 역할을 각각 로그인하고
# 역할별 JWT 와 접근 가능 엔드포인트를 따로 관리합니다.
# =============================================================================

import logging
import requests
from typing import Optional

logger = logging.getLogger(__name__)


class RoleManager:
    """
    여러 역할을 동시에 관리하는 클래스.

    사용 방법:
        rm = RoleManager(cfg, login_info)
        rm.login_all(roles_dict)
        token = rm.get_token("admin")
        session = rm.get_session("admin")

    roles_dict 형식:
        {"admin": "pass123", "user": "pass456", "seller": "pass789"}
    """

    def __init__(self, cfg, login_info: dict):
        """
        Args:
            cfg:        Config 인스턴스
            login_info: SwaggerParser.get_login_info() 의 반환값
                        {path, method, id_field, pw_field, token_path}
        """
        self.cfg = cfg
        self.login_info = login_info

        # 역할별 데이터 저장소
        # { "admin": {"token": "...", "session": requests.Session, "endpoints": []} }
        self._roles: dict = {}

    def _role_override(self, mapping: dict, role_name: str) -> str:
        """Return exact role override, then email local-part override."""
        if not isinstance(mapping, dict):
            return ""
        if role_name in mapping:
            return str(mapping[role_name])
        local_part = role_name.split("@", 1)[0]
        return str(mapping.get(local_part, ""))

    # -------------------------------------------------------------------------
    # 전체 역할 로그인
    # -------------------------------------------------------------------------
    def login_all(self, roles: dict):
        """
        모든 역할에 대해 순서대로 로그인합니다.

        Args:
            roles: {"역할명": "비밀번호"} 딕셔너리
                   아이디는 역할명을 그대로 사용합니다.
                   예: {"admin": "admin123", "user": "user456"}

        사용 예:
            rm.login_all({"admin": "pass", "user": "pass2"})
        """
        for role_name, password in roles.items():
            logger.info(f"[RoleManager] 로그인 시도: {role_name}")
            try:
                token = self._login_api(role_name, role_name, password)
                session = self._make_session(token)
                self._roles[role_name] = {
                    "token":     token,
                    "session":   session,
                    "endpoints": [],  # 나중에 역할별 엔드포인트 채움
                }
                logger.info(f"[RoleManager] 로그인 성공: {role_name} (토큰 앞 20자: {token[:20]}...)")
            except Exception as e:
                logger.error(f"[RoleManager] 로그인 실패: {role_name} ─ {e}")
                # 실패해도 계속 진행 (다른 역할 로그인 시도)
                self._roles[role_name] = {
                    "token":     "",
                    "session":   self._make_session(""),
                    "endpoints": [],
                }

    # -------------------------------------------------------------------------
    # API 로그인 (토큰 발급)
    # -------------------------------------------------------------------------
    def _login_api(self, role_name: str, username: str, password: str) -> str:
        """
        Swagger 명세서에서 찾은 로그인 엔드포인트로 API 호출해서 JWT 를 받아옵니다.

        Args:
            role_name: 역할명. cfg.ROLE_LOGIN_TARGETS 에 이 role의 override가
                       있으면 그 base_url로 로그인한다 (예: admin은 8081 포트).
                       없으면 LOGIN_TARGET → TARGET_URL 순으로 fallback.
            username:  로그인 아이디 (역할명과 동일)
            password:  로그인 비밀번호

        Returns:
            JWT 문자열
        """
        role_login_targets = getattr(self.cfg, "ROLE_LOGIN_TARGETS", {}) or {}
        base_url = (
            self._role_override(role_login_targets, role_name)
            or getattr(self.cfg, "LOGIN_TARGET", "")
            or self.cfg.TARGET_URL
        ).rstrip("/")
        role_login_paths = getattr(self.cfg, "ROLE_LOGIN_PATHS", {}) or {}
        login_path = (
            self._role_override(role_login_paths, role_name)
            or getattr(self.cfg, "LOGIN_PATH", "")
            or self.login_info.get("path", "/login")
        )
        method = self.login_info.get("method", "post")
        id_field = self.login_info.get("id_field", "username")
        pw_field = self.login_info.get("pw_field", "password")
        token_path = self.login_info.get("token_path", ["access_token"])

        url = f"{base_url}{login_path}"
        payload = {
            id_field: username,
            pw_field: password,
        }

        logger.debug(f"[RoleManager] 로그인 요청: {method.upper()} {url}")
        resp = getattr(requests, method)(
            url,
            json=payload,
            timeout=self.cfg.REQUEST_TIMEOUT,
            verify=False,
        )

        if resp.status_code not in (200, 201):
            raise RuntimeError(f"로그인 실패 HTTP {resp.status_code}: {resp.text[:200]}")

        # 응답에서 토큰 추출 (token_path 경로를 따라가며 찾기)
        data = resp.json()
        token = data
        for key in token_path:
            if isinstance(token, dict):
                token = token.get(key, "")
            else:
                token = ""
                break

        if not token:
            # token_path 로 못 찾으면 흔한 키로 직접 찾기
            for key in ["access_token", "token", "jwt", "accessToken", "auth_token"]:
                if isinstance(data, dict) and key in data:
                    token = data[key]
                    break
                if isinstance(data, dict) and "data" in data:
                    token = data["data"].get(key, "")
                    if token:
                        break

        if not token:
            raise RuntimeError(f"토큰을 응답에서 찾을 수 없습니다: {str(data)[:300]}")

        # "Bearer " 접두어 제거
        return str(token).replace("Bearer ", "").strip()

    # -------------------------------------------------------------------------
    # requests.Session 생성
    # -------------------------------------------------------------------------
    def _make_session(self, token: str) -> requests.Session:
        """
        JWT 가 자동으로 붙는 requests.Session 을 만듭니다.

        Args:
            token: JWT 문자열

        Returns:
            헤더에 Authorization 이 설정된 Session 객체
        """
        session = requests.Session()
        session.proxies = self.cfg.PROXIES
        session.verify = False
        session.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}" if token else "",
            "User-Agent": "ARGUS-W16-Fuzzer/3.0",
        })
        return session

    # -------------------------------------------------------------------------
    # 역할별 JWT 갱신
    # -------------------------------------------------------------------------
    def refresh_token(self, role_name: str, password: str) -> bool:
        """
        특정 역할의 JWT 를 재발급받습니다.
        fuzzer 에서 401/403 임계값 도달 시 호출됩니다.

        Args:
            role_name: 갱신할 역할명
            password:  해당 역할의 비밀번호

        Returns:
            True: 갱신 성공, False: 실패
        """
        try:
            new_token = self._login_api(role_name, role_name, password)
            new_session = self._make_session(new_token)
            self._roles[role_name]["token"] = new_token
            self._roles[role_name]["session"] = new_session
            logger.info(f"[RoleManager] JWT 갱신 성공: {role_name}")
            return True
        except Exception as e:
            logger.error(f"[RoleManager] JWT 갱신 실패: {role_name} ─ {e}")
            return False

    # -------------------------------------------------------------------------
    # 공개 인터페이스
    # -------------------------------------------------------------------------
    def get_token(self, role_name: str) -> str:
        """특정 역할의 JWT 를 반환합니다."""
        return self._roles.get(role_name, {}).get("token", "")

    def get_session(self, role_name: str) -> Optional[requests.Session]:
        """특정 역할의 requests.Session 을 반환합니다."""
        return self._roles.get(role_name, {}).get("session")

    def get_all_roles(self) -> list:
        """등록된 모든 역할명 목록을 반환합니다."""
        return list(self._roles.keys())

    def get_primary_token(self) -> str:
        """
        첫 번째 역할의 토큰을 반환합니다.
        ZAP JWT 주입에 사용합니다 (ZAP 은 단일 토큰만 지원).
        admin 역할이 있으면 admin 을 우선합니다.
        """
        if "admin" in self._roles and self._roles["admin"]["token"]:
            return self._roles["admin"]["token"]
        for role in self._roles.values():
            if role["token"]:
                return role["token"]
        return ""

    def summary(self) -> dict:
        """역할별 로그인 상태 요약을 반환합니다."""
        return {
            role: {
                "logged_in": bool(data["token"]),
                "token_preview": data["token"][:20] + "..." if data["token"] else "없음",
            }
            for role, data in self._roles.items()
        }
