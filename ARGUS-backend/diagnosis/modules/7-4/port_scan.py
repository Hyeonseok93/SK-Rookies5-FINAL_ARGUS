"""Sensitive open-port scan for guideline 7-4 (stdlib socket, target-agnostic).

각 대상 host 에 대해 '외부에 노출되면 위험한' 관리/DB/캐시 포트가 열려 있는지
TCP connect 로 확인한다. 애플리케이션 자체 포트는 info(정상)로만 표시.

도메인 하드코딩 없음 — config targets 의 host 를 그대로 스캔한다.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

from diagnosis.result import DiagnosisFinding

# 외부 노출 시 위험한 포트 (port -> (서비스, 심각도))
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    445: ("SMB", "high"),
    3389: ("RDP", "high"),
    2375: ("Docker API (unencrypted)", "high"),
    2376: ("Docker API (TLS)", "medium"),
    3306: ("MySQL/MariaDB", "medium"),
    5432: ("PostgreSQL", "medium"),
    6379: ("Redis", "high"),
    27017: ("MongoDB", "high"),
    9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"),
    5984: ("CouchDB", "medium"),
    5601: ("Kibana", "medium"),
    15672: ("RabbitMQ management", "medium"),
    9000: ("Portainer/SonarQube (common)", "medium"),
    8086: ("InfluxDB", "medium"),
    2181: ("ZooKeeper", "medium"),
}


def _remediation(service: str) -> str:
    return (
        f"Do not expose {service} to untrusted networks; bind to localhost or a private "
        "subnet, enforce authentication, and restrict access via firewall/security groups"
    )


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def scan_ports_for_base_urls(
    base_urls: list[str],
    *,
    timeout: float = 1.5,
    on_progress: Any | None = None,
) -> tuple[list[DiagnosisFinding], dict[str, Any]]:
    findings: list[DiagnosisFinding] = []
    stats: dict[str, Any] = {
        "hosts": 0,
        "ports_scanned": 0,
        "open_sensitive": 0,
        "issues": 0,
        "by_severity": {"high": 0, "medium": 0, "low": 0, "info": 0},
    }
    seen_hosts: set[str] = set()

    for base in base_urls:
        base = (base or "").strip().rstrip("/")
        if not base:
            continue
        host = urlparse(base).hostname
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        stats["hosts"] += 1

        for port, (service, severity) in SENSITIVE_PORTS.items():
            stats["ports_scanned"] += 1
            if not _is_open(host, port, timeout):
                continue
            stats["open_sensitive"] += 1
            stats["issues"] += 1
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += 1
            findings.append(
                DiagnosisFinding(
                    severity=severity,
                    message=f"[7-4] Sensitive port open: {service} ({port}) on {host}",
                    evidence={
                        "rule_id": "7-4-weak-security",
                        "source": "port_scan",
                        "engine": "socket",
                        "check_type": "open_sensitive_port",
                        "reason": f"{service} port {port} is reachable",
                        "base_url": f"{host}:{port}",
                        "url": f"{host}:{port}",
                        "label": f"{host}:{port}",
                        "host": host,
                        "port": port,
                        "service": service,
                        "remediation": _remediation(service),
                    },
                )
            )
        if on_progress:
            on_progress(endpoint_id=host)

    return findings, stats
