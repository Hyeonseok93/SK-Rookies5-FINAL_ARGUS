"""llm_interpret.py — Phase 4: LLM이 1차 탐지된 이상 징후를 해석해 최종 확정

Ported from ARGUS_Backend/scanners/param_manipulation/classifier.py (Phase 4 부분).

이 모듈이 Phase 4로 뒤에 위치하는 이유:
    ARGUS_Backend에서는 원래 LLM이 퍼징 "전"에 파라미터 이름만 보고 분류했다.
    탐지 성공 여부 자체가 LLM 호출에 걸려 있었고, 거기에 request timeout이
    없어서 Ollama 응답이 지연되자 celery 워커가 수 시간째 멈추는 사고가 있었다.
    이 모듈은 compare.py(Phase 3, 규칙 기반, LLM 미사용)가 이미 탐지한
    RawFinding만 해석하므로, LLM이 죽거나 느려도 "탐지 자체"는 영향받지 않는다.

동작:
    - ANTHROPIC_API_KEY 환경변수가 있으면 Claude API 사용
    - 없으면 Ollama 로컬 서버 사용 (config의 ollama_base_url/ollama_model)
    - 연결 실패/응답 실패/타임아웃 시 즉시 규칙 기반 폴백으로 전환 —
      RawFinding을 compare.py가 원래 만들던 것과 동일한 형태의 DiagnosisFinding으로
      승격만 하고 LLM 설명 없이 반환한다 (findings 유실 없음).
    - httpx.Timeout을 명시해 Ollama 호출이 무한 대기하지 않도록 한다
      (이 부분이 ARGUS_Backend 사고의 근본 원인을 고친 지점).
"""

from __future__ import annotations

import json
import logging
import os
import re
from itertools import islice
from typing import Any, Iterator

from diagnosis.result import DiagnosisFinding

from .compare import SEVERITY, RawFinding

logger = logging.getLogger(__name__)

# 백엔드별 청크 크기 — Ollama는 body 포함 시 입력 토큰이 무거우므로 작게 유지
_CHUNK_SIZE: dict[str, int] = {
    "claude": 20,
    "ollama": 5,
}

# 백엔드별 body 미리보기 크기
_BODY_PREVIEW_LEN: dict[str, int] = {
    "claude": 500,
    "ollama": 200,
}

# Ollama 타임아웃 설정 (초)
_OLLAMA_TIMEOUT_CONNECT = 5.0
_OLLAMA_TIMEOUT_READ = 120.0
_OLLAMA_TIMEOUT_WRITE = 10.0
_OLLAMA_TIMEOUT_POOL = 5.0


def interpret_findings(
    raw_findings: list[RawFinding],
    *,
    ollama_base_url: str = "http://localhost:11434",
    ollama_model: str = "qwen2.5:7b",
) -> list[DiagnosisFinding]:
    """RawFinding 목록을 LLM(또는 실패 시 규칙 기반)으로 해석해 DiagnosisFinding으로 확정한다."""
    if not raw_findings:
        return []

    llm_client = _build_llm_client(ollama_base_url=ollama_base_url, ollama_model=ollama_model)
    backend = llm_client[0]

    if backend == "fallback":
        return [_promote(rf) for rf in raw_findings]

    chunk_size = _CHUNK_SIZE[backend]
    findings: list[DiagnosisFinding] = []
    for chunk in _chunks(raw_findings, chunk_size):
        findings.extend(_call_llm(llm_client, chunk))

    logger.info("[1-3 Phase 4] LLM 해석 완료 — 입력 %d건 → 확정 %d건", len(raw_findings), len(findings))
    return findings


def promote_without_llm(raw_findings: list[RawFinding]) -> list[DiagnosisFinding]:
    """LLM을 아예 호출하지 않고 규칙 기반으로만 확정한다 (config로 LLM 비활성화 시 사용)."""
    return [_promote(rf) for rf in raw_findings]


def _build_llm_client(*, ollama_base_url: str, ollama_model: str) -> tuple:
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        try:
            import anthropic

            logger.info("[1-3 Phase 4] LLM 백엔드: Claude API")
            return ("claude", anthropic.Anthropic(api_key=anthropic_key))
        except ImportError:
            logger.warning("anthropic 패키지 없음 — Ollama로 전환")

    try:
        import httpx
        from openai import OpenAI

        client = OpenAI(
            base_url=f"{ollama_base_url}/v1",
            api_key="ollama",
            timeout=httpx.Timeout(
                connect=_OLLAMA_TIMEOUT_CONNECT,
                read=_OLLAMA_TIMEOUT_READ,
                write=_OLLAMA_TIMEOUT_WRITE,
                pool=_OLLAMA_TIMEOUT_POOL,
            ),
        )

        with httpx.Client(timeout=_OLLAMA_TIMEOUT_CONNECT) as probe:
            probe.get(f"{ollama_base_url}/api/tags")

        logger.info("[1-3 Phase 4] LLM 백엔드: Ollama (%s, 모델: %s)", ollama_base_url, ollama_model)
        return ("ollama", client, ollama_model)

    except Exception as e:
        logger.warning("Ollama 연결 실패 (%s): %s — 규칙 기반 폴백 사용", ollama_base_url, e)
        return ("fallback", None)


def _call_llm(llm_client: tuple, chunk: list[RawFinding]) -> list[DiagnosisFinding]:
    backend = llm_client[0]
    diff_list = [_build_diff_summary(i, rf, backend) for i, rf in enumerate(chunk)]

    prompt = f"""\
당신은 웹 보안 취약점 분석 전문가입니다.
다음은 파라미터 조작 테스트 결과입니다. 각 항목에 대해 아래를 판단하세요.

판단 기준:
1. is_vulnerable: 실제 취약점인지 (true/false)
   - true  조건: 권한 없는 요청 성공 / 타인 데이터 노출 / 서버가 조작값을 수용
   - false 조건: 단순 크기 변화 / 에러 메시지 차이 / 정상 검증 후 거부
2. category: PRICE | PRIVILEGE | IDOR | STATUS | ENUM | UNKNOWN
3. severity: high | medium | low
4. description: 한국어로 취약점 설명 (2문장 이내)
5. recommendation: 한국어로 개발자 대상 조치 방안 (1문장)

반드시 JSON 배열로만 응답하세요. 다른 텍스트 없이.

출력 형식:
[{{"index": 0, "is_vulnerable": true, "category": "PRIVILEGE", "severity": "high", "description": "설명", "recommendation": "조치 방안"}}]

입력:
{json.dumps(diff_list, ensure_ascii=False)}
"""

    try:
        if backend == "claude":
            client = llm_client[1]
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text = resp.content[0].text
        else:  # ollama — timeout은 클라이언트 생성 시 이미 적용됨
            client, model = llm_client[1], llm_client[2]
            resp = client.chat.completions.create(
                model=model,
                max_tokens=1024,
                temperature=0,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text = resp.choices[0].message.content

        json_match = re.search(r"\[.*\]", raw_text, re.DOTALL)
        results = json.loads(json_match.group() if json_match else raw_text)
        index_map = {r["index"]: r for r in results}

    except Exception as e:
        logger.warning("[1-3 Phase 4] LLM 호출/파싱 실패: %s — 규칙 기반 폴백으로 전환", e)
        return [_promote(rf) for rf in chunk]

    output: list[DiagnosisFinding] = []
    for i, rf in enumerate(chunk):
        r = index_map.get(i)
        if not r or not r.get("is_vulnerable", False):
            continue
        category = r.get("category", rf.category)
        severity = r.get("severity", SEVERITY.get(rf.anomaly_type, "medium"))
        description = r.get("description", "")
        recommendation = r.get("recommendation", "")
        output.append(_build_finding(rf, category=category, severity=severity, description=description, recommendation=recommendation))

    return output


def _promote(rf: RawFinding) -> DiagnosisFinding:
    """LLM 없이 RawFinding을 그대로 DiagnosisFinding으로 승격 (기존 compare.py 동작과 동일한 message/evidence)."""
    return _build_finding(
        rf,
        category=rf.category,
        severity=SEVERITY.get(rf.anomaly_type, "medium"),
        description="",
        recommendation="",
    )


def _build_finding(
    rf: RawFinding,
    *,
    category: str,
    severity: str,
    description: str,
    recommendation: str,
) -> DiagnosisFinding:
    ep = rf.ep
    message = (
        f"[{rf.anomaly_type}] {ep.method} {ep.path} — `{rf.param_name}` ({rf.param_in}, {category}) "
        f"= {rf.payload_value!r}: {rf.anomaly_detail}"
    )
    if description:
        message += f" — {description}"

    evidence: dict[str, Any] = {
        "rule_id": f"1-3-{rf.anomaly_type.lower().replace('_', '-')}",
        "engine": "httpx",
        "endpoint_id": ep.endpoint_id,
        "method": ep.method,
        "path": ep.path,
        "base_url": ep.base_url,
        "param_in": rf.param_in,
        "param_name": rf.param_name,
        "category": category,
        "payload": rf.payload_value,
        "payload_description": rf.payload_description,
        "anomaly_type": rf.anomaly_type,
        "baseline_status": rf.baseline_status,
        "test_status": rf.test_status,
    }
    if description:
        evidence["llm_description"] = description
    if recommendation:
        evidence["llm_recommendation"] = recommendation

    return DiagnosisFinding(severity=severity, message=message, evidence=evidence)


def _build_diff_summary(index: int, rf: RawFinding, backend: str) -> dict:
    preview_len = _BODY_PREVIEW_LEN.get(backend, 200)
    baseline_preview = rf.baseline_body[:preview_len].decode("utf-8", errors="replace") if rf.baseline_body else ""
    test_preview = rf.test_body[:preview_len].decode("utf-8", errors="replace") if rf.test_body else ""

    return {
        "index": index,
        "url": f"{rf.ep.base_url}{rf.ep.path}",
        "method": rf.ep.method,
        "param_name": rf.param_name,
        "payload_used": rf.payload_value,
        "payload_description": rf.payload_description,
        "baseline_status": rf.baseline_status,
        "test_status": rf.test_status,
        "anomaly_type": rf.anomaly_type,
        "anomaly_detail": rf.anomaly_detail,
        "baseline_body": baseline_preview,
        "test_body": test_preview,
    }


def _chunks(lst: list, size: int) -> Iterator[list]:
    it = iter(lst)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk
