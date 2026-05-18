from __future__ import annotations

from .failure_analyzer import FailureInfo


# 취약점 유형별 oracle 충족 조건
# validator.py의 oracle 판정 기준과 1:1 대응
# 통합 시 oracle 조건이 바뀌면 같이 수정 필요!!!
ORACLE_HINTS: dict[str, str] = {
    "Prototype Pollution": (
        "stdout에 'POC_SUCCESS'와 'exploited' 문자열이 모두 출력되어야 합니다.\n"
        "__proto__.exploited 또는 constructor.prototype.exploited 속성을 실제로 주입하세요.\n"
        "주입 후 반드시 console.log('POC_SUCCESS') 및 exploited 값을 출력하세요."
    ),
    "ReDoS": (
        "실행 시간이 1500ms를 초과해야 합니다.\n"
        "카타스트로픽 백트래킹을 유발하는 입력 패턴을 사용하세요.\n"
        "stdout에 'POC_SUCCESS'를 출력하세요."
    ),
    "Command Injection": (
        "stdout에 'POC_SUCCESS'가 출력되고 /usr/bin/genpoc 파일이 생성되어야 합니다.\n"
        "명령어 인젝션 payload에 '/usr/bin/genpoc' 실행 구문을 포함하세요."
    ),
    "Path Traversal": (
        "stdout에 'POC_SUCCESS'와 '/flag.txt' 문자열이 모두 출력되어야 합니다.\n"
        "페이로드에 '../' 경로 순회 패턴을 포함하고 /flag.txt 읽기를 시도하세요."
    ),
    "Code Injection": (
        "stderr에 'seteuid(42)'가 출력되고 stdout에 'POC_SUCCESS'가 있어야 합니다.\n"
        "process.seteuid(42) 호출이 포함된 페이로드를 사용하세요."
    ),
}


class OracleRefiner:
    name = "OracleRefiner"

    def refine(
        self,
        original_prompt: str,
        previous_poc_code: str,
        failure_info: FailureInfo,
    ) -> str:

        # oracle_type 기반으로 힌트 선택, 없으면 범용 메시지 사용
        oracle_hint = ORACLE_HINTS.get(
            failure_info.oracle_type,
            "oracle 조건을 충족하는 payload를 사용하세요. stdout에 'POC_SUCCESS'를 출력하세요.",
        )

        return f"""
{original_prompt}

이전 PoC는 실행되었지만 취약점별 oracle 검증을 통과하지 못했습니다.

[이전 PoC 코드]
{previous_poc_code}

[Oracle 실패 이유]
{failure_info.error_message}

[oracle 충족 조건 — {failure_info.oracle_type}]
{oracle_hint}

[수정 요구사항]
- 위 oracle 조건을 반드시 충족하는 payload로 수정하세요.
- 단순 실행 성공이 아니라 oracle 조건을 만족해야 합니다.
- 결과를 시뮬레이션하거나 하드코딩하지 마세요.
- 설명 없이 실행 가능한 exploit 코드만 출력하세요.
""".strip()