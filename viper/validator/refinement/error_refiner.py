from __future__ import annotations

from failure_analyzer import FailureInfo


class ErrorRefiner:
    name = "ErrorRefiner"

    def refine(
        self,
        original_prompt: str,
        previous_poc_code: str,
        failure_info: FailureInfo,
    ) -> str:
        return f"""
{original_prompt}

이전 PoC는 문법 오류 또는 실행 오류로 인해 실패했습니다.

[이전 PoC 코드]
{previous_poc_code}

[오류 메시지]
{failure_info.error_message}

[수정 요구사항]
- 문법 오류 또는 실행 오류를 수정하세요.
- 실제 취약 패키지와 취약 함수를 사용하세요.
- 가짜 성공 출력이나 하드코딩된 성공 조건을 사용하지 마세요.
- 설명 없이 실행 가능한 exploit 코드만 출력하세요.
""".strip()