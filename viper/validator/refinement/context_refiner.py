from __future__ import annotations

from failure_analyzer import FailureInfo


class ContextRefiner:
    name = "ContextRefiner"

    def refine(
        self,
        original_prompt: str,
        previous_poc_code: str,
        failure_info: FailureInfo,
    ) -> str:
        return f"""
{original_prompt}

이전 PoC 생성은 명확하지 않은 원인으로 실패했습니다.

[이전 PoC 코드]
{previous_poc_code}

[실패 정보]
{failure_info.error_message}

[수정 요구사항]
- vulnerability type, vulnerable function, usage snippet 정보를 다시 반영하세요.
- 함수 호출 인자와 payload 구조를 더 명확히 구성하세요.
- 실제 패키지를 require/import하여 사용하세요.
- 설명 없이 실행 가능한 exploit 코드만 출력하세요.
""".strip()