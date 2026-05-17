from __future__ import annotations

from failure_analyzer import FailureInfo


class SanityRefiner:
    name = "SanityRefiner"

    def refine(
        self,
        original_prompt: str,
        previous_poc_code: str,
        failure_info: FailureInfo,
    ) -> str:
        return f"""
{original_prompt}

이전 PoC는 실행되었지만 취약 함수 경로를 지나지 못했습니다.

[이전 PoC 코드]
{previous_poc_code}

[Stack Trace]
{failure_info.stack_trace}

[수정 요구사항]
- PoC가 vulnerable function을 직접 호출하거나 취약 호출 경로를 지나도록 수정하세요.
- usage snippet의 함수 호출 방식을 참고하세요.
- 우회 코드가 아니라 실제 취약 함수 경로를 통해 sink에 도달해야 합니다.
- 설명 없이 실행 가능한 exploit 코드만 출력하세요.
""".strip()