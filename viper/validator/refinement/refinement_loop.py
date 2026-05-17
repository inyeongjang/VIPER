from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from failure_analyzer import (
    ExecutionResult,
    ValidationResult,
    FailureInfo,
    FailureAnalyzer,
)
from refiner_selector import RefinerSelector


@dataclass
class RefinementHistory:
    """매 iteration의 정제 이력. 디버깅 및 결과 리포트용."""
    iteration:        int
    failure_type:     str
    selected_refiner: str
    refined_prompt:   str


@dataclass
class RefinementResult:
    """
    RefinementLoop.run() 최종 반환값.

    final_status:
        "PASS"               → oracle + sanity 모두 통과
        "FAILED"             → max_iter 소진, 끝내 실패
        "NEEDS_MANUAL_REVIEW"→ 동일 실패 유형이 repeated_failure_limit 회 연속
    """
    final_status:            str
    final_poc_code:          str
    final_prompt:            str
    last_failure_info:       FailureInfo | None
    last_validation_result:  ValidationResult | None
    history:                 list[RefinementHistory] = field(default_factory=list)


class RefinementLoop:
    def __init__(
        self,
        generator,
        validator,
        max_iter: int = 20,
        repeated_failure_limit: int = 3,
    ):
        self.generator              = generator
        self.validator              = validator
        self.max_iter               = max_iter
        self.repeated_failure_limit = repeated_failure_limit
        self.failure_analyzer       = FailureAnalyzer()
        self.refiner_selector       = RefinerSelector()

    def run(
        self,
        original_prompt: str,
        initial_poc_code: str,
    ) -> RefinementResult:

        current_prompt   = original_prompt
        current_poc_code = initial_poc_code
        history: list[RefinementHistory] = []

        recent_failures: deque[str] = deque(maxlen=self.repeated_failure_limit)

        last_failure_info      = None
        last_validation_result = None

        for iteration in range(1, self.max_iter + 1):

            exec_result, val_result = self.validator.validate(current_poc_code)
            last_validation_result  = val_result

            # PASS: 루프 종료
            if val_result.validation_result == "PASS":
                return RefinementResult(
                    final_status="PASS",
                    final_poc_code=current_poc_code,
                    final_prompt=current_prompt,
                    last_failure_info=None,
                    last_validation_result=val_result,
                    history=history,
                )

            # 실패 원인 분석
            failure_info      = self.failure_analyzer.analyze(exec_result, val_result)
            last_failure_info = failure_info
            recent_failures.append(failure_info.failure_type)

            # 동일 실패 연속: 수동 검토 전환
            # deque가 꽉 찼고 모두 같은 유형이면 자동 정제로는 해결 불가 판단
            if (
                len(recent_failures) == self.repeated_failure_limit
                and len(set(recent_failures)) == 1
            ):
                return RefinementResult(
                    final_status="NEEDS_MANUAL_REVIEW",
                    final_poc_code=current_poc_code,
                    final_prompt=current_prompt,
                    last_failure_info=last_failure_info,
                    last_validation_result=last_validation_result,
                    history=history,
                )

            # refiner 선택 → 프롬프트 정제
            refiner        = self.refiner_selector.select(failure_info)
            refined_prompt = refiner.refine(
                original_prompt=current_prompt,
                previous_poc_code=current_poc_code,
                failure_info=failure_info,
            )

            history.append(RefinementHistory(
                iteration=iteration,
                failure_type=failure_info.failure_type,
                selected_refiner=refiner.name,
                refined_prompt=refined_prompt,
            ))

            # PoC 재생성
            current_prompt   = refined_prompt
            current_poc_code = self.generator.generate(current_prompt)

        # max_iter 소진
        return RefinementResult(
            final_status="FAILED",
            final_poc_code=current_poc_code,
            final_prompt=current_prompt,
            last_failure_info=last_failure_info,
            last_validation_result=last_validation_result,
            history=history,
        )


# Mock (단독 실행 테스트용)

class MockGenerator:
    """generator 대체용 mock. generate() 호출 횟수에 따라 다른 코드 반환."""

    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str) -> str:
        self.call_count += 1

        if self.call_count == 1:
            # 1회차: 문법 오류 코드
            return "const x = ;"

        # 2회차~: 정상 코드
        return (
            'const _ = require("lodash");\n'
            'console.log("POC_SUCCESS");\n'
            'console.log("exploited=true");'
        )


class MockValidator:
    """validator 대체용 mock. poc_code 내용에 따라 결과 분기."""

    def validate(
        self,
        poc_code: str,
    ) -> tuple[ExecutionResult, ValidationResult]:

        if "const x = ;" in poc_code:
            return (
                ExecutionResult(
                    stdout="",
                    stderr="SyntaxError: Unexpected token",
                    exit_code=1,
                ),
                ValidationResult(
                    validation_result="FAIL",
                    oracle_type="Prototype Pollution",
                    oracle_pass=False,
                    sanity_check_pass=False,
                    validation_reason="PoC 문법 오류로 실행에 실패했습니다.",
                ),
            )

        return (
            ExecutionResult(
                stdout="POC_SUCCESS\nexploited=true",
                stderr="at defaultsDeep (lodash.js:100)",
                exit_code=0,
            ),
            ValidationResult(
                validation_result="PASS",
                oracle_type="Prototype Pollution",
                oracle_pass=True,
                sanity_check_pass=True,
                validation_reason="취약점이 성공적으로 트리거되었습니다.",
            ),
        )


if __name__ == "__main__":
    original_prompt = (
        "CVE-2019-10744 lodash Prototype Pollution PoC를 생성하세요.\n"
        "취약 함수는 defaultsDeep입니다.\n"
        "실행 가능한 JavaScript 코드만 출력하세요."
    )
    initial_poc_code = "const x = ;"

    loop = RefinementLoop(
        generator=MockGenerator(),
        validator=MockValidator(),
        max_iter=20,
        repeated_failure_limit=3,
    )

    result = loop.run(
        original_prompt=original_prompt,
        initial_poc_code=initial_poc_code,
    )

    print("=== Refinement Loop 결과 ===")
    print(f"최종 상태: {result.final_status}")
    print("\n=== 최종 PoC 코드 ===")
    print(result.final_poc_code)
    print("\n=== 반복 이력 ===")
    for item in result.history:
        print("-----")
        print(f"반복 횟수    : {item.iteration}")
        print(f"실패 유형    : {item.failure_type}")
        print(f"선택된 Refiner: {item.selected_refiner}")