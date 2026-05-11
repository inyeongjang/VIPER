from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ExecutionResult:
    """
    sandbox.py에서 PoC 실행 후 반환하는 실행 결과.

    추후 from pocgen.validator.validator import ExecutionResult 로 교체.
    """
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: int = 0
    files_created: list[str] | None = None
    crashed: bool = False


@dataclass
class ValidationResult:
    """
    validator.py의 Validator.validate()가 반환하는 검증 결과.
    
    추후 from pocgen.validator.validator import ValidationResult 로 교체.
    """
    validation_result: str  # "PASS" or "FAIL"
    oracle_type: str
    oracle_pass: bool
    sanity_check_pass: bool
    validation_reason: str


@dataclass
class FailureInfo:
    """
    FailureAnalyzer.analyze()가 반환하는 실패 원인 분석 결과.

    oracle_type: OracleRefiner가 취약점 유형별 힌트를 생성할 때 사용.
    """
    failure_type: str
    error_message: str
    stack_trace: str
    oracle_type: str = ""


class FailureAnalyzer:
    """
    ExecutionResult + ValidationResult
    -> 실패 원인 분류, FailureInfo 반환
    """

    def analyze(
        self,
        exec_result: ExecutionResult,
        val_result: ValidationResult,
    ) -> FailureInfo:

        stderr = exec_result.stderr or ""
        stdout = exec_result.stdout or ""

        # 검증 성공 -> 정제 과정 X
        if val_result.validation_result == "PASS":
            return FailureInfo(
                failure_type="none",
                error_message="검증에 성공했습니다.",
                stack_trace=stderr,
                oracle_type=val_result.oracle_type,
            )

        # PoC 코드 내부에서 명시적으로 실패를 선언한 경우
        if "POC_FAILED" in stdout:
            return FailureInfo(
                failure_type="poc_failed_marker",
                error_message="stdout에서 POC_FAILED 마커가 감지되었습니다.",
                stack_trace=stderr,
                oracle_type=val_result.oracle_type,
            )

        # 2순위: 문법 오류
        if "SyntaxError" in stderr:
            return FailureInfo(
                failure_type="syntax_error",
                error_message=stderr,
                stack_trace=stderr,
                oracle_type=val_result.oracle_type,
            )

        # 3순위: 런타임 오류 (비정상 종료)
        if exec_result.exit_code != 0:
            return FailureInfo(
                failure_type="runtime_error",
                error_message=stderr or stdout,
                stack_trace=stderr,
                oracle_type=val_result.oracle_type,
            )

        # 4순위: sanity check 실패 (취약 함수 미경유)
        if not val_result.sanity_check_pass:
            return FailureInfo(
                failure_type="sanity_fail",
                error_message=val_result.validation_reason,
                stack_trace=stderr,
                oracle_type=val_result.oracle_type,
            )

        # 5순위: oracle 실패 (취약점 미트리거)
        if not val_result.oracle_pass:
            return FailureInfo(
                failure_type="oracle_fail",
                error_message=val_result.validation_reason,
                stack_trace=stderr,
                oracle_type=val_result.oracle_type,
            )

        # 6순위: 분류 불가
        return FailureInfo(
            failure_type="unknown",
            error_message=val_result.validation_reason,
            stack_trace=stderr,
            oracle_type=val_result.oracle_type,
        )


if __name__ == "__main__":
    analyzer = FailureAnalyzer()

    fake_exec = ExecutionResult(
        stdout="",
        stderr="SyntaxError: Unexpected token",
        exit_code=1,
    )
    fake_val = ValidationResult(
        validation_result="FAIL",
        oracle_type="Prototype Pollution",
        oracle_pass=False,
        sanity_check_pass=False,
        validation_reason="PoC 실행에 실패했습니다.",
    )

    result = analyzer.analyze(fake_exec, fake_val)
    print("=== 실패 원인 분석 결과 ===")
    print(f"실패 유형  : {result.failure_type}")
    print(f"오류 메시지: {result.error_message}")
    print(f"oracle 유형: {result.oracle_type}")