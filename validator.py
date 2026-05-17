from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger("viper")


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: int
    files_created: list[str]
    crashed: bool


@dataclass
class ValidationResult:
    validation_result: str      # "PASS" | "FAIL"
    oracle_type: str            # 취약점 유형
    oracle_pass: bool           # oracle 통과 여부
    sanity_check_pass: bool     # vulnerable function 경유 여부
    validation_reason: str      # 판정 근거


# ── Oracle 계층 ────────────────────────────────────────────────────────────

class BaseOracle:
    def check(self, result: ExecutionResult) -> bool:
        raise NotImplementedError


class PrototypePollutionOracle(BaseOracle):
    """
    stdout에 POC_SUCCESS 마커 + exploited 확인
    """
    def check(self, result: ExecutionResult) -> bool:
        return (
            "POC_SUCCESS" in result.stdout and
            "exploited" in result.stdout
        )


class ReDoSOracle(BaseOracle):
    """
    실행 시간 1500ms 초과 확인
    """
    THRESHOLD_MS = 1500

    def check(self, result: ExecutionResult) -> bool:
        return (
            "POC_SUCCESS" in result.stdout and
            result.execution_time_ms > self.THRESHOLD_MS
        )


class CommandInjectionOracle(BaseOracle):
    """
    /usr/bin/genpoc 실행으로 파일 생성 확인
    """
    def check(self, result: ExecutionResult) -> bool:
        return (
            "POC_SUCCESS" in result.stdout and
            any("/usr/bin/genpoc" in f for f in result.files_created)
        )


class PathTraversalOracle(BaseOracle):
    """
    /flag.txt 읽기/쓰기 성공 확인
    """
    def check(self, result: ExecutionResult) -> bool:
        return (
            "POC_SUCCESS" in result.stdout and
            "/flag.txt" in result.stdout
        )


class CodeInjectionOracle(BaseOracle):
    """
    process.seteuid(42) 호출 확인
    """
    def check(self, result: ExecutionResult) -> bool:
        return (
            "POC_SUCCESS" in result.stdout and
            "seteuid(42)" in result.stderr
        )


ORACLE_MAP: dict[str, type[BaseOracle]] = {
    "Prototype Pollution": PrototypePollutionOracle,
    "ReDoS":               ReDoSOracle,
    "Command Injection":   CommandInjectionOracle,
    "Path Traversal":      PathTraversalOracle,
    "Code Injection":      CodeInjectionOracle,
}


# ── Sanity Check ───────────────────────────────────────────────────────────

class SanityChecker:
    """
    stack trace에 vulnerable function 호출 포함 여부 확인.
    포함되지 않으면 취약 경로를 실제로 경유하지 않은 것.
    """

    def check(self, stderr: str, function_name: str) -> bool:
        """
        Args:
            stderr:        실행 stderr (stack trace 포함)
            function_name: vulnerable function 이름

        Returns:
            True: 함수 경유 확인 / False: 미경유
        """
        return function_name in stderr


# ── Validator ──────────────────────────────────────────────────────────────

class Validator:
    """
    oracle + sanity check 조합해서 최종 검증 수행.

    판정 기준:
        oracle_pass == True AND sanity_check_pass == True → PASS
        그 외 → FAIL
    """

    def __init__(self):
        self.sanity_checker = SanityChecker()

    def validate(
        self,
        result: ExecutionResult,
        vuln_type: str,
        function_name: str,
    ) -> ValidationResult:
        """
        Args:
            result:        Docker sandbox 실행 결과
            vuln_type:     취약점 유형 (5가지 중 1개)
            function_name: vulnerable function 이름 (sanity check용)

        Returns:
            ValidationResult
        """
        logger.info("=" * 60)
        logger.info("[Validator] 검증 시작")
        logger.info(f"[Validator] 취약점 유형: {vuln_type}")
        logger.info(f"[Validator] 대상 함수: {function_name}")
        logger.info(f"[Validator] exit_code: {result.exit_code}")
        logger.info(f"[Validator] 실행 시간: {result.execution_time_ms}ms")

        # POC_FAILED 마커 있으면 즉시 FAIL
        if "POC_FAILED" in result.stdout:
            logger.warning("[Validator] POC_FAILED 마커 감지 → 즉시 FAIL")
            return ValidationResult(
                validation_result="FAIL",
                oracle_type=vuln_type,
                oracle_pass=False,
                sanity_check_pass=False,
                validation_reason="POC_FAILED marker detected in stdout.",
            )

        # exit_code 0 아니면 즉시 FAIL
        if result.exit_code != 0:
            logger.warning(f"[Validator] exit_code {result.exit_code} → FAIL")
            return ValidationResult(
                validation_result="FAIL",
                oracle_type=vuln_type,
                oracle_pass=False,
                sanity_check_pass=False,
                validation_reason=f"Non-zero exit code: {result.exit_code}. stderr: {result.stderr[:200]}",
            )

        # oracle 선택
        if vuln_type not in ORACLE_MAP:
            logger.error(f"[Validator] 지원하지 않는 취약점 유형: {vuln_type}")
            return ValidationResult(
                validation_result="FAIL",
                oracle_type=vuln_type,
                oracle_pass=False,
                sanity_check_pass=False,
                validation_reason=f"Unsupported vulnerability type: {vuln_type}",
            )

        oracle = ORACLE_MAP[vuln_type]()
        oracle_pass = oracle.check(result)
        logger.info(f"[Validator] oracle_pass: {oracle_pass}")

        # sanity check
        sanity_pass = self.sanity_checker.check(result.stderr, function_name)
        logger.info(f"[Validator] sanity_check_pass: {sanity_pass}")

        # 최종 판정
        final = "PASS" if (oracle_pass and sanity_pass) else "FAIL"
        reason = self._build_reason(oracle_pass, sanity_pass, result)

        logger.info(f"[Validator] 최종 판정: {final}")
        logger.info(f"[Validator] 판정 근거: {reason}")

        return ValidationResult(
            validation_result=final,
            oracle_type=vuln_type,
            oracle_pass=oracle_pass,
            sanity_check_pass=sanity_pass,
            validation_reason=reason,
        )

    def _build_reason(
        self,
        oracle_pass: bool,
        sanity_pass: bool,
        result: ExecutionResult,
    ) -> str:
        if oracle_pass and sanity_pass:
            return "Vulnerability successfully triggered."

        reasons = []
        if not oracle_pass:
            reasons.append("Oracle failed: expected condition not met in stdout/stderr.")
        if not sanity_pass:
            reasons.append("Sanity failed: vulnerable function not found in stack trace.")
        return " ".join(reasons)