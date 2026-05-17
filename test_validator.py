"""
validator.py 테스트
CVE-2019-10744 (lodash Prototype Pollution) 기반
"""
from validator import Validator, ExecutionResult


def make_result(
    stdout="",
    stderr="",
    exit_code=0,
    execution_time_ms=100,
    files_created=None,
    crashed=False,
):
    return ExecutionResult(
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        execution_time_ms=execution_time_ms,
        files_created=files_created or [],
        crashed=crashed,
    )


validator = Validator()
VULN_TYPE = "Prototype Pollution"
FUNCTION_NAME = "defaultsDeep"


def test_pass():
    """정상 트리거 케이스 — PASS 예상"""
    print("\n=== 테스트 1: 정상 트리거 (PASS 예상) ===")
    result = make_result(
        stdout="POC_SUCCESS\nexploited=true",
        stderr=f"at {FUNCTION_NAME} (lodash.js:100)",
    )
    val = validator.validate(result, VULN_TYPE, FUNCTION_NAME)
    print(f"결과: {val.validation_result}")
    print(f"oracle_pass: {val.oracle_pass}")
    print(f"sanity_check_pass: {val.sanity_check_pass}")
    print(f"이유: {val.validation_reason}")
    assert val.validation_result == "PASS"
    print("PASS ✅")


def test_fail_no_oracle():
    """oracle 실패 케이스 — FAIL 예상"""
    print("\n=== 테스트 2: oracle 실패 (FAIL 예상) ===")
    result = make_result(
        stdout="POC_SUCCESS",   # exploited 없음
        stderr=f"at {FUNCTION_NAME} (lodash.js:100)",
    )
    val = validator.validate(result, VULN_TYPE, FUNCTION_NAME)
    print(f"결과: {val.validation_result}")
    print(f"oracle_pass: {val.oracle_pass}")
    print(f"이유: {val.validation_reason}")
    assert val.validation_result == "FAIL"
    print("PASS ✅")


def test_fail_no_sanity():
    """sanity check 실패 케이스 — FAIL 예상"""
    print("\n=== 테스트 3: sanity 실패 (FAIL 예상) ===")
    result = make_result(
        stdout="POC_SUCCESS\nexploited=true",
        stderr="at someOtherFunction (index.js:50)",  # vulnerable function 없음
    )
    val = validator.validate(result, VULN_TYPE, FUNCTION_NAME)
    print(f"결과: {val.validation_result}")
    print(f"sanity_check_pass: {val.sanity_check_pass}")
    print(f"이유: {val.validation_reason}")
    assert val.validation_result == "FAIL"
    print("PASS ✅")


def test_fail_exit_code():
    """exit code 비정상 케이스 — FAIL 예상"""
    print("\n=== 테스트 4: exit code 오류 (FAIL 예상) ===")
    result = make_result(
        stdout="",
        stderr="SyntaxError: Unexpected token",
        exit_code=1,
    )
    val = validator.validate(result, VULN_TYPE, FUNCTION_NAME)
    print(f"결과: {val.validation_result}")
    print(f"이유: {val.validation_reason}")
    assert val.validation_result == "FAIL"
    print("PASS ✅")


def test_fail_poc_failed_marker():
    """POC_FAILED 마커 케이스 — FAIL 예상"""
    print("\n=== 테스트 5: POC_FAILED 마커 (FAIL 예상) ===")
    result = make_result(
        stdout="POC_FAILED\nVulnerability not triggered",
    )
    val = validator.validate(result, VULN_TYPE, FUNCTION_NAME)
    print(f"결과: {val.validation_result}")
    print(f"이유: {val.validation_reason}")
    assert val.validation_result == "FAIL"
    print("PASS ✅")


if __name__ == "__main__":
    print("=" * 50)
    print("validator 테스트 시작")
    print("=" * 50)

    test_pass()
    test_fail_no_oracle()
    test_fail_no_sanity()
    test_fail_exit_code()
    test_fail_poc_failed_marker()

    print("\n" + "=" * 50)
    print("테스트 완료")
    print("=" * 50)