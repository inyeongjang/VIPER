from __future__ import annotations

from .failure_analyzer import FailureInfo
from .error_refiner import ErrorRefiner
from .sanity_refiner import SanityRefiner
from .oracle_refiner import OracleRefiner
from .context_refiner import ContextRefiner


class RefinerSelector:
    def select(self, failure_info: FailureInfo):
        if failure_info.failure_type in (
            "poc_failed_marker",
            "syntax_error",
            "runtime_error",
        ):
            return ErrorRefiner()

        if failure_info.failure_type == "sanity_fail":
            return SanityRefiner()

        if failure_info.failure_type == "oracle_fail":
            return OracleRefiner()

        return ContextRefiner()


if __name__ == "__main__":

    fake_failure = FailureInfo(
        failure_type="syntax_error",
        error_message="SyntaxError: Unexpected token",
        stack_trace="",
        oracle_type="Prototype Pollution",
    )

    selector = RefinerSelector()
    refiner = selector.select(fake_failure)

    print("=== 선택된 Refiner ===")
    print(refiner.name)