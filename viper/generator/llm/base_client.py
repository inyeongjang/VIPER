from typing import Protocol


class LLMClient(Protocol):
    def rank_functions(
        self,
        exports: list[dict],
        cve_report: str,
        vuln_type: str,
        top_k: int,
    ) -> list[dict]:
        ...