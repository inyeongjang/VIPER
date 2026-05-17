from typing import Protocol


class LLMClient(Protocol):
    """Unified LLM client protocol used across the generator.

    Implementations may provide both generation (free-text) and ranking
    utilities. Consumers should only call the methods they require.
    """

    def generate(self, prompt: str) -> str:
        """Generate a text response from an input prompt."""
        ...

    def rank_functions(
        self,
        exports: list[dict],
        cve_report: str,
        vuln_type: str,
        top_k: int,
    ) -> list[dict]:
        """Score and rank exported functions given vulnerability context."""
        ...