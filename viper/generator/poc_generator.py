from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from viper.generator.llm.base_client import LLMClient

from viper.generator.context.function_selector import (
    VulnerableFunctionCandidate,
)
from viper.generator.context.snippet_selector import UsageSnippet


@dataclass
class TaintPath:
    source: str
    sink: str
    steps: list[str]


@dataclass
class PoCGenerationContext:
    package_name: str
    package_version: str | None
    vuln_type: str
    vulnerable_function: VulnerableFunctionCandidate
    usage_snippets: list[UsageSnippet]
    skeleton: str | None
    few_shot_examples: list[str]
    taint_path: TaintPath | None
    cve_report: str


@dataclass
class GeneratedPoC:
    code: str
    filename: str
    explanation: str




class PoCGenerator:
    def __init__(self, llm_client: LLMClient, prompt_builder=None):
        from viper.generator.prompt.poc_generation_prompt import (
            PoCPromptBuilder,
        )

        self.llm_client = llm_client
        self.prompt_builder = prompt_builder or PoCPromptBuilder()

    def generate(self, context: PoCGenerationContext) -> GeneratedPoC:
        prompt = self.prompt_builder.build(context)

        response = self.llm_client.generate(prompt)

        data = self._parse_json_response(response)

        code = data.get("code", "")
        filename = data.get("filename", "poc.js")
        explanation = data.get("explanation", "")

        self._validate_generated_code(code)

        return GeneratedPoC(
            code=code,
            filename=filename,
            explanation=explanation,
        )

    def save(
        self,
        generated: GeneratedPoC,
        output_dir: str | Path,
    ) -> Path:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        file_path = output_path / generated.filename

        file_path.write_text(
            generated.code,
            encoding="utf-8",
        )

        return file_path

    def _parse_json_response(self, response: str) -> dict:
        response = response.strip()

        try:
            parsed = json.loads(response)

            return parsed

        except json.JSONDecodeError:
            pass

        match = re.search(r"\{[\s\S]*\}", response)

        if not match:
            raise ValueError(
                f"LLM response does not contain JSON:\n{response}"
            )

        try:
            parsed = json.loads(match.group(0))

            return parsed

        except json.JSONDecodeError as e:
            raise ValueError(
                f"Invalid JSON from LLM:\n{response}"
            ) from e

    def _validate_generated_code(self, code: str) -> None:
        if not code.strip():
            raise ValueError(
                "Generated PoC code is empty."
            )

        forbidden_patterns = [
            "rm -rf",
            "format c:",
            "del /f /s /q",
            "curl http",
            "wget http",
            "fetch(",
            "XMLHttpRequest",
        ]

        lowered = code.lower()

        for pattern in forbidden_patterns:
            if pattern in lowered:
                raise ValueError(
                    f"Generated PoC contains forbidden pattern: "
                    f"{pattern}"
                )

        if "POC_SUCCESS" not in code:
            raise ValueError(
                "Generated PoC must contain POC_SUCCESS marker."
            )

        if "POC_FAILED" not in code:
            raise ValueError(
                "Generated PoC must contain POC_FAILED marker."
            )