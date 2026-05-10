from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from viper.generator.context.function_selector import (
    VulnerableFunctionCandidate,
)
from viper.generator.context.snippet_selector import UsageSnippet


logger = logging.getLogger("viper")


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


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str:
        ...


class PoCGenerator:
    def __init__(self, llm_client: LLMClient, prompt_builder=None):
        from viper.generator.prompt.poc_generation_prompt import (
            PoCPromptBuilder,
        )

        self.llm_client = llm_client
        self.prompt_builder = prompt_builder or PoCPromptBuilder()

    def generate(self, context: PoCGenerationContext) -> GeneratedPoC:
        logger.info("=" * 80)
        logger.info("[PoCGenerator] PoC generation started")
        logger.info(
            f"[PoCGenerator] Package: "
            f"{context.package_name}@{context.package_version}"
        )
        logger.info(
            f"[PoCGenerator] Vulnerability Type: {context.vuln_type}"
        )
        logger.info(
            f"[PoCGenerator] Target Function: "
            f"{context.vulnerable_function.name}"
        )

        prompt = self.prompt_builder.build(context)

        logger.info(
            f"[PoCGenerator] Prompt length: {len(prompt)} chars"
        )

        response = self.llm_client.generate(prompt)

        logger.info(
            f"[PoCGenerator] Raw response length: "
            f"{len(response)} chars"
        )

        data = self._parse_json_response(response)

        code = data.get("code", "")
        filename = data.get("filename", "poc.js")
        explanation = data.get("explanation", "")

        logger.info(
            f"[PoCGenerator] Parsed filename: {filename}"
        )

        self._validate_generated_code(code)

        logger.info("[PoCGenerator] Validation passed")

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

        logger.info(
            f"[PoCGenerator] Saving PoC to: {file_path}"
        )

        file_path.write_text(
            generated.code,
            encoding="utf-8",
        )

        return file_path

    def _parse_json_response(self, response: str) -> dict:
        response = response.strip()

        logger.info("[PoCGenerator] Parsing LLM response")

        try:
            parsed = json.loads(response)

            logger.info(
                "[PoCGenerator] Direct JSON parsing succeeded"
            )

            return parsed

        except json.JSONDecodeError:
            logger.warning(
                "[PoCGenerator] Direct JSON parsing failed"
            )

        match = re.search(r"\{[\s\S]*\}", response)

        if not match:
            logger.error(
                "[PoCGenerator] JSON block not found in response"
            )

            raise ValueError(
                f"LLM response does not contain JSON:\n{response}"
            )

        try:
            parsed = json.loads(match.group(0))

            logger.info(
                "[PoCGenerator] Regex JSON extraction succeeded"
            )

            return parsed

        except json.JSONDecodeError as e:
            logger.error(
                "[PoCGenerator] Extracted JSON is invalid"
            )

            raise ValueError(
                f"Invalid JSON from LLM:\n{response}"
            ) from e

    def _validate_generated_code(self, code: str) -> None:
        logger.info("[PoCGenerator] Validating generated code")

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
                logger.error(
                    f"[PoCGenerator] Forbidden pattern detected: "
                    f"{pattern}"
                )

                raise ValueError(
                    f"Generated PoC contains forbidden pattern: "
                    f"{pattern}"
                )

        if "POC_SUCCESS" not in code:
            logger.error(
                "[PoCGenerator] Missing POC_SUCCESS marker"
            )

            raise ValueError(
                "Generated PoC must contain POC_SUCCESS marker."
            )

        if "POC_FAILED" not in code:
            logger.error(
                "[PoCGenerator] Missing POC_FAILED marker"
            )

            raise ValueError(
                "Generated PoC must contain POC_FAILED marker."
            )

        logger.info(
            "[PoCGenerator] Generated code validation completed"
        )