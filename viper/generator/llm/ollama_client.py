import json
import logging
from typing import List

import requests

from viper.generator.prompt.function_ranking_prompt import build_ranking_prompt


logger = logging.getLogger("viper.llm.ollama")


class OllamaLLMClient:
    def __init__(self, model: str = "llama3.2:3b", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def rank_functions(
        self,
        exports: list[dict],
        cve_report: str,
        vuln_type: str,
        top_k: int,
    ) -> List[dict]:
        prompt = build_ranking_prompt(exports, cve_report, vuln_type, top_k)

        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0},
                },
                timeout=120,
            )
        except requests.RequestException as e:
            logger.error("[Ollama] request exception: %s", e)
            return []

        if response.status_code != 200:
            logger.error("[Ollama] request failed: %s", response.status_code)
            logger.debug(response.text)
            return []

        text = response.json().get("response", "")

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.error("[Ollama] invalid JSON response, skipped")
            logger.debug(text)
            return []

        if isinstance(parsed, dict):
            if "results" in parsed:
                parsed = parsed["results"]
            elif "exportedFunctionCandidates" in parsed:
                parsed = parsed["exportedFunctionCandidates"]
            elif "candidates" in parsed:
                parsed = parsed["candidates"]
            else:
                parsed = [parsed]

        if not isinstance(parsed, list):
            logger.error("[Ollama] response is not a list, skipped")
            logger.debug(text)
            return []

        return [item for item in parsed if isinstance(item, dict)]

    def generate(self, prompt: str) -> str:
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0},
                },
                timeout=120,
            )
        except requests.RequestException as e:
            logger.exception("Ollama request failed")
            raise RuntimeError(f"Ollama request failed: {e}") from e

        if response.status_code != 200:
            logger.error("Ollama request failed: %s", response.status_code)
            logger.debug(response.text)
            raise RuntimeError(f"Ollama request failed: {response.status_code}\n{response.text}")

        return response.json().get("response", "")