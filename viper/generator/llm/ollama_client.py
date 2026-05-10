import json
from urllib import response
import requests

from viper.generator.prompt.function_ranking_prompt import build_ranking_prompt


class OllamaLLMClient:
    def __init__(
        self,
        model: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def rank_functions(
        self,
        exports: list[dict],
        cve_report: str,
        vuln_type: str,
        top_k: int,
    ) -> list[dict]:
        prompt = build_ranking_prompt(exports, cve_report, vuln_type, top_k)

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

        if response.status_code != 200:
            print(f"[Ollama] request failed: {response.status_code}")
            print(response.text)
            return []

        text = response.json().get("response", "")

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            print("[Ollama] invalid JSON response, skipped:")
            print(text)
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
            print("[Ollama] response is not a list, skipped:")
            print(text)
            return []

        return [item for item in parsed if isinstance(item, dict)]
    

    def generate(self, prompt: str) -> str:
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

        if response.status_code != 200:
            raise RuntimeError(
                f"Ollama request failed: {response.status_code}\n{response.text}"
            )

        return response.json().get("response", "")