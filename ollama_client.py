import json
import requests
from base_client import BaseLLMClient

print("[DEBUG] ollama_client loaded:", __file__)
class OllamaClient(BaseLLMClient):
    """
    Ollama 로컬 서버에 실제 API 호출하는 클라이언트.
    기본적으로 http://localhost:11434 에 떠있는 Ollama 서버와 통신.
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        """
        Args:
            base_url: Ollama 서버 주소 (기본값: http://localhost:11434)
        """
        self.base_url = base_url.rstrip("/")

    def generate(self, prompt: str, model: str) -> str:
        """
        Ollama /api/generate 엔드포인트 호출.
        스트리밍 응답을 줄 단위로 읽어서 누적 후 반환.

        Args:
            prompt: 완성된 프롬프트 문자열
            model:  사용할 모델명 (예: "mistral:latest", "qwen2.5:14b")

        Returns:
            LLM 응답 원문 문자열

        Raises:
            requests.HTTPError: Ollama 서버 응답 오류
            json.JSONDecodeError: 응답 파싱 실패
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        print("[DEBUG] URL:", f"{self.base_url}/api/generate")
        print("[DEBUG] payload:", payload)
        response = requests.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=120,  # 모델 응답이 느릴 수 있으므로 넉넉하게
        )
        response.raise_for_status()

        data = response.json()
        return data.get("response", "")

    def is_available(self) -> bool:
        """
        Ollama 서버가 떠있는지 확인.
        개발/테스트 시작 전 헬스체크용.

        Returns:
            True: 서버 정상, False: 서버 미응답
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.exceptions.ConnectionError:
            return False

    def list_models(self) -> list[str]:
        """
        Ollama에 설치된 모델 목록 반환.

        Returns:
            모델명 리스트 (예: ["mistral:",latest "qwen2.5:14b"])
        """
        response = requests.get(f"{self.base_url}/api/tags", timeout=10)
        response.raise_for_status()
        data = response.json()
        return [model["name"] for model in data.get("models", [])]