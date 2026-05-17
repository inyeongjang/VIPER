from abc import ABC, abstractmethod


class BaseLLMClient(ABC):
    """
    LLM 호출 인터페이스 공통화.
    Ollama 외 다른 백엔드로 교체 시 이 클래스를 상속해서 generate()만 구현하면 됨.
    """

    @abstractmethod
    def generate(self, prompt: str, model: str) -> str:
        """
        프롬프트를 받아 LLM 응답 문자열 반환.

        Args:
            prompt: 완성된 프롬프트 문자열
            model:  사용할 모델명 (예: "mistral:7b", "qwen2.5:14b")

        Returns:
            LLM 응답 원문 문자열

        Raises:
            NotImplementedError: 하위 클래스에서 반드시 구현 필요
        """
        ...