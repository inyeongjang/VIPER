from __future__ import annotations
from base_client import BaseLLMClient


class LLMCallError(Exception):
    """LLM 호출 실패 시 raise. core/errors.py로 이동 가능."""
    pass


class LLMService:
    """
    LLM 호출 흐름 제어.
    각 모듈(vuln_type_classifier, function_selector 등)은
    이 클래스의 call() 메서드만 호출하면 됨.

    - 모델 선택
    - 재시도 (빈 응답 / 오류 시)
    - 모델 교체 (switch_model)
    """

    def __init__(
        self,
        client: BaseLLMClient,
        default_model: str="mistral:latest",
        max_retries: int = 3,
    ):
        """
        Args:
            client:        BaseLLMClient 구현체 (OllamaClient 등)
            default_model: 기본 모델명 (예: "mistral:latest")
            max_retries:   빈 응답/오류 시 최대 재시도 횟수 (기본값: 3)
        """
        self.client = client
        self.default_model = default_model
        self.max_retries = max_retries

    def call(self, prompt: str, model: str | None = None) -> str:
        """
        프롬프트를 받아 LLM 응답 반환.
        빈 응답이거나 예외 발생 시 max_retries까지 재시도.

        Args:
            prompt: 완성된 프롬프트 문자열
            model:  사용할 모델명. None이면 default_model 사용.

        Returns:
            LLM 응답 문자열 (strip 처리됨)

        Raises:
            LLMCallError: max_retries 초과 또는 계속 빈 응답
        """
        target_model = model or self.default_model
        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = self.client.generate(prompt, target_model)
                if response.strip():
                    return response.strip()
                # 빈 응답 → 재시도
                print(f"[LLMService] Empty response (attempt {attempt + 1}/{self.max_retries}), retrying...")
            except Exception as e:
                last_error = e
                print(f"[LLMService] Error on attempt {attempt + 1}/{self.max_retries}: {e}")

        if last_error:
            raise LLMCallError(
                f"LLM call failed after {self.max_retries} retries: {last_error}"
            )
        raise LLMCallError(
            f"LLM returned empty response after {self.max_retries} retries."
        )

    def switch_model(self, model: str) -> None:
        """
        default_model 교체.
        VEX 태그 생성 시 UNDER_INVESTIGATION 케이스에서
        Qwen2.5 14B → Llama 3 70B로 escalate할 때 사용.

        Args:
            model: 교체할 모델명 (예: "llama3:70b")
        """
        self.default_model = model

    @property
    def current_model(self) -> str:
        """현재 default_model 반환."""
        return self.default_model


# ── 테스트/개발용 Mock ──────────────────────────────────────────────────────
class MockLLMClient(BaseLLMClient):
    """
    실제 Ollama 없이 테스트할 때 사용하는 Mock 클라이언트.
    고정 응답 또는 호출별 응답 목록을 설정할 수 있음.

    사용 예시:
        client = MockLLMClient(responses=["Prototype Pollution", '["merge", "mergeWith"]'])
        service = LLMService(client=client, default_model="mock")
    """

    def __init__(self, responses: list[str] | None = None, default: str = "mock response"):
        """
        Args:
            responses: 순서대로 반환할 응답 목록. 소진되면 default 반환.
            default:   responses 소진 후 반환할 기본 응답.
        """
        self._responses = list(responses) if responses else []
        self._default = default
        self._call_count = 0

    def generate(self, prompt: str, model: str) -> str:
        self._call_count += 1
        if self._responses:
            return self._responses.pop(0)
        return self._default

    @property
    def call_count(self) -> int:
        """총 호출 횟수 확인용."""
        return self._call_count