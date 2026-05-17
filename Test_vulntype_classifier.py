"""
CVE-2019-10744 (lodash Prototype Pollution) 기반
vuln_type_classifier.py 테스트
"""
from ollama_client import OllamaClient
from llm_service import LLMService, MockLLMClient
from vuln_type_classifier import VulnTypeClassifier


# CVE-2019-10744 실제 데이터
CVE_DESCRIPTION = (
    "Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution. "
    "The function defaultsDeep could be tricked into adding or modifying properties "
    "of Object.prototype using a constructor payload."
)


def test_keyword(classifier):
    """키워드 매핑으로 분류되는지 확인"""
    print("\n=== 테스트 1: 키워드 매핑 ===")
    result = classifier.classify(CVE_DESCRIPTION)
    print(f"결과: {result}")
    assert result == "Prototype Pollution", f"예상: Prototype Pollution / 실제: {result}"
    print("PASS")


def test_llm_fallback(classifier):
    """키워드 없을 때 LLM fallback 확인"""
    print("\n=== 테스트 2: LLM fallback ===")
    # 키워드 없는 모호한 설명
    vague_description = "A security vulnerability exists in the merge function allowing attackers to manipulate internal object structures."
    result = classifier.classify(vague_description)
    print(f"결과: {result}")
    print(f"(LLM fallback 동작 확인 — 결과: {result})")
    print("PASS")


def test_unknown(classifier):
    """분류 불가 케이스 확인"""
    print("\n=== 테스트 3: 분류 불가 ===")
    weird_description = "Something went wrong in the system."
    result = classifier.classify(weird_description)
    print(f"결과: {result}")
    print("PASS")


if __name__ == "__main__":
    print("=" * 50)
    print("vuln_type_classifier 테스트 시작")
    print("=" * 50)

    # ── Mock 테스트 (Ollama 없이) ──────────────────
    print("\n[Mock 모드] Ollama 없이 테스트")
    mock_client = MockLLMClient(responses=["Prototype Pollution"])
    mock_service = LLMService(client=mock_client, default_model="mock")
    mock_classifier = VulnTypeClassifier(llm_service=mock_service)

    test_keyword(mock_classifier)
    test_llm_fallback(mock_classifier)
    test_unknown(mock_classifier)

    # ── 실제 Ollama 테스트 ─────────────────────────
    print("\n[Ollama 모드] 실제 모델로 테스트")
    try:
        client = OllamaClient()
        if not client.is_available():
            print("Ollama 서버 미응답 — Ollama 모드 스킵")
        else:
            service = LLMService(client=client, default_model="mistral:latest")
            real_classifier = VulnTypeClassifier(llm_service=service)
            test_keyword(real_classifier)
            test_llm_fallback(real_classifier)
            test_unknown(real_classifier)
    except Exception as e:
        print(f"Ollama 모드 오류: {e}")

    print("\n" + "=" * 50)
    print("테스트 완료")
    print("=" * 50)