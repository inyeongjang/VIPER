from llm_service import LLMService


KEYWORD_MAP = {
    "Prototype Pollution": ["prototype", "__proto__", "constructor", "pollution"],
    "Path Traversal": ["path traversal", "directory traversal", "../", "arbitrary file"],
    "Command Injection": ["command injection", "shell", "exec", "spawn", "os command"],
    "Code Injection": ["code injection", "eval", "vm.runin", "arbitrary code"],
    "ReDoS": ["redos", "regular expression", "regex", "catastrophic backtracking"],
}


class VulnTypeClassifier:
    VULN_TYPES = [
        "Path Traversal",
        "Prototype Pollution",
        "Command Injection",
        "Code Injection",
        "ReDoS",
        "Unknown",
    ]

    def __init__(self, llm_service: LLMService):
        self.llm_service = llm_service

    def classify(self, cve_description: str) -> str:
        result = self._keyword_classify(cve_description)
        if result:
            print(f"[VulnTypeClassifier] 키워드 매핑 성공: {result}")
            return result

        print("[VulnTypeClassifier] 키워드 매핑 실패 → LLM 분류 시도")
        result = self._llm_classify(cve_description)
        print(f"[VulnTypeClassifier] LLM 분류 결과: {result}")
        return result

    def _keyword_classify(self, description: str) -> str | None:
        desc_lower = description.lower()
        for vuln_type, keywords in KEYWORD_MAP.items():
            if any(kw in desc_lower for kw in keywords):
                return vuln_type
        return None

    def _llm_classify(self, description: str) -> str:
        prompt = (
            "Classify the following CVE description into exactly one of these types:\n"
            "[Path Traversal, Prototype Pollution, Command Injection, Code Injection, ReDoS, Unknown]\n\n"
            "Rules:\n"
            "- Output ONLY the type name, nothing else\n"
            "- Do not explain, do not add punctuation\n"
            "- If the description is too vague or unrelated, output Unknown\n\n"
            f"CVE description: {description}"
        )

        try:
            response = self.llm_service.call(prompt, model="mistral:latest")
            return self._parse_response(response)
        except Exception as e:
            print(f"[VulnTypeClassifier] LLM 호출 실패: {e}")
            return "Unknown"

    def _parse_response(self, response: str) -> str:
        cleaned = response.strip().strip("\"'.,")

        for vuln_type in self.VULN_TYPES:
            if vuln_type.lower() == cleaned.lower():
                return vuln_type

        for vuln_type in self.VULN_TYPES:
            if vuln_type.lower() in cleaned.lower():
                return vuln_type

        print(f"[VulnTypeClassifier] 파싱 실패 — LLM 응답: '{response}'")
        return "Unknown"