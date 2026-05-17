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

    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def classify(self, cve_description: str) -> str:
        result = self._keyword_classify(cve_description)
        if result:
            return result

        if self.llm_client is None:
            return "Unknown"

        result = self._llm_classify(cve_description)
        return result

    def _keyword_classify(self, description: str) -> str | None:
        desc_lower = description.lower()

        for vuln_type, keywords in KEYWORD_MAP.items():
            if any(keyword in desc_lower for keyword in keywords):
                return vuln_type

        return None

    def _llm_classify(self, description: str) -> str:
        prompt = f"""
Classify the following CVE description into exactly one of these types:
[Path Traversal, Prototype Pollution, Command Injection, Code Injection, ReDoS, Unknown]

Rules:
- Output ONLY the type name, nothing else
- Do not explain
- Do not add punctuation
- If the description is too vague or unrelated, output Unknown

CVE description:
{description}
""".strip()

        try:
            response = self.llm_client.generate(prompt)
            return self._parse_response(response)
        except Exception as e:
            return "Unknown"

    def _parse_response(self, response: str) -> str:
        cleaned = response.strip().strip("\"'.,:")

        for vuln_type in self.VULN_TYPES:
            if vuln_type.lower() == cleaned.lower():
                return vuln_type

        for vuln_type in self.VULN_TYPES:
            if vuln_type.lower() in cleaned.lower():
                return vuln_type

        return "Unknown"