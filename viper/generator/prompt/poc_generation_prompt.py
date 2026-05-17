import json

from viper.generator.poc_generator import PoCGenerationContext, TaintPath


class PoCPromptBuilder:
    def build(self, context: PoCGenerationContext) -> str:
        return f"""
You are a security research assistant.

Your task is to generate a local, single-file proof-of-concept test script
for verifying whether a known vulnerable npm package function is reachable
and potentially exploitable.

Target ecosystem:
npm / Node.js

Package:
{context.package_name}

Package version:
{context.package_version or "unknown"}

Vulnerability type:
{context.vuln_type}

CVE / vulnerability report:
{context.cve_report}

Vulnerable function candidate:
{json.dumps({
    "name": context.vulnerable_function.name,
    "file_path": context.vulnerable_function.file_path,
    "params": context.vulnerable_function.params,
    "reason": context.vulnerable_function.reason,
}, indent=2)}

Usage snippets:
{self._format_snippets(context.usage_snippets)}

Taint path:
{self._format_taint_path(context.taint_path)}

Skeleton:
{context.skeleton or "No skeleton provided."}

Few-shot examples:
{self._format_list(context.few_shot_examples)}

Generate a single Node.js file named poc.js.

The generated PoC must:
- import or require the target package
- call the vulnerable function candidate directly or through the observed usage pattern
- use an external-input-like payload variable
- attempt to trigger the vulnerable behavior through the real package API
- include clear runtime evidence checks
- print "POC_SUCCESS" only when the vulnerable behavior is actually observed
- print "POC_FAILED" otherwise
- avoid network access
- avoid filesystem destruction
- avoid executing system commands unless the vulnerability type specifically requires command execution
- be self-contained and executable with: node poc.js

Do NOT generate these invalid patterns:
- Simulation: reimplementing the vulnerable logic instead of calling the package
- Hardcoded success: printing success without checking the vulnerable behavior
- Bad validation: using unconditional or irrelevant checks
- Mock-only PoC: mocking the vulnerable package instead of invoking it
- Non-executable fragments

Return ONLY a valid JSON object.

Do not include:
- markdown code fences
- ```json
- explanations outside JSON
- JavaScript template literals
- backtick strings
- comments before or after JSON

Important JSON formatting rules:
- The response must be parseable by Python json.loads().
- The "code" field must be a valid JSON string.
- Escape all newlines in the "code" field as \\n.
- Escape all double quotes inside the JavaScript code as \\".
- Do not use backticks for the "code" value.

Return exactly this JSON shape:
{{
  "filename": "poc.js",
  "code": "const pkg = require('PACKAGE_NAME');\\nconsole.log('POC_FAILED');",
  "explanation": "brief explanation of the exploitability path"
}}""".strip()

    def _format_list(self, items: list[str]) -> str:
        if not items:
            return "None provided."

        return "\n\n".join(
            f"[{idx}]\n{item}"
            for idx, item in enumerate(items, start=1)
        )

    def _format_snippets(self, snippets) -> str:
        if not snippets:
            return "None provided."

        formatted = []

        for idx, snippet in enumerate(snippets, start=1):
            formatted.append(
                f"[{idx}]\n"
                f"file: {snippet.file_path}\n"
                f"source: {snippet.source}\n"
                f"lines: {snippet.start_line}-{snippet.end_line}\n"
                f"code:\n{snippet.code}"
            )

        return "\n\n".join(formatted)

    def _format_taint_path(self, taint_path: TaintPath | None) -> str:
        if taint_path is None:
            return "None provided."

        return json.dumps(
            {
                "source": taint_path.source,
                "sink": taint_path.sink,
                "steps": taint_path.steps,
            },
            indent=2,
        )