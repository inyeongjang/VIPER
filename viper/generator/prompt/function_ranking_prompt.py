import json


def build_ranking_prompt(
    exports: list[dict],
    cve_report: str,
    vuln_type: str,
    top_k: int,
) -> str:
    compact_exports = [
        {
            "name": fn.get("name", ""),
            "params": fn.get("params", []),
            "filePath": fn.get("filePath", ""),
        }
        for fn in exports
    ]

    return f"""
You are a security analysis assistant.

Rank the exported functions by likelihood of being the vulnerable API.

Vulnerability type:
{vuln_type}

CVE/OSV report:
{cve_report}

Exported function candidates:
{json.dumps(compact_exports, indent=2)}

Return ONLY valid JSON.

The JSON must be an array with at most {top_k} items:
[
  {{
    "name": "exportedFunctionName",
    "rank": 1,
    "reason": "Brief evidence from the CVE/OSV report and function name/params"
  }}
]

Rules:
- The "name" value should match one of the candidate names.
- Only use functions from the exported function candidates.
- Rank the most suspicious function as 1.
- Prefer functions explicitly mentioned in the CVE/OSV report.
- Do not return markdown.
- Do not return prose outside JSON.
""".strip()