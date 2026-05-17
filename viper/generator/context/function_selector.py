import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from viper.generator.llm.base_client import LLMClient


@dataclass
class VulnerableFunctionCandidate:
    name: str
    file_path: str
    params: list[str]
    is_async: bool
    rank: int
    reason: str



class FunctionSelector:
    """Select vulnerable function candidates from npm package exports."""

    def __init__(self, llm_client: LLMClient, chunk_size: int = 40):
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than 0")

        self.llm_client = llm_client
        self.chunk_size = chunk_size

    def select(
        self,
        source_root: str,
        package_name: str,
        cve_report: str,
        vuln_type: str,
        top_k: int = 5,
    ) -> list[VulnerableFunctionCandidate]:
        exports = self._extract_exports(
            source_root=source_root,
            package_name=package_name,
        )

        if not exports:
            return []

        ranked = self._rank_in_chunks(
            exports=exports,
            cve_report=cve_report,
            vuln_type=vuln_type,
            top_k=top_k,
        )

        return ranked[:top_k]

    def _extract_exports(
        self,
        source_root: str,
        package_name: str,
    ) -> list[dict]:
        script_path = Path(__file__).parent / "scripts" / "extract_exports.js"
        repo_root = Path(source_root).resolve()

        package_root = self._resolve_package_root(
            repo_root=repo_root,
            package_name=package_name,
        )

        if package_root is None:
            raise FileNotFoundError(f"Package source not found: {package_name}")

        result = subprocess.run(
            [
                "node",
                str(script_path),
                str(package_root),
                package_name,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(
                f"Export extraction failed for {package_name}: "
                f"{stderr or 'unknown error'}"
            )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid export JSON for {package_name}: {result.stdout}"
            ) from exc

    def _resolve_package_root(
        self,
        repo_root: Path,
        package_name: str,
    ) -> Path | None:
        """
        Resolve vulnerable npm package source directory.

        Priority:
        1. node_modules/<package_name>
        2. repo root itself if package.json name matches package_name
        """

        node_module_path = repo_root / "node_modules" / package_name

        if node_module_path.exists():
            return node_module_path.resolve()

        package_json_path = repo_root / "package.json"

        if package_json_path.exists():
            try:
                package_data = json.loads(
                    package_json_path.read_text(
                        encoding="utf-8",
                        errors="ignore",
                    )
                )

                if package_data.get("name") == package_name:
                    return repo_root.resolve()

            except json.JSONDecodeError:
                pass

        return None

    def _rank_in_chunks(
        self,
        exports: list[dict],
        cve_report: str,
        vuln_type: str,
        top_k: int,
    ) -> list[VulnerableFunctionCandidate]:
        export_map = self._build_export_map(exports)
        intermediate_exports: list[dict] = []

        for idx, chunk in enumerate(chunked(exports, self.chunk_size), start=1):
            ranked_chunk = self.llm_client.rank_functions(
                exports=chunk,
                cve_report=cve_report,
                vuln_type=vuln_type,
                top_k=top_k,
            )

            selected_from_chunk = self._attach_original_exports(
                ranked_items=ranked_chunk,
                export_map=export_map,
                stage=f"chunk {idx}",
            )

            intermediate_exports.extend(selected_from_chunk)

        intermediate_exports = self._deduplicate_exports(intermediate_exports)

        if not intermediate_exports:
            raise RuntimeError(
                f"No valid function candidates ranked for {top_k=}"
            )

        final_ranked = self.llm_client.rank_functions(
            exports=intermediate_exports,
            cve_report=cve_report,
            vuln_type=vuln_type,
            top_k=top_k,
        )

        return self._to_candidates(
            ranked_items=final_ranked,
            export_map=export_map,
            stage="final ranking",
        )

    def _build_export_map(self, exports: list[dict]) -> dict[str, dict]:
        export_map: dict[str, dict] = {}

        for fn in exports:
            name = fn.get("name")
            if not name:
                continue

            if name in export_map:
                continue

            export_map[name] = fn

        return export_map

    def _deduplicate_exports(self, exports: list[dict]) -> list[dict]:
        seen = set()
        deduped = []

        for item in exports:
            name = item.get("name")
            if not name:
                continue

            if name in seen:
                continue

            seen.add(name)
            deduped.append(item)

        return deduped

    def _get_llm_returned_name(self, item: dict) -> str | None:
        return (
            item.get("name")
            or item.get("function")
            or item.get("function_name")
            or item.get("api")
            or item.get("candidate")
        )

    def _safe_rank(self, item: dict, default: int) -> int:
        try:
            return int(item.get("rank", default))
        except (TypeError, ValueError):
            return default

    def _attach_original_exports(
        self,
        ranked_items: list[dict],
        export_map: dict[str, dict],
        stage: str,
    ) -> list[dict]:
        selected: list[dict] = []

        for idx, item in enumerate(ranked_items, start=1):
            name = self._get_llm_returned_name(item)

            if name not in export_map:
                continue

            original = dict(export_map[name])
            original["rank"] = self._safe_rank(item, idx)
            original["reason"] = item.get("reason", "")
            selected.append(original)

        return selected

    def _to_candidates(
        self,
        ranked_items: list[dict],
        export_map: dict[str, dict],
        stage: str,
    ) -> list[VulnerableFunctionCandidate]:
        candidates: list[VulnerableFunctionCandidate] = []

        for idx, item in enumerate(ranked_items, start=1):
            name = self._get_llm_returned_name(item)

            if name not in export_map:
                continue

            original = export_map[name]

            candidates.append(
                VulnerableFunctionCandidate(
                    name=name,
                    file_path=original.get("filePath", ""),
                    params=original.get("params", []),
                    is_async=original.get("isAsync", False),
                    rank=self._safe_rank(item, idx),
                    reason=item.get("reason", ""),
                )
            )

        return sorted(candidates, key=lambda x: x.rank)


def chunked(items: list[dict], size: int) -> list[list[dict]]:
    return [items[i : i + size] for i in range(0, len(items), size)]