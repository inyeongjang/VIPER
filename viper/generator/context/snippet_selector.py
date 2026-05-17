from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from viper.generator.context.function_selector import VulnerableFunctionCandidate


@dataclass
class UsageSnippet:
    file_path: str
    source: str  # "test" | "docs" | "source"
    start_line: int
    end_line: int
    code: str


class SnippetSelector:
    TEST_FILE_PATTERNS = [
        "test",
        "tests",
        "__tests__",
        "spec",
        ".test.",
        ".spec.",
    ]

    DOC_FILE_NAMES = [
        "README.md",
        "readme.md",
        "README",
        "CHANGELOG.md",
        "CHANGELOG",
    ]

    DOC_DIR_NAMES = [
        "docs",
        "doc",
        "examples",
        "example",
    ]

    SOURCE_DIR_NAMES = [
        "src",
        "lib",
        "dist",
    ]

    CODE_EXTENSIONS = {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
    }

    DOC_EXTENSIONS = {
        ".md",
        ".markdown",
        ".rst",
    }

    def __init__(self, max_snippets: int = 5, context_window: int = 6):
        if max_snippets <= 0:
            raise ValueError("max_snippets must be greater than 0")

        if context_window < 0:
            raise ValueError("context_window must be greater than or equal to 0")

        self.max_snippets = max_snippets
        self.context_window = context_window

    def select(
        self,
        source_root: str,
        function_candidates: list[VulnerableFunctionCandidate],
    ) -> list[UsageSnippet]:
        repo_root = Path(source_root).resolve()

        if not repo_root.exists():
            raise FileNotFoundError(f"source_root does not exist: {source_root}")

        if not function_candidates:
            return []

        search_roots = self._collect_search_roots(
            repo_root=repo_root,
            function_candidates=function_candidates,
        )

        snippets: list[UsageSnippet] = []

        for root in search_roots:
            ignore_node_modules = root == repo_root

            test_files = self._find_test_files(
                root=root,
                ignore_node_modules=ignore_node_modules,
            )

            doc_files = self._find_doc_files(
                root=root,
                ignore_node_modules=ignore_node_modules,
            )

            source_files = self._find_source_files(
                root=root,
                ignore_node_modules=ignore_node_modules,
            )

            for candidate in function_candidates:
                snippets.extend(
                    self._grep_function_calls(
                        files=test_files,
                        function_name=candidate.name,
                        source="test",
                    )
                )

            snippets.extend(
                self._extract_doc_snippets(
                    files=doc_files,
                    function_candidates=function_candidates,
                )
            )

            if not snippets:
                for candidate in function_candidates:
                    snippets.extend(
                        self._grep_function_calls(
                            files=source_files,
                            function_name=candidate.name,
                            source="source",
                        )
                    )

        snippets = self._deduplicate(snippets)
        snippets = self._rank_snippets(snippets, function_candidates)

        return snippets[: self.max_snippets]

    def _collect_search_roots(
        self,
        repo_root: Path,
        function_candidates: list[VulnerableFunctionCandidate],
    ) -> list[Path]:
        roots: list[Path] = [repo_root]
        seen = {repo_root}

        for candidate in function_candidates:
            if not candidate.file_path:
                continue

            file_path = Path(candidate.file_path)

            if not file_path.exists():
                continue

            package_root = self._find_package_root(file_path)

            if package_root and package_root not in seen:
                roots.append(package_root)
                seen.add(package_root)

        return roots

    def _find_package_root(self, file_path: Path) -> Path | None:
        current = file_path if file_path.is_dir() else file_path.parent

        while current != current.parent:
            package_json = current / "package.json"

            if package_json.exists():
                return current.resolve()

            current = current.parent

        return None

    def _find_test_files(
        self,
        root: Path,
        ignore_node_modules: bool,
    ) -> list[Path]:
        result: list[Path] = []

        for path in self._iter_files(root, ignore_node_modules=ignore_node_modules):
            if path.suffix not in self.CODE_EXTENSIONS:
                continue

            lower_path = str(path).lower()

            if any(pattern in lower_path for pattern in self.TEST_FILE_PATTERNS):
                result.append(path)

        return result

    def _find_doc_files(
        self,
        root: Path,
        ignore_node_modules: bool,
    ) -> list[Path]:
        result: list[Path] = []

        for path in self._iter_files(root, ignore_node_modules=ignore_node_modules):
            if path.suffix not in self.DOC_EXTENSIONS:
                continue

            if path.name in self.DOC_FILE_NAMES:
                result.append(path)
                continue

            lower_parts = [part.lower() for part in path.parts]

            if any(dirname in lower_parts for dirname in self.DOC_DIR_NAMES):
                result.append(path)

        return result

    def _find_source_files(
        self,
        root: Path,
        ignore_node_modules: bool,
    ) -> list[Path]:
        result: list[Path] = []

        for path in self._iter_files(root, ignore_node_modules=ignore_node_modules):
            if path.suffix not in self.CODE_EXTENSIONS:
                continue

            lower_parts = [part.lower() for part in path.parts]

            if any(dirname in lower_parts for dirname in self.SOURCE_DIR_NAMES):
                result.append(path)
                continue

            if path.parent == root:
                result.append(path)

        return result

    def _grep_function_calls(
        self,
        files: Iterable[Path],
        function_name: str,
        source: str,
    ) -> list[UsageSnippet]:
        snippets: list[UsageSnippet] = []
        pattern = self._build_function_call_pattern(function_name)

        for file_path in files:
            lines = self._safe_read_lines(file_path)

            if not lines:
                continue

            for index, line in enumerate(lines):
                if pattern.search(line):
                    start = max(0, index - self.context_window)
                    end = min(len(lines), index + self.context_window + 1)

                    code = "".join(lines[start:end]).strip()

                    snippets.append(
                        UsageSnippet(
                            file_path=str(file_path),
                            source=source,
                            start_line=start + 1,
                            end_line=end,
                            code=code,
                        )
                    )

        return snippets

    def _extract_doc_snippets(
        self,
        files: Iterable[Path],
        function_candidates: list[VulnerableFunctionCandidate],
    ) -> list[UsageSnippet]:
        snippets: list[UsageSnippet] = []
        function_names = [candidate.name for candidate in function_candidates]

        for file_path in files:
            text = self._safe_read_text(file_path)

            if not text:
                continue

            code_blocks = self._extract_markdown_code_blocks(text)

            for start_line, end_line, code in code_blocks:
                if self._contains_any_function(code, function_names):
                    snippets.append(
                        UsageSnippet(
                            file_path=str(file_path),
                            source="docs",
                            start_line=start_line,
                            end_line=end_line,
                            code=code.strip(),
                        )
                    )

        return snippets

    def _extract_markdown_code_blocks(self, text: str) -> list[tuple[int, int, str]]:
        lines = text.splitlines()
        blocks: list[tuple[int, int, str]] = []

        in_block = False
        start_line = 0
        buffer: list[str] = []

        for index, line in enumerate(lines, start=1):
            if line.strip().startswith("```"):
                if not in_block:
                    in_block = True
                    start_line = index + 1
                    buffer = []
                else:
                    end_line = index - 1
                    blocks.append((start_line, end_line, "\n".join(buffer)))
                    in_block = False

                continue

            if in_block:
                buffer.append(line)

        return blocks

    def _build_function_call_pattern(self, function_name: str) -> re.Pattern:
        escaped = re.escape(function_name)

        return re.compile(
            rf"(\b{escaped}\s*\(|\.{escaped}\s*\(|\b{escaped}\b)",
            re.MULTILINE,
        )

    def _contains_any_function(self, code: str, function_names: list[str]) -> bool:
        for name in function_names:
            if self._build_function_call_pattern(name).search(code):
                return True

        return False

    def _rank_snippets(
        self,
        snippets: list[UsageSnippet],
        function_candidates: list[VulnerableFunctionCandidate],
    ) -> list[UsageSnippet]:
        candidate_order = {
            candidate.name: index
            for index, candidate in enumerate(function_candidates)
        }

        def score(snippet: UsageSnippet) -> tuple[int, int, int]:
            source_priority = {
                "test": 0,
                "docs": 1,
                "source": 2,
            }

            source_score = source_priority.get(snippet.source, 3)

            matched_rank = len(candidate_order)

            for func_name, rank in candidate_order.items():
                if func_name in snippet.code:
                    matched_rank = min(matched_rank, rank)

            code_length = len(snippet.code)

            return (source_score, matched_rank, code_length)

        return sorted(snippets, key=score)

    def _deduplicate(self, snippets: list[UsageSnippet]) -> list[UsageSnippet]:
        seen: set[tuple[str, int, int, str]] = set()
        unique: list[UsageSnippet] = []

        for snippet in snippets:
            key = (
                snippet.file_path,
                snippet.start_line,
                snippet.end_line,
                snippet.code,
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(snippet)

        return unique

    def _iter_files(
        self,
        root: Path,
        ignore_node_modules: bool,
    ) -> Iterable[Path]:
        ignored_dirs = {
            ".git",
            "coverage",
            ".venv",
            "venv",
            "__pycache__",
        }

        if ignore_node_modules:
            ignored_dirs.add("node_modules")

        for path in root.rglob("*"):
            if not path.is_file():
                continue

            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                relative_parts = path.parts

            if any(part in ignored_dirs for part in relative_parts):
                continue

            yield path

    def _safe_read_text(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def _safe_read_lines(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="ignore").splitlines(
                keepends=True
            )
        except OSError:
            return []