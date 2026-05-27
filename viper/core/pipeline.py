import json
from contextlib import contextmanager
from pathlib import Path

try:
    from pyfiglet import figlet_format
except Exception:
    figlet_format = None

from viper.logger import get_logger
from viper.analyzer.repo_cloner import RepoCloner
from viper.analyzer.syft_runner import SyftRunner
from viper.analyzer.grype_runner import GrypeRunner
from viper.analyzer.codeql_runner import CodeQLRunner

from viper.generator.context.vuln_type_classifier import VulnTypeClassifier
from viper.generator.context.function_selector import FunctionSelector
from viper.generator.context.snippet_selector import SnippetSelector
from viper.generator.llm.ollama_client import OllamaLLMClient

from viper.generator.poc_generator import (
    PoCGenerationContext,
    PoCGenerator,
)


class Pipeline:
    """Main VIPER pipeline."""

    def __init__(self, repo: str):
        self.repo = repo
        self.logger = get_logger(__name__)

        self.repo_path = None
        self.sbom_path = None
        self.vuln_path = None
        self.codeql_result_path = None

        self.vulnerabilities = []
        self.analysis_contexts = []

    def _banner(self, title: str) -> str:
        width = max(len(title) + 8, 52)
        border = "+" + "-" * (width - 2) + "+"
        line = f"| {title.center(width - 4)} |"
        return "\n".join([border, line, border])

    def _logo(self) -> str:
        if figlet_format is not None:
            return figlet_format("VIPER", font="slant")

        return "VIPER"

    def _console(self, message: str, *, color: str = "white", level: str = "info") -> None:
        log_method = getattr(self.logger, level)
        if color == "white":
            log_method(message)
            return

        log_method(message, extra={"console_color": color})

    def _console_spaced(self, message: str, *, color: str = "white", level: str = "info") -> None:
        self._console("", color="white", level=level)
        self._console(message, color=color, level=level)

    def _stage_start(self, stage: str) -> None:
        self._console_spaced(f"[ {stage} STAGE ]", color="blue")

    def _stage_end(self, stage: str) -> None:
        self._console_spaced(f"[ {stage} STAGE ]", color="blue")

    def _module_start(self, module: str) -> None:
        self._console_spaced(f"[ {module} STAGE ]", color="white")

    def _module_end(self, module: str, detail: str = "") -> None:
        message = f"{module} COMPLETED"
        if detail:
            message = f"{message} ({detail})"
        self._console_spaced(message, color="green")

    @contextmanager
    def _stage_indicator(self, stage: str):
        self._stage_start(stage)
        try:
            yield
        except Exception:
            self._console_spaced(f"{stage} FAILED", color="red", level="error")
            raise

    def _detail(self, message: str) -> None:
        self.logger.debug(message)

    def analyze(self) -> None:
        stage = "ANALYZE"
        with self._stage_indicator(stage):
            self._detail(f"Target repository: {self.repo}")

            self._module_start("REPOSITORY PREPARATION")
            self.repo_path = RepoCloner().prepare(self.repo)
            self._module_end("REPOSITORY PREPARATION", str(self.repo_path))
            self._detail(f"Prepared repository: {self.repo_path}")

            self._module_start("SBOM GENERATION")
            self.sbom_path = SyftRunner().run(
                repo_path=self.repo_path,
                output_path="outputs/sbom/sbom.json",
            )
            self._module_end("SBOM GENERATION", str(self.sbom_path))
            self._detail(f"SBOM saved to: {self.sbom_path}")

            self._module_start("VULNERABILITY SCAN")
            self.vuln_path = GrypeRunner().run(
                sbom_path=self.sbom_path,
                output_path="outputs/vulns/grype.json",
            )
            self._module_end("VULNERABILITY SCAN", str(self.vuln_path))
            self._detail(f"Vulnerability report saved to: {self.vuln_path}")

            self._module_start("CODEQL ANALYSIS")
            self.codeql_result_path = CodeQLRunner().run(
                repo_path=self.repo_path,
                db_path="outputs/codeql/db",
                output_path="outputs/codeql/results.sarif",
            )
            self._module_end("CODEQL ANALYSIS", str(self.codeql_result_path))
            self._detail(f"CodeQL result saved to: {self.codeql_result_path}")

            self._module_start("VULNERABILITY LOAD")
            self.vulnerabilities = self._load_vulnerabilities(self.vuln_path)
            self._module_end("VULNERABILITY LOAD", f"{len(self.vulnerabilities)} items")
            self._detail(f"Loaded vulnerability count: {len(self.vulnerabilities)}")

            if not self.vulnerabilities:
                return

            self._detail(f"Loaded {len(self.vulnerabilities)} vulnerabilities")

            llm_client = OllamaLLMClient(
                model="llama3.2:3b",
                base_url="http://localhost:11434",
            )

            self.analysis_contexts = []

            for idx, vulnerability in enumerate(self.vulnerabilities, start=1):
                cve_id = vulnerability["id"]
                package_name = vulnerability["package_name"]
                package_version = vulnerability.get("package_version")
                description = vulnerability["description"]

                self._detail(f"Vulnerability #{idx}: {cve_id} {package_name}@{package_version or 'unknown'}")

                vuln_type = VulnTypeClassifier(
                    llm_client=llm_client,
                ).classify(description)

                self._detail(f"Vulnerability Type: {vuln_type}")

                try:
                    function_candidates = FunctionSelector(
                        llm_client=llm_client,
                        chunk_size=40,
                    ).select(
                        source_root=str(self.repo_path),
                        package_name=package_name,
                        cve_report=description,
                        vuln_type=vuln_type,
                        top_k=5,
                    )

                    usage_snippets = SnippetSelector(
                        max_snippets=5,
                        context_window=6,
                    ).select(
                        source_root=str(self.repo_path),
                        function_candidates=function_candidates,
                    )
                except Exception as e:
                    self.logger.error(f"[ANALYZE] context build failed for {cve_id}")
                    self._detail(f"Analysis context build failed for {cve_id}: {e}")
                    continue

                self._detail(
                    f"Function candidates count: {len(function_candidates)}"
                )
                for candidate in function_candidates:
                    self._detail(
                        f"  - {candidate.name} (rank={candidate.rank}, file={candidate.file_path})"
                    )
                    self._detail(f"    reason: {candidate.reason}")

                self._detail(f"Usage snippets count: {len(usage_snippets)}")
                for snippet in usage_snippets:
                    self._detail(f"  - file: {snippet.file_path}")
                    self._detail(f"    source: {snippet.source}")
                    self._detail(f"    lines: {snippet.start_line}-{snippet.end_line}")
                    self._detail(f"    code preview: {snippet.code[:500]}")

                self.analysis_contexts.append(
                    {
                        "cve_id": cve_id,
                        "package_name": package_name,
                        "package_version": package_version,
                        "description": description,
                        "vuln_type": vuln_type,
                        "function_candidates": function_candidates,
                        "usage_snippets": usage_snippets,
                    }
                )

    def generate_poc(self) -> None:
        stage = "POC GENERATION"
        with self._stage_indicator(stage):
            if not self.analysis_contexts:
                self._detail("No analysis context found")
                return

            llm_client = OllamaLLMClient(
                model="llama3.2:3b",
                base_url="http://localhost:11434",
            )

            generator = PoCGenerator(llm_client=llm_client)

            for context in self.analysis_contexts:
                cve_id = context["cve_id"]
                package_name = context["package_name"]
                package_version = context["package_version"]
                vuln_type = context["vuln_type"]
                description = context["description"]
                function_candidates = context["function_candidates"]
                usage_snippets = context["usage_snippets"]

                if not function_candidates:
                    self._detail(f"Skip {cve_id}: no function candidate")
                    continue

                vulnerable_function = function_candidates[0]

                self._detail(
                    f"Target function: {vulnerable_function.name} @ {vulnerable_function.file_path}"
                )

                poc_context = PoCGenerationContext(
                    package_name=package_name,
                    package_version=package_version,
                    vuln_type=vuln_type,
                    vulnerable_function=vulnerable_function,
                    usage_snippets=usage_snippets,
                    skeleton=None,
                    few_shot_examples=[],
                    taint_path=None,
                    cve_report=description,
                )

                try:
                    generated = generator.generate(poc_context)

                    output_dir = Path("outputs/pocs") / cve_id
                    saved_path = generator.save(generated, output_dir=output_dir)

                    self._detail(f"Generated PoC path: {saved_path}")
                    self._detail(f"Explanation: {generated.explanation}")

                except Exception as e:
                    self._console_spaced(f"failed for {cve_id}", color="red", level="error")
                    self._detail(f"PoC generation failed for {cve_id}: {e}")

    def _load_vulnerabilities(self, vuln_path: str | Path) -> list[dict]:
        vuln_path = Path(vuln_path)

        data = json.loads(vuln_path.read_text(encoding="utf-8"))
        matches = data.get("matches", [])

        vulnerabilities = []

        for match in matches:
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vuln_id = vulnerability.get("id", "")
            package_name = artifact.get("name", "")
            package_version = artifact.get("version")

            description = (
                vulnerability.get("description")
                or vulnerability.get("summary")
                or vulnerability.get("severity")
                or ""
            )

            if not vuln_id or not package_name:
                continue

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "package_name": package_name,
                    "package_version": package_version,
                    "description": description,
                }
            )

        return vulnerabilities

    def validate_poc(self) -> None:
        stage = "VALIDATE POC"
        with self._stage_indicator(stage):
            if not self.analysis_contexts:
                self._detail("No analysis context found")
                return

            from viper.validator.poc_runner import PoCRunner
            runner = PoCRunner()
            
            self.validation_results = []

            for context in self.analysis_contexts:
                cve_id = context["cve_id"]
                poc_dir = Path("outputs/pocs") / cve_id

                self._module_start(f"VALIDATING {cve_id}")
                
                # 가상 환경에서 PoC 동적 실행 및 결과 수집
                result = runner.run_validation(
                    cve_id=cve_id,
                    repo_path=self.repo_path,
                    poc_dir=poc_dir
                )
                
                self.validation_results.append(result)
                self._module_end(f"VALIDATING {cve_id}", result["status"])
                self._detail(f"[{cve_id}] Result Details: {result}")

    def report(self) -> None:
        stage = "REPORT"
        with self._stage_indicator(stage):
            self._detail(f"Target repository: {self.repo}")

            # TODO

    def run(self) -> None:
        self._console(self._logo(), color="blue")

        try:
            self.analyze()
            self.generate_poc()
            self.validate_poc()
            self.report()
        except Exception as e:
            self._console("PIPELINE failed", color="red", level="error")
            self._detail(f"Full pipeline failed: {e}")
            return

        self._console("VIPER pipeline completed", color="green")
