import json
import logging
from pathlib import Path

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


def setup_logger() -> logging.Logger:
    log_dir = Path("outputs/logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("viper")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s"
    )

    file_handler = logging.FileHandler(
        log_dir / "pipeline.log",
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger


class Pipeline:
    """Main VIPER pipeline."""

    def __init__(self, repo: str):
        self.repo = repo
        self.logger = setup_logger()

        self.repo_path = None
        self.sbom_path = None
        self.vuln_path = None
        self.codeql_result_path = None

        self.vulnerabilities = []
        self.analysis_contexts = []

    def analyze(self) -> None:
        self.logger.info("Analysis started")
        self.logger.info(f"Target repository: {self.repo}")

        self.repo_path = RepoCloner().prepare(self.repo)
        self.logger.info(f"Prepared repository: {self.repo_path}")

        self.sbom_path = SyftRunner().run(
            repo_path=self.repo_path,
            output_path="outputs/sbom/sbom.json",
        )
        self.logger.info(f"SBOM saved to: {self.sbom_path}")

        self.vuln_path = GrypeRunner().run(
            sbom_path=self.sbom_path,
            output_path="outputs/vulns/grype.json",
        )
        self.logger.info(f"Vulnerability report saved to: {self.vuln_path}")

        self.codeql_result_path = CodeQLRunner().run(
            repo_path=self.repo_path,
            db_path="outputs/codeql/db",
            output_path="outputs/codeql/results.sarif",
        )
        self.logger.info(f"CodeQL result saved to: {self.codeql_result_path}")

        self.vulnerabilities = self._load_vulnerabilities(self.vuln_path)

        if not self.vulnerabilities:
            self.logger.info("No vulnerabilities found.")
            self.logger.info("Analysis completed")
            return

        self.logger.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities")

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

            self.logger.info("=" * 80)
            self.logger.info(f"Vulnerability #{idx}")
            self.logger.info(f"CVE ID  : {cve_id}")
            self.logger.info(f"Package : {package_name}")
            self.logger.info(f"Version : {package_version or 'unknown'}")

            vuln_type = VulnTypeClassifier(
                llm_client=llm_client,
            ).classify(description)

            self.logger.info(f"Vulnerability Type: {vuln_type}")

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

            if not function_candidates:
                self.logger.info("Function candidates: none")
            else:
                self.logger.info("Function candidates:")
                for candidate in function_candidates:
                    self.logger.info(
                        f"- {candidate.name} "
                        f"(rank={candidate.rank}, file={candidate.file_path})"
                    )
                    self.logger.info(f"  reason: {candidate.reason}")

            usage_snippets = SnippetSelector(
                max_snippets=5,
                context_window=6,
            ).select(
                source_root=str(self.repo_path),
                function_candidates=function_candidates,
            )

            if not usage_snippets:
                self.logger.info("Usage snippets: none")
            else:
                self.logger.info("Usage snippets:")
                for snippet in usage_snippets:
                    self.logger.info("-" * 60)
                    self.logger.info(f"file   : {snippet.file_path}")
                    self.logger.info(f"source : {snippet.source}")
                    self.logger.info(
                        f"lines  : {snippet.start_line}-{snippet.end_line}"
                    )
                    self.logger.info(f"code preview:\n{snippet.code[:500]}")

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

        self.logger.info("Analysis completed")

    def generate_poc(self) -> None:
        self.logger.info("PoC generation started")

        if not self.analysis_contexts:
            self.logger.info("No analysis context found. Run analyze() first.")
            self.logger.info("PoC generation completed")
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
                self.logger.info(
                    f"Skip PoC generation for {cve_id}: no function candidate"
                )
                continue

            vulnerable_function = function_candidates[0]

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

                self.logger.info(f"Generated PoC for {cve_id}: {saved_path}")
                self.logger.info(f"Explanation: {generated.explanation}")

            except Exception as e:
                self.logger.error(f"PoC generation failed for {cve_id}: {e}")

        self.logger.info("PoC generation completed")

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
        self.logger.info("PoC validation started")
        self.logger.info(f"Target repository: {self.repo}")

        # TODO

        self.logger.info("PoC validation completed")

    def report(self) -> None:
        self.logger.info("Report generation started")
        self.logger.info(f"Target repository: {self.repo}")

        # TODO

        self.logger.info("Report generation completed")

    def run(self) -> None:
        self.logger.info("Full pipeline started")

        self.analyze()
        self.generate_poc()
        self.validate_poc()
        self.report()

        self.logger.info("Full pipeline completed")