import shutil
import subprocess
from pathlib import Path


class CodeQLRunner:
    """Run CodeQL database creation and analysis inside Docker container."""

    def __init__(
        self,
        language: str = "javascript-typescript",
        query_suite: str = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    ):
        self.language = language
        self.query_suite = query_suite

    def run(
        self,
        repo_path: str | Path,
        db_path: str | Path = "outputs/codeql/db",
        output_path: str | Path = "outputs/codeql/results.sarif",
    ) -> Path:
        repo_path = Path(repo_path).resolve()
        db_path = Path(db_path).resolve()
        output_path = Path(output_path).resolve()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        if db_path.exists():
            shutil.rmtree(db_path)

        self._create_database(repo_path=repo_path, db_path=db_path)
        self._analyze_database(db_path=db_path, output_path=output_path)

        return output_path

    def _create_database(self, repo_path: Path, db_path: Path) -> None:
        command = [
            "codeql",
            "database",
            "create",
            str(db_path),
            f"--language={self.language}",
            f"--source-root={repo_path}",
            "--overwrite",
        ]

        self._run_command(command, "CodeQL database create failed")

    def _analyze_database(self, db_path: Path, output_path: Path) -> None:
        command = [
            "codeql",
            "database",
            "analyze",
            str(db_path),
            self.query_suite,
            "--format=sarif-latest",
            f"--output={output_path}",
        ]

        self._run_command(command, "CodeQL database analyze failed")

    def _run_command(self, command: list[str], error_prefix: str) -> None:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"{error_prefix}:\n"
                f"{' '.join(command)}\n\n"
                f"{result.stderr}"
            )