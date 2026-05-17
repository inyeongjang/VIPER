import subprocess
from pathlib import Path


class GrypeRunner:
    """Run Grype inside Docker container."""

    def run(
        self,
        sbom_path: str | Path,
        output_path: str | Path = "outputs/vulns/grype.json",
    ) -> Path:

        sbom_path = Path(sbom_path).resolve()
        output_path = Path(output_path).resolve()

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        command = [
            "grype",
            f"sbom:{sbom_path}",
            "-o",
            "json",
        ]

        print(
            f"[GrypeRunner] Running command: "
            f"{' '.join(command)}"
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Grype failed:\n{result.stderr}"
            )

        output_path.write_text(
            result.stdout,
            encoding="utf-8",
        )

        print(
            f"[GrypeRunner] Vulnerability report saved to: "
            f"{output_path}"
        )

        return output_path