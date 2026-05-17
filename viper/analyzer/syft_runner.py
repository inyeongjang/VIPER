from pathlib import Path
import subprocess


class SyftRunner:
    """Run Syft inside Docker container."""

    def run(
        self,
        repo_path: str | Path,
        output_path: str | Path = "outputs/sbom/sbom.json",
    ) -> Path:

        repo_path = Path(repo_path).resolve()
        output_path = Path(output_path).resolve()

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        command = [
            "syft",
            str(repo_path),
            "-o",
            "json",
        ]

        print(
            f"[SyftRunner] Running command: "
            f"{' '.join(command)}"
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Syft failed:\n{result.stderr}"
            )

        output_path.write_text(
            result.stdout,
            encoding="utf-8",
        )

        print(
            f"[SyftRunner] SBOM saved to: "
            f"{output_path}"
        )

        return output_path