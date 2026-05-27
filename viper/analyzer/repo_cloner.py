from pathlib import Path
import shutil
import subprocess


class RepoCloner:
    """Prepare target repository for analysis."""

    def prepare(
        self,
        repo: str,
        workdir: str = "outputs/repos",
        install_dependencies: bool = True,
    ) -> Path:
        repo_path = Path(repo)

        if repo_path.exists():
            prepared_path = repo_path.resolve()
        elif repo.startswith("http://") or repo.startswith("https://"):
            prepared_path = self._clone(repo, workdir)
        else:
            raise ValueError(f"Invalid repository input: {repo}")

        if install_dependencies:
            self._install_npm_dependencies(prepared_path)

        return prepared_path

    def _clone(self, repo_url: str, workdir: str) -> Path:
        output_dir = Path(workdir)
        output_dir.mkdir(parents=True, exist_ok=True)

        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        target_path = output_dir / repo_name

        if target_path.exists():
            return target_path.resolve()

        git_executable = self._resolve_executable("git")

        result = subprocess.run(
            [git_executable, "clone", repo_url, str(target_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed:\n{result.stderr}")

        return target_path.resolve()

    def _install_npm_dependencies(self, repo_path: Path) -> None:
        package_json = repo_path / "package.json"
        node_modules = repo_path / "node_modules"

        if not package_json.exists():
            return

        if node_modules.exists():
            return

        command = self._get_npm_install_command(repo_path)

        result = subprocess.run(
            command,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            raise RuntimeError(
                "npm dependency installation failed:\n"
                f"Command: {' '.join(command)}\n\n"
                f"STDOUT:\n{result.stdout}\n\n"
                f"STDERR:\n{result.stderr}"
            )

    def _get_npm_install_command(self, repo_path: Path) -> list[str]:
        package_lock = repo_path / "package-lock.json"
        npm_executable = self._resolve_executable("npm")

        if package_lock.exists():
            return [npm_executable, "ci"]

        return [npm_executable, "install"]

    def _resolve_executable(self, executable_name: str) -> str:
        resolved = shutil.which(executable_name)

        if resolved:
            return resolved

        raise FileNotFoundError(
            f"Required executable not found on PATH: {executable_name}"
        )