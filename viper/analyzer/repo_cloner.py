from pathlib import Path
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
            print(f"[RepoCloner] Using local repository: {repo_path}")
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
            print(f"[RepoCloner] Repository already exists: {target_path}")
            return target_path.resolve()

        print(f"[RepoCloner] Cloning repository: {repo_url}")

        result = subprocess.run(
            ["git", "clone", repo_url, str(target_path)],
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
            print("[RepoCloner] package.json not found. Skipping npm install.")
            return

        if node_modules.exists():
            print("[RepoCloner] node_modules already exists. Skipping npm install.")
            return

        command = self._get_npm_install_command(repo_path)

        print(f"[RepoCloner] Installing npm dependencies: {' '.join(command)}")

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

        print("[RepoCloner] npm dependencies installed.")

    def _get_npm_install_command(self, repo_path: Path) -> list[str]:
        package_lock = repo_path / "package-lock.json"

        if package_lock.exists():
            return ["npm", "ci"]

        return ["npm", "install"]