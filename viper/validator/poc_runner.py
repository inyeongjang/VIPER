# viper/validator/poc_runner.py
import docker
from pathlib import Path
from viper.logger import get_logger

class PoCRunner:
    def __init__(self):
        self.logger = get_logger(__name__)
        try:
            # 호스트의 도커 엔진과 연결
            self.client = docker.from_env()
        except Exception as e:
            self.logger.error(f"도커 엔진 연결 실패: {e}")
            raise

    def run_validation(self, cve_id: str, repo_path: Path, poc_dir: Path) -> dict:
        """
        특정 CVE에 대해 격리된 도커 환경을 만들고 PoC를 실행하여 검증합니다.
        """
        # 1. PoC 파일 찾기 ex.poc.js (js 파일?로)
        poc_file = poc_dir / "poc.js" # llm 팀이 지정한 파일명으로 수정
        if not poc_file.exists():
            return {"cve_id": cve_id, "status": "SKIPPED", "reason": "PoC 파일 없음"}

        self.logger.info(f"[{cve_id}] PoC 동적 검증 시작...")

        # 호스트의 소스코드와 PoC 파일을 컨테이너 내부로 마운트할 경로 설정
        # PoC가 원본 코드를 오염시키지 않도록 읽기 전용 권장
        volumes = {
            str(repo_path.resolve()): {"bind": "/workspace/app", "mode": "ro"},
            str(poc_file.resolve()): {"bind": "/workspace/poc.js", "mode": "ro"}
        }

        container = None
        try:
            # 2. 격리된 환경 셋업 및 PoC 실행
            # 타깃 어플리케이션 환경에 맞는 베이스 이미지 선택 (여기선 임시로 node:18-alpine)
            container = self.client.containers.run(
                image="node:18-alpine",
                command="node /workspace/poc.js", # PoC 실행 명령어
                volumes=volumes,
                working_dir="/workspace/app",
                network_mode="none",              # 아웃바운드 네트워크 완전 차단(보안상 필요)
                mem_limit="512m",                 # 리소스 제한
                nano_cpus=1000000000,             # CPU 1개로... 제한
                detach=True
            )

            # 3. PoC가 끝날 때까지 대기 (최대 30초 타임아웃 설정으로 무한루프 방지)
            result = container.wait(timeout=30)
            exit_code = result.get("StatusCode", -1)

            # 4. 실행 로그 수집
            logs = container.logs().decode("utf-8", errors="ignore")
            
            # 5. 취약점 성공 여부 판단 (Exit code 기반 혹은 특정 로그 검사)
            # 예시: 특정 에러 코드가 나거나, 공격 시그니처 로그가 남았는지 체크하기
            if exit_code != 0 or "EXPLOIT_SUCCESS" in logs:
                status = "VULNERABLE"
            else:
                status = "SAFE"

            return {
                "cve_id": cve_id,
                "status": status,
                "exit_code": exit_code,
                "logs": logs
            }

        except docker.errors.ContainerError as ce:
            return {"cve_id": cve_id, "status": "ERROR", "reason": f"컨테이너 에러: {ce}"}
        except Exception as e:
            return {"cve_id": cve_id, "status": "ERROR", "reason": f"검증 실패: {e}"}
        finally:

            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
