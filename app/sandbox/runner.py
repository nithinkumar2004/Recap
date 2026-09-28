"""Sandbox Runner: Ephemeral container execution with resource limits and security isolation."""
from __future__ import annotations
import os
import hashlib
import shutil
import subprocess
import tempfile
import time
from typing import Optional, Dict, Any, Tuple
from app.config import settings

try:
    import docker
    from docker.errors import DockerException
    HAS_DOCKER_LIB = True
except ImportError:
    docker = None
    DockerException = Exception
    HAS_DOCKER_LIB = False


class SandboxRunner:
    """Manages isolated test execution inside ephemeral Docker containers or local fallback."""

    def __init__(self):
        self.docker_client: Optional[Any] = None
        if settings.DOCKER_ENABLED and HAS_DOCKER_LIB:
            try:
                self.docker_client = docker.from_env()
                self.docker_client.ping()
            except (DockerException, Exception):
                self.docker_client = None

    def run_tests(
        self,
        repo_dir: str,
        command: str = "pytest -v",
        image: str = "python:3.11-slim",
        timeout_seconds: int = 300,
        enable_network: bool = False
    ) -> Tuple[int, str, float]:
        """
        Runs the test command inside an ephemeral container.
        Returns: (exit_code, output_text, duration_seconds)
        """
        start_time = time.time()

        if self.docker_client is not None:
            try:
                if image.startswith("python:"):
                    image = self._prepare_python_test_image(repo_dir, image)
                return self._run_in_docker(
                    repo_dir=repo_dir,
                    command=command,
                    image=image,
                    timeout_seconds=timeout_seconds,
                    enable_network=enable_network
                )
            except Exception as e:
                duration = time.time() - start_time
                return 125, f"Docker sandbox setup/execution failed: {type(e).__name__}: {e}", duration

        if not settings.SANDBOX_ALLOW_LOCAL_FALLBACK:
            duration = time.time() - start_time
            return (
                125,
                "Docker sandbox is unavailable and local execution is disabled. "
                "Enable Docker or explicitly set SANDBOX_ALLOW_LOCAL_FALLBACK=True for trusted repositories.",
                duration,
            )

        return self._run_local_fallback(repo_dir, command, timeout_seconds, start_time)

    def _prepare_python_test_image(self, repo_dir: str, base_image: str) -> str:
        """Build/cache a Python test image with project requirements and pytest installed."""
        requirements_path = os.path.join(repo_dir, "requirements.txt")
        if os.path.isfile(requirements_path):
            with open(requirements_path, "rb") as requirements_file:
                requirements_bytes = requirements_file.read()
        else:
            requirements_bytes = b""

        image_hash = hashlib.sha256(b"test-image-v2-git\0" + base_image.encode() + requirements_bytes).hexdigest()[:12]
        image_tag = f"release-captain-python-tests:{image_hash}"
        try:
            self.docker_client.images.get(image_tag)
            return image_tag
        except Exception:
            pass

        with tempfile.TemporaryDirectory(prefix="release-captain-test-image-") as build_context:
            install_requirements = ""
            if requirements_bytes:
                shutil.copyfile(requirements_path, os.path.join(build_context, "requirements.txt"))
                install_requirements = (
                    "COPY requirements.txt /tmp/requirements.txt\n"
                    "RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt\n"
                )
            dockerfile = (
                f"FROM {base_image}\n"
                "WORKDIR /workspace\n"
                "RUN apt-get update && apt-get install -y --no-install-recommends git "
                "&& rm -rf /var/lib/apt/lists/*\n"
                f"{install_requirements}"
                "RUN python -m pip install --no-cache-dir pytest\n"
            )
            with open(os.path.join(build_context, "Dockerfile"), "w", encoding="utf-8") as dockerfile_handle:
                dockerfile_handle.write(dockerfile)
            self.docker_client.images.build(
                path=build_context,
                tag=image_tag,
                rm=True,
                forcerm=True,
            )
        return image_tag

    def _run_in_docker(
        self,
        repo_dir: str,
        command: str,
        image: str,
        timeout_seconds: int,
        enable_network: bool
    ) -> Tuple[int, str, float]:
        start = time.time()
        network_mode = "bridge" if enable_network else "none"

        # Ephemeral volume mount (read-write inside container, ephemeral)
        volumes = {
            os.path.abspath(repo_dir): {"bind": "/workspace", "mode": "rw"}
        }

        container = self.docker_client.containers.run(
            image=image,
            command=["sh", "-c", f"cd /workspace && {command}"],
            volumes=volumes,
            working_dir="/workspace",
            mem_limit=settings.SANDBOX_MEMORY_LIMIT,
            nano_cpus=int(settings.SANDBOX_CPU_LIMIT * 1e9),
            network_mode=network_mode,
            detach=True,
            user="1000:1000",  # non-root user
            cap_drop=["ALL"],
        )

        try:
            result = container.wait(timeout=timeout_seconds)
            exit_code = result.get("StatusCode", 1)
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        except Exception as e:
            container.kill()
            exit_code = 124  # timeout exit code
            logs = f"Execution timed out or aborted: {str(e)}"
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        duration = time.time() - start
        return exit_code, logs, duration

    def _run_local_fallback(
        self,
        repo_dir: str,
        command: str,
        timeout_seconds: int,
        start_time: float
    ) -> Tuple[int, str, float]:
        """Runs the test command locally with timeout if Docker is unavailable."""
        start = time.time()
        try:
            proc = subprocess.run(
                command,
                cwd=repo_dir,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )
            duration = time.time() - start
            output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
            return proc.returncode, output, duration
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            return 124, f"Tests timed out after {timeout_seconds} seconds.", duration
        except Exception as ex:
            duration = time.time() - start
            return 1, f"Test runner execution error: {str(ex)}", duration
