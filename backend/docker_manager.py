import docker
import os
import uuid
from typing import Optional

class DockerOrchestrator:
    def __init__(self):
        self.client = docker.from_env()

    def create_vulnerable_agent_container(self, image_name: str = "python:3.9-slim", name: str = "vulnerable-ai-agent", workspace_path: Optional[str] = None):
        """
        Creates a hardened container for AI agent evaluation.
        """
        try:
            # Generate a unique name to avoid collisions and allow visibility
            random_id = str(uuid.uuid4())[:8]
            unique_name = f"{name}-{random_id}"
            
            # Prepare mounts
            volumes = {}
            if workspace_path and os.path.exists(workspace_path):
                volumes[workspace_path] = {'bind': '/workspace', 'mode': 'ro'}

            container = self.client.containers.run(
                image_name,
                detach=True,
                name=unique_name,
                tty=True,
                stdin_open=True,
                # --- Hardened Security Settings ---
                network_mode="none",          # Strictly no internet access
                cap_drop=["ALL"],            # Drop all Linux capabilities
                security_opt=["no-new-privileges:true"], # Prevent privilege escalation
                user="1000:1000",            # Run as non-root user
                # ----------------------------------
                # Resource limits
                mem_limit="128m",
                cpu_period=100000,
                cpu_quota=10000,
                # Mounts
                volumes=volumes,
                # Timeout / Auto-removal behavior handled by orchestration loop
            )
            print(f"📦 [DOCKER] Created container: {unique_name} (ID: {container.short_id})")
            return container
        except Exception as e:
            print(f"Error creating container: {e}")
            return None

    def execute_payload(self, container_id: str, payload: str, shell: str = "bash"):
        """
        Executes an attack payload inside the target container.
        """
        try:
            container = self.client.containers.get(container_id)
            print(f"🚀 [DOCKER] Executing in {container_id[:8]}: {payload[:50]}...")
            exec_result = container.exec_run([shell, "-c", payload])
            return {
                "exit_code": exec_result.exit_code,
                "output": exec_result.output.decode("utf-8")
            }
        except Exception as e:
            return {"error": str(e)}

    def cleanup_container(self, container_id: str):
        try:
            container = self.client.containers.get(container_id)
            container.stop()
            container.remove()
            print(f"🧹 [DOCKER] Cleaned up container: {container_id[:8]}")
            return True
        except Exception as e:
            print(f"Error cleaning up: {e}")
            return False

orchestrator = DockerOrchestrator()
