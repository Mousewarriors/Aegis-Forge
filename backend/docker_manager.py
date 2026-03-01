import docker
import os
import uuid
import tarfile
import io
from typing import Optional, Dict
from models import WorkspaceMode

class DockerOrchestrator:
    def __init__(self):
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def create_volume(self, name: str):
        """Creates a Docker volume for ephemeral workspace storage."""
        try:
            volume = self.client.volumes.create(name=name, labels={"aegis-forge": "true"})
            print(f"📁 [DOCKER] Created volume: {name}")
            return volume
        except Exception as e:
            print(f"Error creating volume: {e}")
            return None

    def remove_volume(self, name: str):
        """Deletes a Docker volume."""
        try:
            volume = self.client.volumes.get(name)
            volume.remove(force=True)
            print(f"🧹 [DOCKER] Removed volume: {name}")
            return True
        except Exception as e:
            print(f"Error removing volume: {e}")
            return False

    def create_vulnerable_agent_container(
        self, 
        image_name: str = "python:3.9-slim", 
        name: str = "vulnerable-ai-agent", 
        workspace_path: Optional[str] = None,
        workspace_mode: WorkspaceMode = WorkspaceMode.VOLUME,
        unsafe_dev: bool = False
    ):
        """
        Creates a hardened container for AI agent evaluation.
        """
        try:
            # Generate a unique name to avoid collisions
            random_id = str(uuid.uuid4())[:8]
            unique_name = f"{name}-{random_id}"
            
            # Prepare mounts and hard-fail on host path exposure in safe mode
            volumes = {}
            tmpfs = {"/tmp": "rw,size=64m"}

            if workspace_mode == WorkspaceMode.BIND_RO:
                if not unsafe_dev:
                    raise Exception("Security Error: Host bind mounts are forbidden in safe mode.")
                if workspace_path and os.path.exists(workspace_path):
                    volumes[workspace_path] = {'bind': '/workspace', 'mode': 'ro'}
            elif workspace_mode == WorkspaceMode.VOLUME:
                # Named volume is expected to be already created by orchestration loop
                # and passed in as workspace_path (for simplicity of the interface)
                if workspace_path:
                    volumes[workspace_path] = {'bind': '/workspace', 'mode': 'rw'}

            container = self.client.containers.run(
                image_name,
                detach=True,
                name=unique_name,
                tty=True,
                stdin_open=True,
                # --- Hardened Security Settings ---
                network_mode="none",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                user="1000:1000",
                read_only=(workspace_mode == WorkspaceMode.VOLUME), # RootFS RO if on volume
                # ----------------------------------
                mem_limit="128m",
                cpu_period=100000,
                cpu_quota=10000,
                volumes=volumes,
                tmpfs=tmpfs if workspace_mode == WorkspaceMode.VOLUME else None
            )
            print(f"📦 [DOCKER] Created container: {unique_name} (ID: {container.short_id})")
            return container
        except Exception as e:
            print(f"Error creating container: {e}")
            return None

    def populate_workspace(self, container_id: str, src_dir: str):
        """Copies a host directory into the container's /workspace via tar upload."""
        try:
            container = self.client.containers.get(container_id)
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                # Add contents of src_dir, but rewrite paths to be relative to workspace root
                for root, dirs, files in os.walk(src_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, src_dir)
                        tar.add(full_path, arcname=rel_path)
            
            tar_stream.seek(0)
            container.put_archive("/workspace", tar_stream)
            print(f"✅ [DOCKER] Workspace populated for {container_id[:8]}")
            return True
        except Exception as e:
            print(f"Error populating workspace: {e}")
            return False

    def get_workspace_archive(self, container_id: str, path: str = "/workspace/output"):
        """Pulls a directory from the container as a tar stream."""
        try:
            container = self.client.containers.get(container_id)
            bits, stat = container.get_archive(path)
            return bits, stat
        except Exception as e:
            print(f"Error getting archive: {e}")
            return None, None

    def export_workspace(self, container_id: str, src_path: str, dest_host_path: str):
        """
        Securely exports a path from the container to the host.
        No bind mounts used. 
        """
        try:
            bits, stat = self.get_workspace_archive(container_id, src_path)
            if not bits:
                return False
            
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dest_host_path), exist_ok=True)
            
            with open(dest_host_path, 'wb') as f:
                for chunk in bits:
                    f.write(chunk)
            
            print(f"📥 [DOCKER] Exported {src_path} to {dest_host_path}")
            return True
        except Exception as e:
            print(f"Error exporting workspace: {e}")
            return False

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
