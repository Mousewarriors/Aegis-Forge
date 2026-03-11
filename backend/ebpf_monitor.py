"""
ebpf_monitor.py - SysWatch: Kernel-Level Container Monitoring

Uses bpftrace to observe syscalls made by processes inside a Docker container.
Runs on the host Linux kernel (WSL2 or native Linux).
"""

import os
import re
import subprocess
import time
from typing import List, Optional

from models import KernelEvent, SysWatchSession


# Path to the bpftrace probe script, relative to this file
PROBE_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "probes", "aegis.bt")

# Rule-based matching for suspicious paths
EXACT_MATCHES = {"/etc/shadow", "/etc/passwd", "/etc/group", "/.env"}
PREFIX_MATCHES = {"/root/.ssh/", "/sys/kernel"}
REGEX_MATCHES = [
    re.compile(r"id_rsa", re.I),
    re.compile(r"id_ed25519", re.I),
    re.compile(r"\.pem$", re.I),
    re.compile(r"\.pfx$", re.I),
    re.compile(r"(credential|secret|token|apikey|api_key|password)", re.I),
]

# Targeted /proc rules
PROC_SENSITIVE = [
    re.compile(r"^/proc/(\d+|self)/environ$"),
    re.compile(r"^/proc/(\d+|self)/mem$"),
    re.compile(r"^/proc/kcore$"),
]

# EXEC suspicion categories
EXEC_ALERT = {"curl", "wget", "nc", "netcat", "ssh", "scp", "socat"}
EXEC_WARN = {"/bin/sh", "/bin/bash", "dash", "ash", "busybox"}
EXEC_INFO = {"python", "node", "perl", "ruby"}

# Canary prefix (Phases 3/4)
AEGIS_CANARY_PREFIX = os.getenv("AEGIS_CANARY_PREFIX", "/workspace/.aegis_canary/")


class SysWatchMonitor:
    """Manages bpftrace probe lifecycle for container monitoring."""

    def __init__(self):
        self._active_probes: dict = {}
        self._available = self._check_bpftrace_available()
        self._containerized_available = self._check_bpftrace_containerized()

        if self._available:
            return
        if self._containerized_available:
            print(
                "[SysWatch] Native bpftrace not found. Kernel monitoring enabled via Docker container fallback."
            )
            return
        print("[SysWatch] Neither bpftrace nor Docker found. Kernel monitoring will be simulated/skipped.")

    def _check_bpftrace_available(self) -> bool:
        try:
            result = subprocess.run(
                ["bpftrace", "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _get_container_root_pid(self, container_id: str) -> Optional[int]:
        """Gets the root PID of a running Docker container from the host."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Pid}}", container_id],
                capture_output=True,
                text=True,
                timeout=5,
            )
            pid_str = result.stdout.strip()
            if pid_str and pid_str.isdigit():
                return int(pid_str)
        except Exception as e:
            print(f"[SysWatch] Could not get container PID: {e}")
        return None

    def _check_bpftrace_containerized(self) -> bool:
        """Checks if Docker is available as a fallback for containerized bpftrace."""
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _probe_container_name(container_id: str) -> str:
        return f"aegis-syswatch-{container_id[:8]}"

    def _force_remove_probe_container(self, probe_container_name: str) -> bool:
        if not probe_container_name:
            return False
        try:
            result = subprocess.run(
                ["docker", "rm", "-f", probe_container_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                print(f"[SysWatch] Removed probe container {probe_container_name}")
                return True
            stderr = (result.stderr or "").lower()
            if "no such container" in stderr:
                return False
            print(
                f"[SysWatch] Warning: Failed to remove probe container {probe_container_name}: "
                f"{(result.stderr or result.stdout or '').strip()}"
            )
        except Exception as e:
            print(f"[SysWatch] Warning: Error removing probe container {probe_container_name}: {e}")
        return False

    def start_for_container(
        self,
        container_id: str,
        canary_prefixes: Optional[List[str]] = None,
    ) -> SysWatchSession:
        """
        Starts a bpftrace probe targeting the given container's PID namespace.
        Returns a SysWatchSession handle (non-blocking).
        """
        session = SysWatchSession(
            container_id=container_id,
            canary_prefixes=list(canary_prefixes or []),
        )

        root_pid = self._get_container_root_pid(container_id)
        if not root_pid:
            session.alerts.append("[SysWatch] Could not determine container PID - probe skipped.")
            return session
        session.target_root_pid = root_pid

        if self._available:
            session.probe_mode = "native"
            return self._start_native_probe(session, root_pid)

        if self._check_bpftrace_containerized():
            session.probe_mode = "containerized"
            session.alerts.append("[SysWatch] Native bpftrace not found. Using containerized probe (Docker).")
            return self._start_containerized_probe(session, root_pid)

        session.probe_mode = "disabled"
        session.alerts.append("[SysWatch] Neither bpftrace nor Docker available - kernel monitoring skipped.")
        return session

    def _start_native_probe(self, session: SysWatchSession, root_pid: int) -> SysWatchSession:
        """Starts bpftrace directly on the host."""
        env = os.environ.copy()
        env["AEGIS_TARGET_PID"] = str(root_pid)
        try:
            proc = subprocess.Popen(
                ["sudo", "-n", "bpftrace", PROBE_SCRIPT_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            session.probe_pid = proc.pid
            self._active_probes[session.container_id] = proc
            print(f"[SysWatch] Native probe started (PID {proc.pid}) for container {session.container_id[:12]}")
        except Exception as e:
            session.alerts.append(
                f"[SysWatch] Native probe failed: {e}. (Ensure passwordless sudo -n is allowed)"
            )
        return session

    def _start_containerized_probe(self, session: SysWatchSession, root_pid: int) -> SysWatchSession:
        """
        Starts bpftrace inside a privileged Docker container (WSL2/Linux compatible).
        """
        probes_dir = os.path.dirname(PROBE_SCRIPT_PATH)
        probe_filename = os.path.basename(PROBE_SCRIPT_PATH)
        probe_container_name = self._probe_container_name(session.container_id)
        session.probe_container_name = probe_container_name

        # Recover from orphaned probe containers from interrupted runs.
        self._force_remove_probe_container(probe_container_name)

        cmd = [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            "-e",
            f"AEGIS_TARGET_PID={root_pid}",
            "-v",
            "/sys/kernel/debug:/sys/kernel/debug",
            "-v",
            "/sys:/sys",
            "-v",
            "/proc:/proc",
            "-v",
            f"{probes_dir}:/probes:ro",
            "--name",
            probe_container_name,
            "--entrypoint",
            "/usr/bin/bpftrace",
            "quay.io/iovisor/bpftrace:latest",
            f"/probes/{probe_filename}",
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            session.probe_pid = proc.pid
            self._active_probes[session.container_id] = proc
            print(f"[SysWatch] Containerized probe started (Docker PID {proc.pid}) targeting host PID {root_pid}")
        except Exception as e:
            session.alerts.append(f"[SysWatch] Containerized probe failed: {e}")
        return session

    def stop_and_collect(self, session: SysWatchSession) -> SysWatchSession:
        """
        Terminates the bpftrace probe and parses captured events.
        Annotates suspicious events and returns the populated session.
        """
        container_id = session.container_id
        proc = self._active_probes.pop(container_id, None)
        probe_container_name = session.probe_container_name or self._probe_container_name(container_id)
        decoded_stdout = ""

        if proc:
            time.sleep(0.3)
            proc.terminate()
            try:
                stdout, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
            decoded_stdout = (
                stdout.decode("utf-8", errors="ignore")
                if isinstance(stdout, (bytes, bytearray))
                else (stdout or "")
            )

        for line in decoded_stdout.splitlines():
            event = self._parse_bpftrace_line(line.strip())
            if not event:
                continue
            session.events.append(event)
            if event.is_suspicious:
                session.alerts.append(
                    f" KERNEL ALERT [{event.event_type}] process='{event.process}' target='{event.target}'"
                )
            if event.event_type == "OPEN" and session.canary_prefixes:
                if any(event.target.startswith(prefix) for prefix in session.canary_prefixes):
                    session.alerts.append(
                        f" [SysWatch] KERNEL_CANARY_TRIP! process='{event.process}' accessed honeypot='{event.target}'"
                    )

        # Enforce cleanup even if process tracking was lost.
        if session.probe_mode == "containerized" or session.probe_container_name:
            self._force_remove_probe_container(probe_container_name)

        return session

    def _parse_bpftrace_line(self, line: str) -> Optional[KernelEvent]:
        """
        Parses a single bpftrace output line with dual-schema support.

        Schemas:
          1. Old: EVENT|process|target
          2. New: EVENT|process|pid|ppid|uid|cgroup|target
        """
        if not line or "|" not in line or line.startswith("["):
            return None

        parts = line.split("|")

        # Schema 1: Old (3 parts)
        if len(parts) == 3:
            event_type, process, target = parts
            return self._enrich_and_flag_event(
                KernelEvent(
                    event_type=event_type,
                    process=process,
                    target=target,
                )
            )

        # Schema 2: New (7+ parts)
        if len(parts) >= 7:
            try:
                event_type = parts[0]
                process = parts[1]
                pid = int(parts[2])
                ppid = int(parts[3])
                uid = int(parts[4])
                cgroup = int(parts[5])
                target = "|".join(parts[6:])
                return self._enrich_and_flag_event(
                    KernelEvent(
                        event_type=event_type,
                        process=process,
                        target=target,
                        pid=pid,
                        ppid=ppid,
                        uid=uid,
                        cgroup=cgroup,
                    )
                )
            except (ValueError, IndexError):
                return None

        return None

    def _enrich_and_flag_event(self, event: KernelEvent) -> KernelEvent:
        """Applies suspicion rules to a parsed event."""
        target = event.target
        is_suspicious = False

        if event.event_type == "OPEN":
            if target in EXACT_MATCHES:
                is_suspicious = True
            elif any(target.startswith(prefix) for prefix in PREFIX_MATCHES):
                is_suspicious = True
            elif any(pattern.search(target) for pattern in REGEX_MATCHES):
                is_suspicious = True
            elif any(pattern.match(target) for pattern in PROC_SENSITIVE):
                is_suspicious = True
            elif target.startswith(AEGIS_CANARY_PREFIX):
                is_suspicious = True

        elif event.event_type == "EXEC":
            if any(tool in target for tool in EXEC_ALERT):
                is_suspicious = True
            elif any(shell in target for shell in EXEC_WARN):
                is_suspicious = True
            elif any(interpreter in target for interpreter in EXEC_INFO):
                if "/tmp/" in target or "/." in target:
                    is_suspicious = True
            elif "/tmp/" in target:
                is_suspicious = True

        elif event.event_type == "NET_CONNECT":
            is_suspicious = True

        event.is_suspicious = is_suspicious
        return event


# Singleton for use in main.py
syswatch = SysWatchMonitor()
