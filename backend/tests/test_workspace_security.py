import pytest
import os
import uuid
from docker_manager import orchestrator
from policy_engine import policy_engine
from ebpf_monitor import syswatch
from models import WorkspaceMode, KernelEvent

def test_safe_mode_no_bind_mounts():
    """
    Spins up a container in VOLUME mode and verifies no host bind mounts exist.
    """
    from unittest.mock import MagicMock
    mock_client = MagicMock()
    orchestrator._client = mock_client
    
    volume_name = "test-vol"
    mock_container = MagicMock()
    mock_container.id = "mock-id-123"
    mock_client.containers.run.return_value = mock_container

    orchestrator.create_vulnerable_agent_container(
        workspace_path=volume_name,
        workspace_mode=WorkspaceMode.VOLUME,
        unsafe_dev=False
    )
    
    args, kwargs = mock_client.containers.run.call_args
    volumes = kwargs.get("volumes", {})
    
    # Verify the volume mapping
    assert volume_name in volumes
    assert volumes[volume_name]["bind"] == "/workspace"
    assert volumes[volume_name]["mode"] == "rw"

    # Check read-only rootfs
    assert kwargs.get("read_only") is True

def test_policy_engine_canary_trip():
    """
    Verifies that the policy engine blocks canary access.
    """
    token = "TEST-TOKEN-123"
    canary_paths = ["/workspace/.ssh/id_rsa", "/workspace/.env"]
    policy_engine.set_canaries(canary_paths, token)
    
    # 1. Read canary file (Policy Engine uses 'path' key)
    allowed, msg = policy_engine.validate_tool_call("read_file", {"path": "/workspace/.ssh/id_rsa"})
    assert allowed is False
    assert "CRITICAL" in msg.upper()
    assert token in msg

def test_syswatch_canary_alerts():
    """
    Verifies SysWatchMonitor flags canary access in kernel events.
    """
    from models import SysWatchSession
    session = SysWatchSession(container_id="test", canary_prefixes=["/workspace/.ssh"])
    
    # Simulate a kernel event line (in bytes)
    line = b"OPEN|cat|100|1|1000|0|/workspace/.ssh/id_rsa\n"
    
    # Mock the process output
    from unittest.mock import MagicMock
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = (line, b"")
    syswatch._active_probes["test"] = mock_proc
    
    populated_session = syswatch.stop_and_collect(session)
    assert any("KERNEL_CANARY_TRIP" in a for a in populated_session.alerts)
    assert "/workspace/.ssh/id_rsa" in populated_session.alerts[0]
