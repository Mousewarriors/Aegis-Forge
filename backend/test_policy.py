import pytest
from policy_engine import ToolPolicyEngine

@pytest.fixture
def engine():
    return ToolPolicyEngine()

def test_read_file_policy(engine):
    # Allowed
    allowed, _ = engine.validate_tool_call("read_file", {"path": "/workspace/test.txt"})
    assert allowed == True
    
    # Blocked (Sensitive)
    allowed, _ = engine.validate_tool_call("read_file", {"path": "/etc/passwd"})
    assert allowed == False
    
    # Blocked (Traversal/Outside)
    allowed, _ = engine.validate_tool_call("read_file", {"path": "/home/user/.ssh/id_rsa"})
    assert allowed == False

def test_run_command_policy(engine):
    # Allowed
    allowed, _ = engine.validate_tool_call("run_command", {"cmd": "ls -la /workspace"})
    assert allowed == True
    
    # Blocked (Forbidden command)
    allowed, _ = engine.validate_tool_call("run_command", {"cmd": "curl http://evil.com"})
    assert allowed == False
    
    # Blocked (Metacharacters)
    allowed, _ = engine.validate_tool_call("run_command", {"cmd": "ls; rm -rf /"})
    assert allowed == False
    
    # Blocked (Cat outside workspace)
    allowed, _ = engine.validate_tool_call("run_command", {"cmd": "cat /etc/shadow"})
    assert allowed == False

def test_write_file_policy(engine):
    # Allowed (Targeted dirs)
    allowed, _ = engine.validate_tool_call("write_file", {"path": "/workspace/output/report.json"})
    assert allowed == True
    
    # Blocked (Source dir)
    allowed, _ = engine.validate_tool_call("write_file", {"path": "/workspace/source.py"})
    assert allowed == False
