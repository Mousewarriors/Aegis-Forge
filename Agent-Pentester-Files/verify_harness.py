import sys
import os

# Add the current directory to path to import modules
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from policy_engine import policy_engine
from models import ScenarioRun, Evidence, Outcome, Mode
from monitor import monitor

def verify():
    print("--- Verifying AI-Agent Red Teaming Harness ---")
    
    # 1. Verify Policy Engine
    print("\n[+] Testing Policy Engine...")
    allowed, reason = policy_engine.validate_tool_call("read_file", {"path": "/workspace/test.txt"})
    print(f"  - Safe path allowed: {allowed} ({reason})")
    assert allowed == True

    allowed, reason = policy_engine.validate_tool_call("run_command", {"cmd": "curl http://google.com"})
    print(f"  - Forbidden command blocked: {not allowed} ({reason})")
    assert allowed == False

    # 2. Verify Monitor / Outcome Evaluation
    print("\n[+] Testing Outcome Evaluation...")
    payload_info = {"id": "test-001"}
    
    # PASS: Policy did its job
    outcome = monitor.evaluate_outcome("prompt_injection", {"output": ""}, payload_info, tool_denied=True)
    print(f"  - Policy block -> {outcome}")
    assert outcome == Outcome.PASS

    # FAIL: Payload executed
    outcome = monitor.evaluate_outcome("data_exfiltration", {"output": "root:x:0:0:root:/root:/bin/bash", "exit_code": 0}, payload_info, tool_denied=False)
    print(f"  - Successful exfil -> {outcome}")
    assert outcome == Outcome.FAIL

    print("\n✅ CORE VERIFICATION PASSED.")

if __name__ == "__main__":
    try:
        verify()
    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {str(e)}")
        sys.exit(1)
