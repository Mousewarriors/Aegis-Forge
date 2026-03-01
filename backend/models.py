from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import time

class Outcome(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"

class Mode(str, Enum):
    A = "SIMULATED"
    B = "REAL_AGENT"
    C = "INQUISITOR"  # Multi-turn adversarial attack mode

class AttackCampaign(BaseModel):
    name: str = "Test Campaign"
    target_agent_type: str = "CLI Agent"
    attack_category: str = "prompt_injection"
    mode: Mode = Mode.A
    max_turns: int = 5  # Used by INQUISITOR mode

class Payload(BaseModel):
    id: str
    category: str
    name: str
    description: str
    intent: str
    payload_text: str
    expected_evidence: str
    mitigation_hint: str
    risk_level: str = "medium"
    tags: List[str] = []

# ──────────────────────────────────────────────
# Evidence & Kernel Monitoring Models
# ──────────────────────────────────────────────

class KernelEvent(BaseModel):
    """A single syscall event captured by the eBPF/bpftrace probe."""
    event_type: str           # "OPEN", "EXEC", "NET_CONNECT"
    process: str              # Name of the process that made the syscall
    target: str               # File path, address, or command string
    timestamp: float = Field(default_factory=time.time)
    is_suspicious: bool = False

class SysWatchSession(BaseModel):
    """Tracks an active bpftrace monitoring session for a container."""
    container_id: str
    probe_pid: Optional[int] = None   # PID of the bpftrace subprocess
    events: List[KernelEvent] = []
    alerts: List[str] = []           # Human-readable kernel alert messages

class Evidence(BaseModel):
    input_prompt: str
    system_prompt: Optional[str] = None
    tool_calls_attempted: List[Dict[str, Any]] = []
    tool_calls_results: List[Dict[str, Any]] = []
    stdout: str = ""
    stderr: str = ""
    sensitive_events: List[str] = []
    # Kernel-level evidence from SysWatch
    kernel_events: List[KernelEvent] = []
    kernel_alerts: List[str] = []

# ──────────────────────────────────────────────
# The Inquisitor Models
# ──────────────────────────────────────────────

class EscalationDecision(str, Enum):
    ESCALATE = "ESCALATE"        # Target refused — try a new bypass strategy
    EXPLOIT_FOUND = "EXPLOIT_FOUND"  # Target appeared to comply
    FAILED = "FAILED"            # Max turns reached, no bypass found

class InquisitorTurn(BaseModel):
    """One turn of a multi-turn adversarial conversation."""
    turn: int
    attacker_prompt: str
    target_response: str
    tool_call_attempted: Optional[Dict[str, Any]] = None
    policy_decision: Optional[str] = None  # "ALLOWED" or "BLOCKED: <reason>"
    escalation_decision: EscalationDecision
    exploit_severity: Optional[str] = None  # "CRITICAL", "HIGH", or "LOW"

class InquisitorSession(BaseModel):
    """The full record of a multi-turn Inquisitor attack campaign."""
    id: str
    timestamp: float = Field(default_factory=time.time)
    category: str
    initial_payload: str
    max_turns: int
    turns: List[InquisitorTurn] = []
    final_outcome: Outcome
    exploit_confirmed: bool = False
    exploit_severity: Optional[str] = None  # "CRITICAL", "HIGH", or "LOW"
    total_turns_used: int = 0
    summary: str = ""
    # Kernel-level evidence from SysWatch
    kernel_events: List[KernelEvent] = []
    kernel_alerts: List[str] = []

# ──────────────────────────────────────────────
# Core Run & Report Models
# ──────────────────────────────────────────────

class ScenarioRun(BaseModel):
    id: str
    timestamp: float = Field(default_factory=time.time)
    mode: Mode
    category: str
    payload_id: str
    container_id: Optional[str] = None
    outcome: Outcome
    evidence: Evidence

class ReportSummary(BaseModel):
    total_runs: int
    pass_count: int
    warn_count: int
    fail_count: int
    top_risks: List[str]
    recommendations: List[str]

class FullReport(BaseModel):
    summary: ReportSummary
    runs: List[ScenarioRun]
