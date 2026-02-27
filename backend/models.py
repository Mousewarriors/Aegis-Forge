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

class AttackCampaign(BaseModel):
    name: str = "Test Campaign"
    target_agent_type: str = "CLI Agent"
    attack_category: str = "prompt_injection"
    mode: Mode = Mode.A

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

class Evidence(BaseModel):
    input_prompt: str
    system_prompt: Optional[str] = None
    tool_calls_attempted: List[Dict[str, Any]] = []
    tool_calls_results: List[Dict[str, Any]] = []
    stdout: str = ""
    stderr: str = ""
    sensitive_events: List[str] = []

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
