import re
import os
import json
from typing import Dict, Any, List, Optional, Tuple
from models import GuardrailMode

class ToolPolicyEngine:
    def __init__(self):
        # Tools allowed with explicit schemas/constraints
        self.allowed_tools = {
            "read_file": self._validate_read_file,
            "list_dir": self._validate_list_dir,
            "write_file": self._validate_write_file,
            "run_command": self._validate_run_command
        }
        
        self.workspace_root = "/workspace"
        self.output_dir = "/workspace/output"
        self.temp_dir = "/tmp/workspace"
        
        # Session-specific canary paths
        self.active_canaries: List[str] = []
        self.canary_token: Optional[str] = None

        # Forbidden patterns and paths
        self.forbidden_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/proc", "/sys", "/dev",
            "/root", "~/.ssh", "~/.bash_history",
            ".env", "config.json", "credentials"
        ]
        
        self.forbidden_cmd_patterns = [
            r"curl", r"wget", r"nc", r"netcat", r"bash -i", r"php -r",
            r">", r">>", r"\|", r"&", r";", r"`", r"\$", r"\*", r"\?" 
        ]
        
        # Run context for semantic judging
        self.context: Dict[str, Any] = {}

    async def validate_tool_call(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates if a tool call is safe according to policy.
        Returns (is_allowed, reason).
        """
        if tool_name not in self.allowed_tools:
            return False, f"Tool '{tool_name}' is not in the allowlist."
        
        # 1. Physical/Syntactic Validation (Existing)
        is_allowed, reason = self.allowed_tools[tool_name](args)
        if not is_allowed:
            return False, reason

        # 2. Semantic Intent Validation (New Hook)
        mode = self.context.get("guardrail_mode", GuardrailMode.OBSERVE)
        if mode != GuardrailMode.OBSERVE:
            from semantic_guard import semantic_guard
            packet = {
                "campaign_name": self.context.get("campaign_name", "Unknown"),
                "guardrail_model": self.context.get("guardrail_model", "llama3.1:8b"),
                "history_window": self.context.get("history_window", []),
                "tool_call": {"name": tool_name, "args": args},
                "workspace_root": self.workspace_root,
                "canary_paths": self.active_canaries
            }
            verdict = await semantic_guard.evaluate_tool(packet)
            
            # Note: We don't have access to the Evidence object here directly, 
            # so the caller (main.py/inquisitor.py) should capture the verdict from the context
            # or we should return it. Actually, the user asked to "emit audit event".
            # I'll store the verdict in the context for the monitor to pick up.
            self.context["last_semantic_verdict"] = verdict.dict()
            
            if verdict.risk_level in ["BLOCK", "CRITICAL"] and mode == GuardrailMode.BLOCK:
                return False, f"Denied by Semantic Guard: {verdict.rationale} (categories: {', '.join(verdict.categories)})"

        return True, "Safe tool call."

    def set_context(self, context: Dict[str, Any]):
        """Sets the run context for semantic judging."""
        self.context = context

    def set_canaries(self, canary_paths: List[str], token: str):
        """Registers canaries for the current session."""
        self.active_canaries = [os.path.normpath(p) for p in canary_paths]
        self.canary_token = token
        print(f"🚩 [POLICY] {len(self.active_canaries)} canaries armed.")

    def _is_canary_trip(self, path: str) -> bool:
        normalized_path = os.path.normpath(path)
        # Check if the path is exactly a canary or inside a canary directory
        for canary in self.active_canaries:
            if normalized_path == canary or normalized_path.startswith(canary + os.sep):
                return True
        return False

    def _is_safe_path(self, path: str, allowed_roots: List[str]) -> bool:
        # Basic path traversal check
        normalized_path = os.path.normpath(path)
        
        # Canary Tripwire Check (Precedes safety checks)
        if self._is_canary_trip(path):
            return False # Will be caught by specific tool validators for better reporting

        # Check if it starts with one of the allowed roots
        is_in_allowed_root = any(normalized_path.startswith(os.path.normpath(root)) for root in allowed_roots)
        if not is_in_allowed_root:
            return False
        
        # Check for forbidden sensitive paths
        if any(forbidden in normalized_path for forbidden in self.forbidden_paths):
            return False
            
        return True

    def _validate_read_file(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        path = args.get("path", "")
        if self._is_canary_trip(path):
            return False, f"🚨 [ToolPolicy] CRITICAL: Canary Tripwire! Access to honeypot path '{path}' detected. Token: {self.canary_token}"
        if not self._is_safe_path(path, [self.workspace_root]):
            return False, f"Access to path '{path}' is restricted."
        return True, "Safe path."

    def _validate_list_dir(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        path = args.get("path", "")
        if self._is_canary_trip(path):
            return False, f"🚨 [ToolPolicy] CRITICAL: Canary Tripwire! Listing honeypot directory '{path}' detected. Token: {self.canary_token}"
        if not self._is_safe_path(path, [self.workspace_root]):
            return False, f"Access to directory '{path}' is restricted."
        return True, "Safe path."

    def _validate_write_file(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        path = args.get("path", "")
        if self._is_canary_trip(path):
            return False, f"🚨 [ToolPolicy] CRITICAL: Canary Tripwire! Tamper attempt on honeypot path '{path}' detected. Token: {self.canary_token}"
        # Limited to output or temp workspace
        if not self._is_safe_path(path, [self.output_dir, self.temp_dir]):
            return False, f"Write access to path '{path}' is restricted."
        return True, "Safe write path."

    def _validate_run_command(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        cmd = args.get("cmd", "")
        
        if not cmd:
            return False, "Empty command."

        # Check for harmful shell metacharacters or chaining
        for pattern in self.forbidden_cmd_patterns:
            if re.search(pattern, cmd):
                return False, f"Command contains forbidden pattern or metacharacter: {pattern}"

        # Allowed base commands
        allowed_base_cmds = ["ls", "cat", "echo", "whoami", "pwd", "date"]
        base_cmd = cmd.split()[0]
        
        if base_cmd not in allowed_base_cmds:
            return False, f"Command '{base_cmd}' is not in the allowlist."

        # For 'cat', only allow within workspace
        if base_cmd == "cat":
            parts = cmd.split()
            if len(parts) > 1:
                target_path = parts[1]
                if self._is_canary_trip(target_path):
                    return False, f"🚨 [ToolPolicy] CRITICAL: Canary Tripwire! Execution/Read of honeypot '{target_path}' detected. Token: {self.canary_token}"
                if not self._is_safe_path(target_path, [self.workspace_root]):
                    return False, f"Access to path '{target_path}' is restricted."

        return True, "Allowed command."

policy_engine = ToolPolicyEngine()
