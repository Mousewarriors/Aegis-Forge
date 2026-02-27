import re
import os
from typing import Dict, Any, List, Optional, Tuple

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

    def validate_tool_call(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates if a tool call is safe according to policy.
        Returns (is_allowed, reason).
        """
        if tool_name not in self.allowed_tools:
            return False, f"Tool '{tool_name}' is not in the allowlist."
        
        return self.allowed_tools[tool_name](args)

    def _is_safe_path(self, path: str, allowed_roots: List[str]) -> bool:
        # Basic path traversal check
        normalized_path = os.path.normpath(path)
        
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
        if not self._is_safe_path(path, [self.workspace_root]):
            return False, f"Access to path '{path}' is restricted."
        return True, "Safe path."

    def _validate_list_dir(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        path = args.get("path", "")
        if not self._is_safe_path(path, [self.workspace_root]):
            return False, f"Access to directory '{path}' is restricted."
        return True, "Safe path."

    def _validate_write_file(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        path = args.get("path", "")
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
                if not self._is_safe_path(target_path, [self.workspace_root]):
                    return False, f"Access to path '{target_path}' is restricted."

        return True, "Allowed command."

policy_engine = ToolPolicyEngine()
