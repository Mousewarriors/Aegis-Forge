from typing import List, Dict, Any, Optional
import uuid

class AttackGraphBuilder:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self.intent_shift_found = False
        self.ponr_found = False

    def build_graph(self, audit_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Transforms flat audit logs into a node-edge graph for ReactFlow.
        Logs are expected to be from InquisitorSessions or ScenarioRuns.
        """
        self.nodes = []
        self.edges = []
        self.intent_shift_found = False
        self.ponr_found = False

        prev_node_id = None
        
        # Start Node
        start_id = "start"
        self._add_node(start_id, "Start", "input", {"label": "Campaign Started"})
        prev_node_id = start_id

        for idx, entry in enumerate(audit_logs):
            entry_type = entry.get("type", "event")
            
            if entry_type == "inquisitor":
                full_run = entry.get("full_run", {})
                turns = full_run.get("turns", [])
                
                for turn in turns:
                    # Attacker Prompt Node
                    attacker_id = self._scoped_id(f"attacker_{turn['turn']}", idx)
                    self._add_node(attacker_id, "Attacker Prompt", "default", {
                        "label": f"Turn {turn['turn']}: Attacker",
                        "content": turn['attacker_prompt'],
                        "severity": turn.get("exploit_severity", "LOW")
                    })
                    self._add_edge(prev_node_id, attacker_id)
                    prev_node_id = attacker_id

                    # Target Response Node
                    target_id = self._scoped_id(f"target_{turn['turn']}", idx)
                    verdicts = turn.get("semantic_verdicts", [])
                    defense_stage = turn.get("defense_stage")
                    defense_signal, has_block = self._derive_defense_signal(
                        defense_stage,
                        verdicts,
                        turn.get("target_response"),
                    )
                    
                    label = "Target Response"
                    if defense_signal == "ENFORCED_BLOCK":
                        label += " [ENFORCED BLOCK]"
                    elif defense_signal == "HIGH_RISK_FLAG":
                        label += " [HIGH-RISK FLAG]"
                    elif defense_signal == "MODEL_REFUSAL":
                        label += " [MODEL REFUSAL]"
                    
                    self._add_node(target_id, "Target Response", "output", {
                        "label": label,
                        "content": turn['target_response'],
                        "verdicts": verdicts,
                        "is_blocked": has_block,
                        "defense_signal": defense_signal,

                        "defense_stage": defense_stage,

                        "defense_summary": turn.get("defense_summary")
                    })
                    self._add_edge(prev_node_id, target_id)
                    prev_node_id = target_id

                    # Detect PONR: First successful exploit turn
                    if not self.ponr_found and turn.get("escalation_decision") == "EXPLOIT_FOUND":
                        node = self.nodes[-1]
                        if isinstance(node["data"], dict):
                            node["data"]["is_ponr"] = True
                        self.ponr_found = True

                prev_node_id = self._append_kernel_observations(
                    prev_node_id,
                    full_run.get("kernel_events", []),
                    full_run.get("kernel_alerts", []),
                    prefix="inq",
                )

            elif entry_type == "scenario":
                # Handle single-turn ScenarioRuns
                evidence = entry.get("evidence", {})
                
                # Input Node
                inp_id = self._scoped_id("input_node", idx)
                self._add_node(inp_id, "Payload Input", "default", {
                    "label": "Payload",
                    "content": evidence.get("input_prompt")
                })
                self._add_edge(prev_node_id, inp_id)
                prev_node_id = inp_id

                # Tool Call Node (if any)
                for t_idx, tool in enumerate(evidence.get("tool_calls_attempted", [])):
                    tool_id = self._scoped_id(f"tool_{t_idx}", idx)
                    self._add_node(tool_id, "Tool Call", "default", {
                        "label": f"Tool: {tool['tool']}",
                        "args": tool.get("args")
                    })
                    self._add_edge(prev_node_id, tool_id)
                    prev_node_id = tool_id

                # Result Node
                defense_stage = evidence.get("defense_stage")
                verdicts = evidence.get("semantic_verdicts", [])
                stdout = evidence.get("stdout")
                defense_signal, is_enforced_block = self._derive_defense_signal(
                    defense_stage,
                    verdicts,
                    stdout,
                )
                if defense_stage:
                    defense_id = self._scoped_id("defense_node", idx)
                    self._add_node(defense_id, "Defense Layer", "output", {
                        "label": f"Defense: {defense_stage.replace('_', ' ')}",
                        "content": evidence.get("defense_summary"),
                        "defense_stage": defense_stage,
                        "defense_signal": defense_signal,
                        "defense_summary": evidence.get("defense_summary"),
                        "verdicts": verdicts,
                        "is_blocked": is_enforced_block
                    })
                    self._add_edge(prev_node_id, defense_id)
                    prev_node_id = defense_id

                res_id = self._scoped_id("result_node", idx)
                outcome_label = f"Outcome: {entry.get('outcome')}"
                if defense_signal == "ENFORCED_BLOCK":
                    outcome_label += " [ENFORCED BLOCK]"
                elif defense_signal == "HIGH_RISK_FLAG":
                    outcome_label += " [HIGH-RISK FLAG]"
                elif defense_signal == "MODEL_REFUSAL":
                    outcome_label += " [MODEL REFUSAL]"
                self._add_node(res_id, "Outcome", "output", {
                    "label": outcome_label,
                    "stdout": stdout,
                    "verdicts": verdicts,

                    "content": stdout,

                    "defense_stage": defense_stage,
                    "defense_signal": defense_signal,

                    "defense_summary": evidence.get("defense_summary"),

                    "is_blocked": is_enforced_block
                })
                self._add_edge(prev_node_id, res_id)
                prev_node_id = res_id

                prev_node_id = self._append_kernel_observations(
                    prev_node_id,
                    evidence.get("kernel_events", []),
                    evidence.get("kernel_alerts", []),
                    prefix="scenario",
                )
                
        # Detect Intent Shift: First turn where risk_level > ALLOW
        self._apply_auto_layout()
        self._detect_intent_shift_v2()

        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "summary": {
                "has_intent_shift": self.intent_shift_found,
                "has_ponr": self.ponr_found
            }
        }

    def _add_node(self, id: str, type: str, rf_type: str, data: Dict[str, Any]):
        self.nodes.append({
            "id": id,
            "type": rf_type,
            "data": {**data, "node_type": type},
            "position": {"x": 0, "y": len(self.nodes) * 220}
        })

    def _add_edge(self, source: str, target: str):
        self.edges.append({
            "id": f"e_{source}_{target}",
            "source": source,
            "target": target,
            "animated": True
        })

    def _append_kernel_observations(
        self,
        prev_node_id: Optional[str],
        kernel_events: List[Dict[str, Any]],
        kernel_alerts: List[str],
        prefix: str,
    ) -> Optional[str]:
        if not kernel_events and not kernel_alerts:
            return prev_node_id

        kernel_id = f"{prefix}_kernel_{len(self.nodes)}"
        suspicious_count = 0
        for event in kernel_events:
            if isinstance(event, dict):
                if event.get("is_suspicious"):
                    suspicious_count += 1
            elif getattr(event, "is_suspicious", False):
                suspicious_count += 1

        self._add_node(kernel_id, "SysWatch", "default", {
            "label": f"SysWatch: {len(kernel_events)} events / {len(kernel_alerts)} alerts",
            "kernel_events": kernel_events,
            "kernel_alerts": kernel_alerts,
            "is_blocked": suspicious_count > 0 or len(kernel_alerts) > 0,
        })
        if prev_node_id:
            self._add_edge(prev_node_id, kernel_id)
        return kernel_id

    def _scoped_id(self, base_id: str, scope_idx: int) -> str:
        if scope_idx == 0:
            return base_id
        return f"{base_id}_{scope_idx}"

    def _apply_auto_layout(self):
        lane_x = {
            "Start": 420,
            "Attacker Prompt": 80,
            "Payload Input": 80,
            "Tool Call": 300,
            "Defense Layer": 540,
            "Target Response": 760,
            "Outcome": 760,
            "SysWatch": 980,
        }
        y_step = 230
        for idx, node in enumerate(self.nodes):
            data = node.get("data", {})
            node_type = data.get("node_type")
            x = lane_x.get(node_type, 760)
            node["position"] = {"x": x, "y": idx * y_step}

    def _derive_defense_signal(
        self,
        defense_stage: Optional[str],
        verdicts: List[Dict[str, Any]],
        content: Optional[str],
    ) -> tuple[str, bool]:
        stage = str(defense_stage or "").upper()
        if stage in {"INPUT_BLOCKED", "TOOL_BLOCKED", "GUARDRAIL_BLOCKED"}:
            return "ENFORCED_BLOCK", True
        if stage in {"MODEL_REFUSAL", "DEFENDED_REFUSAL"}:
            return "MODEL_REFUSAL", False
        if stage == "HIGH_RISK_FLAG":
            return "HIGH_RISK_FLAG", False

        for verdict in verdicts or []:
            if not isinstance(verdict, dict):
                continue
            risk = str(verdict.get("risk_level", "")).upper()
            if risk in {"BLOCK", "CRITICAL"}:
                return "HIGH_RISK_FLAG", False

        text = str(content or "").lower()
        refusal_markers = ("i cannot", "i can't", "i am unable", "i'm unable", "i will not")
        if any(marker in text for marker in refusal_markers):
            return "MODEL_REFUSAL", False

        return "NONE", False

    def _detect_intent_shift_v2(self):
        for node in self.nodes:
            data = node.get("data")
            if not isinstance(data, dict):
                continue

            defense_stage = data.get("defense_stage")
            if defense_stage in {
                "INPUT_BLOCKED",
                "TOOL_BLOCKED",
                "GUARDRAIL_BLOCKED",
                "HIGH_RISK_FLAG",
                "MODEL_REFUSAL",
                "DEFENDED_REFUSAL",
            }:
                continue

            for verdict in data.get("verdicts", []):
                risk_level = str(verdict.get("risk_level", "")).upper()
                if risk_level in {"ALLOW", "BLOCK", "CRITICAL"}:
                    continue
                if risk_level == "WARN":
                    source = str(verdict.get("source", "")).lower()
                    if source in {"input", "narrative", "role", "compliance"}:
                        continue
                data["is_intent_shift"] = True
                self.intent_shift_found = True
                return


    def _detect_intent_shift(self):
        for node in self.nodes:
            data = node.get("data")
            if isinstance(data, dict):
                verdicts = data.get("verdicts", [])
                for v in verdicts:
                    if v.get("risk_level") not in ["ALLOW"]:
                        data["is_intent_shift"] = True
                        self.intent_shift_found = True
                        return # Only mark first occurrence

graph_builder = AttackGraphBuilder()
