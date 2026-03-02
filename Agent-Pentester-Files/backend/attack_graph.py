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
                    attacker_id = f"attacker_{turn['turn']}"
                    self._add_node(attacker_id, "Attacker Prompt", "default", {
                        "label": f"Turn {turn['turn']}: Attacker",
                        "content": turn['attacker_prompt'],
                        "severity": turn.get("exploit_severity", "LOW")
                    })
                    self._add_edge(prev_node_id, attacker_id)
                    prev_node_id = attacker_id

                    # Target Response Node
                    target_id = f"target_{turn['turn']}"
                    verdicts = turn.get("semantic_verdicts", [])
                    has_block = any(v['risk_level'] in ["BLOCK", "CRITICAL"] for v in verdicts)
                    
                    label = "Target Response"
                    if has_block:
                        label += " [BLOCKED]"
                    
                    self._add_node(target_id, "Target Response", "output", {
                        "label": label,
                        "content": turn['target_response'],
                        "verdicts": verdicts,
                        "is_blocked": has_block
                    })
                    self._add_edge(prev_node_id, target_id)
                    prev_node_id = target_id

                    # Detect PONR: First successful exploit turn
                    if not self.ponr_found and turn.get("escalation_decision") == "EXPLOIT_FOUND":
                        node = self.nodes[-1]
                        if isinstance(node["data"], dict):
                            node["data"]["is_ponr"] = True
                        self.ponr_found = True

            elif entry_type == "scenario":
                # Handle single-turn ScenarioRuns
                evidence = entry.get("evidence", {})
                
                # Input Node
                inp_id = "input_node"
                self._add_node(inp_id, "Payload Input", "default", {
                    "label": "Payload",
                    "content": evidence.get("input_prompt")
                })
                self._add_edge(prev_node_id, inp_id)
                prev_node_id = inp_id

                # Tool Call Node (if any)
                for t_idx, tool in enumerate(evidence.get("tool_calls_attempted", [])):
                    tool_id = f"tool_{t_idx}"
                    self._add_node(tool_id, "Tool Call", "default", {
                        "label": f"Tool: {tool['tool']}",
                        "args": tool.get("args")
                    })
                    self._add_edge(prev_node_id, tool_id)
                    prev_node_id = tool_id

                # Result Node
                res_id = "result_node"
                self._add_node(res_id, "Outcome", "output", {
                    "label": f"Outcome: {entry.get('outcome')}",
                    "stdout": evidence.get("stdout"),
                    "verdicts": evidence.get("semantic_verdicts", [])
                })
                self._add_edge(prev_node_id, res_id)
                
        # Detect Intent Shift: First turn where risk_level > ALLOW
        self._detect_intent_shift()

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
            "position": {"x": 0, "y": len(self.nodes) * 100} # Vertical layout default
        })

    def _add_edge(self, source: str, target: str):
        self.edges.append({
            "id": f"e_{source}_{target}",
            "source": source,
            "target": target,
            "animated": True
        })

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
