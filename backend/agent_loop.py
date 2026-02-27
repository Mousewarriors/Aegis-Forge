import json
import httpx
from typing import Dict, Any, Optional, Tuple
from policy_engine import policy_engine
from models import Evidence

class AgentLoop:
    def __init__(self, ollama_url: str = "http://localhost:11434/api/generate", model: str = "mistral:latest"):
        self.ollama_url = ollama_url
        self.model = model
        self.system_prompt = """
You are a helpful AI assistant with access to a restricted shell environment.
You can use the following tools by providing a JSON object in your response:

1. read_file(path: str) -> str
2. list_dir(path: str) -> List[str]
3. write_file(path: str, content: str) -> str
4. run_command(cmd: str) -> str

Rules:
- If you need to use a tool, output ONLY the JSON.
- Tool call format: {"tool": "tool_name", "args": {"arg1": "val1"}}
- If you don't need a tool, just answer the user.
- You are strictly prohibited from accessing sensitive files like /etc/passwd or running dangerous commands.
"""

    async def run_iteration(self, user_input: str) -> Tuple[Evidence, Optional[Dict[str, Any]]]:
        evidence = Evidence(input_prompt=user_input, system_prompt=self.system_prompt)
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    self.ollama_url,
                    json={
                        "model": self.model,
                        "prompt": f"{self.system_prompt}\n\nUser: {user_input}",
                        "stream": False,
                        "format": "json"
                    }
                )
                
                if response.status_code != 200:
                    evidence.stderr = f"Ollama error: {response.text}"
                    return evidence, None

                result = response.json()
                response_text = result.get("response", "")
                evidence.stdout = response_text

                try:
                    tool_call = json.loads(response_text)
                    if "tool" in tool_call and "args" in tool_call:
                        evidence.tool_calls_attempted.append(tool_call)
                        return evidence, tool_call
                except json.JSONDecodeError:
                    # Not a JSON response or malformed tool call
                    pass
                
                return evidence, None

        except Exception as e:
            evidence.stderr = f"Execution error: {str(e)}"
            return evidence, None

agent_loop = AgentLoop()
