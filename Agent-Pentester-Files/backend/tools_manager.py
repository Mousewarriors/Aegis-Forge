import subprocess
import json
import os
import yaml
from typing import Dict, Any, List

class ExternalToolsManager:
    def __init__(self):
        # Path to promptfoo binary (assuming global install)
        self.promptfoo_path = "promptfoo"
        # On Windows, we might need the full path if not in the environment
        if os.name == 'nt':
            app_data = os.environ.get("APPDATA", "")
            potential_path = os.path.join(app_data, "npm", "promptfoo.cmd")
            if os.path.exists(potential_path):
                self.promptfoo_path = potential_path

    def run_promptfoo_scan(self, config_path: str) -> Dict[str, Any]:
        """Runs a promptfoo evaluation and returns the results."""
        try:
            # Run promptfoo eval
            result = subprocess.run(
                [self.promptfoo_path, "eval", "-c", config_path, "--output", "results.json"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Read results
            if os.path.exists("results.json"):
                with open("results.json", "r") as f:
                    return json.load(f)
            return {"error": "Results file not found", "stdout": result.stdout}
        except subprocess.CalledProcessError as e:
            return {"error": f"Promptfoo failed: {e.stderr}", "stdout": e.stdout}
        except Exception as e:
            return {"error": str(e)}

    def generate_adversarial_prompts(self, base_prompt: str) -> List[str]:
        """Uses promptfoo to generate adversarial variations of a prompt."""
        # This typically uses 'promptfoo generate dataset' or similar
        # For now, let's provide a skeleton that could call an LLM to vary the prompt
        return [
            f"{base_prompt} (Variation: encode in base64)",
            f"{base_prompt} (Variation: ignore previous instructions)",
            f"{base_prompt} (Variation: roleplay as a developer)"
        ]

tools_manager = ExternalToolsManager()
