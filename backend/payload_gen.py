import random
import base64
import json
import os
from typing import List, Dict, Any

class PayloadGenerator:
    def __init__(self, database_path: str = "payloads.json"):
        self.database_path = database_path
        self.payload_data = {}
        self.load_database()

    def load_database(self):
        """Loads the payload database from a JSON file. Falls back to payloads_example.json if missing."""
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, 'r') as f:
                    self.payload_data = json.load(f)
                return
            except Exception as e:
                print(f"Error loading payload database: {e}")

        # Fallback to example payloads for public/demo version
        fallback_path = self.database_path.replace("payloads.json", "payloads_example.json")
        if os.path.exists(fallback_path):
            try:
                with open(fallback_path, 'r') as f:
                    self.payload_data = json.load(f)
                print(f"Loaded example database from {fallback_path}")
            except Exception as e:
                print(f"Error loading fallback database: {e}")
                self.payload_data = {}
        else:
            print(f"Warning: Neither {self.database_path} nor {fallback_path} found.")
            self.payload_data = {}

    def _parse_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a payload entry - handles both base64 and plaintext payloads."""
        raw_payload = entry.get("payload", "")
        # Try base64 decode first, fall back to plaintext
        try:
            decoded = base64.b64decode(raw_payload).decode("utf-8")
        except Exception:
            decoded = raw_payload  # It's already plaintext

        return {
            "id": entry.get("id", "unknown"),
            "payload": decoded,
            "name": entry.get("name", "Unknown"),
            "description": entry.get("description", ""),
            "intent": entry.get("intent", ""),
            "expected_evidence": entry.get("expected_evidence", ""),
            "shell_cmd": entry.get("shell_cmd", f"echo '{decoded[:50]}'"),
            "mitigation_hint": entry.get("mitigation_hint", ""),
            "risk_level": entry.get("risk_level", "medium"),
            "tags": entry.get("tags", [])
        }

    def get_random_payload(self, category: str) -> Dict[str, Any]:
        """Get a random payload from a category."""
        self.load_database()
        if category in self.payload_data and self.payload_data[category]:
            entry = random.choice(self.payload_data[category])
            return self._parse_entry(entry)
        return {"id": "NONE", "payload": "echo 'no-payload'", "shell_cmd": "echo 'no-payload'", "name": "No Payload", "description": "No payload found.", "expected_evidence": "", "risk_level": "Low", "tags": []}

    def get_all_payloads_for_category(self, category: str) -> List[Dict[str, Any]]:
        """Get ALL payloads for a given category (for full library sweep)."""
        self.load_database()
        if category in self.payload_data:
            return [self._parse_entry(entry) for entry in self.payload_data[category]]
        return []

    def get_all_categories(self) -> List[str]:
        self.load_database()
        return list(self.payload_data.keys())

# Get the absolute path to ensure it loads correctly regardless of where main.py is run
base_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(base_dir, "payloads.json")
payload_gen = PayloadGenerator(db_path)
