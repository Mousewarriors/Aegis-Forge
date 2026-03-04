from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

ROLE_PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


@dataclass(frozen=True)
class RoleSpec:
    role_id: str
    display_name: str
    prompt_markdown_path: Path


ROLE_REGISTRY: Dict[str, RoleSpec] = {
    "bank_support": RoleSpec(
        role_id="bank_support",
        display_name="Bank Support",
        prompt_markdown_path=ROLE_PROMPT_DIR / "bank_support.md",
    ),
    "travel_agent": RoleSpec(
        role_id="travel_agent",
        display_name="Travel Agent",
        prompt_markdown_path=ROLE_PROMPT_DIR / "travel_agent.md",
    ),
    "retail_support": RoleSpec(
        role_id="retail_support",
        display_name="Retail Support",
        prompt_markdown_path=ROLE_PROMPT_DIR / "retail_support.md",
    ),
}


def load_role_prompt(role_id: str) -> str:
    spec = ROLE_REGISTRY.get(role_id)
    if not spec:
        raise ValueError(f"Unknown role_id: {role_id}")
    return spec.prompt_markdown_path.read_text(encoding="utf-8")


def maybe_load_role_prompt(role_id: Optional[str]) -> str:
    if not role_id:
        return ""
    return load_role_prompt(role_id)
