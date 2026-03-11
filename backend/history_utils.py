from typing import Any, Dict, List, Optional


def normalize_context_turns(value: Optional[int]) -> int:
    """Normalize context turn settings; 0 means keep the full transcript."""
    try:
        turns = int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0
    return turns if turns > 0 else 0


def select_history_window(history: List[Dict[str, Any]], context_turns: Optional[int]) -> List[Dict[str, Any]]:
    """Return the full history unless the caller explicitly requests a positive cap."""
    if not history:
        return []

    turns = normalize_context_turns(context_turns)
    if turns == 0:
        return list(history)
    return list(history[-turns:])
