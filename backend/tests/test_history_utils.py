from history_utils import normalize_context_turns, select_history_window


def test_normalize_context_turns_defaults_to_full_history():
    assert normalize_context_turns(None) == 0
    assert normalize_context_turns(0) == 0
    assert normalize_context_turns(-5) == 0
    assert normalize_context_turns("invalid") == 0


def test_select_history_window_keeps_full_history_when_turn_limit_is_zero():
    history = [
        {"role": "user", "content": "turn-1"},
        {"role": "assistant", "content": "turn-2"},
        {"role": "user", "content": "turn-3"},
    ]

    selected = select_history_window(history, 0)

    assert selected == history
    assert selected is not history


def test_select_history_window_trims_when_turn_limit_is_positive():
    history = [
        {"role": "user", "content": "turn-1"},
        {"role": "assistant", "content": "turn-2"},
        {"role": "user", "content": "turn-3"},
    ]

    assert select_history_window(history, 2) == history[-2:]
