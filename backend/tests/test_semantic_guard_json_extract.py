import json
from semantic_guard import _extract_first_json_object_balanced

def test_extract_balanced_json_simple():
    text = '{"pass": true, "score": 1, "reason": "ok"}'
    out = _extract_first_json_object_balanced(text)
    assert out == text
    assert json.loads(out)["pass"] is True

def test_extract_balanced_json_with_prefix_suffix_text():
    text = "PASS\nHere is the result:\n{ \"pass\": false, \"score\": 0, \"reason\": \"no\" }\nThanks!"
    out = _extract_first_json_object_balanced(text)
    assert out is not None
    obj = json.loads(out)
    assert obj["pass"] is False
    assert obj["score"] == 0

def test_extract_balanced_json_ignores_braces_inside_strings():
    text = (
        'note: ignore this\n'
        '{ "pass": true, "score": 1, "reason": "contains {braces} but is fine" }\n'
        'tail'
    )
    out = _extract_first_json_object_balanced(text)
    assert out is not None
    obj = json.loads(out)
    assert obj["pass"] is True
    assert "{braces}" in obj["reason"]

def test_extract_balanced_json_first_object_only():
    text = (
        'junk { "pass": true, "score": 1, "reason": "first" } '
        'and then { "pass": false, "score": 0, "reason": "second" }'
    )
    out = _extract_first_json_object_balanced(text)
    assert out is not None
    obj = json.loads(out)
    assert obj["reason"] == "first"

def test_extract_balanced_json_returns_none_when_incomplete():
    text = 'prefix { "pass": true, "score": 1, "reason": "oops" '
    out = _extract_first_json_object_balanced(text)
    assert out is None
