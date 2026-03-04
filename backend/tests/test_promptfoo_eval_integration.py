import asyncio
import json
import time
from unittest.mock import patch

import main
from models import AttackCampaign, EvalRequest, Evidence, GuardrailMode, Outcome


def test_build_promptfoo_config_includes_purpose_and_assertions():
    request = EvalRequest(num_tests=1, plugins=["pliny"], strategies=["jailbreak-templates"])

    config = main._build_promptfoo_config(
        request=request,
        filtered_plugins=["pliny"],
        normalized_strategies=["jailbreak-templates"],
    )

    assert "The application is an AI security research environment" in config
    assert "type: llm-rubric" in config
    assert "metric: UnsafeContentCheck" in config
    assert "jailbreak-templates" in config
    assert "redteam:\n  injectVar: injectVar\n  provider:" in config
    assert "  purpose: |\n" in config
    assert "\n  numTests: 1\n  plugins:\n" not in config


def test_extract_promptfoo_result_prefers_official_grading_result():
    raw = {
        "success": True,
        "metadata": {"pluginId": "pliny"},
        "prompt": {"raw": "unsafe prompt"},
        "response": {"output": "unsafe output"},
        "gradingResult": {
            "pass": False,
            "reason": "One or more assertions failed",
            "componentResults": [
                {"reason": "Unsafe instructions were provided"}
            ],
        },
    }

    parsed = main._extract_promptfoo_result(raw)

    assert parsed["plugin_id"] == "pliny"
    assert parsed["passed"] is False
    assert parsed["prompt"] == "unsafe prompt"
    assert parsed["response"] == "unsafe output"
    assert "Unsafe instructions were provided" in parsed["reason"]


def test_effective_guardrail_mode_respects_hardening():
    original_policy_hardened = main.policy_engine.hardened
    original_agent_hardened = main.agent_loop.hardened

    try:
        main.policy_engine.hardened = False
        main.agent_loop.hardened = False
        assert main._effective_guardrail_mode(GuardrailMode.WARN) == GuardrailMode.WARN

        main.policy_engine.hardened = True
        assert main._effective_guardrail_mode(GuardrailMode.WARN) == GuardrailMode.BLOCK
    finally:
        main.policy_engine.hardened = original_policy_hardened
        main.agent_loop.hardened = original_agent_hardened


def test_record_promptfoo_results_uses_official_grade_in_audit_stream(tmp_path):
    run_id = "eval-test-123"
    report_path = tmp_path / f"report-{run_id}.json"
    report_path.write_text(
        json.dumps(
            {
                "results": {
                    "results": [
                        {
                            "success": True,
                            "metadata": {"pluginId": "pliny"},
                            "prompt": {"raw": "unsafe prompt"},
                            "response": {"output": "unsafe output"},
                            "gradingResult": {
                                "pass": False,
                                "reason": "One or more assertions failed",
                                "componentResults": [
                                    {"reason": "Unsafe instructions were provided"}
                                ],
                            },
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    main.active_evals[run_id] = {}

    try:
        with patch.object(main, "_get_eval_dir", return_value=str(tmp_path)):
            with patch.object(main.monitor, "record_scenario") as record_scenario:
                main._record_promptfoo_results(run_id)

        assert record_scenario.called
        recorded_run = record_scenario.call_args[0][0]
        assert recorded_run.outcome == Outcome.FAIL
        assert recorded_run.payload_id == "PROMPTFOO:pliny"
        assert recorded_run.evidence.sensitive_events[0] == "Promptfoo Official Grade: FAIL"
        assert "Unsafe instructions were provided" in recorded_run.evidence.sensitive_events[1]
        assert main.active_evals[run_id]["audit_recorded"] is True
    finally:
        main.active_evals.pop(run_id, None)


def test_estimate_eval_progress_advances_before_counts_exist():
    now = time.time()
    progress, eta_seconds, phase = main._estimate_eval_progress(
        {
            "status": "running",
            "completed_tests": 0,
            "total_tests": 0,
            "started_at": now - 12,
            "estimated_duration_seconds": 60,
            "phase": "Preparing attack chain",
            "last_reported_progress": 0.0,
        }
    )

    assert progress > 0.15
    assert progress < 0.9
    assert eta_seconds is not None and eta_seconds > 0
    assert phase == "Preparing attack chain"


def test_estimate_eval_progress_does_not_reset_when_total_arrives():
    progress, eta_seconds, phase = main._estimate_eval_progress(
        {
            "status": "running",
            "completed_tests": 0,
            "total_tests": 1,
            "started_at": time.time() - 8,
            "phase": "Running evaluations",
            "last_reported_progress": 0.31,
        }
    )

    assert progress >= 0.31
    assert eta_seconds is not None and eta_seconds > 0
    assert phase == "Running evaluations"


def test_get_stats_surfaces_semantic_guard_summary():
    summary = {
        "total_runs": 1,
        "fail_count": 0,
        "pass_count": 1,
        "campaign_history": [
            {
                "timestamp": time.time(),
                "mode": "REAL_AGENT",
                "payload_id": "payload-1",
                "category": "prompt_injection",
                "outcome": Outcome.PASS,
                "evidence": {
                    "input_prompt": "test prompt",
                    "stdout": "safe refusal",
                    "semantic_verdicts": [
                        {"risk_level": "WARN", "rationale": "Input flagged", "source": "input"},
                        {"risk_level": "ALLOW", "rationale": "Audited safe", "source": "compliance"},
                    ],
                },
            }
        ],
    }

    with patch.object(main.monitor, "get_summary", return_value=summary):
        stats = asyncio.run(main.get_stats())

    entry = stats["campaign_history"][0]
    assert entry["semantic_guard_summary"]["highest_risk"] == "WARN"
    assert "WARN x1" in entry["semantic_guard_summary"]["headline"]
    assert entry["semantic_guard_summary"]["latest_source"] == "compliance"
    assert len(entry["semantic_guard_verdicts"]) == 2


def test_get_stats_includes_running_promptfoo_evals():
    run_id = "eval-live-123"
    original_active_evals = dict(main.active_evals)

    main.active_evals.clear()
    main.active_evals[run_id] = {
        "status": "running",
        "started_at": time.time(),
        "completed_tests": 1,
        "total_tests": 10,
        "phase": "Running evaluations",
        "estimated_duration_seconds": 120,
        "last_reported_progress": 0.1,
        "last_output_line": "Running promptfoo checks",
        "filtered_plugins": ["pliny", "excessive-agency"],
        "live_results": [
            {
                "type": "promptfoo_live",
                "timestamp": time.time(),
                "campaign": "PROMPTFOO-LIVE - pliny",
                "category": "pliny",
                "success": False,
                "output_snippet": "Live pass result",
                "phase": "Awaiting official Promptfoo grade",
                "eval_status": "running",
                "semantic_guard_verdicts": [],
                "semantic_guard_summary": {"highest_risk": None, "headline": "", "latest_rationale": "", "latest_source": "", "total_verdicts": 0},
            }
        ],
    }

    with patch.object(main.monitor, "get_summary", return_value={
        "total_runs": 0,
        "fail_count": 0,
        "pass_count": 0,
        "campaign_history": [],
    }):
        stats = asyncio.run(main.get_stats())

    try:
        assert len(stats["campaign_history"]) == 2
        entry = stats["campaign_history"][0]
        live_entry = stats["campaign_history"][1]
        assert entry["type"] == "promptfoo_eval"
        assert entry["run_id"] == run_id
        assert entry["phase"] == "Running evaluations"
        assert entry["output_snippet"] == "Running promptfoo checks"
        assert live_entry["type"] == "promptfoo_live"
        assert live_entry["campaign"] == "PROMPTFOO-LIVE - pliny"
    finally:
        main.active_evals.clear()
        main.active_evals.update(original_active_evals)


def test_classify_defense_path_detects_input_block():
    evidence = Evidence(
        input_prompt="malicious prompt",
        stdout="I cannot process that request. (Input Blocked: malicious intent detected)",
    )

    stage, summary = main._classify_defense_path(
        evidence,
        campaign=AttackCampaign(proxy_enabled=True, session_hardened=True),
    )

    assert stage == "INPUT_BLOCKED"
    assert "inbound prompt" in summary
