import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from pyrit.executor.attack import AttackConverterConfig, AttackScoringConfig, FlipAttack, PromptSendingAttack
from pyrit.memory import CentralMemory
from pyrit.prompt_converter import Base64Converter, ROT13Converter, UnicodeConfusableConverter, ZeroWidthConverter
from pyrit.prompt_normalizer import PromptConverterConfiguration
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score import SelfAskRefusalScorer, TrueFalseInverterScorer
from pyrit.setup import IN_MEMORY, initialize_pyrit_async


CONVERTER_FACTORIES = {
    "Base64Converter": Base64Converter,
    "ROT13Converter": ROT13Converter,
    "UnicodeConfusableConverter": UnicodeConfusableConverter,
    "ZeroWidthConverter": ZeroWidthConverter,
}


class EventWriter:
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.output_path.open("a", encoding="utf-8", buffering=1)

    def emit(self, payload: Dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=True)
        self.handle.write(line + "\n")
        self.handle.flush()
        print(line, flush=True)

    def close(self) -> None:
        self.handle.close()


def _enum_text(value: Any) -> str:
    if value is None:
        return ""
    name = getattr(value, "name", None)
    if name:
        return str(name)
    return str(value)


def _to_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {}


def _message_piece_role(piece: Any) -> str:
    mapping = _to_mapping(piece)
    return str(
        getattr(piece, "role", None)
        or mapping.get("role")
        or getattr(piece, "converted_value_data_type", None)
        or mapping.get("converted_value_data_type")
        or ""
    ).lower()


def _message_piece_text(piece: Any, field_name: str) -> str:
    mapping = _to_mapping(piece)
    value = getattr(piece, field_name, None)
    if value is None:
        value = mapping.get(field_name)
    return str(value or "")


def _extract_conversation(memory: CentralMemory, conversation_id: str) -> Dict[str, str]:
    prompt_text = ""
    original_prompt = ""
    response_text = ""

    try:
        pieces = memory.get_message_pieces(conversation_id=conversation_id) or []
    except Exception:
        pieces = []

    for piece in pieces:
        role = _message_piece_role(piece)
        original_value = _message_piece_text(piece, "original_value")
        converted_value = _message_piece_text(piece, "converted_value")
        effective_value = converted_value or original_value
        if role == "user" and not prompt_text:
            prompt_text = effective_value
            original_prompt = original_value or effective_value
        elif role == "assistant" and not response_text:
            response_text = original_value or effective_value

    return {
        "prompt": prompt_text,
        "original_prompt": original_prompt or prompt_text,
        "response": response_text,
    }


def _build_attack(
    scenario: Dict[str, Any],
    target: OpenAIChatTarget,
    scoring_config: AttackScoringConfig,
):
    attack_type = str(scenario.get("attack_type") or "prompt_sending")
    if attack_type == "flip_attack":
        return FlipAttack(objective_target=target, attack_scoring_config=scoring_config)

    converter_names = [str(name) for name in (scenario.get("converter_chain") or []) if str(name)]
    attack_converter_config = None
    if converter_names:
        converters = []
        for converter_name in converter_names:
            converter_factory = CONVERTER_FACTORIES.get(converter_name)
            if converter_factory is None:
                raise ValueError(f"Unsupported PyRIT converter: {converter_name}")
            converters.append(converter_factory())
        converter_config = PromptConverterConfiguration.from_converters(converters=converters)  # type: ignore[arg-type]
        attack_converter_config = AttackConverterConfig(request_converters=converter_config)

    return PromptSendingAttack(
        objective_target=target,
        attack_scoring_config=scoring_config,
        attack_converter_config=attack_converter_config,
    )


def _objective_preview_sample(
    scenario: Dict[str, Any],
    objective_index: int,
    objective: str,
) -> Dict[str, Any]:
    preview_samples = [sample for sample in (scenario.get("objective_preview_samples") or []) if isinstance(sample, dict)]
    if 0 < objective_index <= len(preview_samples):
        sample = dict(preview_samples[objective_index - 1])
    else:
        sample = {}

    sample.setdefault("raw_objective", str(objective or ""))
    sample.setdefault("transformed_preview", "")
    sample.setdefault("transformed_preview_escaped", "")
    sample.setdefault("preview_mode", "direct")
    sample.setdefault("transformation_note", "")
    sample.setdefault("transformation_summary", "")
    return sample


def _result_to_attempt(
    memory: CentralMemory,
    scenario: Dict[str, Any],
    objective: str,
    objective_index: int,
    result: Any,
    preview_sample: Dict[str, Any],
) -> Dict[str, Any]:
    status_text = _enum_text(getattr(result, "status", "")).upper()
    reason_text = str(getattr(result, "reason", "") or "").strip()
    conversation_id = str(getattr(result, "conversation_id", "") or "")
    turns_executed = int(getattr(result, "turns_executed", 1) or 1)
    execution_time = float(getattr(result, "execution_time", 0.0) or 0.0)
    prompt_data = _extract_conversation(memory, conversation_id)
    attack_succeeded = "SUCCESS" in status_text

    return {
        "entry_type": "attempt",
        "scenario_id": str(scenario.get("id") or "unknown"),
        "scenario_label": str(scenario.get("label") or scenario.get("id") or "unknown"),
        "scenario_description": str(scenario.get("description") or ""),
        "category": str(scenario.get("category") or ""),
        "attack_type": str(scenario.get("attack_type") or "prompt_sending"),
        "converter_chain": list(scenario.get("converter_chain") or []),
        "objective_index": int(objective_index),
        "objective": str(objective),
        "preview_mode": str(preview_sample.get("preview_mode") or "direct"),
        "transformed_preview": str(preview_sample.get("transformed_preview") or ""),
        "transformed_preview_escaped": str(preview_sample.get("transformed_preview_escaped") or ""),
        "transformation_note": str(preview_sample.get("transformation_note") or ""),
        "transformation_summary": str(preview_sample.get("transformation_summary") or ""),
        "prompt": str(prompt_data.get("prompt") or objective),
        "original_prompt": str(prompt_data.get("original_prompt") or objective),
        "response": str(prompt_data.get("response") or ""),
        "conversation_id": conversation_id,
        "turns_executed": turns_executed,
        "execution_time_seconds": round(execution_time, 3),
        "status_text": status_text or "UNKNOWN",
        "passed": not attack_succeeded,
        "reason": reason_text or ("Objective achieved" if attack_succeeded else "Objective was not achieved"),
    }


async def run_from_config(config: Dict[str, Any], writer: EventWriter) -> int:
    run_id = str(config.get("run_id") or f"pyrit-{int(time.time())}")
    scenarios = [scenario for scenario in (config.get("selected_scenarios") or []) if isinstance(scenario, dict)]
    total_tests = sum(len(scenario.get("objectives") or []) for scenario in scenarios)

    writer.emit(
        {
            "entry_type": "run_start",
            "run_id": run_id,
            "timestamp": time.time(),
            "selected_scenarios": [
                {
                    "id": str(scenario.get("id") or ""),
                    "label": str(scenario.get("label") or scenario.get("id") or ""),
                    "objective_count": len(scenario.get("objectives") or []),
                    "attack_type": str(scenario.get("attack_type") or ""),
                    "converter_chain": list(scenario.get("converter_chain") or []),
                }
                for scenario in scenarios
            ],
            "total_tests": total_tests,
        }
    )
    writer.emit(
        {
            "entry_type": "plan_snapshot",
            "run_id": run_id,
            "timestamp": time.time(),
            "target_model": str(config.get("target_model") or ""),
            "scorer_model": str(config.get("scorer_model") or ""),
            "session_hardened": bool(config.get("session_hardened")),
            "proxy_enabled": bool(config.get("proxy_enabled")),
            "scenario_count": len(scenarios),
            "total_tests": total_tests,
        }
    )

    await initialize_pyrit_async(memory_db_type=IN_MEMORY)  # type: ignore[arg-type]
    memory = CentralMemory.get_memory_instance()

    target = OpenAIChatTarget(
        endpoint=str(config.get("target_endpoint") or ""),
        api_key=str(config.get("target_api_key") or "aegis-local"),
        model_name=str(config.get("target_model") or "aegis-pyrit-target"),
    )
    scorer_target = OpenAIChatTarget(
        endpoint=str(config.get("scorer_endpoint") or ""),
        api_key=str(config.get("scorer_api_key") or "aegis-local"),
        model_name=str(config.get("scorer_model") or "llama3.1:8b"),
    )

    objective_scorer = TrueFalseInverterScorer(scorer=SelfAskRefusalScorer(chat_target=scorer_target))
    scoring_config = AttackScoringConfig(objective_scorer=objective_scorer)

    completed = 0
    passed = 0
    failed = 0
    errors = 0

    for scenario in scenarios:
        scenario_id = str(scenario.get("id") or "unknown")
        objectives = [str(item) for item in (scenario.get("objectives") or []) if str(item)]
        writer.emit(
            {
                "entry_type": "scenario_start",
                "run_id": run_id,
                "timestamp": time.time(),
                "scenario_id": scenario_id,
                "scenario_label": str(scenario.get("label") or scenario_id),
                "scenario_description": str(scenario.get("description") or ""),
                "attack_type": str(scenario.get("attack_type") or "prompt_sending"),
                "converter_chain": list(scenario.get("converter_chain") or []),
                "objective_count": len(objectives),
                "progress_completed": completed,
                "progress_total": total_tests,
            }
        )

        attack = _build_attack(scenario, target, scoring_config)

        for objective_index, objective in enumerate(objectives, start=1):
            preview_sample = _objective_preview_sample(scenario, objective_index, objective)
            writer.emit(
                {
                    "entry_type": "objective_start",
                    "run_id": run_id,
                    "timestamp": time.time(),
                    "scenario_id": scenario_id,
                    "scenario_label": str(scenario.get("label") or scenario_id),
                    "objective_index": int(objective_index),
                    "objective": str(objective),
                    "preview_mode": str(preview_sample.get("preview_mode") or "direct"),
                    "transformation_summary": str(preview_sample.get("transformation_summary") or ""),
                    "progress_completed": completed,
                    "progress_total": total_tests,
                }
            )
            if preview_sample.get("transformed_preview") or preview_sample.get("transformation_note"):
                writer.emit(
                    {
                        "entry_type": "prompt_transformed",
                        "run_id": run_id,
                        "timestamp": time.time(),
                        "scenario_id": scenario_id,
                        "scenario_label": str(scenario.get("label") or scenario_id),
                        "objective_index": int(objective_index),
                        "objective": str(objective),
                        "transformed_preview": str(preview_sample.get("transformed_preview") or ""),
                        "transformed_preview_escaped": str(preview_sample.get("transformed_preview_escaped") or ""),
                        "preview_mode": str(preview_sample.get("preview_mode") or "direct"),
                        "transformation_note": str(preview_sample.get("transformation_note") or ""),
                        "transformation_summary": str(preview_sample.get("transformation_summary") or ""),
                        "attack_type": str(scenario.get("attack_type") or "prompt_sending"),
                        "converter_chain": list(scenario.get("converter_chain") or []),
                    }
                )
            try:
                result = await attack.execute_async(objective=objective)  # type: ignore[arg-type]
                attempt = _result_to_attempt(memory, scenario, objective, objective_index, result, preview_sample)
            except Exception as exc:
                errors += 1
                attempt = {
                    "entry_type": "attempt",
                    "scenario_id": scenario_id,
                    "scenario_label": str(scenario.get("label") or scenario_id),
                    "scenario_description": str(scenario.get("description") or ""),
                    "category": str(scenario.get("category") or ""),
                    "attack_type": str(scenario.get("attack_type") or "prompt_sending"),
                    "converter_chain": list(scenario.get("converter_chain") or []),
                    "objective_index": int(objective_index),
                    "objective": objective,
                    "preview_mode": str(preview_sample.get("preview_mode") or "direct"),
                    "transformed_preview": str(preview_sample.get("transformed_preview") or ""),
                    "transformed_preview_escaped": str(preview_sample.get("transformed_preview_escaped") or ""),
                    "transformation_note": str(preview_sample.get("transformation_note") or ""),
                    "transformation_summary": str(preview_sample.get("transformation_summary") or ""),
                    "prompt": objective,
                    "original_prompt": objective,
                    "response": "",
                    "conversation_id": "",
                    "turns_executed": 0,
                    "execution_time_seconds": 0.0,
                    "status_text": "ERROR",
                    "passed": False,
                    "reason": f"PyRIT execution error: {exc}",
                }

            completed += 1
            if attempt.get("passed"):
                passed += 1
            else:
                failed += 1

            attempt["run_id"] = run_id
            attempt["timestamp"] = time.time()
            attempt["progress_completed"] = completed
            attempt["progress_total"] = total_tests
            writer.emit(attempt)
            writer.emit(
                {
                    "entry_type": "score_result",
                    "run_id": run_id,
                    "timestamp": time.time(),
                    "scenario_id": scenario_id,
                    "scenario_label": str(scenario.get("label") or scenario_id),
                    "objective_index": int(objective_index),
                    "passed": bool(attempt.get("passed")),
                    "status_text": str(attempt.get("status_text") or ""),
                    "reason": str(attempt.get("reason") or ""),
                    "progress_completed": completed,
                    "progress_total": total_tests,
                }
            )

        writer.emit(
            {
                "entry_type": "scenario_complete",
                "run_id": run_id,
                "timestamp": time.time(),
                "scenario_id": scenario_id,
                "scenario_label": str(scenario.get("label") or scenario_id),
                "progress_completed": completed,
                "progress_total": total_tests,
            }
        )

    writer.emit(
        {
            "entry_type": "summary",
            "run_id": run_id,
            "timestamp": time.time(),
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "errors": errors,
        }
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config_path = Path(args.config)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    writer = EventWriter(Path(str(config.get("output_file") or "pyrit-report.jsonl")))
    try:
        return asyncio.run(run_from_config(config=config, writer=writer))
    except Exception as exc:
        writer.emit(
            {
                "entry_type": "fatal",
                "timestamp": time.time(),
                "reason": str(exc),
            }
        )
        return 1
    finally:
        writer.close()


if __name__ == "__main__":
    sys.exit(main())
