import os

import garak.__main__
import garak.generators.ollama as ollama_module
from garak.probes.base import Probe


ollama_host = str(os.getenv("OLLAMA_HOST", "")).strip()
if ollama_host:
    ollama_module.OllamaGenerator.DEFAULT_PARAMS = {
        **ollama_module.OllamaGenerator.DEFAULT_PARAMS,
        "host": ollama_host,
    }
    ollama_module.OllamaGeneratorChat.DEFAULT_PARAMS = {
        **ollama_module.OllamaGeneratorChat.DEFAULT_PARAMS,
        "host": ollama_host,
    }


prompt_cap_raw = str(os.getenv("AEGIS_GARAK_PROMPT_CAP", "")).strip()
try:
    prompt_cap = int(prompt_cap_raw) if prompt_cap_raw else 0
except ValueError:
    prompt_cap = 0

if prompt_cap > 0 and not getattr(Probe, "_aegis_prompt_cap_patched", False):
    _original_probe = Probe.probe

    def _probe_with_cap(self, generator):
        prompts = getattr(self, "prompts", None)
        try:
            prompt_count = len(prompts)
        except Exception:
            prompt_count = 0

        if prompt_count <= 0 or prompt_count <= prompt_cap:
            return _original_probe(self, generator)

        original_prompts = self.prompts
        original_triggers = getattr(self, "triggers", None)
        has_parallel_triggers = (
            original_triggers is not None
            and hasattr(original_triggers, "__len__")
            and len(original_triggers) == prompt_count
        )
        try:
            self.prompts = list(original_prompts)[:prompt_cap]
            if has_parallel_triggers:
                self.triggers = list(original_triggers)[:prompt_cap]
            return _original_probe(self, generator)
        finally:
            self.prompts = original_prompts
            if has_parallel_triggers:
                self.triggers = original_triggers

    Probe.probe = _probe_with_cap
    Probe._aegis_prompt_cap_patched = True

garak.__main__.main()
