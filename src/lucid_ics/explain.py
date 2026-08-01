"""Natural-language explanation and triage-playbook generation.

The explanation layer is provider-agnostic by design: `LLMBackend` is a
one-method interface, and any instruction-tuned LLM (Claude, GPT-4-class
models, a locally hosted Llama, etc.) can be plugged in via `generate()`.

The reference implementation shipped and evaluated in this repository is
`TemplateBackend`: a deterministic, knowledge-grounded generator that turns
(detector output + feature attribution + MITRE ATT&CK/NIST-800-82 grounding
from knowledge_base.py) into an operator-readable narrative, with no network
call and no API key required. We evaluate this reference implementation
end-to-end in the paper. `AnthropicBackend`/`OpenAIBackend` below are working
adapters for teams that want a genuinely LLM-generated narrative in place of
the template -- we did not have API credentials available in the build
environment for this project, so no live-LLM results are reported; see the
paper's Limitations section for this explicit disclosure.
"""
from __future__ import annotations

import abc
import dataclasses
import os

from .attribution import LocalAttribution
from .knowledge_base import TechniqueMapping, lookup


@dataclasses.dataclass
class TriageRecord:
    window: int
    t_start: float
    attack_type: str
    risk_score: float
    family_confidence: float
    top_features: list[tuple[str, float]]
    technique: TechniqueMapping | None
    narrative: str
    playbook: list[str]


class LLMBackend(abc.ABC):
    """Minimal interface any explanation backend must satisfy."""

    @abc.abstractmethod
    def generate(self, prompt: str) -> str:
        ...


class TemplateBackend(LLMBackend):
    """Deterministic, offline reference backend (default; used in all
    experiments reported in the paper)."""

    def generate(self, prompt: str) -> str:  # pragma: no cover - trivial passthrough
        return prompt


class AnthropicBackend(LLMBackend):
    """Adapter for Claude models via the official `anthropic` SDK.

    Requires ANTHROPIC_API_KEY in the environment and the `anthropic`
    package installed. Not exercised in the paper's reported results
    (no API key was available in the build environment) -- provided as a
    working extension point.
    """

    def __init__(self, model: str = "claude-sonnet-5"):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        import anthropic  # local import: optional dependency

        self._client = anthropic.Anthropic()
        self._model = model

    def generate(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in msg.content if hasattr(block, "text"))


class OpenAIBackend(LLMBackend):
    """Adapter for GPT-class models via the official `openai` SDK. Same
    caveat as AnthropicBackend: not exercised in reported results."""

    def __init__(self, model: str = "gpt-4o"):
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not set")
        import openai  # local import: optional dependency

        self._client = openai.OpenAI()
        self._model = model

    def generate(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""


_FEATURE_DESCRIPTIONS = {
    "unauthorized_write_count": "writes to actuator registers from a source other than the "
        "authorized HMI",
    "register_address_entropy": "spread of distinct register addresses touched in the window",
    "response_time_mean": "average device response latency",
    "response_time_p95": "tail (95th percentile) device response latency",
    "duplicate_value_ratio": "fraction of repeated/duplicate values",
    "n_unique_src": "number of distinct source hosts talking to the PLC",
    "n_unique_function_codes": "number of distinct Modbus function codes used",
    "value_max_delta": "largest single-step change in a reported value",
    "write_ratio": "fraction of requests that were writes rather than reads",
    "request_rate": "requests per second",
    "inter_arrival_mean": "average time between consecutive requests",
    "inter_arrival_std": "variability in time between consecutive requests",
    "value_std": "variability of reported values within the window",
    "n_events": "total number of protocol events",
}


def _feature_phrase(name: str, z: float) -> str:
    desc = _FEATURE_DESCRIPTIONS.get(name, name.replace("_", " "))
    direction = "elevated" if z > 0 else "suppressed"
    # ASCII-only ("stdev" not "sigma") so this renders on any console codepage.
    return f"{desc} was {direction} ({z:+.1f} stdev from the learned normal-traffic baseline)"


def build_prompt(record_input: dict) -> str:
    """Builds the natural-language prompt a live LLM backend would receive.
    TemplateBackend renders this same information deterministically instead
    of sending it to a model -- see module docstring."""
    return (
        "You are an OT security triage assistant. An ICS anomaly detector flagged "
        f"window {record_input['window']} (t={record_input['t_start']:.0f}s) as "
        f"'{record_input['attack_type']}' with risk score {record_input['risk_score']:.2f} "
        f"and classifier confidence {record_input['family_confidence']:.2f}. "
        f"The most anomalous features were: {record_input['top_features']}. "
        "Explain in two sentences, for a control-room operator with no ML background, why this "
        "was flagged, then give a short prioritized response checklist."
    )


def explain_alert(
    window: int,
    t_start: float,
    attack_type: str,
    risk_score: float,
    family_confidence: float,
    attribution: LocalAttribution,
    backend: LLMBackend | None = None,
) -> TriageRecord:
    technique = lookup(attack_type)
    backend = backend or TemplateBackend()

    if attack_type == "normal":
        narrative = (
            f"Window {window} (t={t_start:.0f}s) looks consistent with normal operation "
            f"(risk score {risk_score:.2f}); no action required."
        )
        playbook: list[str] = []
    else:
        feature_phrases = [_feature_phrase(name, z) for name, z in attribution.top_features]
        attck_phrase = (
            f" This pattern is consistent with MITRE ATT&CK for ICS technique "
            f"{technique.attck_id} ({technique.attck_name})." if technique else ""
        )
        narrative = (
            f"Window {window} (t={t_start:.0f}s) was flagged as '{attack_type}' with risk score "
            f"{risk_score:.2f} (classifier confidence {family_confidence:.2f}). "
            f"The strongest contributing signals were: {'; '.join(feature_phrases)}."
            f"{attck_phrase}"
        )
        prompt = build_prompt(dict(window=window, t_start=t_start, attack_type=attack_type,
                                    risk_score=risk_score, family_confidence=family_confidence,
                                    top_features=attribution.top_features))
        if not isinstance(backend, TemplateBackend):
            narrative = backend.generate(prompt)
        playbook = list(technique.playbook) if technique else []

    return TriageRecord(
        window=window, t_start=t_start, attack_type=attack_type, risk_score=risk_score,
        family_confidence=family_confidence, top_features=attribution.top_features,
        technique=technique, narrative=narrative, playbook=playbook,
    )
