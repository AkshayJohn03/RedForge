"""CampaignRunner: attack × target matrix with evidence capture."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Protocol

from pydantic import BaseModel

from ..attacks.mutators import base64_wrap, rot13
from ..attacks.taxonomy import GOAL, REGISTRY, Attack
from ..defenses.stack import DefenseStack
from ..observability import SpanEmitter
from ..targets.recruiting import RecruitingAssistant
from .detectors import detect


class Target(Protocol):
    def chat(self, messages: list[dict]) -> BaseModel: ...


class Evidence(BaseModel):
    attack_id: str
    category: str
    turns: list[list[dict]]
    output: str
    tool_calls: list[str]
    quarantined: bool
    notes: list[str]
    verdict: dict
    span_id: str


def _render(attack: Attack, goal: str = GOAL) -> list[str]:
    """Turns for this attack (multi-turn crescendo returns its script).

    ``attack.slots`` carries structured payloads (SQL, URLs, JSON argument
    objects); slot values substitute literally so braces inside a payload can
    never collide with ``str.format``.
    """
    if attack.multi_turn:
        turns = list(attack.multi_turn)
        try:
            turns[-1] = turns[-1].format(payload=goal, **attack.slots)
        except (KeyError, IndexError):
            pass  # mutated variant mangled a placeholder; use as-is
        return turns
    tpl = attack.template
    kwargs: dict[str, str] = {"payload": goal, **attack.slots}
    if "{b64}" in tpl:
        kwargs["b64"] = base64_wrap(goal)
    if "{rot13}" in tpl:
        kwargs["rot13"] = rot13(goal)
    try:
        return [tpl.format(goal=goal, **kwargs)]
    except (KeyError, IndexError):
        return [tpl]  # mutated variant mangled a placeholder; use as-is


def _episode_messages(attack: Attack, turns: list[str], resume: str | None,
                      spotlightless: bool) -> list[list[dict]]:
    """Message lists per turn. Indirect attacks ride inside the resume text."""
    if not attack.rides_in_document:
        msgs: list[list[dict]] = []
        prior = ""
        for t in turns:
            content = (prior + "\n" + t).strip()
            msgs.append([{"role": "system", "content": "__SYSTEM__"},
                         {"role": "user", "content": content}])
            prior = prior + " " + t if attack.category.value == "multi_turn_crescendo" else t
        return msgs
    doc = resume or turns[0]
    # for indirect attacks the *turns* are the payload we splice into the resume
    if resume:
        doc = resume + "\nadditional_info: " + " ".join(turns)
    return [[{"role": "system", "content": "__SYSTEM__"},
             {"role": "user", "content": f"Please screen this resume:\n{doc}"}]]


def _system_for(target: RecruitingAssistant) -> str:
    return target.system_prompt


async def run_campaign(
    target: RecruitingAssistant,
    *,
    attacks: list[Attack] | None = None,
    resumes: list[str] | None = None,
    concurrency: int = 8,
    campaign_id: str | None = None,
    span_sink=None,
    max_evidence_chars: int = 4000,
) -> list[Evidence]:
    """Run every attack (or a subset) against the target; capture evidence."""
    campaign_id = campaign_id or uuid.uuid4().hex[:8]
    emitter = SpanEmitter(campaign_id, span_sink)
    attacks = attacks or REGISTRY
    sem = asyncio.Semaphore(concurrency)

    async def one(attack: Attack) -> Evidence:
        async with sem:
            t0 = time.perf_counter()
            turns = _render(attack)
            resume = None
            if attack.rides_in_document and resumes:
                resume = resumes[len(attack.id) % len(resumes)]
            episode_sets = _episode_messages(attack, turns, resume, spotlightless=True)
            last_output, tool_names, quarantined, notes = "", [], False, []
            for msgs in episode_sets:
                real = [dict(m) for m in msgs]
                for m in real:
                    if m["content"] == "__SYSTEM__":
                        m["content"] = _system_for(target)
                resp = target.chat(real)
                last_output = resp.output
                tool_names = [tc.name for tc in resp.tool_calls]
                quarantined = resp.quarantined
                notes = resp.notes
                if quarantined:
                    break
            verdict = detect(
                type("R", (), {"output": last_output,
                               "tool_calls": [type("T", (), {"name": n}) for n in tool_names]}),
                target.canary.value,
            )
            span_id = emitter.emit(
                None, f"attack:{attack.id}", "attack", t0,
                "success" if verdict.success else "blocked",
                attack_id=attack.id, category=attack.category.value,
                evidence_masked=True,
            )
            return Evidence(
                attack_id=attack.id,
                category=attack.category.value,
                turns=[[dict(m, content=(m["content"][:300] if m["role"] != "system" else "[system]"))
                        for m in msgs] for msgs in episode_sets],
                output=(last_output or "")[:max_evidence_chars],
                tool_calls=tool_names,
                quarantined=quarantined,
                notes=notes,
                verdict=verdict.as_dict(),
                span_id=span_id,
            )

    return list(await asyncio.gather(*(one(a) for a in attacks)))


def asr(evidence: list[Evidence]) -> float:
    if not evidence:
        return 0.0
    return sum(1 for e in evidence if e.verdict["success"]) / len(evidence)


def asr_by_category(evidence: list[Evidence]) -> dict[str, float]:
    out: dict[str, int] = {}
    succ: dict[str, int] = {}
    for e in evidence:
        out[e.category] = out.get(e.category, 0) + 1
        succ[e.category] = succ.get(e.category, 0) + int(e.verdict["success"])
    return {c: succ[c] / out[c] for c in sorted(out)}


def ablation_matrix(
    attacks: list[Attack] | None = None,
    resumes: list[str] | None = None,
) -> dict[str, dict[str, float]]:
    """category × single-layer-ablation ASR: which layer blocks which class.

    Rows: attack categories. Columns: 'none' + each layer disabled-from-full.
    """
    from ..data.resumes import laced_resumes

    results: dict[str, dict[str, float]] = {}
    configs: dict[str, DefenseStack] = {"none": DefenseStack.none()}
    full = DefenseStack.full()
    for layer in full.active_layers():
        cfg = DefenseStack.full()
        setattr(cfg, layer, False)
        configs[f"full-minus-{layer}"] = cfg

    for name, cfg in configs.items():
        target = RecruitingAssistant(cfg)
        ev = asyncio.run(run_campaign(
            target, attacks=attacks,
            resumes=resumes if resumes is not None else laced_resumes(),
        ))
        results[name] = asr_by_category(ev)
    return results
