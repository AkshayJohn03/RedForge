"""Evolutionary search, CI gate, observability spans, report output."""

from __future__ import annotations

import asyncio
import json

from redforge.attacks.evolution import evolve
from redforge.attacks.taxonomy import REGISTRY
from redforge.data.resumes import laced_resumes
from redforge.engine.gate import evaluate
from redforge.engine.report import CampaignReport, to_markdown
from redforge.engine.runner import run_campaign
from redforge.targets.recruiting import HardenedTarget, VulnerableTarget


def test_evolution_raises_asr_on_vulnerable_target():
    target = VulnerableTarget()
    history = evolve(target, generations=3, seed=42)
    assert len(history) == 3
    assert history[-1].asr >= history[0].asr, "evolution must not degrade attack fitness"
    assert history[-1].asr > 0, "evolved attacks must keep succeeding on the weak target"
    assert history[-1].winners, "winning variants must be retained"


def test_gate_exit_codes():
    passed, payload = evaluate(0.0, max_asr=0.05)
    assert passed and payload["passed"]
    passed, payload = evaluate(0.92, max_asr=0.05)
    assert not passed and not payload["passed"]


def test_cli_gate_integration(tmp_path):
    from redforge.cli import main

    out = tmp_path / "gate.json"
    rc = main(["gate", "--max-asr", "0.05", "--out", str(out)])
    assert rc == 0, "hardened target must pass the CI gate"
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["hardened_asr"] == 0.0


def test_span_emission_shape():
    spans = []
    ev = asyncio.run(run_campaign(
        HardenedTarget(), resumes=laced_resumes(),
        attacks=REGISTRY[:3], span_sink=spans.append,
    ))
    assert spans, "span sink must receive spans"
    for span in spans:
        assert {"span_id", "parent_id", "name", "stage", "duration_ms", "status", "attrs"} <= set(span)
        assert span["stage"] == "attack"
        assert span["status"] in ("success", "blocked")


def test_guarded_telemetry_silent_without_config():
    from redforge.observability import langfuse_export, otel_export

    span = {"span_id": "s1", "parent_id": None, "name": "x", "stage": "attack",
            "duration_ms": 1.0, "status": "blocked", "attrs": {}}
    otel_export(span)      # must not raise without the SDK/endpoint
    langfuse_export(span)  # must not raise without keys


def test_report_markdown_and_json(tmp_path):
    ev = asyncio.run(run_campaign(VulnerableTarget(), resumes=laced_resumes()))
    report = CampaignReport.from_evidence("vulnerable", ev)
    md = to_markdown(report, ablation={
        "none": {"indirect_document": 1.0},
        "full": {"indirect_document": 0.0},
    })
    assert "mermaid" in md and "Overall ASR" in md
    assert report.successes >= report.total_attacks * 0.8
    json.dumps(report.model_dump())  # serializable
