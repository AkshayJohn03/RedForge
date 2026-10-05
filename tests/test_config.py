"""Declarative campaigns: redforge.yaml loading, validation, attack selection,
and the ``redforge run --config`` CLI path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redforge.config import (
    RedForgeConfig,
    RedForgeConfigError,
    build_target,
    select_attacks,
)
from redforge.defenses.stack import DefenseStack
from redforge.targets.recruiting import VulnerableTarget

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_load_committed_redforge_yaml():
    cfg = RedForgeConfig.load(REPO_ROOT / "redforge.yaml")
    assert cfg.target.name == "hardened"
    assert cfg.gate.max_asr == 0.05
    assert cfg.compliance.standards == ["owasp_llm_top10", "nist_ai_rmf", "eu_ai_act"]
    assert cfg.report.out_dir == "redforge-output"
    assert cfg.seed == 42


def test_load_missing_and_malformed_files(tmp_path):
    with pytest.raises(RedForgeConfigError, match="not found"):
        RedForgeConfig.load(tmp_path / "nope.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("target: [unclosed", encoding="utf-8")
    with pytest.raises(RedForgeConfigError):
        RedForgeConfig.load(bad)
    root = tmp_path / "root.yaml"
    root.write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(RedForgeConfigError, match="mapping"):
        RedForgeConfig.load(root)


@pytest.mark.parametrize("yaml_text,field", [
    ("gate: {max_asr: 2.0}\n", "gate.max_asr"),
    ("gate: {max_asr: oops}\n", "gate.max_asr"),
    ("target:\n  name: nonsense\n", "target.name"),
    ("target:\n  defenses: [lightsaber]\n", "target.defenses"),
    ("attacks:\n  categories: [sql_gods]\n", "attacks.categories"),
    ("attacks:\n  depth: {tool_abuse: -3}\n", "attacks.depth"),
    ("compliance:\n  standards: [sox]\n", "compliance.standards"),
])
def test_invalid_fields_raise_named_error(tmp_path, yaml_text, field):
    p = tmp_path / "c.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(RedForgeConfigError) as ei:
        RedForgeConfig.load(p)
    assert field in str(ei.value), f"error must name the offending field {field}: {ei.value}"


def test_select_attacks_respects_categories_and_depth():
    cfg = RedForgeConfig.model_validate({
        "attacks": {"categories": ["tool_abuse"], "depth": {"tool_abuse": 3},
                    "mutations": False},
    })
    attacks = select_attacks(cfg)
    assert len(attacks) == 3
    assert {a.category.value for a in attacks} == {"tool_abuse"}


def test_select_attacks_mutations_deterministic_and_additive():
    base = RedForgeConfig.model_validate({"attacks": {"mutations": False}})
    plain = select_attacks(base)
    seeded_a = RedForgeConfig.model_validate({"seed": 42})
    seeded_b = RedForgeConfig.model_validate({"seed": 42})
    mut_a, mut_b = select_attacks(seeded_a), select_attacks(seeded_b)
    assert len(plain) == 35  # 25 text-layer + 10 tool-abuse templates
    assert len(mut_a) == 70  # one deterministic variant per selected attack
    assert [a.template for a in mut_a] == [a.template for a in mut_b]


def test_build_target_variants():
    assert build_target(RedForgeConfig.model_validate({"target": {"name": "vulnerable"}}).target).__class__ is VulnerableTarget
    custom = build_target(RedForgeConfig.model_validate(
        {"target": {"name": "custom", "defenses": ["tool_firewall", "input_scanner"]}}).target)
    assert custom.defenses.tool_firewall and custom.defenses.input_scanner
    assert not custom.defenses.output_filter


def test_cli_run_with_config_end_to_end(tmp_path):
    from redforge.cli import main

    cfg = tmp_path / "redforge.yaml"
    out = tmp_path / "out"
    cfg.write_text(
        "target:\n  name: hardened\n"
        "gate:\n  max_asr: 0.05\n"
        "compliance:\n  standards: [owasp_llm_top10, nist_ai_rmf, eu_ai_act]\n"
        f"report:\n  out_dir: {out.as_posix()}\n",
        encoding="utf-8",
    )
    rc = main(["run", "--config", str(cfg)])
    assert rc == 0, "hardened config must pass its own gate"
    body = json.loads((out / "campaign_report.json").read_text(encoding="utf-8"))
    assert body["compliance"] and set(body["compliance"]) == {
        "owasp_llm_top10", "nist_ai_rmf", "eu_ai_act"}
    md = (out / "campaign_report.md").read_text(encoding="utf-8")
    assert "## Compliance" in md


def test_cli_run_with_config_vulnerable_depth(tmp_path):
    from redforge.cli import main

    cfg = tmp_path / "redforge.yaml"
    out = tmp_path / "out"
    cfg.write_text(
        "target:\n  name: vulnerable\n"
        "attacks:\n  categories: [tool_abuse]\n  depth: {tool_abuse: 4}\n  mutations: false\n"
        f"report:\n  out_dir: {out.as_posix()}\n",
        encoding="utf-8",
    )
    rc = main(["run", "--config", str(cfg)])
    assert rc == 0, "exposure-baseline runs are informative, not gating"
    body = json.loads((out / "campaign_report.json").read_text(encoding="utf-8"))
    assert body["report"]["total_attacks"] == 4
    assert body["report"]["asr"] == 1.0


def test_cli_run_with_broken_config_fails_cleanly(tmp_path):
    from redforge.cli import main

    cfg = tmp_path / "broken.yaml"
    cfg.write_text("compliance:\n  standards: [sox]\n", encoding="utf-8")
    assert main(["run", "--config", str(cfg)]) == 2


def test_defense_stack_untouched_by_config_layer():
    # DefenseStack defaults remain off; config only toggles named layers
    assert DefenseStack.none().active_layers() == []
