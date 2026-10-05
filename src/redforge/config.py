"""Declarative campaign configuration: ``redforge.yaml`` -> ``RedForgeConfig``.

Security engineers configure a full campaign — target, defense stack, attack
selection and depth, mutation/evolution knobs, CI gate threshold, compliance
standards and report location — without writing orchestration code. Every
field is Pydantic-validated; ``RedForgeConfigError`` names the offending field.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from .attacks.taxonomy import REGISTRY, Attack, Category
from .compliance import STANDARDS
from .defenses.stack import DefenseStack
from .targets.recruiting import HardenedTarget, RecruitingAssistant, VulnerableTarget


class RedForgeConfigError(ValueError):
    """Config file missing, unreadable, malformed, or failing validation."""


TargetName = Literal["vulnerable", "hardened", "custom"]


class TargetConfig(BaseModel):
    name: TargetName = "hardened"
    # explicit defense stack (makes the target 'custom'); empty -> use name
    defenses: list[str] = Field(default_factory=list)

    @field_validator("defenses")
    @classmethod
    def _known_layers(cls, v: list[str]) -> list[str]:
        unknown = [d for d in v if d not in DefenseStack.model_fields]
        if unknown:
            raise ValueError(
                f"unknown defense layer(s) {unknown}; valid layers: {sorted(DefenseStack.model_fields)}"
            )
        return v


class AttacksConfig(BaseModel):
    categories: list[str] = Field(default_factory=list)  # empty = every category
    depth: dict[str, int] = Field(default_factory=dict)  # per-category attack cap
    mutations: bool = True
    generations: int = Field(default=0, ge=0, le=10)

    @field_validator("categories", "depth")
    @classmethod
    def _known_categories(cls, v):
        valid = {c.value for c in Category}
        keys = v if isinstance(v, list) else list(v)
        unknown = [k for k in keys if k not in valid]
        if unknown:
            raise ValueError(f"unknown attack category(ies) {unknown}; valid: {sorted(valid)}")
        return v

    @model_validator(mode="after")
    def _depth_non_negative(self):
        for cat, cap in self.depth.items():
            if cap < 0:
                raise ValueError(f"attacks.depth.{cat} must be >= 0, got {cap}")
        return self


class GateConfig(BaseModel):
    max_asr: float = Field(default=0.05, ge=0.0, le=1.0)


class ComplianceConfig(BaseModel):
    standards: list[str] = Field(
        default_factory=lambda: ["owasp_llm_top10", "nist_ai_rmf", "eu_ai_act"]
    )

    @field_validator("standards")
    @classmethod
    def _known_standards(cls, v: list[str]) -> list[str]:
        unknown = [s for s in v if s not in STANDARDS]
        if unknown:
            raise ValueError(f"unknown compliance standard(s) {unknown}; valid: {list(STANDARDS)}")
        return v


class ReportConfig(BaseModel):
    out_dir: str = "redforge-output"


class RedForgeConfig(BaseModel):
    target: TargetConfig = Field(default_factory=TargetConfig)
    attacks: AttacksConfig = Field(default_factory=AttacksConfig)
    gate: GateConfig = Field(default_factory=GateConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    seed: int = 42

    @classmethod
    def load(cls, path: str | Path) -> RedForgeConfig:
        """Load + validate a YAML campaign config; raise RedForgeConfigError
        with the offending field on any problem."""
        p = Path(path)
        if not p.is_file():
            raise RedForgeConfigError(f"config file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            raise RedForgeConfigError(f"unreadable config {p}: {exc}") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise RedForgeConfigError(f"config root must be a mapping, got {type(data).__name__}")
        try:
            return cls.model_validate(data)
        except Exception as exc:  # pydantic.ValidationError and friends
            details = getattr(exc, "errors", lambda: None)()
            if details:
                fields = "; ".join(
                    ".".join(str(loc) for loc in err.get("loc", ["<root>"])) or "<root>"
                    for err in details
                )
                raise RedForgeConfigError(f"invalid redforge config field(s): {fields} ({exc})") from exc
            raise RedForgeConfigError(f"invalid redforge config: {exc}") from exc


def build_target(t: TargetConfig) -> RecruitingAssistant:
    """Materialize the configured target: named preset or a custom stack."""
    if t.defenses:
        return RecruitingAssistant(DefenseStack(**{d: True for d in t.defenses}))
    if t.name == "vulnerable":
        return VulnerableTarget()
    if t.name == "hardened":
        return HardenedTarget()
    return RecruitingAssistant(DefenseStack.none())


def select_attacks(cfg: RedForgeConfig) -> list[Attack]:
    """Resolve the configured attack list: category filter, per-category depth,
    optional deterministic mutation variants, optional evolved winners."""
    import random

    from .attacks.evolution import evolve
    from .attacks.mutators import MUTATORS

    cats = set(cfg.attacks.categories) or {c.value for c in Category}
    selected = [a for a in REGISTRY if a.category.value in cats]
    if cfg.attacks.depth:
        counts: dict[str, int] = {}
        capped: list[Attack] = []
        for a in selected:
            cap = cfg.attacks.depth.get(a.category.value)
            if cap is not None and counts.get(a.category.value, 0) >= cap:
                continue
            counts[a.category.value] = counts.get(a.category.value, 0) + 1
            capped.append(a)
        selected = capped

    rng = random.Random(cfg.seed)
    if cfg.attacks.mutations:
        ops = list(MUTATORS)
        variants = []
        for i, a in enumerate(selected):
            variant = a.model_copy(update={"template": MUTATORS[ops[i % len(ops)]](a.template, rng)})
            variants.append(variant)
        selected = selected + variants

    if cfg.attacks.generations > 0:
        # evolve against the configured target and append discovered winners
        target = build_target(cfg.target)
        history = evolve(target, generations=cfg.attacks.generations, seed=cfg.seed,
                         attacks=selected)
        winner_ids: set[str] = set()
        for gen in history:
            winner_ids.update(gen.winners)
        winners = [a for a in selected if a.id in winner_ids]
        selected = selected + winners
    return selected
