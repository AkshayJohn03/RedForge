"""Compliance mapping: evidence -> OWASP LLM Top-10 / NIST AI RMF / EU AI Act."""

from __future__ import annotations

import asyncio

import pytest

from redforge.attacks.taxonomy import REGISTRY
from redforge.compliance import STANDARDS, map_findings
from redforge.data.resumes import laced_resumes
from redforge.engine.report import CampaignReport, to_markdown
from redforge.engine.runner import run_campaign
from redforge.targets.recruiting import HardenedTarget, VulnerableTarget


@pytest.fixture(scope="module")
def vulnerable_evidence():
    return asyncio.run(run_campaign(VulnerableTarget(), resumes=laced_resumes()))


def test_map_findings_emits_all_configured_standards(vulnerable_evidence):
    sections = map_findings(vulnerable_evidence, list(STANDARDS))
    assert set(sections) == set(STANDARDS)
    for std, rows in sections.items():
        assert rows, f"{std} section must have entries"
        assert all(r["status"] == "GAP" for r in rows), (
            "vulnerable-target evidence must mark every category as a gap"
        )


def test_tool_abuse_maps_to_owasp_llm06_and_nist(vulnerable_evidence):
    sections = map_findings(vulnerable_evidence, list(STANDARDS))
    owasp_rows = [r for r in sections["owasp_llm_top10"] if r["category"] == "tool_abuse"]
    assert any("LLM06" in r["owasp_item"] for r in owasp_rows)
    nist_rows = [r for r in sections["nist_ai_rmf"] if r["category"] == "tool_abuse"]
    assert nist_rows and nist_rows[0]["function"] in {"GOVERN", "MAP", "MEASURE", "MANAGE"}
    eu_rows = [r for r in sections["eu_ai_act"] if r["category"] == "tool_abuse"]
    assert eu_rows and eu_rows[0]["article"] in {"Art. 14", "Art. 15"}


def test_hardened_target_passes_all_standards():
    ev = asyncio.run(run_campaign(HardenedTarget(), resumes=laced_resumes()))
    sections = map_findings(ev, list(STANDARDS))
    for std, rows in sections.items():
        assert rows and all(r["status"] == "PASS" for r in rows), (
            f"hardened target must show PASS across {std}"
        )


def test_unknown_standard_rejected(vulnerable_evidence):
    with pytest.raises(ValueError, match="sox"):
        map_findings(vulnerable_evidence, ["sox"])


def test_report_markdown_gains_compliance_section(vulnerable_evidence):
    sections = map_findings(vulnerable_evidence, list(STANDARDS))
    report = CampaignReport.from_evidence("vulnerable", vulnerable_evidence)
    md = to_markdown(report, compliance=sections)
    assert "## Compliance" in md
    assert "OWASP LLM Top-10 (2025)" in md
    assert "NIST AI RMF 1.0" in md
    assert "EU AI Act" in md and "Art. 15" in md and "Art. 14" in md
    # without configured standards the section is absent
    assert "## Compliance" not in to_markdown(report)


def test_every_registry_category_is_compliance_mapped(vulnerable_evidence):
    # every category present in evidence must appear in each standard's section
    sections = map_findings(vulnerable_evidence, list(STANDARDS))
    cats_in_evidence = {e.category for e in vulnerable_evidence}
    cats_in_registry = {a.category.value for a in REGISTRY}
    assert cats_in_evidence == cats_in_registry
    for std, rows in sections.items():
        mapped = {r["category"] for r in rows}
        assert cats_in_registry <= mapped, f"{std} misses {cats_in_registry - mapped}"
