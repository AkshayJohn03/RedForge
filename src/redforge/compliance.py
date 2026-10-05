"""Compliance mapping: RedForge findings -> enterprise control frameworks.

``map_findings`` turns campaign evidence into per-standard report sections:

- OWASP LLM Top-10 (2025): every attack category maps to the item(s) it probes.
- NIST AI RMF 1.0: every category carries a GOVERN / MAP / MEASURE / MANAGE
  function tag (attack-level ``nist`` fields where set, category default else).
- EU AI Act: categories map to Art. 15 (accuracy and robustness) or Art. 14
  (human oversight) obligations the finding speaks to.

The section is additive to the ASR numbers: it tells a compliance reviewer
WHICH control is evidenced by WHICH red-team result, not just the pass rate.
"""

from __future__ import annotations

from .attacks.taxonomy import REGISTRY
from .engine.runner import Evidence

STANDARDS = ("owasp_llm_top10", "nist_ai_rmf", "eu_ai_act")

OWASP_ITEMS: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM06": "Excessive Agency",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM10": "Unbounded Consumption",
}

# category -> (owasp items, nist function, eu article, eu title)
_CATEGORY_COMPLIANCE: dict[str, tuple[list[str], str, str, str]] = {
    "direct_injection": (["LLM01"], "MEASURE", "Art. 15", "Accuracy and robustness"),
    "roleplay_jailbreak": (["LLM01"], "MEASURE", "Art. 15", "Accuracy and robustness"),
    "encoding": (["LLM01"], "MEASURE", "Art. 15", "Accuracy and robustness"),
    "payload_splitting": (["LLM01"], "MEASURE", "Art. 15", "Accuracy and robustness"),
    "context_switching": (["LLM01", "LLM06"], "MAP", "Art. 15", "Accuracy and robustness"),
    "hypothetical_framing": (["LLM01"], "MEASURE", "Art. 15", "Accuracy and robustness"),
    "tool_exfil": (["LLM01", "LLM02"], "MANAGE", "Art. 14", "Human oversight"),
    "multi_turn_crescendo": (["LLM01"], "MANAGE", "Art. 14", "Human oversight"),
    "indirect_document": (["LLM01", "LLM08"], "MAP", "Art. 15", "Accuracy and robustness"),
    "tool_abuse": (["LLM06", "LLM01"], "GOVERN", "Art. 15", "Accuracy and robustness"),
}


def _category_nist(category: str, default: str) -> str:
    """Prefer the attack-level NIST tag when the category's attacks agree."""
    tags = sorted({a.nist[0] for a in REGISTRY if a.category.value == category and a.nist})
    return tags[0] if len(tags) == 1 else default


def map_findings(evidence: list[Evidence], standards: list[str] | tuple[str, ...]) -> dict[str, list[dict]]:
    """Aggregate evidence per attack category and emit one section per standard.

    Unknown standards raise ValueError (the config layer wraps this into a
    RedForgeConfigError naming the field).
    """
    invalid = [s for s in standards if s not in STANDARDS]
    if invalid:
        raise ValueError(f"unknown compliance standard(s) {invalid}; valid: {list(STANDARDS)}")

    stats: dict[str, dict] = {}
    for e in evidence:
        row = stats.setdefault(e.category, {"attacks": 0, "successes": 0})
        row["attacks"] += 1
        if e.verdict.get("success"):
            row["successes"] += 1

    sections: dict[str, list[dict]] = {s: [] for s in standards}
    for cat in sorted(stats):
        owasp_items, nist_default, article, title = _CATEGORY_COMPLIANCE.get(
            cat, (["LLM01"], "MEASURE", "Art. 15", "Accuracy and robustness")
        )
        nist = _category_nist(cat, nist_default)
        attacks_n = stats[cat]["attacks"]
        successes = stats[cat]["successes"]
        status = "GAP" if successes else "PASS"
        if "owasp_llm_top10" in sections:
            for item in owasp_items:
                sections["owasp_llm_top10"].append({
                    "category": cat, "owasp_item": f"{item} — {OWASP_ITEMS[item]}",
                    "attacks": attacks_n, "successes": successes, "status": status,
                })
        if "nist_ai_rmf" in sections:
            sections["nist_ai_rmf"].append({
                "category": cat, "function": nist,
                "attacks": attacks_n, "successes": successes, "status": status,
            })
        if "eu_ai_act" in sections:
            sections["eu_ai_act"].append({
                "category": cat, "article": article, "title": title,
                "attacks": attacks_n, "successes": successes, "status": status,
            })
    return sections


_SECTION_COLUMNS: dict[str, tuple[str, list[tuple[str, str]]]] = {
    "owasp_llm_top10": ("OWASP LLM Top-10 (2025)", [
        ("attack category", "category"), ("OWASP item", "owasp_item"),
        ("attacks", "attacks"), ("successes", "successes"), ("status", "status"),
    ]),
    "nist_ai_rmf": ("NIST AI RMF 1.0", [
        ("attack category", "category"), ("RMF function", "function"),
        ("attacks", "attacks"), ("successes", "successes"), ("status", "status"),
    ]),
    "eu_ai_act": ("EU AI Act", [
        ("attack category", "category"), ("article", "article"), ("title", "title"),
        ("attacks", "attacks"), ("successes", "successes"), ("status", "status"),
    ]),
}


def compliance_markdown(sections: dict[str, list[dict]]) -> str:
    """Render the Compliance report section (called from engine.report)."""
    if not sections:
        return ""
    lines = ["", "## Compliance", ""]
    for std in STANDARDS:
        rows = sections.get(std) or []
        if not rows:
            continue
        title, cols = _SECTION_COLUMNS[std]
        lines += [f"### {title}", "",
                  "| " + " | ".join(head for head, _ in cols) + " |",
                  "|" + "---|" * len(cols)]
        for r in rows:
            lines.append("| " + " | ".join(str(r.get(key, "")) for _, key in cols) + " |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
