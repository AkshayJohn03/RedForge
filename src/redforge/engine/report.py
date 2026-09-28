"""Campaign report: ASR metrics, ablation heatmap (mermaid), JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from .runner import Evidence, asr, asr_by_category


class CampaignReport(BaseModel):
    target_name: str
    total_attacks: int
    successes: int
    asr: float
    by_category: dict[str, float]
    detector_reasons: dict[str, int]
    evidence: list[dict]

    @classmethod
    def from_evidence(cls, target_name: str, evidence: list[Evidence]) -> CampaignReport:
        reasons: dict[str, int] = {}
        for e in evidence:
            for r in e.verdict["reasons"]:
                reasons[r] = reasons.get(r, 0) + 1
        return cls(
            target_name=target_name,
            total_attacks=len(evidence),
            successes=sum(1 for e in evidence if e.verdict["success"]),
            asr=asr(evidence),
            by_category=asr_by_category(evidence),
            detector_reasons=reasons,
            evidence=[e.model_dump() for e in evidence],
        )


def _heatmap(matrix: dict[str, dict[str, float]], categories: list[str]) -> str:
    cols = list(matrix.keys())
    lines = [
        "```mermaid",
        "graph TD",
        "  subgraph ASR[Attack Success Rate — lower is better]",
    ]
    for col in cols:
        for cat in categories:
            v = matrix[col].get(cat, 0.0)
            label = "LEAK" if v > 0 else "ok"
            lines.append(f"    {col.replace('-', '_')}__{cat}[\"{col} · {cat}: {v:.2f} {label}\"]")
    lines.append("  end")
    lines.append("```")
    return "\n".join(lines)


def to_markdown(report: CampaignReport, ablation: dict[str, dict[str, float]] | None = None) -> str:
    lines = [
        f"# RedForge campaign report — {report.target_name}",
        "",
        f"- **Attacks run:** {report.total_attacks}",
        f"- **Successes:** {report.successes}",
        f"- **Overall ASR:** {report.asr:.2%}",
        "",
        "## ASR by attack category",
        "",
        "| category | ASR |",
        "|---|---|",
    ]
    for cat, v in report.by_category.items():
        lines.append(f"| {cat} | {v:.2f} |")
    lines += ["", "## Success evidence by detector", ""]
    for r, n in sorted(report.detector_reasons.items()):
        lines.append(f"- `{r}`: {n}")
    if ablation:
        cats = sorted({c for col in ablation.values() for c in col})
        lines += ["", "## Defense ablation (ASR per category)", "",
                  _heatmap(ablation, cats), ""]
        header = "| category | " + " | ".join(ablation.keys()) + " |"
        lines += [header, "|---" * (len(ablation.keys()) + 1) + "|"]
        for cat in cats:
            rows = [f"{ablation[col].get(cat, 0.0):.2f}" for col in ablation]
            lines.append(f"| {cat} | " + " | ".join(rows) + " |")
    return "\n".join(lines) + "\n"


def save(report: CampaignReport, out_dir: str | Path, ablation=None) -> Path:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "campaign_report.md").write_text(to_markdown(report, ablation), encoding="utf-8")
    (d / "campaign_report.json").write_text(
        json.dumps({"report": report.model_dump(), "ablation": ablation}, indent=2),
        encoding="utf-8",
    )
    return d / "campaign_report.md"
