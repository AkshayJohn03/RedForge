"""Multi-turn crescendo: turns execute in order; the final turn carries the goal."""

from __future__ import annotations

from redforge.attacks.taxonomy import BY_ID
from redforge.engine.detectors import detect
from redforge.engine.runner import _episode_messages, _render
from redforge.targets.recruiting import VulnerableTarget


def test_crescendo_script_order_and_success():
    attack = BY_ID["RF-MC-001"]
    turns = _render(attack)
    assert len(turns) == 3
    assert "get_salary_band" in turns[-1], "goal lands in the final turn"

    target = VulnerableTarget()
    msgs_sets = _episode_messages(attack, turns, resume=None, spotlightless=True)
    assert len(msgs_sets) == 3
    final = None
    for msgs in msgs_sets:
        real = [dict(m) for m in msgs if m["role"] != "system"]
        final = target.chat([{"role": "system", "content": target.system_prompt}] + real)
    verdict = detect(final, target.canary.value)
    assert verdict.success, "crescendo must succeed on the unguarded target"
