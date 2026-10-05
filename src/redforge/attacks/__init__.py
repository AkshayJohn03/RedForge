"""RedForge attacks package."""
from . import taxonomy
from .tool_abuse import TOOL_ABUSE_REGISTRY

# merge the tool-boundary attacks into the canonical registry. The extension
# lives here (not inside taxonomy.py) so ``import redforge.attacks.tool_abuse``
# can never hit a partially-initialized taxonomy <-> tool_abuse cycle: parent
# package __init__ always runs before any submodule import.
for _attack in TOOL_ABUSE_REGISTRY:
    if _attack.id not in taxonomy.BY_ID:
        taxonomy.REGISTRY.append(_attack)
        taxonomy.BY_ID[_attack.id] = _attack
