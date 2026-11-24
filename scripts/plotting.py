"""What the plotting scripts share: matplotlib, loaded for the run only, and the colours of the side that adapts.

matplotlib is not a project dependency (the benchmark never plots): a script that draws runs under `uv run --with matplotlib`.
So matplotlib is loaded here by name and typed as `Any`, after the Agg backend is chosen, and the type checker never needs it
installed.
"""

import importlib
from typing import Any

matplotlib: Any = importlib.import_module("matplotlib")
# Choosing the file-only backend before pyplot is loaded, so the scripts draw without a display.
matplotlib.use("Agg")
plt: Any = importlib.import_module("matplotlib.pyplot")
patches: Any = importlib.import_module("matplotlib.patches")

# Who the orchestrator chose to adapt after a round, green defender and red attacker as in the loop diagrams, grey end. The green
# and the red are the bluish green and the vermillion of Okabe and Ito, which a reader with red-green colour blindness tells apart.
WHO_COLORS: dict[str, str] = {"defender": "#009e73", "attacker": "#d55e00", "": "#9e9e9e"}
