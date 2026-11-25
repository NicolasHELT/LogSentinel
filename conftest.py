"""Ajoute src/ au sys.path pour que pytest trouve le package sans installation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
