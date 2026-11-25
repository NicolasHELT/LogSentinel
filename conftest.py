"""Ajoute la racine du projet au sys.path pour que pytest trouve le package."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
