import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_DIR = os.path.join(ROOT, "ml")
SCRIPTS_DIR = os.path.join(ROOT, "scripts")

for path in (ROOT, ML_DIR, SCRIPTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)