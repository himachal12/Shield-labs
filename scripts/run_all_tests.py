"""Wrapper script for run_all_tests.py located in the root directory."""

import sys
from pathlib import Path

# Insert root directory into sys.path
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

if __name__ == "__main__":
    import run_all_tests
