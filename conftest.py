"""Pytest configuration shared across the test suite.

Ensures the repo root is importable so tests can `import config`, `import safety`,
etc. the same way the bot modules import each other.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
