#!/usr/bin/env python3
"""Run all OpenAll tests:  python3 tests/run_tests.py   (the builder tests need: pip install capstone pefile)"""
import sys, unittest
from pathlib import Path

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).resolve().parent), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
