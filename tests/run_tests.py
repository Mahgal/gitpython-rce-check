#!/usr/bin/env python3
"""Run the gitpython-rce-check test suite (stdlib unittest only)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main():
    loader = unittest.TestLoader()
    suite = loader.discover(str(Path(__file__).resolve().parent), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("tests run: %d, failures: %d, errors: %d"
          % (result.testsRun, len(result.failures), len(result.errors)))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
