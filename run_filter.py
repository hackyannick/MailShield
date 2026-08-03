#!/usr/bin/env python3
"""Postfix-pipe-Einstiegspunkt. Aufruf: run_filter.py <sender> <recipient> ..."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shield.filter import main  # noqa: E402

sys.exit(main(sys.argv[1:]))
