#!/usr/bin/env python3
"""Convenience launcher: runs ai_security_agent.main from repo root."""

import sys
from pathlib import Path

# Run package main when executed as script from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_security_agent.main import main

if __name__ == "__main__":
    sys.exit(main())
