#!/usr/bin/env python3
"""
Root entrypoint for Kubernetes Log Investigation Agent.
"""

import sys
from k8s_agent.cli import main

if __name__ == "__main__":
    sys.exit(main())
