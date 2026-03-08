#!/usr/bin/env python3
"""
rek_policy.py

Load runtime policy configuration for REK guard modules.

Policy file: rek_policy.yaml (project root)
Defaults: development mode, guards disabled, minimal logging.
"""

import yaml
from pathlib import Path

DEFAULT_POLICY = {
    "mode": "development",
    "scope_guard": {"enabled": False},
    "domain_gate": {"enabled": False},
    "logging": {"level": "minimal"},
}


def load_policy():
    path = Path(__file__).parent / "rek_policy.yaml"

    if not path.exists():
        return DEFAULT_POLICY

    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}

    merged = DEFAULT_POLICY.copy()
    merged.update(data)

    return merged


POLICY = load_policy()
