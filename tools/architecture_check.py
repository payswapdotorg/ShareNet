#!/usr/bin/env python3
"""Static governance checks for the frozen ShareNet architecture.

This intentionally uses only the Python standard library. It validates the
repository-local control plane rather than implementation behavior.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED = [
    "spec/architecture.md",
    "spec/architecture-lock.md",
    "spec/protocol-registry.yaml",
    "spec/roadmap.yaml",
    "spec/work-items.yaml",
    "spec/dependency-graph.md",
    "spec/architect/current-state.yaml",
    "docs/tech-lead/SHARENET-ORCHESTRATOR-HANDOFF.md",
    "AGENTS.md",
]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> int:
    errors: list[str] = []
    for path in REQUIRED:
        if not (ROOT / path).is_file():
            errors.append(f"missing required authority: {path}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    locks = text("spec/architecture-lock.md")
    architecture = text("spec/architecture.md")
    agents = text("AGENTS.md")
    handoff = text("docs/tech-lead/SHARENET-ORCHESTRATOR-HANDOFF.md")
    current = text("spec/architect/current-state.yaml")
    items = text("spec/work-items.yaml")

    required_lock_ids = [f"L{i:03d}" for i in range(1, 26)]
    for lock_id in required_lock_ids:
        if not re.search(rf"\|\s*{lock_id}\s*\|", locks):
            errors.append(f"missing architecture lock {lock_id}")

    for phrase in (
        "ConnectivityPort",
        "ConnectivityContract",
        "QUIC",
        "ICE/STUN/TURN",
        "LIVE",
        "OPPORTUNISTIC",
        "DTN",
        "Civic Points",
    ):
        if phrase not in architecture:
            errors.append(f"architecture missing frozen concept: {phrase}")

    for phrase in (
        "Maximum three direct workers",
        "Completion requires",
        "fresh-audit",
        "R4",
        "R7",
        "R8",
        "R10",
    ):
        if phrase not in handoff:
            errors.append(f"orchestrator handoff missing control: {phrase}")

    for phrase in (
        "execution scheduling authority",
        "Maximum three direct workers",
        "No second source of truth",
        "origin/main",
    ):
        if phrase.lower() not in agents.lower():
            errors.append(f"AGENTS.md missing governance rule: {phrase}")

    if "status: ARCHITECTURE_FROZEN_IMPLEMENTATION_NOT_STARTED" not in current:
        errors.append("current-state does not declare the implementation baseline")

    ids = set(re.findall(r"^\s*- id: (R\d+-\d+)\s*$", items, re.MULTILINE))
    if len(ids) < 10:
        errors.append("work-item registry appears incomplete")

    deps = re.findall(r"depends_on: \[([^]]*)\]", items)
    for dep_group in deps:
        for dep in [x.strip() for x in dep_group.split(",") if x.strip()]:
            if dep not in ids:
                errors.append(f"work item references missing predecessor: {dep}")

    if "R6-005" in items and "R8-004" in items:
        block = re.search(r"- id: R6-005(?P<body>.*?)(?=\n  - id: |\Z)", items, re.S)
        if block and "R8-004" in block.group("body"):
            errors.append("R6-005 must not depend on Civic Points; priority integration is downstream")

    if "R7-001" in items:
        block = re.search(r"- id: R7-001(?P<body>.*?)(?=\n  - id: |\Z)", items, re.S)
        if block and "R5-005" in block.group("body"):
            errors.append("R7-001 core failure detection must not depend on ADCOS gateway admission")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("ShareNet architecture governance checks: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
