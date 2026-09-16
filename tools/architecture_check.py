#!/usr/bin/env python3
"""Static governance checks for the frozen ShareNet architecture."""
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

    for i in range(1, 26):
        lock_id = f"L{i:03d}"
        if not re.search(rf"\|\s*{lock_id}\s*\|", locks):
            errors.append(f"missing architecture lock {lock_id}")

    for phrase in ("ConnectivityPort", "ConnectivityContract", "QUIC", "ICE/STUN/TURN", "LIVE", "OPPORTUNISTIC", "DTN", "Civic Points"):
        if phrase not in architecture:
            errors.append(f"architecture missing frozen concept: {phrase}")

    for phrase in ("Maximum three direct workers", "Completion requires", "fresh-audit", "R4", "R7", "R8", "R10"):
        if phrase.lower() not in handoff.lower():
            errors.append(f"orchestrator handoff missing control: {phrase}")

    for phrase in ("execution scheduling authority", "Maximum three direct workers", "No second source of truth", "origin/main"):
        if phrase.lower() not in agents.lower():
            errors.append(f"AGENTS.md missing governance rule: {phrase}")

    if "status: FROZEN_PATH_EXECUTION_COMPLETE" not in current:
        errors.append("current-state does not declare the execution-complete closure status")

    entries = re.findall(r"- \{id: ([A-Z0-9-]+), .*?depends: \[([^]]*)\]", items)
    ids = {item_id for item_id, _ in entries}
    if len(ids) != 48:
        errors.append(f"expected 48 work items, found {len(ids)}")

    graph: dict[str, list[str]] = {}
    for item_id, dep_group in entries:
        deps = [d.strip() for d in dep_group.split(",") if d.strip()]
        graph[item_id] = deps
        for dep in deps:
            if dep not in ids:
                errors.append(f"work item {item_id} references missing predecessor {dep}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            errors.append(f"dependency cycle detected at {node}")
            return
        if node in visited:
            return
        visiting.add(node)
        for dep in graph.get(node, []):
            visit(dep)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)

    def deps_of(item_id: str) -> set[str]:
        return set(graph.get(item_id, []))

    if "R8-004" in deps_of("R6-005"):
        errors.append("R6-005 must not depend on Civic Points; priority is an integration overlay")
    if "R5-005" in deps_of("R7-001"):
        errors.append("R7-001 core failure detector must not depend on ADCOS gateway admission")
    if deps_of("R5-001"):
        errors.append("R5-001 ConnectivityPort must be independently freezable from circuit implementation")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("ShareNet architecture governance checks: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
