"""Directional 28-day ShareNet agent simulation.

This is an architecture exploration model, not field evidence or a survey.
Run with: python3 simulation/simulate.py
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

DAYS = 28
RUNS = 500

SEGMENTS = {
    "Enterprise": {"n": 120, "direct": 0.82, "gateway": 0.10, "radius": 0.16, "demand": 0.15},
    "Medium": {"n": 60, "direct": 0.68, "gateway": 0.13, "radius": 0.12, "demand": 0.25},
    "SME": {"n": 24, "direct": 0.55, "gateway": 0.18, "radius": 0.14, "demand": 0.38},
    "Individual": {"n": 12, "direct": 0.35, "gateway": 0.25, "radius": 0.18, "demand": 0.55},
}

COMPETITORS = ("ShareNet", "CommunityMesh", "Hotspot", "Satellite", "Tailscale")


def reachable(link_up: np.ndarray, gateways: np.ndarray, hops: int) -> np.ndarray:
    n = len(gateways)
    seen = set(np.where(gateways)[0].tolist())
    front = set(seen)
    for _ in range(hops):
        nxt: set[int] = set()
        for u in front:
            for v in np.where(link_up[u])[0]:
                if int(v) not in seen:
                    nxt.add(int(v))
        seen |= nxt
        front = nxt
        if not front:
            break
    result = np.zeros(n, dtype=bool)
    result[list(seen)] = True
    return result


def simulate_segment(segment: str) -> dict[str, float]:
    cfg = SEGMENTS[segment]
    totals = {k: 0 for k in COMPETITORS}
    attempts = 0

    for run in range(RUNS):
        rng = np.random.default_rng(10_000 + run)
        n = cfg["n"]
        positions = rng.random((n, 2))
        direct = rng.random(n) < cfg["direct"]
        gateway = direct & (rng.random(n) < cfg["gateway"])

        run_totals = {k: 0 for k in COMPETITORS}
        run_attempts = 0

        for day in range(DAYS):
            positions = np.clip(positions + rng.normal(0, 0.065, size=(n, 2)), 0, 1)
            direct = rng.random(n) < np.clip(cfg["direct"] + rng.normal(0, 0.025, n), 0.05, 0.98)

            incentive_ramp = 1 + 0.85 * day / (DAYS - 1)
            gateway = (gateway & (rng.random(n) < 0.98)) | (
                direct & (rng.random(n) < np.clip(cfg["gateway"] * incentive_ramp, 0, 0.55))
            )
            gateway &= direct

            distances = np.linalg.norm(positions[:, None, :] - positions[None, :, :], axis=2)
            link_up = (distances < cfg["radius"]) & (distances > 0)
            link_up &= rng.random((n, n)) < 0.955
            link_up = np.triu(link_up, 1)
            link_up |= link_up.T

            adc_os_backhaul = gateway & (rng.random(n) < 0.96)
            share_reach = reachable(link_up, adc_os_backhaul, hops=5)
            community_reach = reachable(link_up, adc_os_backhaul, hops=3)

            direct_hotspot = np.zeros(n, dtype=bool)
            for g in np.where(adc_os_backhaul)[0]:
                direct_hotspot |= link_up[g] & (rng.random(n) < 0.86)
            direct_hotspot |= adc_os_backhaul & (rng.random(n) < 0.86)

            sat_gateway = direct & (rng.random(n) < 0.05)
            satellite_reach = np.zeros(n, dtype=bool)
            for g in np.where(sat_gateway)[0]:
                satellite_reach |= (distances[g] < cfg["radius"] * 1.4) & (rng.random(n) < 0.93)
            satellite_reach |= sat_gateway

            tailscale = direct
            offline_demand = (~direct) & (rng.random(n) < cfg["demand"])
            attempts_day = int(offline_demand.sum())
            run_attempts += attempts_day

            outcomes = {
                "ShareNet": share_reach,
                "CommunityMesh": community_reach,
                "Hotspot": direct_hotspot,
                "Satellite": satellite_reach,
                "Tailscale": tailscale,
            }
            for name, reach in outcomes.items():
                run_totals[name] += int((offline_demand & reach).sum())

        attempts += run_attempts
        for name in COMPETITORS:
            totals[name] += run_totals[name]

    return {name: totals[name] / max(1, attempts) for name in COMPETITORS}


def logistic(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def main() -> None:
    results = {segment: simulate_segment(segment) for segment in SEGMENTS}
    for segment, row in results.items():
        print(segment)
        for name, value in row.items():
            print(f"  {name:16s} {value * 100:6.2f}%")

    print("\nNote: willingness-to-switch figures in results.md use a separate synthetic utility model")
    print("based on reliability gain, perceived contribution benefits, trust and switching friction.")


if __name__ == "__main__":
    main()
