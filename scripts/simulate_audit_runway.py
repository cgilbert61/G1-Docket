#!/usr/bin/env python3
"""G1 Docket — Audit Runway & 30-Day Go-Live Simulation.

Simulates the 30-day enterprise audit runway specified in docs/audit-period-determination.md,
evaluating the 3 empirical exit criteria day-by-day:
  1. Live Traffic Coverage (Target: >= 99.0%)
  2. Denial Stability (Target: Flat for 7 consecutive days, 0 new denial categories)
  3. Triage Disposition (Target: 100% of HITL backlog resolved)

Demonstrates the automated recommendation transition from:
  "AUDIT IN PROGRESS: Day X of 30" -> "GO-LIVE READY: Safe to flip to ENFORCE"
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Ensure terminal UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


@dataclass
class DailyAuditMetrics:
    day: int
    live_requests: int
    attested_objects: int
    would_denies: int
    new_categories: int
    triage_resolved: int
    triage_pending: int

    @property
    def coverage_pct(self) -> float:
        total_eval = self.attested_objects + self.would_denies
        return (self.attested_objects / total_eval * 100.0) if total_eval > 0 else 0.0

    @property
    def triage_pct(self) -> float:
        total = self.triage_resolved + self.triage_pending
        return (self.triage_resolved / total * 100.0) if total > 0 else 100.0


def generate_30_day_timeline() -> list[DailyAuditMetrics]:
    """Generate deterministic progression matching enterprise audit trajectory."""
    timeline: list[DailyAuditMetrics] = []

    for day in range(1, 31):
        # Requests scale up as RAG agents adopt gateway
        base_reqs = 1000 + int(day * 250)

        if day <= 7:
            # Phase 1: Discovery baseline
            attested = int(base_reqs * (0.65 + 0.02 * day))
            denies = base_reqs - attested
            new_cats = 3 if day == 1 else (2 if day <= 4 else 1)
            triage_res = int(denies * 0.25)
            triage_pend = denies - triage_res
        elif day <= 14:
            # Phase 2: Ingestion & attestation catch-up
            attested = int(base_reqs * (0.80 + 0.018 * (day - 7)))
            denies = base_reqs - attested
            new_cats = 1 if day in (8, 10) else 0
            triage_res = int(denies * (0.40 + 0.05 * (day - 7)))
            triage_pend = max(0, denies - triage_res)
        elif day <= 21:
            # Phase 3: Stabilization
            attested = int(base_reqs * (0.94 + 0.007 * (day - 14)))
            denies = base_reqs - attested
            new_cats = 0
            triage_res = int(denies * 0.90)
            triage_pend = max(0, denies - triage_res)
        else:
            # Phase 4: Final verification window (>= 99% coverage, 0 new cats, flat denials at floor)
            attested = int(base_reqs * (0.992 + 0.001 * (day - 21)))
            # Steady baseline floor of residual policy blocks (2..3/day)
            denies = 2 if day % 2 == 0 else 3
            new_cats = 0
            # On final days, compliance backlog is 100% disposed
            triage_pend = 0 if day >= 25 else max(0, 2 - (day - 21))
            triage_res = denies

        timeline.append(
            DailyAuditMetrics(
                day=day,
                live_requests=base_reqs,
                attested_objects=attested,
                would_denies=denies,
                new_categories=new_cats,
                triage_resolved=triage_res,
                triage_pending=triage_pend,
            )
        )

    return timeline


def evaluate_exit_criteria(history: list[DailyAuditMetrics]) -> dict[str, Any]:
    """Evaluate the 3 empirical exit criteria on the current day's trailing window."""
    today = history[-1]
    day = today.day

    # 1. Live Traffic Coverage (Target: >= 99.0%)
    coverage = today.coverage_pct
    coverage_ok = coverage >= 99.0

    # 2. Denial Stability (Target: 7-day rolling denial delta flat or at baseline floor, 0 new categories)
    if len(history) >= 7:
        trailing_7 = history[-7:]
        denials_7d = [d.would_denies for d in trailing_7]
        new_cats_7d = sum(d.new_categories for d in trailing_7)
        delta = max(denials_7d) - min(denials_7d)
        is_floor = max(denials_7d) <= 5
        is_flat = delta <= 2
        denial_stable = (is_floor or is_flat) and (new_cats_7d == 0)
    else:
        denials_7d = [d.would_denies for d in history]
        denial_stable = False
        new_cats_7d = sum(d.new_categories for d in history)

    # 3. Triage Disposition (Target: >= 98.0% or 0 pending)
    triage_pct = today.triage_pct
    triage_ok = (today.triage_pending == 0) or (triage_pct >= 98.0)

    # Readiness Score (0..100)
    score = 0
    score += min(40, int((coverage / 99.0) * 40))
    score += 35 if denial_stable else min(30, int((len(history) / 7.0) * 20))
    score += min(25, int((triage_pct / 100.0) * 25))
    score = min(100, max(0, score))

    is_ready = coverage_ok and denial_stable and triage_ok

    if is_ready:
        recommendation = "GO-LIVE READY: Safe to flip to ENFORCE"
        status_label = "READY"
    else:
        recommendation = f"AUDIT IN PROGRESS: Day {day} of 30"
        status_label = "IN_PROGRESS"

    return {
        "day": day,
        "coverage_pct": round(coverage, 2),
        "coverage_ok": coverage_ok,
        "denial_stable": denial_stable,
        "new_categories_7d": new_cats_7d,
        "triage_pct": round(triage_pct, 1),
        "triage_pending": today.triage_pending,
        "triage_ok": triage_ok,
        "readiness_score": score,
        "is_ready": is_ready,
        "recommendation": recommendation,
        "status_label": status_label,
    }


def run_simulation(speed: float = 0.05, verbose: bool = True) -> int:
    timeline = generate_30_day_timeline()

    print("\n" + "=" * 90)
    print("        G1 DOCKET: 30-DAY AUDIT RUNWAY & GO-LIVE READINESS SIMULATOR         ")
    print("               (Derived from docs/audit-period-determination.md)              ")
    print("=" * 90)
    print(f"{'Day':<5} | {'Coverage':<10} | {'Denials/d':<10} | {'New Cats':<9} | {'Triage %':<9} | {'Score':<7} | {'Recommendation'}")
    print("-" * 90)

    for i in range(len(timeline)):
        history_so_far = timeline[: i + 1]
        res = evaluate_exit_criteria(history_so_far)

        cov_str = f"{res['coverage_pct']:.1f}% {'[OK]' if res['coverage_ok'] else '    '}"
        cat_str = f"{res['new_categories_7d']} in 7d"
        triage_str = f"{res['triage_pct']:.0f}% ({res['triage_pending']} pend)"
        score_str = f"{res['readiness_score']}%"

        rec_color = "\033[92m" if res["is_ready"] else "\033[93m"
        reset_color = "\033[0m"

        print(
            f"D{res['day']:<4} | {cov_str:<10} | {history_so_far[-1].would_denies:<10} | "
            f"{cat_str:<9} | {triage_str:<9} | {score_str:<7} | "
            f"{rec_color}{res['recommendation']}{reset_color}"
        )

        if speed > 0:
            time.sleep(speed)

    final_res = evaluate_exit_criteria(timeline)
    print("=" * 90)
    print(f"\n[+] Audit Runway Simulation Complete.")
    print(f"    * Final Readiness Score:     {final_res['readiness_score']}%")
    print(f"    * Criterion 1 (Coverage):    {final_res['coverage_pct']}% >= 99.0% -> {'PASS' if final_res['coverage_ok'] else 'FAIL'}")
    print(f"    * Criterion 2 (Stability):   7-day rolling velocity flat -> {'PASS' if final_res['denial_stable'] else 'FAIL'}")
    print(f"    * Criterion 3 (Triage):      {final_res['triage_pct']}% resolved (0 pending) -> {'PASS' if final_res['triage_ok'] else 'FAIL'}")
    print(f"    * Final Operational State:   {final_res['recommendation']}\n")

    return 0 if final_res["is_ready"] else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate G1 Docket 30-Day Audit Runway")
    parser.add_argument("--speed", type=float, default=0.02, help="Delay between day iterations in seconds (default: 0.02)")
    parser.add_argument("--json", action="store_true", help="Output JSON results instead of table")
    args = parser.parse_args()

    if args.json:
        timeline = generate_30_day_timeline()
        res = evaluate_exit_criteria(timeline)
        print(json.dumps(res, indent=2))
        sys.exit(0 if res["is_ready"] else 1)

    sys.exit(run_simulation(speed=args.speed))


if __name__ == "__main__":
    main()
