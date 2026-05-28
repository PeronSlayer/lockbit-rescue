#!/usr/bin/env python3
"""Summarize recovery quality metrics from a manifest CSV."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from recovery_metrics import aggregate_manifest_rows  # noqa: E402


def load_rows(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")


def print_summary(metrics: dict) -> None:
    print("Recovery Benchmark Summary")
    print(f"  files_total: {metrics.get('files_total', 0)}")
    print(f"  files_ok: {metrics.get('files_ok', 0)}")
    print(f"  files_review: {metrics.get('files_review', 0)}")
    print(f"  files_fail: {metrics.get('files_fail', 0)}")
    print(f"  bytes_total: {metrics.get('bytes_total', 0)}")
    print(f"  bytes_recovered: {metrics.get('bytes_recovered', 0)}")
    print(f"  recovery_rate_percent: {metrics.get('recovery_rate_percent', 0)}")
    print(f"  files_fully_recovered_percent: {metrics.get('files_fully_recovered_percent', 0)}")
    print(f"  avg_confidence_score: {metrics.get('avg_confidence_score', 0)}")
    by_phase = metrics.get("by_phase", {}) or {}
    if by_phase:
        print("  by_phase:")
        for phase, phase_metrics in sorted(by_phase.items()):
            print(
                f"    {phase}: files={phase_metrics.get('files_total', 0)} "
                f"ok={phase_metrics.get('files_ok', 0)} "
                f"review={phase_metrics.get('files_review', 0)} "
                f"fail={phase_metrics.get('files_fail', 0)} "
                f"recovery={phase_metrics.get('recovery_rate_percent', 0)}%"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize recovery metrics from manifest.csv")
    parser.add_argument("--manifest", required=True, help="Path to manifest.csv")
    parser.add_argument("--report-json", default=None, help="Optional path for benchmark JSON output")
    args = parser.parse_args()

    manifest = Path(args.manifest)
    if not manifest.is_file():
        print(f"ERROR: manifest not found: {manifest}", file=sys.stderr)
        return 2

    rows = load_rows(manifest)
    metrics = aggregate_manifest_rows(rows)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest": str(manifest),
        "metrics": metrics,
    }

    print_summary(metrics)
    if args.report_json:
        write_json(Path(args.report_json), payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
