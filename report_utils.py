#!/usr/bin/env python3
"""Report helpers for JSON run summaries."""

from __future__ import annotations

import json
import html
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json_report(path: Path, payload: dict):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")


def write_html_report(path: Path, payload: dict):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        scan = payload.get("scan", {}) or {}
        plan = payload.get("plan", {}) or {}
        phase1 = payload.get("phase1", {}) or {}
        phase2 = payload.get("phase2", {}) or {}
        metrics = payload.get("metrics", {}) or {}
        groups = plan.get("groups", []) or []

        def esc(value) -> str:
                return html.escape(str(value if value is not None else ""))

        rows = []
        for group in groups[:500]:
                rows.append(
                        "<tr>"
                        f"<td>{esc(group.get('kek'))}</td>"
                        f"<td>{esc(group.get('files'))}</td>"
                        f"<td>{esc(group.get('phase1_targets'))}</td>"
                        f"<td>{esc(group.get('phase2_candidates'))}</td>"
                        f"<td>{esc(group.get('oracle_fei_len'))}</td>"
                        f"<td>{esc(group.get('coverage_bytes'))}</td>"
                        f"<td>{esc(group.get('status'))}</td>"
                        "</tr>"
                )

        metric_cards = ""
        if metrics:
                metric_cards = (
                        f"<div class=\"metric\"><span>Recovery rate</span><strong>{esc(metrics.get('recovery_rate_percent', 0))}%</strong></div>"
                        f"<div class=\"metric\"><span>Bytes recovered</span><strong>{esc(metrics.get('bytes_recovered', 0))}</strong></div>"
                        f"<div class=\"metric\"><span>Fully recovered</span><strong>{esc(metrics.get('files_fully_recovered_percent', 0))}%</strong></div>"
                        f"<div class=\"metric\"><span>Avg confidence</span><strong>{esc(metrics.get('avg_confidence_score', 0))}</strong></div>"
                )

        content = f"""<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\">
    <title>LockBit Rescue Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2933; }}
        h1, h2 {{ margin-bottom: 8px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
        .metric {{ border: 1px solid #d8dee4; border-radius: 6px; padding: 12px; }}
        .metric strong {{ display: block; font-size: 22px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
        th, td {{ border: 1px solid #d8dee4; padding: 6px 8px; text-align: left; }}
        th {{ background: #f6f8fa; }}
        code {{ background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>LockBit Rescue Report</h1>
    <p>Generated at <code>{esc(payload.get('generated_at'))}</code></p>
    <div class=\"grid\">
        <div class=\"metric\"><span>Scanned</span><strong>{esc(scan.get('scanned', 0))}</strong></div>
        <div class=\"metric\"><span>Matched</span><strong>{esc(scan.get('matched', 0))}</strong></div>
        <div class=\"metric\"><span>Groups</span><strong>{esc(scan.get('groups', 0))}</strong></div>
        <div class=\"metric\"><span>Phase 1 targets</span><strong>{esc(plan.get('targets_to_attempt', 0))}</strong></div>
        <div class=\"metric\"><span>Recovered</span><strong>{esc(phase1.get('ok', 0) + (phase2.get('totals', {}) or {}).get('ok', 0))}</strong></div>
        <div class=\"metric\"><span>Review</span><strong>{esc(phase1.get('review', 0) + (phase2.get('totals', {}) or {}).get('review', 0))}</strong></div>
        {metric_cards}
    </div>
    <h2>Plan By Group</h2>
    <table>
        <thead><tr><th>KEK</th><th>Files</th><th>Phase 1 targets</th><th>Phase 2 candidates</th><th>Oracle FEI</th><th>Coverage</th><th>Status</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
</body>
</html>
"""
        path.write_text(content, encoding="utf-8")
