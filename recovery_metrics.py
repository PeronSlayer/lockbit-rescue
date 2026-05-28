#!/usr/bin/env python3
"""Recovery metric helpers for manifest rows and reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

METRIC_HEADERS = [
    "recovered_bytes",
    "recovery_rate_percent",
    "phase_attempted",
    "confidence_score",
    "magic_rule_id",
    "keystream_offset_start",
    "keystream_offset_end",
    "is_truncated",
]


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _format_percent(value: float) -> str:
    return f"{max(0.0, min(100.0, value)):.2f}"


def default_confidence(status: str) -> int:
    status = (status or "").upper()
    if status == "OK":
        return 95
    if status == "REVIEW":
        return 50
    if status == "FAIL":
        return 0
    return 0


def metric_fields(
    *,
    status: str,
    file_size_bytes: int | str | None,
    recovered_output_path: str = "",
    recovered_bytes: int | str | None = None,
    recovery_rate_percent: float | str | None = None,
    phase_attempted: str = "",
    confidence_score: int | str | None = None,
    magic_rule_id: str = "",
    keystream_offset_start: int | str | None = "",
    keystream_offset_end: int | str | None = "",
    is_truncated: bool | str | None = None,
) -> dict[str, str]:
    """Build normalized manifest metric fields.

    Values are stored as strings to keep CSV migration predictable.
    """
    size = _to_int(file_size_bytes, 0)
    status_upper = (status or "").upper()

    if recovered_bytes in (None, ""):
        recovered = ""
        if recovered_output_path:
            try:
                recovered = str(Path(recovered_output_path).stat().st_size)
            except OSError:
                recovered = ""
        if recovered == "" and status_upper == "FAIL":
            recovered = "0"
    else:
        recovered = str(max(0, _to_int(recovered_bytes, 0)))

    if recovery_rate_percent in (None, ""):
        if recovered != "" and size > 0:
            rate = _format_percent((_to_int(recovered) / size) * 100.0)
        elif status_upper == "FAIL":
            rate = "0.00"
        else:
            rate = ""
    else:
        rate = _format_percent(_to_float(recovery_rate_percent))

    if confidence_score in (None, ""):
        confidence = str(default_confidence(status_upper))
    else:
        confidence = str(max(0, min(100, _to_int(confidence_score))))

    if is_truncated is None:
        if recovered != "" and size > 0:
            truncated = "true" if _to_int(recovered) < size else "false"
        else:
            truncated = ""
    elif isinstance(is_truncated, bool):
        truncated = "true" if is_truncated else "false"
    else:
        truncated = str(is_truncated).lower()

    return {
        "recovered_bytes": recovered,
        "recovery_rate_percent": rate,
        "phase_attempted": str(phase_attempted or ""),
        "confidence_score": confidence,
        "magic_rule_id": str(magic_rule_id or ""),
        "keystream_offset_start": "" if keystream_offset_start is None else str(keystream_offset_start),
        "keystream_offset_end": "" if keystream_offset_end is None else str(keystream_offset_end),
        "is_truncated": truncated,
    }


def _empty_phase_metrics() -> dict[str, Any]:
    return {
        "files_total": 0,
        "files_ok": 0,
        "files_review": 0,
        "files_fail": 0,
        "bytes_total": 0,
        "bytes_recovered": 0,
        "recovery_rate_percent": 0.0,
        "files_fully_recovered_percent": 0.0,
        "avg_confidence_score": 0.0,
    }


def aggregate_manifest_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = _empty_phase_metrics()
    by_phase: dict[str, dict[str, Any]] = {}
    confidence_sum = 0.0
    confidence_count = 0
    fully_recovered = 0
    sized_files = 0

    for row in rows:
        status = (row.get("status") or "UNKNOWN").upper()
        phase = (row.get("phase_attempted") or "unknown").strip() or "unknown"
        phase_metrics = by_phase.setdefault(phase, _empty_phase_metrics())

        size = _to_int(row.get("file_size_bytes"), 0)
        recovered = _to_int(row.get("recovered_bytes"), 0)
        confidence_raw = row.get("confidence_score")

        for target in (metrics, phase_metrics):
            target["files_total"] += 1
            target["bytes_total"] += size
            target["bytes_recovered"] += recovered
            if status == "OK":
                target["files_ok"] += 1
            elif status == "REVIEW":
                target["files_review"] += 1
            elif status == "FAIL":
                target["files_fail"] += 1

        if size > 0:
            sized_files += 1
            if recovered >= size:
                fully_recovered += 1
        if confidence_raw not in (None, ""):
            confidence_sum += _to_float(confidence_raw)
            confidence_count += 1

    def finalize(target: dict[str, Any]) -> None:
        bytes_total = target["bytes_total"]
        if bytes_total > 0:
            target["recovery_rate_percent"] = round((target["bytes_recovered"] / bytes_total) * 100.0, 2)
        if target["files_total"] > 0:
            phase_rows = [r for r in rows if (r.get("phase_attempted") or "unknown" or "unknown") == target.get("_phase")]
            target.pop("_phase", None)
            if phase_rows:
                phase_sized = [r for r in phase_rows if _to_int(r.get("file_size_bytes"), 0) > 0]
                phase_full = [
                    r for r in phase_sized
                    if _to_int(r.get("recovered_bytes"), 0) >= _to_int(r.get("file_size_bytes"), 0)
                ]
                target["files_fully_recovered_percent"] = round((len(phase_full) / len(phase_sized)) * 100.0, 2) if phase_sized else 0.0
                phase_conf = [_to_float(r.get("confidence_score")) for r in phase_rows if r.get("confidence_score") not in (None, "")]
                target["avg_confidence_score"] = round(sum(phase_conf) / len(phase_conf), 2) if phase_conf else 0.0

    for phase, phase_metrics in by_phase.items():
        phase_metrics["_phase"] = phase
        finalize(phase_metrics)

    if metrics["bytes_total"] > 0:
        metrics["recovery_rate_percent"] = round((metrics["bytes_recovered"] / metrics["bytes_total"]) * 100.0, 2)
    metrics["files_fully_recovered_percent"] = round((fully_recovered / sized_files) * 100.0, 2) if sized_files else 0.0
    metrics["avg_confidence_score"] = round(confidence_sum / confidence_count, 2) if confidence_count else 0.0
    metrics["by_phase"] = by_phase
    return metrics
