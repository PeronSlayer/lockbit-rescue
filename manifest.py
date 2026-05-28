#!/usr/bin/env python3
"""Manifest CSV writer for recovery runs."""

from __future__ import annotations

import csv
import fcntl
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from recovery_metrics import METRIC_HEADERS, aggregate_manifest_rows, metric_fields


class Manifest:
    HEADERS = [
        "group_kek",
        "original_basename",
        "original_extension",
        "encrypted_source_path",
        "recovered_output_path",
        "status",
        "file_type_magic",
        "status_reason",
        "file_size_bytes",
        "fei_len",
        "timestamp",
    ] + METRIC_HEADERS

    def __init__(self, output_dir: Path, default_phase: str = ""):
        self.path = Path(output_dir) / "manifest.csv"
        self.default_phase = default_phase
        self._seen = set()
        self._rows = []
        self._lock = Lock()
        self._load_existing()

    def _load_existing(self):
        if not self.path.exists():
            return
        with self.path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            needs_migration = list(reader.fieldnames or []) != self.HEADERS
            for row in reader:
                normalized = {header: row.get(header, "") for header in self.HEADERS}
                self._rows.append(normalized)
                src = (row.get("encrypted_source_path") or "").strip()
                status = (row.get("status") or "").strip()
                dst = (row.get("recovered_output_path") or "").strip()
                if src:
                    self._seen.add((src, status, dst))
        if needs_migration:
            self._rewrite_rows()

    def _rewrite_rows(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.HEADERS)
            writer.writeheader()
            writer.writerows(self._rows)

    def add(
        self,
        group_kek: str,
        original_basename: str,
        original_extension: str,
        encrypted_source_path: str,
        recovered_output_path: str,
        status: str,
        file_type_magic: str,
        file_size_bytes: int,
        fei_len: int,
        status_reason: str = "",
        recovered_bytes: int | str | None = None,
        recovery_rate_percent: float | str | None = None,
        phase_attempted: str = "",
        confidence_score: int | str | None = None,
        magic_rule_id: str = "",
        keystream_offset_start: int | str | None = "",
        keystream_offset_end: int | str | None = "",
        is_truncated: bool | str | None = None,
    ) -> bool:
        src = str(encrypted_source_path)
        if not src:
            return False
        row = {
            "group_kek": str(group_kek),
            "original_basename": str(original_basename),
            "original_extension": str(original_extension),
            "encrypted_source_path": src,
            "recovered_output_path": str(recovered_output_path or ""),
            "status": str(status),
            "file_type_magic": str(file_type_magic or ""),
            "status_reason": str(status_reason or ""),
            "file_size_bytes": int(file_size_bytes),
            "fei_len": int(fei_len),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        row.update(metric_fields(
            status=status,
            file_size_bytes=file_size_bytes,
            recovered_output_path=str(recovered_output_path or ""),
            recovered_bytes=recovered_bytes,
            recovery_rate_percent=recovery_rate_percent,
            phase_attempted=phase_attempted or self.default_phase,
            confidence_score=confidence_score,
            magic_rule_id=magic_rule_id,
            keystream_offset_start=keystream_offset_start,
            keystream_offset_end=keystream_offset_end,
            is_truncated=is_truncated,
        ))
        return self._append_row(row)

    def _append_row(self, row: dict) -> bool:
        key = (
            row["encrypted_source_path"],
            row["status"],
            row["recovered_output_path"],
        )
        with self._lock:
            if key in self._seen:
                return False
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a+", newline="", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    first_write = f.read(1) == ""
                    f.seek(0, 2)
                    writer = csv.DictWriter(f, fieldnames=self.HEADERS)
                    if first_write:
                        writer.writeheader()
                    writer.writerow(row)
                    f.flush()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    self._seen.add(key)
                    self._rows.append(dict(row))
            return True

    def has_source_status(self, encrypted_source_path: str, statuses=("OK", "REVIEW")) -> bool:
        src = str(encrypted_source_path)
        wanted = set(statuses)
        with self._lock:
            return any(
                row.get("encrypted_source_path") == src and row.get("status") in wanted
                for row in self._rows
            )

    def rows(self) -> list[dict]:
        with self._lock:
            return [dict(row) for row in self._rows]

    def export_json(self, path: Path | None = None) -> Path:
        target = Path(path) if path else self.path.with_suffix(".json")
        rows = self.rows()
        totals = {}
        for row in rows:
            status = row.get("status") or "UNKNOWN"
            totals[status] = totals.get(status, 0) + 1
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "csv_path": str(self.path),
            "totals": totals,
            "metrics": aggregate_manifest_rows(rows),
            "rows": rows,
        }
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
            f.write("\n")
        return target
