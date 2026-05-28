#!/usr/bin/env python3
"""Manifest CSV writer for recovery runs."""

from __future__ import annotations

import csv
import fcntl
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class Manifest:
    HEADERS = [
        "group_kek",
        "original_basename",
        "original_extension",
        "encrypted_source_path",
        "recovered_output_path",
        "status",
        "file_type_magic",
        "file_size_bytes",
        "fei_len",
        "timestamp",
    ]

    def __init__(self, output_dir: Path):
        self.path = Path(output_dir) / "manifest.csv"
        self._seen = set()
        self._lock = Lock()
        self._load_existing()

    def _load_existing(self):
        if not self.path.exists():
            return
        with self.path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = (row.get("encrypted_source_path") or "").strip()
                status = (row.get("status") or "").strip()
                dst = (row.get("recovered_output_path") or "").strip()
                if src:
                    self._seen.add((src, status, dst))

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
            "file_size_bytes": int(file_size_bytes),
            "fei_len": int(fei_len),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
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
            return True
