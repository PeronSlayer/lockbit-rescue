#!/usr/bin/env python3
"""Benchmark helper utilities for scanner profiling."""

from __future__ import annotations

import collections
import os
import struct
from pathlib import Path

FOOTER_TOTAL = 134
KEK_LEN = 128

DEFAULT_COMMON_EXTS = {
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
    "pdf", "doc", "docx", "odt", "rtf", "txt", "md",
    "xls", "xlsx", "ods", "csv", "ppt", "pptx", "odp",
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
}


def read_footer(path: Path):
    with path.open("rb") as f:
        f.seek(-FOOTER_TOTAL, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-KEK_LEN, 2)
        kek_blob = f.read(KEK_LEN)
    return fei_len, kek_blob


def kek_fingerprint(kek_blob: bytes) -> str:
    return kek_blob[:6].hex()


def is_target(fname: str, ransom_ext: str) -> bool:
    if not fname.endswith(ransom_ext):
        return False
    base = fname[: -len(ransom_ext)]
    if "." not in base:
        return False
    ext = base.rsplit(".", 1)[1].lower()
    return ext in DEFAULT_COMMON_EXTS


def run_scan(source: Path, ransom_ext: str, min_size: int, max_size: int) -> dict:
    groups = collections.defaultdict(int)
    scanned = matched = 0

    for dirpath, _dirnames, files in os.walk(source):
        for fname in files:
            if not fname.endswith(ransom_ext):
                continue
            scanned += 1
            fpath = Path(dirpath) / fname
            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            if size < min_size or size > max_size:
                continue
            if is_target(fname, ransom_ext):
                matched += 1
            try:
                _fei_len, kek_blob = read_footer(fpath)
            except (OSError, struct.error):
                continue
            groups[kek_fingerprint(kek_blob)] += 1

    return {
        "scanned": scanned,
        "matched": matched,
        "groups": len(groups),
    }
