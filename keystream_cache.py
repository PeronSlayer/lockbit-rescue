#!/usr/bin/env python3
"""Keystream cache helpers for LockBit recovery tools."""

from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path

FOOTER_TOTAL = 134
DEFAULT_SKIPPED_BYTES = 0x520000
DEFAULT_BEFORE_CHUNK_COUNT = 3
DEFAULT_AFTER_CHUNK_COUNT = 3


def _compress_filename_utf16le_aplib(name: str) -> bytes:
    raw = name.encode("utf-16le") + b"\x00\x00"
    try:
        import aplib  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "Python package 'aplib' is required for keystream extraction. "
            "Install it with: pip install aplib"
        ) from e

    if hasattr(aplib, "compress"):
        return bytes(aplib.compress(raw))
    if hasattr(aplib, "Compressor"):
        return bytes(aplib.Compressor().compress(raw))
    raise RuntimeError("Unsupported aplib module API; expected compress() or Compressor().compress()")


def _build_known_plaintext(compressed_name: bytes) -> bytes:
    sz = len(compressed_name)
    trailer = bytearray(18)
    trailer[0:2] = struct.pack("<H", sz)
    trailer[2:10] = struct.pack("<Q", DEFAULT_SKIPPED_BYTES)
    trailer[10:14] = struct.pack("<I", DEFAULT_BEFORE_CHUNK_COUNT)
    trailer[14:18] = struct.pack("<I", DEFAULT_AFTER_CHUNK_COUNT)
    return compressed_name + bytes(trailer)


def extract_keystream(oracle_path: Path, oracle_orig_name: str):
    """Extract oracle keystream bytes with known-plaintext XOR.

    Returns:
        tuple(bytes_keystream, meta_dict)
    """
    oracle_path = Path(oracle_path)
    compressed = _compress_filename_utf16le_aplib(oracle_orig_name)
    known_plain = _build_known_plaintext(compressed)

    with oracle_path.open("rb") as f:
        f.seek(-FOOTER_TOTAL, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-(FOOTER_TOTAL + fei_len), 2)
        fei_cipher = f.read(fei_len)

    known_len = len(known_plain)
    if known_len > fei_len:
        raise ValueError(f"oracle FEI too short for known plaintext: known_len={known_len}, fei_len={fei_len}")

    ks = bytes(c ^ p for c, p in zip(fei_cipher[:known_len], known_plain))
    meta = {
        "length": len(ks),
        "known_len": known_len,
        "oracle_fei_len": fei_len,
        "defaults": {
            "skipped_bytes": DEFAULT_SKIPPED_BYTES,
            "before_chunk_count": DEFAULT_BEFORE_CHUNK_COUNT,
            "after_chunk_count": DEFAULT_AFTER_CHUNK_COUNT,
        },
    }
    return ks, meta


def decrypt_fei_prefix(oracle_path: Path, ks_bytes: bytes) -> bytes:
    """Decrypt FEI prefix using available keystream bytes."""
    oracle_path = Path(oracle_path)
    with oracle_path.open("rb") as f:
        f.seek(-FOOTER_TOTAL, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-(FOOTER_TOTAL + fei_len), 2)
        fei_cipher = f.read(fei_len)

    usable = min(len(ks_bytes), fei_len)
    return bytes(c ^ k for c, k in zip(fei_cipher[:usable], ks_bytes[:usable]))


def extract_chunking_params(oracle_path: Path, ks_bytes: bytes, known_len: int | None = None):
    """Extract skipped/before/after chunk params from decrypted FEI bytes."""
    plain = decrypt_fei_prefix(oracle_path, ks_bytes)
    if len(plain) < 18:
        raise ValueError("Not enough decrypted FEI bytes to extract chunking params")

    if known_len is None:
        known_len = len(plain)
    meta_start = known_len - 18
    if meta_start < 0 or (meta_start + 18) > len(plain):
        raise ValueError("Known plaintext range is not fully covered by keystream")

    filename_size = struct.unpack("<H", plain[meta_start:meta_start + 2])[0]
    skipped_bytes = struct.unpack("<Q", plain[meta_start + 2:meta_start + 10])[0]
    before_chunk_count = struct.unpack("<I", plain[meta_start + 10:meta_start + 14])[0]
    after_chunk_count = struct.unpack("<I", plain[meta_start + 14:meta_start + 18])[0]

    return {
        "filename_size": int(filename_size),
        "skipped_bytes": int(skipped_bytes),
        "before_chunk_count": int(before_chunk_count),
        "after_chunk_count": int(after_chunk_count),
    }


def save_keystream(group_dir: Path, ks_bytes: bytes, oracle_info: dict):
    group_dir = Path(group_dir)
    group_dir.mkdir(parents=True, exist_ok=True)
    ks_path = group_dir / "keystream.bin"
    meta_path = group_dir / "keystream.meta.json"

    ks_path.write_bytes(ks_bytes)

    meta = dict(oracle_info or {})
    meta["length"] = len(ks_bytes)
    meta["timestamp"] = datetime.now(timezone.utc).isoformat()
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def load_keystream(group_dir: Path):
    group_dir = Path(group_dir)
    ks_path = group_dir / "keystream.bin"
    meta_path = group_dir / "keystream.meta.json"
    if not ks_path.exists() or not meta_path.exists():
        return None

    try:
        ks = ks_path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    if not isinstance(meta, dict):
        return None
    return ks, meta
