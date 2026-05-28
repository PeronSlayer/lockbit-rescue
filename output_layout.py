#!/usr/bin/env python3
"""Output naming/layout helpers shared by Phase 1 and Phase 2."""

from __future__ import annotations

from pathlib import Path
import hashlib


_MAGIC_TO_EXT = {
    "pdf document": ".pdf",
    "png image data": ".png",
    "jpeg image data": ".jpg",
    "gif image data": ".gif",
    "zip archive data": ".zip",
    "rar archive data": ".rar",
    "7-zip archive data": ".7z",
    "microsoft excel": ".xls",
    "microsoft word": ".doc",
    "microsoft powerpoint": ".ppt",
    "rich text format": ".rtf",
    "html document": ".html",
    "xml": ".xml",
    "json": ".json",
    "sqlite 3.x database": ".sqlite",
    "mp3": ".mp3",
    "wave audio": ".wav",
    "matroska": ".mkv",
    "iso media": ".mp4",
}


def compute_output_relative(
    encrypted_source_path: str,
    source_root: Path | None,
    ransom_ext: str,
    fallback_name: str,
) -> Path:
    """Build a safe relative output path preserving source tree when possible."""
    if source_root is None:
        return Path(fallback_name)

    try:
        src_abs = Path(encrypted_source_path).resolve()
        rel = src_abs.relative_to(source_root.resolve())
    except Exception:
        return Path(fallback_name)

    rel_parent = rel.parent
    rel_name = rel.name
    if ransom_ext and rel_name.endswith(ransom_ext):
        rel_name = rel_name[: -len(ransom_ext)]
    if not rel_name:
        rel_name = fallback_name

    # Keep output path safely under the group directory.
    safe_parts = [p for p in rel_parent.parts if p not in ("", ".", "..")]
    return Path(*safe_parts) / rel_name if safe_parts else Path(rel_name)


def guess_extension_from_magic(file_type_magic: str) -> str:
    text = (file_type_magic or "").strip().lower()
    if not text:
        return ""
    for needle, ext in _MAGIC_TO_EXT.items():
        if needle in text:
            return ext
    return ""


def maybe_predict_name(path: Path, file_type_magic: str, enabled: bool) -> Path:
    """Append guessed extension when file has no extension and prediction is enabled."""
    if not enabled:
        return path
    if path.suffix:
        return path

    ext = guess_extension_from_magic(file_type_magic)
    if not ext:
        return path

    candidate = path.with_name(path.name + ext)
    if candidate.exists():
        idx = 1
        while True:
            alt = path.with_name(f"{path.name}_{idx}{ext}")
            if not alt.exists():
                return alt
            idx += 1
    return candidate


def collision_safe_path(path: Path, encrypted_source_path: str) -> Path:
    """Return a deterministic non-conflicting path for basename collisions."""
    if not path.exists():
        return path

    digest = hashlib.sha1(str(encrypted_source_path).encode("utf-8", errors="ignore")).hexdigest()[:8]
    stem = path.stem or path.name
    suffix = path.suffix
    candidate = path.with_name(f"{stem}__{digest}{suffix}")
    if not candidate.exists():
        return candidate

    idx = 2
    while True:
        alt = path.with_name(f"{stem}__{digest}_{idx}{suffix}")
        if not alt.exists():
            return alt
        idx += 1
