#!/usr/bin/env python3
"""Shared Phase 2 pipeline (keystream extension + direct decrypt)."""

from __future__ import annotations

import collections
import concurrent.futures
import hashlib
import os
import shutil
import struct
import subprocess
from pathlib import Path

from keystream_cache import (
    DEFAULT_AFTER_CHUNK_COUNT,
    DEFAULT_BEFORE_CHUNK_COUNT,
    DEFAULT_SKIPPED_BYTES,
    extract_chunking_params,
    extract_keystream,
    load_keystream,
    save_keystream,
)
from output_layout import collision_safe_path, compute_output_relative, maybe_predict_name

MAGIC_DB = {
    "jpg": ["ffd8ffe000104a464946", "ffd8ffe100", "ffd8ffdb", "ffd8ffe2", "ffd8ffe800"],
    "jpeg": ["ffd8ffe000104a464946", "ffd8ffe100", "ffd8ffdb"],
    "png": ["89504e470d0a1a0a"],
    "gif": ["474946383961", "474946383761"],
    "bmp": ["424d", None],
    "tif": ["49492a00", "4d4d002a"],
    "tiff": ["49492a00", "4d4d002a"],
    "webp": ["52494646", None],
    "pdf": ["25504446 2d 31 2e"],
    "doc": ["d0cf11e0a1b11ae1"],
    "xls": ["d0cf11e0a1b11ae1"],
    "ppt": ["d0cf11e0a1b11ae1"],
    "msi": ["d0cf11e0a1b11ae1"],
    "msg": ["d0cf11e0a1b11ae1"],
    "docx": ["504b0304140006"],
    "xlsx": ["504b0304140006"],
    "pptx": ["504b0304140006"],
    "odt": ["504b0304"],
    "ods": ["504b0304"],
    "odp": ["504b0304"],
    "rtf": ["7b5c727466 31"],
    "txt": None,
    "zip": ["504b0304", "504b0506"],
    "rar": ["526172211a07"],
    "7z": ["377abcaf271c"],
    "gz": ["1f8b08"],
    "bz2": ["425a68"],
    "xz": ["fd377a585a 00"],
    "mp4": ["00000018 66747970", "00000020 66747970"],
    "mov": ["00000014 66747970", "00000020 66747970"],
    "m4v": ["00000020 66747970"],
    "mkv": ["1a45dfa3"],
    "webm": ["1a45dfa3"],
    "avi": ["52494646", None],
    "mp3": ["49443304", "fffb"],
    "wav": ["52494646"],
    "flac": ["664c6143"],
    "ogg": ["4f676753"],
    "m4a": ["00000020 66747970 4d3441"],
    "psd": ["38425053"],
    "ai": ["25504446 2d 31"],
    "html": ["3c21444f43545950 45", "3c68746d 6c", "3c4854 4d4c"],
    "htm": ["3c21444f43545950 45", "3c68746d 6c"],
    "xml": ["3c3f786d6c"],
    "json": None,
    "epub": ["504b0304"],
    "db": ["53514c69746520666f726d6174"],
    "sqlite": ["53514c69746520666f726d6174"],
}


def hex_clean(h: str) -> str:
    return h.replace(" ", "").replace(":", "").lower()


def kek_fingerprint(blob: bytes) -> str:
    return hashlib.md5(blob).hexdigest()[:12]


def read_footer_meta(path: Path):
    with open(path, "rb") as f:
        f.seek(-134, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-128, 2)
        kek = f.read(128)
    return fei_len, kek_fingerprint(kek)


def detect_extension(source: Path, sample_limit: int = 5000) -> str:
    counts = collections.Counter()
    seen = 0
    for dirpath, _, files in os.walk(source):
        for fn in files:
            if "." not in fn:
                continue
            ext = "." + fn.rsplit(".", 1)[-1]
            if len(ext) == 10 and ext[1:].isalnum() and not ext[1:].isdigit():
                counts[ext] += 1
                seen += 1
                if seen >= sample_limit:
                    break
        if seen >= sample_limit:
            break
    return counts.most_common(1)[0][0] if counts else ""


def scan_batches(source: Path, ransom_ext: str):
    groups = collections.defaultdict(list)
    scanned = 0
    for dirpath, _, files in os.walk(source):
        if "RECOVERED" in dirpath:
            continue
        for fn in files:
            if not fn.endswith(ransom_ext):
                continue
            scanned += 1
            p = Path(dirpath) / fn
            try:
                fei_len, kek = read_footer_meta(p)
                sz = os.path.getsize(p)
                groups[kek].append((fei_len, fn, str(p), sz))
            except (OSError, struct.error):
                continue
    return groups, scanned


def file_ext(fname: str, ransom_ext: str) -> str:
    base = fname[: -len(ransom_ext)]
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[-1].lower()


def original_extension(base_name: str) -> str:
    if "." not in base_name:
        return ""
    return base_name.rsplit(".", 1)[-1].lower()


def parse_brute(stdout: str):
    out = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def libmagic(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["file", "-b", str(path)], stderr=subprocess.DEVNULL, timeout=10
        ).decode(errors="ignore").strip()
    except Exception:
        return "unknown"


def is_bad(ftype: str) -> bool:
    f = (ftype or "").lower()
    return f.startswith("data") or "corrupted" in f or f in ("", "empty")


def _derive_chunking_params(oracle_path: str, ks_bytes: bytes, ks_meta: dict,
                            before_chunk: int | None,
                            after_chunk: int | None,
                            skipped_hex: str | None):
    skipped = None
    if skipped_hex:
        skipped = int(str(skipped_hex), 0)

    if before_chunk is not None and after_chunk is not None and skipped is not None:
        return before_chunk, after_chunk, skipped

    auto_before = auto_after = auto_skipped = None
    try:
        params = extract_chunking_params(Path(oracle_path), ks_bytes, ks_meta.get("known_len"))
        auto_before = params["before_chunk_count"]
        auto_after = params["after_chunk_count"]
        auto_skipped = params["skipped_bytes"]
    except Exception:
        defaults = ks_meta.get("defaults", {}) if isinstance(ks_meta, dict) else {}
        auto_before = int(defaults.get("before_chunk_count", DEFAULT_BEFORE_CHUNK_COUNT))
        auto_after = int(defaults.get("after_chunk_count", DEFAULT_AFTER_CHUNK_COUNT))
        auto_skipped = int(defaults.get("skipped_bytes", DEFAULT_SKIPPED_BYTES))

    final_before = auto_before if before_chunk is None else before_chunk
    final_after = auto_after if after_chunk is None else after_chunk
    final_skipped = auto_skipped if skipped is None else skipped
    return final_before, final_after, final_skipped


def _fuse_oracle_keystreams(files, ransom_ext: str, max_sources: int = 16):
    sources = []
    for fei_len, fname, path, _sz in sorted(files, key=lambda x: -x[0])[:max_sources]:
        orig = fname[: -len(ransom_ext)]
        try:
            ks, meta = extract_keystream(Path(path), orig)
        except Exception:
            continue
        if not ks:
            continue
        sources.append({
            "ks": ks,
            "meta": meta,
            "oracle_name": orig,
            "oracle_path": str(path),
        })

    if not sources:
        return None

    max_len = max(len(s["ks"]) for s in sources)
    votes = [collections.Counter() for _ in range(max_len)]
    for src in sources:
        for i, b in enumerate(src["ks"]):
            votes[i][b] += 1

    fused = bytearray()
    for i in range(max_len):
        if not votes[i]:
            break
        fused.append(votes[i].most_common(1)[0][0])

    primary = max(sources, key=lambda x: len(x["ks"]))
    fused_meta = {
        "oracle_name": primary["oracle_name"],
        "oracle_path": primary["oracle_path"],
        "known_len": int(primary["meta"].get("known_len", len(primary["ks"]))),
        "oracle_fei_len": int(primary["meta"].get("oracle_fei_len", 0)),
        "source_count": len(sources),
        "source": "multi_oracle_fusion",
    }
    return bytes(fused), fused_meta


def process_batch(
    kek,
    files,
    output_root: Path,
    scratch_root: Path,
    brute_bin: Path,
    direct_bin: Path,
    ransom_ext: str,
    max_brute_bytes: int,
    before_chunk: int | None,
    after_chunk: int | None,
    skipped_hex: str | None,
    brute_timeout: int,
    brute_retry_timeout: int,
    manifest,
    brute_threads: int = 1,
    enable_fusion: bool = True,
    source_root: Path | None = None,
    restore_tree: bool = False,
    predict_names: bool = False,
    aggressive: bool = False,
):
    if manifest and hasattr(manifest, "default_phase"):
        manifest.default_phase = "phase2"

    files = list(files)
    files.sort(key=lambda x: x[0])
    oracle_fei, oracle_fname, oracle_path, _oracle_sz = files[-1]
    oracle_orig = oracle_fname[: -len(ransom_ext)]

    group_out = output_root / f"group_{kek}"
    group_out.mkdir(parents=True, exist_ok=True)
    review_dir = group_out / "_needs_review"
    review_dir.mkdir(exist_ok=True)

    ks_loaded = load_keystream(group_out)
    ks_bytes = b""
    ks_meta = {}
    if ks_loaded:
        ks_bytes, ks_meta = ks_loaded

    if not ks_bytes:
        try:
            base_ks, base_meta = extract_keystream(Path(oracle_path), oracle_orig)
            ks_bytes = base_ks
            ks_meta = {
                "oracle_name": oracle_orig,
                "oracle_path": str(oracle_path),
                "known_len": int(base_meta.get("known_len", len(base_ks))),
                "oracle_fei_len": int(base_meta.get("oracle_fei_len", oracle_fei)),
                "source": "phase2_bootstrap",
            }
            save_keystream(group_out, ks_bytes, ks_meta)
        except Exception:
            pass

    if enable_fusion:
        fused = _fuse_oracle_keystreams(files, ransom_ext)
        if fused:
            fused_bytes, fused_meta = fused
            if len(fused_bytes) > len(ks_bytes):
                ks_bytes = fused_bytes
                ks_meta = fused_meta
                save_keystream(group_out, ks_bytes, ks_meta)

    if ks_bytes:
        oracle_path = ks_meta.get("oracle_path", oracle_path)
        oracle_orig = ks_meta.get("oracle_name", oracle_orig)

    known_len = int(ks_meta.get("known_len", min(106, len(ks_bytes)))) if ks_bytes else 0
    known_len = max(0, min(known_len, len(ks_bytes)))
    ks_extend_hex = ks_bytes[known_len:].hex() if len(ks_bytes) > known_len else ""
    ks_cache_blob = bytearray(ks_bytes) if ks_bytes else None

    before_count, after_count, skipped_bytes = _derive_chunking_params(
        oracle_path, ks_bytes, ks_meta, before_chunk, after_chunk, skipped_hex
    )
    skipped_hex_final = hex(skipped_bytes)

    scratch = scratch_root / f"batch_{kek}"
    scratch.mkdir(parents=True, exist_ok=True)

    ok = review = fail = skipped = 0
    frozen = False

    targets = [t for t in files if not (t[1] == oracle_fname and t[2] == oracle_path)]
    targets.sort(key=lambda x: x[0])

    for fei_len, fname, path, sz in targets:
        orig = fname[: -len(ransom_ext)]
        if manifest and manifest.has_source_status(path):
            ok += 1
            continue
        rel_out = compute_output_relative(path, source_root if restore_tree else None, ransom_ext, orig)
        out_path = group_out / rel_out
        out_path = collision_safe_path(out_path, path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if out_path.exists():
            ok += 1
            continue

        ext = file_ext(fname, ransom_ext)
        magics = MAGIC_DB.get(ext)
        if magics is None:
            if aggressive:
                magics = [
                    "25504446",      # PDF
                    "89504e470d0a1a0a",  # PNG
                    "ffd8ff",        # JPEG family
                    "504b0304",      # ZIP/OOXML
                    "d0cf11e0a1b11ae1",  # OLE2
                    "47494638",      # GIF
                ]
            else:
                skipped += 1
                if manifest:
                    manifest.add(kek, orig, original_extension(orig), path, "", "FAIL",
                                 "NO_MAGIC_RULE", sz, fei_len)
                continue

        result = None
        timed_out = False
        for m in magics:
            if m is None:
                continue
            mhex = hex_clean(m)
            cmd = [
                str(brute_bin), str(path), str(oracle_path), oracle_orig,
                mhex, str(max_brute_bytes), str(before_count), str(after_count),
                skipped_hex_final, ks_extend_hex,
            ]
            env = dict(os.environ)
            env["BRUTE_THREADS"] = str(max(1, int(brute_threads)))
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=brute_timeout, text=True, env=env)
            except subprocess.TimeoutExpired:
                try:
                    p = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=brute_retry_timeout,
                        text=True,
                        env=env,
                    )
                except subprocess.TimeoutExpired:
                    timed_out = True
                    continue

            parsed = parse_brute(p.stdout)
            status = parsed.get("STATUS", "")
            if status in ("OK_BRUTE", "OK_NOBRUTE"):
                result = parsed
                break
            if status == "GAP_TOO_BIG":
                break

        if timed_out and result is None:
            fail += 1
            frozen = True
            if manifest:
                manifest.add(kek, orig, original_extension(orig), path, "", "FAIL",
                             "BRUTE_TIMEOUT", sz, fei_len)
            break

        if not result:
            fail += 1
            if manifest:
                manifest.add(kek, orig, original_extension(orig), path, "", "FAIL",
                             "NO_BRUTE_MATCH", sz, fei_len)
            continue

        fek_hex = result["FEK"]
        new_ks_ext = result.get("KSEXT", "")
        if new_ks_ext:
            ks_extend_hex = (ks_extend_hex + new_ks_ext).lower()
            if ks_cache_blob is not None:
                try:
                    ks_cache_blob.extend(bytes.fromhex(new_ks_ext))
                    save_keystream(group_out, bytes(ks_cache_blob), {
                        "oracle_name": oracle_orig,
                        "oracle_path": str(oracle_path),
                        "known_len": known_len,
                        "before_chunk_count": before_count,
                        "after_chunk_count": after_count,
                        "skipped_bytes": skipped_bytes,
                        "source": "phase2_extend",
                    })
                except Exception:
                    pass

        try:
            subprocess.run(
                [
                    str(direct_bin), str(path), str(out_path), fek_hex,
                    str(before_count), str(after_count), skipped_hex_final,
                ],
                capture_output=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            fail += 1
            if manifest:
                manifest.add(kek, orig, original_extension(orig), path, "", "FAIL",
                             "DIRECT_DECRYPT_TIMEOUT", sz, fei_len)
            continue

        if not out_path.exists() or out_path.stat().st_size == 0:
            fail += 1
            if manifest:
                manifest.add(kek, orig, original_extension(orig), path, "", "FAIL",
                             "EMPTY_OUTPUT", sz, fei_len)
            continue

        ft = libmagic(out_path)
        if is_bad(ft):
            review_path = review_dir / rel_out
            review_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(out_path), str(review_path))
                review += 1
                if manifest:
                    manifest.add(kek, orig, original_extension(orig), path, str(review_path),
                                 "REVIEW", ft, sz, fei_len)
            except Exception:
                fail += 1
                if manifest:
                    manifest.add(kek, orig, original_extension(orig), path, "", "FAIL",
                                 ft, sz, fei_len)
        else:
            final_out = maybe_predict_name(out_path, ft, predict_names)
            if final_out != out_path:
                final_out.parent.mkdir(parents=True, exist_ok=True)
                out_path.rename(final_out)
                out_path = final_out
            ok += 1
            if manifest:
                manifest.add(kek, orig, original_extension(orig), path, str(out_path),
                             "OK", ft, sz, fei_len)

    try:
        shutil.rmtree(scratch)
    except Exception:
        pass

    return {
        "ok": ok,
        "review": review,
        "fail": fail,
        "skipped": skipped,
        "frozen": frozen,
        "chunking": {
            "before": before_count,
            "after": after_count,
            "skipped": skipped_bytes,
        },
    }


def run_phase2_batches(
    work_batches,
    output: Path,
    scratch: Path,
    brute_bin: Path,
    direct_bin: Path,
    ransom_ext: str,
    max_brute_bytes: int,
    before_chunk: int | None,
    after_chunk: int | None,
    skipped_hex: str | None,
    brute_timeout: int,
    brute_retry_timeout: int,
    manifest,
    jobs: int = 1,
    brute_threads: int = 1,
    enable_fusion: bool = True,
    source_root: Path | None = None,
    restore_tree: bool = False,
    predict_names: bool = False,
    aggressive: bool = False,
    min_oracle_fei_len: int = 90,
):
    totals = {"ok": 0, "review": 0, "fail": 0, "skipped": 0, "frozen": 0, "batches": []}
    filtered = []
    for kek, files in work_batches:
        oracle = max(files, key=lambda x: x[0])
        if oracle[0] >= int(min_oracle_fei_len):
            filtered.append((kek, files))

    if jobs <= 1:
        for bi, (kek, files) in enumerate(filtered):
            print(f"\n=== PHASE2 BATCH {bi+1}/{len(filtered)} {kek} ===")
            stats = process_batch(
                kek,
                files,
                output,
                scratch,
                brute_bin,
                direct_bin,
                ransom_ext,
                max_brute_bytes,
                before_chunk,
                after_chunk,
                skipped_hex,
                brute_timeout,
                brute_retry_timeout,
                manifest,
                brute_threads=brute_threads,
                enable_fusion=enable_fusion,
                source_root=source_root,
                restore_tree=restore_tree,
                predict_names=predict_names,
                aggressive=aggressive,
            )
            totals["ok"] += stats["ok"]
            totals["review"] += stats["review"]
            totals["fail"] += stats["fail"]
            totals["skipped"] += stats["skipped"]
            totals["frozen"] += 1 if stats.get("frozen") else 0
            totals["batches"].append({
                "kek": kek,
                "ok": stats.get("ok", 0),
                "review": stats.get("review", 0),
                "fail": stats.get("fail", 0),
                "skipped": stats.get("skipped", 0),
                "frozen": bool(stats.get("frozen", False)),
                "chunking": stats.get("chunking", {}),
            })
            print(
                f"[phase2 running] ok={totals['ok']} review={totals['review']} "
                f"fail={totals['fail']} skipped={totals['skipped']} frozen={totals['frozen']}"
            )
        return totals

    print(f"[*] Phase 2 parallel mode: {len(filtered)} batches, jobs={jobs}")
    with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = {}
        for kek, files in filtered:
            futures[pool.submit(
                _process_batch_worker,
                {
                    "kek": kek,
                    "files": files,
                    "output": str(output),
                    "scratch": str(scratch),
                    "brute_bin": str(brute_bin),
                    "direct_bin": str(direct_bin),
                    "ransom_ext": ransom_ext,
                    "max_brute_bytes": max_brute_bytes,
                    "before_chunk": before_chunk,
                    "after_chunk": after_chunk,
                    "skipped_hex": skipped_hex,
                    "brute_timeout": brute_timeout,
                    "brute_retry_timeout": brute_retry_timeout,
                    "enable_fusion": enable_fusion,
                    "brute_threads": brute_threads,
                    "source_root": str(source_root) if source_root else "",
                    "restore_tree": restore_tree,
                    "predict_names": predict_names,
                    "aggressive": aggressive,
                },
            )] = kek

        for fut in concurrent.futures.as_completed(futures):
            kek = futures[fut]
            try:
                stats = fut.result()
            except Exception:
                totals["fail"] += 1
                totals["frozen"] += 1
                totals["batches"].append({
                    "kek": kek,
                    "ok": 0,
                    "review": 0,
                    "fail": 1,
                    "skipped": 0,
                    "frozen": True,
                    "worker_error": True,
                })
                print(f"[phase2 running] batch {kek} failed in worker")
                continue
            totals["ok"] += stats.get("ok", 0)
            totals["review"] += stats.get("review", 0)
            totals["fail"] += stats.get("fail", 0)
            totals["skipped"] += stats.get("skipped", 0)
            totals["frozen"] += 1 if stats.get("frozen") else 0
            totals["batches"].append({
                "kek": kek,
                "ok": stats.get("ok", 0),
                "review": stats.get("review", 0),
                "fail": stats.get("fail", 0),
                "skipped": stats.get("skipped", 0),
                "frozen": bool(stats.get("frozen", False)),
                "chunking": stats.get("chunking", {}),
            })
            print(
                f"[phase2 running] ok={totals['ok']} review={totals['review']} "
                f"fail={totals['fail']} skipped={totals['skipped']} frozen={totals['frozen']}"
            )
    return totals


def _process_batch_worker(payload: dict):
    from manifest import Manifest

    output = Path(payload["output"])
    scratch = Path(payload["scratch"])
    manifest = Manifest(output, default_phase="phase2")
    return process_batch(
        payload["kek"],
        payload["files"],
        output,
        scratch,
        Path(payload["brute_bin"]),
        Path(payload["direct_bin"]),
        payload["ransom_ext"],
        int(payload["max_brute_bytes"]),
        payload["before_chunk"],
        payload["after_chunk"],
        payload["skipped_hex"],
        int(payload["brute_timeout"]),
        int(payload["brute_retry_timeout"]),
        manifest,
        brute_threads=int(payload.get("brute_threads", 1)),
        enable_fusion=bool(payload.get("enable_fusion", True)),
        source_root=Path(payload["source_root"]) if payload.get("source_root") else None,
        restore_tree=bool(payload.get("restore_tree", False)),
        predict_names=bool(payload.get("predict_names", False)),
        aggressive=bool(payload.get("aggressive", False)),
    )
