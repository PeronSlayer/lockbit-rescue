#!/usr/bin/env python3
"""
lockbit-rescue.py
=================
End-to-end recovery tool for files encrypted by LockBit 3.0 ("Black") /
CriptomanGizmo, exploiting the documented keystream-reuse weakness.

Designed to be runnable by non-experts:
  python3 lockbit-rescue.py <SOURCE_DIR> <OUTPUT_DIR>

It will:
  1) Auto-detect the ransomware extension (random 9-char suffix per attack)
  2) Scan SOURCE_DIR for encrypted files
  3) Group files by their RSA-encrypted KEK fingerprint (same batch == same keystream)
  4) For each group, use the file with the longest original filename as the
     "oracle" (it provides enough known plaintext to recover the keystream)
  5) Decrypt all other files in the group whose footer-encryption-info
     length fits within the recovered keystream
  6) Save recovered files to OUTPUT_DIR/group_<kek>/<original_name>
  7) Verify each output with libmagic and skip writes for raw "data" results

Requires:
  - The `stream-reuse` binary (built from yohanes/lockbit-v3-linux-decryptor)
  - The `file` command (libmagic)
  - Python 3.8+ and `tqdm` (pip install tqdm)

Usage examples:
  # Basic
  python3 lockbit-rescue.py /mnt/infected /mnt/recovered

  # Custom extension + no extension filter + smaller min size
  python3 lockbit-rescue.py /mnt/infected /mnt/recovered \
      --ext .MoHsVxKYI --min-size 4096 --no-extension-filter

  # Specify path to stream-reuse if it's not next to this script
  python3 lockbit-rescue.py /mnt/infected /mnt/recovered \
      --stream-reuse /opt/lockbit-v3-linux-decryptor/stream-reuse
"""

import argparse
import collections
import concurrent.futures
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

from keystream_cache import extract_keystream, load_keystream, save_keystream
from manifest import Manifest
from output_layout import collision_safe_path, compute_output_relative, maybe_predict_name
from phase2 import run_phase2_batches
from report_utils import utc_now_iso, write_html_report, write_json_report
from runtime_profiles import VALID_PROFILES, resolve_recovery_profile

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: tqdm not installed. Run: pip install tqdm  (or: pip install -r requirements.txt)")
    sys.exit(1)

# ----- Defaults -----
DEFAULT_COMMON_EXTS = {
    # images
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
    "raw", "cr2", "nef", "arw", "dng",
    # documents
    "pdf", "doc", "docx", "odt", "rtf", "txt", "md",
    "xls", "xlsx", "ods", "csv", "ppt", "pptx", "odp",
    # archives
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
    # video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg",
    # audio
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma",
    # design
    "psd", "ai", "eps", "indd", "sketch", "xd",
    # data / misc
    "html", "htm", "xml", "json",
    "pst", "ost", "eml", "msg", "vcf",
    "dwg", "dxf", "stl", "obj", "3ds",
    "epub", "mobi", "azw3",
    "db", "sqlite", "mdb", "accdb",
}

# Footer layout of LockBit 3.0 ("Black") encrypted files:
#   last 134 bytes total
#   [-134:-132] 2-byte little-endian footer-encryption-info length (fei_len)
#   [-132:-128] 4-byte checksum
#   [-128:    ] 128-byte RSA-encrypted Key Encryption Key (KEK)
# All files encrypted in the same batch share the same KEK blob,
# which is the fingerprint we use to group them.
FOOTER_TOTAL = 134
KEK_LEN = 128

# The known-plaintext we can recover from the long-named "oracle" file:
#   apLib-compressed UTF-16LE original filename + 18 bytes of footer metadata
# Coverage formula derived empirically: see TECHNICAL.md.
COVERAGE_OFFSET = 18
COVERAGE_BASE_FROM_FEI = 82  # bytes consumed by fixed metadata


def detect_extension(source: Path, sample_limit: int = 5000) -> str:
    """Sample files to find the most common ransomware extension."""
    counts = collections.Counter()
    seen = 0
    for dirpath, _, files in os.walk(source):
        for fn in files:
            if "." not in fn:
                continue
            ext = "." + fn.rsplit(".", 1)[-1]
            # LockBit 3 extensions are 9 mixed-case alphanumeric chars
            if len(ext) == 10 and ext[1:].isalnum() and not ext[1:].isdigit():
                counts[ext] += 1
                seen += 1
                if seen >= sample_limit:
                    break
        if seen >= sample_limit:
            break
    if not counts:
        return ""
    ext, _ = counts.most_common(1)[0]
    return ext


def is_target(fname: str, ransom_ext: str, common_exts, no_extension_filter: bool) -> bool:
    if not fname.endswith(ransom_ext):
        return False
    base = fname[: -len(ransom_ext)]
    if "." not in base:
        # If the base has no extension at all, only accept when filter is disabled.
        return no_extension_filter
    if no_extension_filter:
        return True
    return base.rsplit(".", 1)[1].lower() in common_exts


def original_extension(base_name: str) -> str:
    if "." not in base_name:
        return ""
    return base_name.rsplit(".", 1)[-1].lower()


def fmt_size(b: int) -> str:
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}PB"


def copy_with_progress(src: Path, dst: Path, label: str, position: int = 2):
    sz = os.path.getsize(src)
    bar = tqdm(
        total=sz, desc=label, unit="B", unit_scale=True, unit_divisor=1024,
        leave=False, mininterval=0.3, position=position,
    )
    try:
        with open(src, "rb") as fi, open(dst, "wb") as fo:
            use_sendfile = hasattr(os, "sendfile")
            if use_sendfile:
                offset = 0
                while offset < sz:
                    sent = os.sendfile(fo.fileno(), fi.fileno(), offset, min(8 * 1024 * 1024, sz - offset))
                    if sent == 0:
                        break
                    offset += sent
                    bar.update(sent)
            else:
                while True:
                    buf = fi.read(1024 * 1024)
                    if not buf:
                        break
                    fo.write(buf)
                    bar.update(len(buf))
    finally:
        bar.close()


def read_footer(path: Path):
    """Return (fei_len, kek_blob) from the last 134 bytes of an encrypted file."""
    with open(path, "rb") as f:
        f.seek(-FOOTER_TOTAL, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-KEK_LEN, 2)
        kek_blob = f.read(KEK_LEN)
    return fei_len, kek_blob


def kek_fingerprint(kek_blob: bytes) -> str:
    return hashlib.md5(kek_blob).hexdigest()[:12]


def scan(source: Path, ransom_ext: str, common_exts, no_extension_filter: bool,
         min_size: int, max_size: int):
    """Walk source, group encrypted files by KEK fingerprint."""
    groups = collections.defaultdict(list)
    scanned = matched = skipped_too_small = skipped_too_big = skipped_extension = 0
    bar = tqdm(desc="Scanning", unit="file", mininterval=0.5)
    for dirpath, _, files in os.walk(source):
        for fname in files:
            if not fname.endswith(ransom_ext):
                continue
            scanned += 1
            bar.update(1)
            fpath = Path(dirpath) / fname
            try:
                sz = os.path.getsize(fpath)
            except OSError:
                continue
            if sz < min_size:
                skipped_too_small += 1
                continue
            if sz > max_size:
                skipped_too_big += 1
                continue
            ext_ok = is_target(fname, ransom_ext, common_exts, no_extension_filter)
            if ext_ok:
                matched += 1
            else:
                skipped_extension += 1
            try:
                fei_len, kek_blob = read_footer(fpath)
            except (OSError, struct.error):
                continue
            groups[kek_fingerprint(kek_blob)].append((fei_len, fname, str(fpath), sz, ext_ok))
            bar.set_postfix({"match": matched, "grp": len(groups), "small": skipped_too_small, "big": skipped_too_big})
    bar.close()
    return groups, scanned, matched, skipped_too_small, skipped_too_big, skipped_extension


def build_plan(groups, ransom_ext: str, use_all_extensions: bool = False, only_keks=None):
    """Choose an oracle for each group and list decryptable targets."""
    selected_keks = set(only_keks) if only_keks is not None else None
    plans = []
    for kek, members in groups.items():
        if selected_keks is not None and kek not in selected_keks:
            continue
        if use_all_extensions:
            candidates = list(members)
        else:
            candidates = [m for m in members if m[4]]
        if not candidates:
            continue
        # Oracle = the file in this batch with the largest fei_len
        candidates.sort(key=lambda x: -x[0])
        oracle = candidates[0]
        coverage = (oracle[0] - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET
        targets = [m for m in candidates if m[0] <= coverage and m != oracle]
        if targets:
            plans.append((len(targets), kek, oracle, targets))
    plans.sort(key=lambda x: -x[0])
    return plans


def summarize_plan(groups, plans, ransom_ext: str):
    plan_by_kek = {kek: (oracle, targets) for _count, kek, oracle, targets in plans}
    rows = []
    for kek, members in sorted(groups.items()):
        oracle_targets = plan_by_kek.get(kek)
        if oracle_targets:
            oracle, targets = oracle_targets
            coverage = (oracle[0] - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET
            phase2_candidates = sum(1 for m in members if m != oracle and m[0] > coverage)
            status = "phase1" if targets else "phase2_only"
            rows.append({
                "kek": kek,
                "files": len(members),
                "oracle_name": oracle[1][: -len(ransom_ext)],
                "oracle_fei_len": oracle[0],
                "coverage_bytes": coverage,
                "phase1_targets": len(targets),
                "phase2_candidates": phase2_candidates,
                "status": status,
            })
        else:
            rows.append({
                "kek": kek,
                "files": len(members),
                "oracle_name": "",
                "oracle_fei_len": 0,
                "coverage_bytes": 0,
                "phase1_targets": 0,
                "phase2_candidates": 0,
                "status": "blocked_no_oracle",
            })
    rows.sort(key=lambda row: (-int(row.get("phase1_targets", 0)), -int(row.get("phase2_candidates", 0)), row["kek"]))
    return rows


def decrypt_target(tool: Path, target_path: Path, oracle_path: Path,
                   oracle_orig_name: str, scratch: Path, timeout: int = 600) -> Path:
    """Invoke stream-reuse. Returns the resulting 'decrypted' file path or None."""
    decrypted = scratch / "decrypted"
    if decrypted.exists():
        decrypted.unlink()
    try:
        subprocess.run(
            [str(tool), str(target_path), str(oracle_path), oracle_orig_name],
            cwd=str(scratch), capture_output=True, timeout=timeout,
        )
    except Exception:
        return None
    return decrypted if decrypted.exists() else None


def libmagic(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["file", "-b", str(path)], timeout=10, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
    except Exception:
        return "unknown"


def is_bad_decrypt(ftype: str) -> bool:
    f = (ftype or "").lower()
    return f.startswith("data") or "corrupted" in f or f in ("", "empty")


def _fast_copy(src: Path, dst: Path):
    sz = os.path.getsize(src)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        if hasattr(os, "sendfile"):
            offset = 0
            while offset < sz:
                sent = os.sendfile(fo.fileno(), fi.fileno(), offset, min(8 * 1024 * 1024, sz - offset))
                if sent == 0:
                    break
                offset += sent
        else:
            while True:
                buf = fi.read(1024 * 1024)
                if not buf:
                    break
                fo.write(buf)


def _phase1_group_worker(payload: dict):
    output = Path(payload["output"])
    scratch_root = Path(payload["scratch"]) / ".parallel_phase1"
    scratch_root.mkdir(parents=True, exist_ok=True)
    manifest = Manifest(output)

    kek = payload["kek"]
    args_ext = payload["args_ext"]
    tool = Path(payload["tool"])
    timeout = int(payload["timeout"])
    oracle = payload["oracle"]
    targets = payload["targets"]
    source_root = Path(payload["source_root"]) if payload.get("source_root") else None
    restore_tree = bool(payload.get("restore_tree", False))
    predict_names = bool(payload.get("predict_names", False))
    t_start = time.time()

    oracle_fei_len, oracle_fname, oracle_path, _oracle_sz, _oracle_ext_ok = oracle
    oracle_orig = oracle_fname[: -len(args_ext)]

    group_out = output / f"group_{kek}"
    group_out.mkdir(parents=True, exist_ok=True)
    review_dir = group_out / "_needs_review"
    review_dir.mkdir(exist_ok=True)

    cached = load_keystream(group_out)
    ks_cached = cached is not None

    local_scratch = scratch_root / f"{os.getpid()}_{kek}"
    local_scratch.mkdir(parents=True, exist_ok=True)
    local_oracle = local_scratch / f"_oracle_{kek}{args_ext}"
    try:
        _fast_copy(Path(oracle_path), local_oracle)
    except Exception:
        shutil.rmtree(local_scratch, ignore_errors=True)
        return {"ok": 0, "review": 0, "fail": len(targets), "attempted": len(targets)}

    ok = review = fail = attempted = 0
    for fei_len, tfname, tpath, tsz, _ext_ok in targets:
        torig = tfname[: -len(args_ext)]
        if manifest.has_source_status(tpath):
            continue
        rel_out = compute_output_relative(tpath, source_root if restore_tree else None, args_ext, torig)
        out_path = group_out / rel_out
        out_path = collision_safe_path(out_path, tpath)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            continue
        attempted += 1

        local_target = local_scratch / f"_target{args_ext}"
        try:
            _fast_copy(Path(tpath), local_target)
        except Exception:
            fail += 1
            continue

        decrypted = decrypt_target(tool, local_target, local_oracle, oracle_orig, local_scratch, timeout)
        if decrypted is None:
            fail += 1
            manifest.add(kek, torig, original_extension(torig), tpath, "", "FAIL", "", tsz, fei_len)
        else:
            ftype = libmagic(decrypted)
            if is_bad_decrypt(ftype):
                review_path = review_dir / rel_out
                review_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    _fast_copy(decrypted, review_path)
                    review += 1
                    manifest.add(
                        kek,
                        torig,
                        original_extension(torig),
                        tpath,
                        str(review_path),
                        "REVIEW",
                        ftype,
                        tsz,
                        fei_len,
                    )
                except Exception:
                    fail += 1
                    manifest.add(kek, torig, original_extension(torig), tpath, "", "FAIL", ftype, tsz, fei_len)
            else:
                try:
                    final_out = maybe_predict_name(out_path, ftype, predict_names)
                    _fast_copy(decrypted, out_path)
                    if final_out != out_path:
                        final_out.parent.mkdir(parents=True, exist_ok=True)
                        out_path.rename(final_out)
                    out_path = final_out
                    ok += 1
                    manifest.add(
                        kek,
                        torig,
                        original_extension(torig),
                        tpath,
                        str(out_path),
                        "OK",
                        ftype,
                        tsz,
                        fei_len,
                    )
                    if not ks_cached:
                        try:
                            ks_bytes, ks_meta = extract_keystream(Path(oracle_path), oracle_orig)
                            save_keystream(
                                group_out,
                                ks_bytes,
                                {
                                    "oracle_name": oracle_orig,
                                    "oracle_path": str(oracle_path),
                                    "oracle_fei_len": oracle_fei_len,
                                    "ransom_ext": args_ext,
                                    "known_len": ks_meta.get("known_len"),
                                    "source": "phase1_oracle_extract",
                                },
                            )
                            ks_cached = True
                        except Exception:
                            pass
                except Exception:
                    fail += 1
                    manifest.add(kek, torig, original_extension(torig), tpath, "", "FAIL", ftype, tsz, fei_len)

            try:
                decrypted.unlink()
            except Exception:
                pass

        try:
            local_target.unlink()
        except Exception:
            pass

    shutil.rmtree(local_scratch, ignore_errors=True)
    return {
        "kek": kek,
        "ok": ok,
        "review": review,
        "fail": fail,
        "attempted": attempted,
        "targets": len(targets),
        "duration_sec": round(time.time() - t_start, 3),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Recover files encrypted by LockBit 3.0 via keystream reuse",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See README.md and TECHNICAL.md for details.",
    )
    ap.add_argument("source", help="Directory containing encrypted files")
    ap.add_argument("output", help="Destination directory for recovered files")
    ap.add_argument("--ext", help='Ransomware extension (e.g. ".MoHsVxKYI"). Auto-detected if omitted.')
    ap.add_argument("--stream-reuse", default=None,
                    help="Path to the stream-reuse binary (default: ./stream-reuse next to script, "
                         "then ../lockbit-v3-linux-decryptor/stream-reuse)")
    ap.add_argument("--min-size", type=int, default=10 * 1024,
                    help="Minimum file size to attempt (default: 10240 bytes)")
    ap.add_argument("--max-size", type=int, default=1024 * 1024 * 1024,
                    help="Maximum file size to attempt (default: 1 GiB)")
    ap.add_argument("--no-extension-filter", action="store_true",
                    help="Try to decrypt ALL files, not only common formats")
    ap.add_argument("--restore-tree", action="store_true",
                    help="Preserve source subdirectories inside each group_<kek> output")
    ap.add_argument("--predict-names", action="store_true",
                    help="Append extension by libmagic when decrypted filename has no suffix")
    ap.add_argument("--aggressive", action="store_true",
                    help="Increase coverage attempts (implies --no-extension-filter and deeper Phase 2)")
    ap.add_argument("--plan-only", action="store_true",
                    help="Scan and print plan without decrypting files")
    ap.add_argument("--scratch", default=None,
                    help="Scratch directory for per-job temp files (default: <output>/.scratch)")
    ap.add_argument("--timeout", type=int, default=600,
                    help="Per-file decryption timeout in seconds (default: 600)")
    ap.add_argument("--profile", choices=VALID_PROFILES, default="balanced",
                    help="Runtime profile for CPU/I/O usage (default: balanced)")
    ap.add_argument("--jobs", type=int, default=None,
                    help="Parallel groups for Phase 1 (default: profile-dependent)")
    ap.add_argument("--no-phase2", action="store_true",
                    help="Disable automatic Phase 2 (keystream extension) pass")
    ap.add_argument("--phase2-max-brute-bytes", type=int, default=4,
                    help="Phase 2: max keystream bytes to brute-force per file (default: 4)")
    ap.add_argument("--phase2-before-chunk", type=int, default=None,
                    help="Phase 2 override: before_chunk_count (auto-detected when omitted)")
    ap.add_argument("--phase2-after-chunk", type=int, default=None,
                    help="Phase 2 override: after_chunk_count (auto-detected when omitted)")
    ap.add_argument("--phase2-skipped-hex", default=None,
                    help="Phase 2 override: skipped_bytes hex (auto-detected when omitted)")
    ap.add_argument("--phase2-brute-timeout", type=int, default=900,
                    help="Phase 2: brute timeout seconds (default: 900)")
    ap.add_argument("--phase2-brute-retry-timeout", type=int, default=1800,
                    help="Phase 2: retry timeout seconds after timeout (default: 1800)")
    ap.add_argument("--phase2-jobs", type=int, default=None,
                    help="Phase 2: parallel batches (default: profile-dependent)")
    ap.add_argument("--phase2-brute-threads", type=int, default=None,
                    help="Phase 2: threads per brute-extend process (default: profile-dependent)")
    ap.add_argument("--phase2-no-fusion", action="store_true",
                    help="Phase 2: disable multi-oracle keystream fusion")
    ap.add_argument("--report-json", default=None,
                    help="Write a JSON run report (phase stats, batch details, timings)")
    ap.add_argument("--report-html", default=None,
                    help="Write an HTML run report (scan/plan/recovery summary)")
    ap.add_argument("--manifest-json", default=None,
                    help="Write manifest rows as JSON (default: <output>/manifest.json when enabled)")
    ap.add_argument("--brute-extend", default=None,
                    help="Path to brute-extend binary for Phase 2 (default: ./brute-extend)")
    ap.add_argument("--direct-decrypt", default=None,
                    help="Path to direct-decrypt binary for Phase 2 (default: ./direct-decrypt)")
    args = ap.parse_args()

    if args.aggressive:
        args.no_extension_filter = True
        if args.phase2_max_brute_bytes <= 4:
            args.phase2_max_brute_bytes = 5

    resolved_profile = resolve_recovery_profile(
        args.profile,
        args.jobs,
        args.phase2_jobs,
        args.phase2_brute_threads,
    )
    args.jobs = resolved_profile["jobs"]
    args.phase2_jobs = resolved_profile["phase2_jobs"]
    args.phase2_brute_threads = resolved_profile["phase2_brute_threads"]

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        print(f"ERROR: source not a directory: {source}")
        sys.exit(2)
    output.mkdir(parents=True, exist_ok=True)
    manifest = Manifest(output)
    run_started = time.time()
    report = {
        "tool": "lockbit-rescue",
        "generated_at": utc_now_iso(),
        "source": str(source),
        "output": str(output),
        "args": vars(args),
        "runtime_profile": resolved_profile,
        "scan": {},
        "plan": {},
        "phase1": {"groups": []},
        "phase2": {"enabled": False, "totals": {}, "batches": []},
    }

    def flush_report():
        report["duration_sec"] = round(time.time() - run_started, 3)
        report["generated_at"] = utc_now_iso()
        if args.report_json:
            write_json_report(Path(args.report_json), report)
        if args.report_html:
            write_html_report(Path(args.report_html), report)

    def flush_manifest_json():
        if args.manifest_json:
            return manifest.export_json(Path(args.manifest_json))
        return None

    # Locate stream-reuse
    here = Path(__file__).resolve().parent
    candidates = []
    if args.stream_reuse:
        candidates.append(Path(args.stream_reuse))
    candidates += [
        here / "stream-reuse",
        here.parent / "lockbit-v3-linux-decryptor" / "stream-reuse",
        Path("/usr/local/bin/stream-reuse"),
    ]
    tool = next((c for c in candidates if c.is_file() and os.access(c, os.X_OK)), None)
    if not tool:
        print("ERROR: stream-reuse binary not found. Try --stream-reuse PATH or run install.sh.")
        print("Looked in:")
        for c in candidates:
            print(f"  - {c}")
        sys.exit(3)
    print(f"[i] Using stream-reuse: {tool}")

    # Detect extension if not provided
    if not args.ext:
        print(f"[i] Detecting ransomware extension in {source} ...")
        args.ext = detect_extension(source)
        if not args.ext:
            print("ERROR: could not auto-detect extension. Re-run with --ext .EXAMPLEEXT")
            sys.exit(4)
        print(f"[i] Detected extension: {args.ext}")
    elif not args.ext.startswith("."):
        args.ext = "." + args.ext

    common_exts = DEFAULT_COMMON_EXTS
    if args.no_extension_filter:
        print("[i] Extension filter disabled — attempting ALL file types")
    if args.restore_tree:
        print("[i] Output mode: restore source tree within each group directory")
    if args.predict_names:
        print("[i] Name prediction enabled for extensionless decrypted files")
    if args.aggressive:
        print("[i] Aggressive mode enabled: wider candidate set and deeper Phase 2 attempts")
    print(
        f"[i] Runtime profile: {args.profile} "
        f"(phase1_jobs={args.jobs}, phase2_jobs={args.phase2_jobs}, "
        f"brute_threads={args.phase2_brute_threads})"
    )

    # Locate phase2 binaries now so auto handoff is ready after phase1.
    brute_bin = None
    direct_bin = None
    phase2_candidates_brute = []
    phase2_candidates_direct = []
    if args.brute_extend:
        phase2_candidates_brute.append(Path(args.brute_extend))
    if args.direct_decrypt:
        phase2_candidates_direct.append(Path(args.direct_decrypt))
    phase2_candidates_brute += [
        here / "brute-extend",
        here.parent / "lockbit-v3-linux-decryptor" / "brute-extend",
        Path("/usr/local/bin/brute-extend"),
    ]
    phase2_candidates_direct += [
        here / "direct-decrypt",
        here.parent / "lockbit-v3-linux-decryptor" / "direct-decrypt",
        Path("/usr/local/bin/direct-decrypt"),
    ]
    brute_bin = next((c for c in phase2_candidates_brute if c.is_file() and os.access(c, os.X_OK)), None)
    direct_bin = next((c for c in phase2_candidates_direct if c.is_file() and os.access(c, os.X_OK)), None)
    if not args.no_phase2 and (not brute_bin or not direct_bin):
        print("[!] Phase 2 auto-run disabled: brute-extend/direct-decrypt binaries not found")
        args.no_phase2 = True

    # Scratch dir (per-job to avoid collisions when running multiple instances)
    scratch = Path(args.scratch) if args.scratch else (output / ".scratch")
    scratch.mkdir(parents=True, exist_ok=True)

    # --- Scan ---
    print(f"[*] Scanning {source} ...")
    t0 = time.time()
    groups, scanned, matched, skipped_small, skipped_big, skipped_extension = scan(
        source, args.ext, common_exts, args.no_extension_filter,
        args.min_size, args.max_size,
    )
    report["scan"] = {
        "scanned": scanned,
        "matched": matched,
        "groups": len(groups),
        "skipped_too_small": skipped_small,
        "skipped_too_big": skipped_big,
        "skipped_extension_filter": skipped_extension,
    }
    print(f"[+] Scanned {scanned} encrypted files in {time.time()-t0:.1f}s")
    print(
        f"    match={matched}, groups={len(groups)}, skipped_too_small={skipped_small}, "
        f"skipped_too_big={skipped_big}, skipped_extension_filter={skipped_extension}"
    )

    # --- Plan ---
    plans = build_plan(groups, args.ext, use_all_extensions=args.no_extension_filter)
    fallback_keks = set()
    if not args.no_extension_filter:
        planned_keks = {p[1] for p in plans}
        orphan_keks = set(groups.keys()) - planned_keks
        if orphan_keks:
            print(f"[*] Re-scanning {len(orphan_keks)} orphan batches without extension filter...")
            fallback_plans = build_plan(groups, args.ext, use_all_extensions=True, only_keks=orphan_keks)
            if fallback_plans:
                plans.extend(fallback_plans)
                plans.sort(key=lambda x: -x[0])
                fallback_keks = {p[1] for p in fallback_plans}
                print(f"[+] Added {len(fallback_plans)} batch(es) through no-extension fallback")
    total_targets = sum(p[0] for p in plans)
    no_oracle = len(groups) - len(plans)
    print(f"[+] Plan: {len(plans)} decryptable groups / {len(groups)} total")
    print(f"    ({no_oracle} groups skipped — no oracle file with long enough filename)")
    print(f"    targets to attempt: {total_targets}")
    print(f"    output: {output}")
    report["plan"] = {
        "decryptable_groups": len(plans),
        "total_groups": len(groups),
        "groups_without_oracle": no_oracle,
        "targets_to_attempt": total_targets,
        "fallback_groups": sorted(fallback_keks),
        "groups": summarize_plan(groups, plans, args.ext),
    }
    phase2_candidates = sum(row.get("phase2_candidates", 0) for row in report["plan"]["groups"])
    blocked_groups = sum(1 for row in report["plan"]["groups"] if row.get("status") == "blocked_no_oracle")
    print(f"    phase2_candidates: {phase2_candidates}, blocked_groups: {blocked_groups}")
    if args.plan_only:
        if total_targets == 0:
            print("[!] Nothing to decrypt. Probably no group has a long-named oracle.")
        print("[*] Plan-only mode: no decryption performed.")
        for row in report["plan"]["groups"][:10]:
            print(
                f"    group {row['kek']}: files={row['files']} phase1={row['phase1_targets']} "
                f"phase2={row['phase2_candidates']} status={row['status']}"
            )
        report["phase1"]["status"] = "plan_only"
        flush_report()
        flush_manifest_json()
        return
    if total_targets == 0:
        print("[!] Nothing to decrypt. Probably no group has a long-named oracle.")
        report["phase1"]["status"] = "no_targets"
        flush_report()
        flush_manifest_json()
        return

    # --- Resume bookkeeping ---
    already = 0
    for _, kek, _, targets in plans:
        gdir = output / f"group_{kek}"
        if gdir.is_dir():
            for _, tfname, _, _, _ in targets:
                if (gdir / tfname[: -len(args.ext)]).exists():
                    already += 1
    if already:
        print(f"[i] Resume: {already} files already in output, will skip")
    report["plan"]["already_present"] = already

    total_ok = total_fail = total_review = 0
    remaining = total_targets - already
    overall = tqdm(total=remaining, desc="Overall", unit="file", mininterval=0.5, position=0)

    # --- Per-group decryption ---
    if int(args.jobs) > 1:
        print(f"[*] Phase 1 parallel mode: groups={len(plans)} jobs={int(args.jobs)}")
        futures = {}
        with concurrent.futures.ProcessPoolExecutor(max_workers=max(1, int(args.jobs))) as pool:
            for gi, (n_targets, kek, oracle, targets) in enumerate(plans):
                futures[pool.submit(
                    _phase1_group_worker,
                    {
                        "group_index": gi + 1,
                        "group_total": len(plans),
                        "kek": kek,
                        "oracle": oracle,
                        "targets": targets,
                        "args_ext": args.ext,
                        "output": str(output),
                        "scratch": str(scratch),
                        "tool": str(tool),
                        "timeout": int(args.timeout),
                        "source_root": str(source),
                        "restore_tree": bool(args.restore_tree),
                        "predict_names": bool(args.predict_names),
                    },
                )] = kek

            for fut in concurrent.futures.as_completed(futures):
                kek = futures[fut]
                try:
                    stats = fut.result()
                except Exception:
                    total_fail += 1
                    print(f"[GROUP worker] {kek} failed")
                    continue
                total_ok += stats.get("ok", 0)
                total_review += stats.get("review", 0)
                total_fail += stats.get("fail", 0)
                overall.update(stats.get("attempted", 0))
                report["phase1"]["groups"].append(stats)
                print(
                    f"[GROUP worker] {kek} ok={stats.get('ok',0)} review={stats.get('review',0)} "
                    f"fail={stats.get('fail',0)}"
                )
    else:
        for gi, (n_targets, kek, oracle, targets) in enumerate(plans):
            oracle_fei_len, oracle_fname, oracle_path, oracle_sz, _oracle_ext_ok = oracle
            oracle_orig = oracle_fname[: -len(args.ext)]
            group_out = output / f"group_{kek}"
            group_out.mkdir(parents=True, exist_ok=True)
            review_dir = group_out / "_needs_review"
            review_dir.mkdir(exist_ok=True)

            cached = load_keystream(group_out)
            ks_cached = cached is not None
            if ks_cached:
                ks_bytes, ks_meta = cached
                print(f"   [i] keystream cache loaded: {len(ks_bytes)} byte(s)")

            # Skip group if fully done
            existing = sum(1 for _, tf, _, _, _ in targets if (group_out / tf[:-len(args.ext)]).exists())
            if existing == len(targets):
                print(f"[GROUP {gi+1}/{len(plans)}] {kek} already complete, skip")
                continue

            print(f"\n[GROUP {gi+1}/{len(plans)}] {kek}  oracle=\"{oracle_orig[:60]}\" "
                f"({fmt_size(oracle_sz)})  -> {len(targets)} target(s)")

            # Stage oracle locally to avoid re-reading slow source over and over
            local_oracle = scratch / f"_oracle_{kek}{args.ext}"
            try:
                copy_with_progress(Path(oracle_path), local_oracle, f"  copy oracle {fmt_size(oracle_sz)}")
            except Exception as e:
                print(f"   [!] oracle copy failed: {e}")
                overall.update(len(targets))
                continue

            grp_ok = grp_fail = grp_review = 0
            grp_bar = tqdm(targets, desc=f"  {kek}", unit="file", leave=False,
                           mininterval=0.3, position=1)
            t_start = time.time()
            for (fei_len, tfname, tpath, tsz, _ext_ok) in grp_bar:
                torig = tfname[: -len(args.ext)]
                if manifest.has_source_status(tpath):
                    grp_ok += 1
                    overall.update(1)
                    continue
                rel_out = compute_output_relative(tpath, source if args.restore_tree else None, args.ext, torig)
                out_path = group_out / rel_out
                out_path = collision_safe_path(out_path, tpath)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                short = (torig[:35] + "...") if len(torig) > 35 else torig
                grp_bar.set_postfix({"cur": short, "sz": fmt_size(tsz),
                                     "ok": grp_ok, "review": grp_review, "fail": grp_fail})

                if out_path.exists():
                    grp_ok += 1
                    overall.update(1)
                    continue

                local_target = scratch / f"_target{args.ext}"
                try:
                    copy_with_progress(Path(tpath), local_target, f"    fetch {short}")
                except Exception:
                    grp_fail += 1
                    overall.update(1)
                    continue

                decrypted = decrypt_target(tool, local_target, local_oracle,
                                           oracle_orig, scratch, args.timeout)
                if decrypted is None:
                    grp_fail += 1
                    manifest.add(
                    kek,
                    torig,
                    original_extension(torig),
                    tpath,
                    "",
                    "FAIL",
                    "",
                    tsz,
                    fei_len,
                )
                else:
                    ftype = libmagic(decrypted)
                    if is_bad_decrypt(ftype):
                        review_path = review_dir / rel_out
                        review_path.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            copy_with_progress(decrypted, review_path, f"    review {short}")
                            grp_review += 1
                            manifest.add(
                            kek,
                            torig,
                            original_extension(torig),
                            tpath,
                            str(review_path),
                            "REVIEW",
                            ftype,
                            tsz,
                            fei_len,
                        )
                        except Exception:
                            grp_fail += 1
                            manifest.add(
                            kek,
                            torig,
                            original_extension(torig),
                            tpath,
                            "",
                            "FAIL",
                            ftype,
                            tsz,
                            fei_len,
                        )
                        try:
                            decrypted.unlink()
                        except Exception:
                            pass
                    else:
                        try:
                            final_out = maybe_predict_name(out_path, ftype, args.predict_names)
                            copy_with_progress(decrypted, out_path, f"    save {short}")
                            if final_out != out_path:
                                final_out.parent.mkdir(parents=True, exist_ok=True)
                                out_path.rename(final_out)
                            out_path = final_out
                            grp_ok += 1
                            manifest.add(
                            kek,
                            torig,
                            original_extension(torig),
                            tpath,
                            str(out_path),
                            "OK",
                            ftype,
                            tsz,
                            fei_len,
                        )
                            if not ks_cached:
                                try:
                                    ks_bytes, ks_meta = extract_keystream(Path(oracle_path), oracle_orig)
                                    save_keystream(
                                    group_out,
                                    ks_bytes,
                                    {
                                        "oracle_name": oracle_orig,
                                        "oracle_path": str(oracle_path),
                                        "oracle_fei_len": oracle_fei_len,
                                        "ransom_ext": args.ext,
                                        "known_len": ks_meta.get("known_len"),
                                        "source": "phase1_oracle_extract",
                                    },
                                )
                                    ks_cached = True
                                    print(f"   [i] keystream cache saved for group {kek} ({len(ks_bytes)} byte(s))")
                                except Exception as e:
                                    print(f"   [!] keystream cache extraction failed for group {kek}: {e}")
                            try:
                                decrypted.unlink()
                            except Exception:
                                pass
                        except Exception:
                            grp_fail += 1
                            manifest.add(
                            kek,
                            torig,
                            original_extension(torig),
                            tpath,
                            "",
                            "FAIL",
                            ftype,
                            tsz,
                            fei_len,
                        )
                            try:
                                decrypted.unlink()
                            except Exception:
                                pass

                try:
                    local_target.unlink()
                except Exception:
                    pass
                overall.update(1)

            grp_bar.close()
            print(
                f"   GROUP DONE {kek}: {grp_ok} ok / {grp_review} review / {grp_fail} fail "
                f"in {time.time()-t_start:.0f}s"
            )
            report["phase1"]["groups"].append({
                "kek": kek,
                "ok": grp_ok,
                "review": grp_review,
                "fail": grp_fail,
                "attempted": len(targets),
                "targets": len(targets),
                "duration_sec": round(time.time() - t_start, 3),
            })
            total_ok += grp_ok
            total_review += grp_review
            total_fail += grp_fail
            try:
                local_oracle.unlink()
            except Exception:
                pass

    overall.close()
    print(f"\n[*] FINISHED. Recovered: {total_ok}  |  Review: {total_review}  |  Failed: {total_fail}")
    print(f"[*] Output: {output}")
    print(f"[*] Manifest: {output / 'manifest.csv'}")
    report["phase1"].update({
        "status": "completed",
        "ok": total_ok,
        "review": total_review,
        "fail": total_fail,
        "remaining_after_resume": remaining,
    })

    if not args.no_phase2 and brute_bin and direct_bin:
        report["phase2"]["enabled"] = True
        phase2_batches = []
        for kek, members in groups.items():
            use_all = args.no_extension_filter or (kek in fallback_keks)
            candidates = list(members) if use_all else [m for m in members if m[4]]
            if len(candidates) < 2:
                continue
            oracle = max(candidates, key=lambda x: x[0])
            coverage = (oracle[0] - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET
            has_leftovers = any(m[0] > coverage for m in candidates if m != oracle)
            if not has_leftovers:
                continue
            phase2_batches.append((kek, [(m[0], m[1], m[2], m[3]) for m in candidates]))

        if phase2_batches:
            print(f"\n[*] Auto Phase 2: {len(phase2_batches)} batch(es) with uncovered targets")
            phase2_totals = run_phase2_batches(
                phase2_batches,
                output,
                scratch,
                brute_bin,
                direct_bin,
                args.ext,
                args.phase2_max_brute_bytes,
                args.phase2_before_chunk,
                args.phase2_after_chunk,
                args.phase2_skipped_hex,
                args.phase2_brute_timeout,
                args.phase2_brute_retry_timeout,
                manifest,
                jobs=max(1, int(args.phase2_jobs)),
                brute_threads=max(1, int(args.phase2_brute_threads)),
                enable_fusion=(not args.phase2_no_fusion),
                source_root=source if args.restore_tree else None,
                restore_tree=bool(args.restore_tree),
                predict_names=bool(args.predict_names),
                aggressive=bool(args.aggressive),
                min_oracle_fei_len=(0 if args.aggressive else 90),
            )
            print(
                f"[*] Phase 2 totals: recovered={phase2_totals['ok']} review={phase2_totals['review']} "
                f"failed={phase2_totals['fail']} frozen={phase2_totals['frozen']}"
            )
            report["phase2"]["totals"] = {
                "ok": phase2_totals.get("ok", 0),
                "review": phase2_totals.get("review", 0),
                "fail": phase2_totals.get("fail", 0),
                "skipped": phase2_totals.get("skipped", 0),
                "frozen": phase2_totals.get("frozen", 0),
            }
            report["phase2"]["batches"] = phase2_totals.get("batches", [])
        else:
            print("[*] Auto Phase 2: no uncovered targets detected")
            report["phase2"]["totals"] = {
                "ok": 0,
                "review": 0,
                "fail": 0,
                "skipped": 0,
                "frozen": 0,
            }
            report["phase2"]["batches"] = []
    else:
        report["phase2"]["enabled"] = False

    print(f"[i] Tip: verify integrity with verify-recovered.py {output}")
    manifest_json_path = flush_manifest_json()
    if manifest_json_path:
        print(f"[*] Manifest JSON: {manifest_json_path}")
    flush_report()


if __name__ == "__main__":
    main()
