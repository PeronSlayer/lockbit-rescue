#!/usr/bin/env python3
"""Standalone Phase 2 runner using the shared phase2 pipeline."""

import argparse
import os
import sys
import time
from pathlib import Path

from manifest import Manifest
from phase2 import detect_extension, run_phase2_batches, scan_batches
from report_utils import utc_now_iso, write_html_report, write_json_report
from runtime_profiles import VALID_PROFILES, resolve_phase2_profile


def main():
    ap = argparse.ArgumentParser(
        description="Phase 2 keystream-extension automation for LockBit 3.0 recovery"
    )
    ap.add_argument("source", help="Directory containing encrypted files")
    ap.add_argument("output", help="Destination directory (merges into group_<kek>/)")
    ap.add_argument("--ext", help="Ransomware extension (auto-detected if omitted)")
    ap.add_argument("--max-brute-bytes", type=int, default=4,
                    help="Max keystream bytes to brute-force per file (default: 4)")
    ap.add_argument("--before-chunk", type=int, default=None,
                    help="Optional override for before_chunk_count (auto by default)")
    ap.add_argument("--after-chunk", type=int, default=None,
                    help="Optional override for after_chunk_count (auto by default)")
    ap.add_argument("--skipped-hex", default=None,
                    help="Optional override for skipped_bytes (auto by default, e.g. 0x520000)")
    ap.add_argument("--scratch", default=None,
                    help="Scratch directory (default: <output>/.extend_scratch)")
    ap.add_argument("--brute-extend", default=None,
                    help="Path to brute-extend binary (default: ./brute-extend)")
    ap.add_argument("--direct-decrypt", default=None,
                    help="Path to direct-decrypt binary (default: ./direct-decrypt)")
    ap.add_argument("--brute-timeout", type=int, default=900,
                    help="Per-file brute-force timeout in seconds (default: 900)")
    ap.add_argument("--brute-retry-timeout", type=int, default=1800,
                    help="Retry timeout for timed-out brute steps (default: 1800)")
    ap.add_argument("--profile", choices=VALID_PROFILES, default="balanced",
                    help="Runtime profile for CPU/I/O usage (default: balanced)")
    ap.add_argument("--jobs", type=int, default=None,
                    help="Parallel Phase 2 batches (default: profile-dependent)")
    ap.add_argument("--brute-threads", type=int, default=None,
                    help="Threads per brute-extend invocation (default: profile-dependent)")
    ap.add_argument("--no-fusion", action="store_true",
                    help="Disable multi-oracle keystream fusion")
    ap.add_argument("--restore-tree", action="store_true",
                    help="Preserve source subdirectories inside each group_<kek> output")
    ap.add_argument("--predict-names", action="store_true",
                    help="Append extension by libmagic when decrypted filename has no suffix")
    ap.add_argument("--aggressive", action="store_true",
                    help="Increase coverage attempts (lower oracle threshold + fallback magic rules)")
    ap.add_argument("--plan-only", action="store_true",
                    help="Scan and print plan without running brute/direct decrypt")
    ap.add_argument("--report-json", default=None,
                    help="Write a JSON run report (phase stats, batch details, timings)")
    ap.add_argument("--report-html", default=None,
                    help="Write an HTML run report (scan/plan/phase summary)")
    ap.add_argument("--manifest-json", default=None,
                    help="Write manifest rows as JSON")
    args = ap.parse_args()

    if args.aggressive and args.max_brute_bytes <= 4:
        args.max_brute_bytes = 5

    resolved_profile = resolve_phase2_profile(args.profile, args.jobs, args.brute_threads)
    args.jobs = resolved_profile["jobs"]
    args.brute_threads = resolved_profile["brute_threads"]

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        print(f"ERROR: source not a directory: {source}")
        sys.exit(2)

    output.mkdir(parents=True, exist_ok=True)
    manifest = Manifest(output)
    run_started = time.time()
    report = {
        "tool": "lockbit-extend",
        "generated_at": utc_now_iso(),
        "source": str(source),
        "output": str(output),
        "args": vars(args),
        "runtime_profile": resolved_profile,
        "scan": {},
        "plan": {},
        "phase2": {"enabled": True, "totals": {}, "batches": []},
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

    here = Path(__file__).resolve().parent
    brute_bin = Path(args.brute_extend) if args.brute_extend else (here / "brute-extend")
    direct_bin = Path(args.direct_decrypt) if args.direct_decrypt else (here / "direct-decrypt")
    if not brute_bin.exists() or not os.access(brute_bin, os.X_OK):
        print(f"ERROR: brute-extend binary not found at {brute_bin}")
        sys.exit(3)
    if not direct_bin.exists() or not os.access(direct_bin, os.X_OK):
        print(f"ERROR: direct-decrypt binary not found at {direct_bin}")
        sys.exit(3)

    ransom_ext = args.ext or ""
    if not ransom_ext:
        print(f"[i] Detecting ransomware extension in {source}...")
        ransom_ext = detect_extension(source)
        if not ransom_ext:
            print("ERROR: could not auto-detect ransom extension; pass --ext .XYZ")
            sys.exit(4)
    if not ransom_ext.startswith("."):
        ransom_ext = "." + ransom_ext

    scratch = Path(args.scratch) if args.scratch else (output / ".extend_scratch")
    scratch.mkdir(parents=True, exist_ok=True)

    print(
        f"[i] Runtime profile: {args.profile} "
        f"(jobs={args.jobs}, brute_threads={args.brute_threads})"
    )

    print(f"[*] Scanning {source}...")
    t0 = time.time()
    groups, scanned = scan_batches(source, ransom_ext)
    print(f"[+] Scanned {scanned} encrypted files in {time.time() - t0:.1f}s")
    print(f"    {len(groups)} distinct batches found")
    report["scan"] = {
        "scanned": scanned,
        "groups": len(groups),
    }

    work_batches = [(k, v) for k, v in groups.items() if len(v) >= 2]
    work_batches.sort(key=lambda x: -len(x[1]))
    total_targets = sum(len(v) - 1 for _, v in work_batches)
    print(f"    {len(work_batches)} batches have >= 2 files")
    print(f"    total candidate targets: {total_targets}")
    report["plan"] = {
        "work_batches": len(work_batches),
        "total_candidate_targets": total_targets,
    }

    if args.plan_only:
        print("[*] Plan-only mode: no decryption performed.")
        report["phase2"]["enabled"] = False
        report["phase2"]["status"] = "plan_only"
        flush_report()
        flush_manifest_json()
        return

    totals = run_phase2_batches(
        work_batches,
        output,
        scratch,
        brute_bin,
        direct_bin,
        ransom_ext,
        args.max_brute_bytes,
        args.before_chunk,
        args.after_chunk,
        args.skipped_hex,
        args.brute_timeout,
        args.brute_retry_timeout,
        manifest,
        jobs=max(1, int(args.jobs)),
        brute_threads=max(1, int(args.brute_threads)),
        enable_fusion=(not args.no_fusion),
        source_root=source if args.restore_tree else None,
        restore_tree=bool(args.restore_tree),
        predict_names=bool(args.predict_names),
        aggressive=bool(args.aggressive),
        min_oracle_fei_len=(0 if args.aggressive else 90),
    )

    print(
        f"\n[*] PHASE2 FINISHED. Recovered: {totals['ok']}  Review: {totals['review']}  "
        f"Failed: {totals['fail']}  Frozen: {totals['frozen']}"
    )
    print(f"[*] Output: {output}")
    report["phase2"]["totals"] = {
        "ok": totals.get("ok", 0),
        "review": totals.get("review", 0),
        "fail": totals.get("fail", 0),
        "skipped": totals.get("skipped", 0),
        "frozen": totals.get("frozen", 0),
    }
    report["phase2"]["batches"] = totals.get("batches", [])
    report["phase2"]["status"] = "completed"
    flush_report()
    manifest_json_path = flush_manifest_json()
    if manifest_json_path:
        print(f"[*] Manifest JSON: {manifest_json_path}")


if __name__ == "__main__":
    main()
