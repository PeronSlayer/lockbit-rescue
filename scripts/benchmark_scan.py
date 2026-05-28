#!/usr/bin/env python3
"""Synthetic scan benchmark for lockbit-rescue scanner throughput."""

from __future__ import annotations

import argparse
import os
import random
import string
import time
from pathlib import Path

from lockbit_rescue_bench import run_scan


def _rand_name(length: int) -> str:
    alpha = string.ascii_letters + string.digits
    return "".join(random.choice(alpha) for _ in range(length))


def _write_fake_encrypted(path: Path, fei_len: int):
    body = os.urandom(1024)
    checksum = os.urandom(4)
    kek = os.urandom(128)
    footer = fei_len.to_bytes(2, "little") + checksum + kek
    path.write_bytes(body + footer)


def generate_dataset(root: Path, ext: str, groups: int, files_per_group: int):
    root.mkdir(parents=True, exist_ok=True)
    for g in range(groups):
        gdir = root / f"group_{g:04d}"
        gdir.mkdir(parents=True, exist_ok=True)
        for i in range(files_per_group):
            base = f"doc_{g}_{i}_{_rand_name(8)}.pdf"
            fei_len = random.randint(90, 220)
            _write_fake_encrypted(gdir / f"{base}{ext}", fei_len)


def main():
    ap = argparse.ArgumentParser(description="Benchmark lockbit-rescue scan phase on synthetic files")
    ap.add_argument("dataset", help="Path to synthetic encrypted dataset")
    ap.add_argument("--ext", default=".ABCDEFGHJ", help="Synthetic ransomware extension")
    ap.add_argument("--groups", type=int, default=50, help="Number of KEK-like groups to generate")
    ap.add_argument("--files-per-group", type=int, default=40, help="Files per group")
    ap.add_argument("--regenerate", action="store_true", help="Delete and regenerate dataset before benchmark")
    ap.add_argument("--min-size", type=int, default=1, help="Min size for scan")
    ap.add_argument("--max-size", type=int, default=1_000_000_000, help="Max size for scan")
    args = ap.parse_args()

    dataset = Path(args.dataset).resolve()
    if args.regenerate and dataset.exists():
        for p in sorted(dataset.rglob("*"), reverse=True):
            if p.is_file() or p.is_symlink():
                p.unlink(missing_ok=True)
            elif p.is_dir():
                p.rmdir()

    if not dataset.exists() or not any(dataset.rglob(f"*{args.ext}")):
        print("[*] generating synthetic dataset ...")
        generate_dataset(dataset, args.ext, args.groups, args.files_per_group)

    t0 = time.time()
    stats = run_scan(dataset, args.ext, args.min_size, args.max_size)
    elapsed = time.time() - t0
    print(f"[+] scan_seconds={elapsed:.3f}")
    print(f"[+] scanned={stats['scanned']} matched={stats['matched']} groups={stats['groups']}")
    if elapsed > 0:
        print(f"[+] files_per_second={stats['scanned'] / elapsed:.1f}")


if __name__ == "__main__":
    main()
