#!/usr/bin/env python3
"""Simple guided CMD UI for lockbit-rescue and verify-recovered."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


def _script_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _has_wsl() -> bool:
    if not _is_windows():
        return False
    try:
        p = subprocess.run(
            ["wsl", "-e", "sh", "-lc", "echo ok"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return p.returncode == 0
    except Exception:
        return False


def _to_wsl_path(path: Path) -> str:
    p = subprocess.run(["wsl", "wslpath", "-a", str(path)], capture_output=True, text=True, timeout=10)
    if p.returncode != 0:
        raise RuntimeError(f"cannot convert path to wsl: {path}")
    return p.stdout.strip()


def _ask(prompt: str, default: str | None = None) -> str:
    if default is None:
        return input(prompt).strip()
    ans = input(f"{prompt} [{default}]: ").strip()
    return ans or default


def _ask_yes_no(prompt: str, default_yes: bool = True) -> bool:
    default = "Y/n" if default_yes else "y/N"
    ans = input(f"{prompt} ({default}): ").strip().lower()
    if not ans:
        return default_yes
    return ans in ("y", "yes", "s", "si")


def _run(cmd: list[str], cwd: Path | None = None) -> int:
    print("\n[RUN]", " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    return p.returncode


def _fmt_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}PB"


def _count_candidate_files(source: Path) -> int:
    total = 0
    try:
        for _dirpath, _dirnames, filenames in os.walk(source):
            total += len(filenames)
    except OSError:
        return 0
    return total


def _ensure_output_folder(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path.is_dir()
    except OSError as exc:
        print(f"[ERROR] Cannot create output folder: {exc}")
        return False


def _show_disk_space(path: Path):
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return
    print(f"[i] Output free space: {_fmt_size(usage.free)}")


def _run_recovery_ui(base: Path):
    print("\n=== Guided Recovery ===")
    src = Path(_ask("Encrypted SOURCE folder"))
    out = Path(_ask("Recovered OUTPUT folder"))

    if not src.exists() or not src.is_dir():
        print("[ERROR] Source folder not found.")
        return
    if src.resolve() == out.resolve():
        print("[ERROR] Source and output folders must be different.")
        return
    if not _ensure_output_folder(out):
        return

    _show_disk_space(out)
    print(f"[i] Files visible under source: {_count_candidate_files(src)}")
    if _is_windows():
        print(f"[i] WSL backend detected: {'yes' if _has_wsl() else 'no'}")

    mode = _ask("Mode: standard/aggressive", "standard").lower()
    aggressive = mode.startswith("a")
    restore_tree = _ask_yes_no("Preserve source subfolders in output", True)
    predict_names = _ask_yes_no("Predict missing extensions with file magic", True)
    plan_only = _ask_yes_no("Plan-only (no decryption)", False)
    report_json = _ask("Optional report JSON path (blank to skip)", "").strip()
    report_html = _ask("Optional report HTML path (blank to skip)", "").strip()
    manifest_json = _ask("Optional manifest JSON path (blank for output\\manifest.json)", "").strip()

    ext = _ask("Ransom extension (leave blank for auto-detect)", "").strip()

    args = [str(base / "lockbit-rescue.py"), str(src), str(out)]
    if ext:
        args += ["--ext", ext]
    if aggressive:
        args += ["--aggressive"]
    if restore_tree:
        args += ["--restore-tree"]
    if predict_names:
        args += ["--predict-names"]
    if plan_only:
        args += ["--plan-only"]
    if report_json:
        args += ["--report-json", report_json]
    if report_html:
        args += ["--report-html", report_html]
    if manifest_json:
        args += ["--manifest-json", manifest_json]
    elif not plan_only:
        args += ["--manifest-json", str(out / "manifest.json")]

    print("\n=== Recovery Summary ===")
    print(f"Source:       {src}")
    print(f"Output:       {out}")
    print(f"Mode:         {'aggressive' if aggressive else 'standard'}")
    print(f"Restore tree: {'yes' if restore_tree else 'no'}")
    print(f"Predict ext:  {'yes' if predict_names else 'no'}")
    print(f"Plan-only:    {'yes' if plan_only else 'no'}")
    if report_json:
        print(f"Report JSON:  {report_json}")
    if report_html:
        print(f"Report HTML:  {report_html}")
    print("========================")
    if not _ask_yes_no("Start with these settings", True):
        print("Cancelled.")
        return

    if _is_windows() and _has_wsl():
        use_wsl = _ask_yes_no("Use WSL backend (recommended on Windows)", True)
        if use_wsl:
            try:
                base_wsl = _to_wsl_path(base)
                src_wsl = _to_wsl_path(src)
                out_wsl = _to_wsl_path(out)
                wsl_args = ["python3", f"{base_wsl}/lockbit-rescue.py", src_wsl, out_wsl]
                if ext:
                    wsl_args += ["--ext", ext]
                if aggressive:
                    wsl_args += ["--aggressive"]
                if restore_tree:
                    wsl_args += ["--restore-tree"]
                if predict_names:
                    wsl_args += ["--predict-names"]
                if plan_only:
                    wsl_args += ["--plan-only"]
                if report_json:
                    rp = _to_wsl_path(Path(report_json))
                    wsl_args += ["--report-json", rp]
                if report_html:
                    rp = _to_wsl_path(Path(report_html))
                    wsl_args += ["--report-html", rp]
                if manifest_json:
                    rp = _to_wsl_path(Path(manifest_json))
                    wsl_args += ["--manifest-json", rp]
                elif not plan_only:
                    rp = _to_wsl_path(out / "manifest.json")
                    wsl_args += ["--manifest-json", rp]
                cmd_str = " ".join([shlex_quote(a) for a in wsl_args])
                rc = _run(["wsl", "bash", "-lc", f"cd {shlex_quote(base_wsl)} && {cmd_str}"])
                print("\n[OK] Finished with exit code", rc)
                return
            except Exception as e:
                print(f"[WARN] WSL launch failed: {e}")

    py = shutil.which("python") or shutil.which("python3")
    if not py:
        print("[ERROR] Python not found. Install Python or use WSL mode.")
        return
    rc = _run([py] + args, cwd=base)
    print("\n[OK] Finished with exit code", rc)


def _run_verify_ui(base: Path):
    print("\n=== Verify Recovered Files ===")
    out = Path(_ask("Recovered OUTPUT folder"))
    if not out.exists() or not out.is_dir():
        print("[ERROR] Output folder not found.")
        return

    if _is_windows() and _has_wsl() and _ask_yes_no("Use WSL backend", True):
        try:
            base_wsl = _to_wsl_path(base)
            out_wsl = _to_wsl_path(out)
            cmd_str = f"python3 {shlex_quote(base_wsl + '/verify-recovered.py')} {shlex_quote(out_wsl)}"
            rc = _run(["wsl", "bash", "-lc", f"cd {shlex_quote(base_wsl)} && {cmd_str}"])
            print("\n[OK] Verify finished with exit code", rc)
            return
        except Exception as e:
            print(f"[WARN] WSL verify failed: {e}")

    py = shutil.which("python") or shutil.which("python3")
    if not py:
        print("[ERROR] Python not found.")
        return
    rc = _run([py, str(base / "verify-recovered.py"), str(out)], cwd=base)
    print("\n[OK] Verify finished with exit code", rc)


def shlex_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def main():
    base = _script_dir()
    print("lockbit-rescue wizard")
    print("Simple menu for non-expert users")
    print(f"Base directory: {base}")

    while True:
        print("\nChoose an option:")
        print("1) Guided recovery")
        print("2) Verify recovered files")
        print("3) Exit")
        choice = _ask(">", "1")

        if choice == "1":
            _run_recovery_ui(base)
        elif choice == "2":
            _run_verify_ui(base)
        elif choice == "3":
            print("Bye.")
            return
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
