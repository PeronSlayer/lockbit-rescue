#!/usr/bin/env python3
"""Runtime profile helpers for recovery performance tuning."""

from __future__ import annotations

import os


VALID_PROFILES = ("safe", "balanced", "fast")


def cpu_count() -> int:
    return max(1, os.cpu_count() or 1)


def resolve_recovery_profile(
    profile: str,
    jobs: int | None,
    phase2_jobs: int | None,
    phase2_brute_threads: int | None,
) -> dict:
    cpus = cpu_count()
    selected = profile or "balanced"
    if selected not in VALID_PROFILES:
        raise ValueError(f"invalid profile: {selected}")

    if selected == "safe":
        defaults = {
            "jobs": 1,
            "phase2_jobs": 1,
            "phase2_brute_threads": max(1, min(2, cpus)),
        }
    elif selected == "fast":
        defaults = {
            "jobs": max(1, min(8, cpus)),
            "phase2_jobs": max(1, min(8, cpus)),
            "phase2_brute_threads": cpus,
        }
    else:
        defaults = {
            "jobs": max(1, min(4, cpus)),
            "phase2_jobs": max(1, min(4, cpus)),
            "phase2_brute_threads": cpus,
        }

    return {
        "profile": selected,
        "jobs": max(1, int(jobs if jobs is not None else defaults["jobs"])),
        "phase2_jobs": max(1, int(phase2_jobs if phase2_jobs is not None else defaults["phase2_jobs"])),
        "phase2_brute_threads": max(
            1,
            int(phase2_brute_threads if phase2_brute_threads is not None else defaults["phase2_brute_threads"]),
        ),
    }


def resolve_phase2_profile(
    profile: str,
    jobs: int | None,
    brute_threads: int | None,
) -> dict:
    resolved = resolve_recovery_profile(profile, jobs, jobs, brute_threads)
    return {
        "profile": resolved["profile"],
        "jobs": resolved["phase2_jobs"],
        "brute_threads": resolved["phase2_brute_threads"],
    }