from runtime_profiles import resolve_phase2_profile, resolve_recovery_profile


def test_safe_profile_limits_parallelism():
    cfg = resolve_recovery_profile("safe", None, None, None)
    assert cfg["profile"] == "safe"
    assert cfg["jobs"] == 1
    assert cfg["phase2_jobs"] == 1
    assert cfg["phase2_brute_threads"] >= 1


def test_fast_profile_can_be_overridden():
    cfg = resolve_recovery_profile("fast", 2, 3, 4)
    assert cfg["jobs"] == 2
    assert cfg["phase2_jobs"] == 3
    assert cfg["phase2_brute_threads"] == 4


def test_phase2_profile_defaults():
    cfg = resolve_phase2_profile("balanced", None, None)
    assert cfg["profile"] == "balanced"
    assert cfg["jobs"] >= 1
    assert cfg["brute_threads"] >= 1
