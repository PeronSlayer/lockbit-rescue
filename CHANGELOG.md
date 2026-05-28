# Changelog

All notable changes in this fork are documented here, grouped by sprint milestones executed during this recovery-hardening effort.

## 2026-05-28 - Sprint 1 (Foundation and Reliability)

### Added
- Added keystream cache module with persistence and metadata handling:
  - `keystream_cache.py`
- Added manifest tracking module for resumable, deduplicated run logs:
  - `manifest.py`
- Added manifest writing in both Phase 1 and Phase 2 paths.

### Changed
- `lockbit-rescue.py`
  - Added manifest integration across OK/REVIEW/FAIL outcomes.
  - Added fallback planning for orphan KEK groups using no-extension mode.
  - Added `_needs_review` handling for suspicious decryptions.
  - Added keystream cache save/load hooks.
- `lockbit-extend.py`
  - Aligned result handling and reporting with manifest/review behavior.
- `verify-recovered.py`
  - Added `UNKNOWN_FORMAT` handling for files under `_needs_review` with niche/ambiguous extensions.
- `requirements.txt`
  - Added `aplib>=0.6`.

## 2026-05-28 - Sprint 2 (Phase 2 Crypto Enhancement)

### Added
- Introduced shared Phase 2 engine:
  - `phase2.py`
- Added automatic Phase 1 -> Phase 2 handoff in `lockbit-rescue.py` (opt-out with `--no-phase2`).

### Changed
- `phase2.py`
  - Implemented FEI-derived chunking auto-extraction.
  - Implemented multi-oracle keystream fusion.
  - Added timeout, retry-timeout, and batch freeze behavior.
  - Added manifest-aware status emission for all outcomes.
- `lockbit-extend.py`
  - Refactored as thin standalone entrypoint over shared `phase2.py` pipeline.

## 2026-05-28 - Sprint 3 (Performance and Scalability)

### Added
- Inter-batch parallelization:
  - Phase 1 via `lockbit-rescue.py --jobs`
  - Phase 2 via `--phase2-jobs` and `lockbit-extend.py --jobs`
- Threaded brute-force in C helper:
  - `src/_brute_extend.c` with `BRUTE_THREADS` support
- Exposed brute thread controls:
  - `--phase2-brute-threads` and `lockbit-extend.py --brute-threads`

### Changed
- `lockbit-rescue.py`
  - Added process-pool worker path for Phase 1 groups.
  - Added `os.sendfile()` fast-copy path where available.
- `phase2.py`
  - Added parallel ProcessPool execution for batches.
  - Removed per-target staging in Phase 2 and switched to direct source-path processing.
- `install.sh`
  - Linked brute binary with `-lpthread`.
- `README.md`
  - Documented new parallel/performance controls.

## 2026-05-28 - Build and Runtime Hardening

### Fixed
- `install.sh`
  - Corrected upstream build invocation to use default `make` target.
  - Added robust fallback builds when strict 32-bit/static path fails.
- `src/_direct_decrypt.c`
  - Added missing `<stdbool.h>` include required by `frank.h` `bool` declaration.

## 2026-05-28 - Sprint 4 (Usability and Coverage UX)

### Added
- New shared output layout/naming helper:
  - `output_layout.py`
- New report helper module:
  - `report_utils.py`
- New CLI options in `lockbit-rescue.py`:
  - `--restore-tree`
  - `--predict-names`
  - `--aggressive`
  - `--plan-only`
  - `--report-json PATH`
- New CLI options in `lockbit-extend.py`:
  - `--restore-tree`
  - `--predict-names`
  - `--aggressive`
  - `--plan-only`
  - `--report-json PATH`

### Changed
- `lockbit-rescue.py`
  - Added source-tree restoration under each `group_<kek>/` output when enabled.
  - Added extension prediction for extensionless recovered files via libmagic mapping.
  - Added aggressive mode behavior (wider target set + deeper Phase 2 defaults).
  - Added plan-only dry execution mode.
  - Added JSON report export with scan/plan/phase summaries and group details.
- `phase2.py`
  - Added restore-tree and name-prediction support in Phase 2 outputs.
  - Added aggressive fallback magic signatures for unknown extension classes.
  - Added configurable minimum oracle FEI threshold for batch eligibility.
  - Added per-batch details in return payload for report export.
- `lockbit-extend.py`
  - Wired Sprint 4 options to shared Phase 2 engine.
  - Added JSON report export (scan, plan, totals, batch-level details).
- `README.md`
  - Documented Sprint 4 UX/coverage/reporting features.

## 2026-05-28 - Sprint 5 (Quality, CI, Release Readiness)

### Added
- Test suite for core utilities and CLI smoke paths:
  - `tests/test_output_layout.py`
  - `tests/test_manifest.py`
  - `tests/test_report_utils.py`
  - `tests/test_cli_smoke.py`
- GitHub Actions CI workflow:
  - `.github/workflows/ci.yml`
  - Runs dependency install, Python compile checks, and pytest on push/PR.

### Changed
- `.gitignore`
  - Added `.pytest_cache/`.
- `README.md`
  - Added local quality-check commands and CI workflow reference.

## 2026-05-28 - Sprint 6 (Governance and Release Hygiene)

### Changed
- `README.md`
  - Added CI badge at top-level project header.
  - Added branch protection recommendations for `main`.
  - Added lightweight release flow guidance (PR -> CI -> squash -> tag -> release notes).

### Added
- Automated release workflow on push:
  - `.github/workflows/release-on-push.yml`
  - Builds binaries, packages tarball, and publishes prerelease on each push to `main`.
- Reproducible local bundle build script:
  - `scripts/build_release_bundle.sh`
  - Produces `dist/lockbit-rescue-<version>.tar.gz`.
- `.gitignore`
  - Added `dist/` for local release artifacts.

---

Notes:
- This changelog tracks the complete set of fork-specific modifications introduced during the current multi-sprint implementation cycle.
