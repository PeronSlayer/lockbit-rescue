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

## 2026-05-28 - Sprint 7 (Windows UX and Full Auto-Release)

### Added
- Guided Windows/CMD user interface:
  - `lockbit-wizard.py`
  - `lockbit-wizard.cmd`
  - Menu-driven recovery/verify flow designed for non-expert users.
- WSL backend support in wizard for Windows execution paths.

### Changed
- `.github/workflows/release-on-push.yml`
  - Added Windows build job with PyInstaller (`lockbit-wizard.exe`).
  - Added packaging of Windows ZIP bundle.
  - Release job now publishes both Linux tarball and Windows ZIP on every push to `main`.
- `scripts/build_release_bundle.sh`
  - Includes wizard files in distribution and compile checks.
- `.github/workflows/ci.yml`
  - Compile checks now include `lockbit-wizard.py`.
- `README.md`
  - Documented CMD wizard usage and Windows release artifact behavior.

## 2026-05-28 - Sprint 7 Follow-up (Release Integrity Hardening)

### Added
- Windows release guide:
  - `README-WINDOWS.txt`
- Release checksum generation:
  - `SHA256SUMS.txt` is generated for GitHub release assets.
  - Local bundle builds now emit `dist/SHA256SUMS.txt`.

### Changed
- `.github/workflows/release-on-push.yml`
  - Validates Linux tarball, Windows ZIP, standalone EXE, and checksums before publishing.
  - Publishes `SHA256SUMS.txt` alongside release artifacts.
  - Packages the Windows ZIP with a clear root folder instead of loose files.
  - Uses clean release tags and titles instead of legacy `auto-*` naming.
  - Forces generated releases to full release status and marks them as latest.
  - Removes legacy `auto-*` releases and retains only the latest generated `release-*` releases.
- `scripts/build_release_bundle.sh`
  - Includes `README-WINDOWS.txt` in Linux/local bundles.
  - Emits `SHA256SUMS.txt` for manual tarball builds.
- `README.md`
  - Documents release checksums, verification command, and Windows release guide.

## 2026-05-28 - Sprints 8-9 (UX Recovery and Recovery Quality)

### Added
- HTML run reports:
  - `lockbit-rescue.py --report-html PATH`
  - `report_utils.write_html_report(...)`
- Manifest JSON export:
  - `lockbit-rescue.py --manifest-json PATH`
  - `Manifest.export_json(...)`
- Collision-safe output path helper:
  - `output_layout.collision_safe_path(...)`

### Changed
- `lockbit-rescue.py`
  - Adds per-group plan details to JSON/HTML reports.
  - Prints Phase 2 candidate and blocked-group counts during planning.
  - Exports manifest JSON on request.
  - Uses manifest-aware resume checks before skipping existing outputs.
  - Resolves basename collisions with deterministic source-hash suffixes.
- `phase2.py`
  - Uses the same collision-safe output behavior and manifest-aware resume checks.
- `lockbit-wizard.py`
  - Validates source/output folders before running.
  - Shows output free space and WSL backend availability.
  - Supports optional HTML report and manifest JSON paths.
  - Shows a final settings summary before execution.
- `README.md`
  - Documents report HTML, manifest JSON, collision handling, and wizard validation behavior.

### Tests
- Added coverage for collision-safe paths, manifest JSON export, and HTML report generation.

## 2026-05-28 - Sprints 10-11 (Performance and Quality Tooling)

### Added
- Runtime profile helper module:
  - `runtime_profiles.py`
  - Profiles: `safe`, `balanced`, `fast`.
- Synthetic scan benchmark utilities:
  - `scripts/benchmark_scan.py`
  - `lockbit_rescue_bench.py`
- Development quality config files:
  - `pyproject.toml` (ruff config)
  - `requirements-dev.txt` (pytest + ruff)

### Changed
- `lockbit-rescue.py`
  - Added `--profile safe|balanced|fast` for profile-based concurrency defaults.
  - `--jobs`, `--phase2-jobs`, `--phase2-brute-threads` now default via profile when omitted.
  - Scan stats now include explicit counters for `skipped_too_small`, `skipped_too_big`, and `skipped_extension_filter`.
- `lockbit-extend.py`
  - Added `--profile safe|balanced|fast`.
  - `--jobs` and `--brute-threads` now default via profile when omitted.
- `.github/workflows/ci.yml`
  - Added lint/validation job running `ruff`, `actionlint`, and `shellcheck`.
  - Test job now depends on lint/validation.
  - CI jobs now install `requirements-dev.txt` for consistent local/CI tooling.
- `README.md`
  - Documented runtime profiles and Sprint 11 CI quality tooling.

### Tests
- Added profile behavior tests in `tests/test_runtime_profiles.py`.

## 2026-05-28 - Sprint 12 (Security and Governance)

### Added
- Security policy:
  - `SECURITY.md`
- Issue management templates:
  - `.github/ISSUE_TEMPLATE/bug_report.yml`
  - `.github/ISSUE_TEMPLATE/recovery_help.yml`
  - `.github/ISSUE_TEMPLATE/feature_request.yml`
  - `.github/ISSUE_TEMPLATE/config.yml`
- Dependency update automation:
  - `.github/dependabot.yml` (GitHub Actions + pip)

### Changed
- `.github/workflows/release-on-push.yml`
  - Release notes are now generated automatically from built assets.
  - Release body now includes explicit artifact list and full SHA256 checksums.

---

Notes:
- This changelog tracks the complete set of fork-specific modifications introduced during the current multi-sprint implementation cycle.
