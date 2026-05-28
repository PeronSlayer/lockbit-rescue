# lockbit-rescue

[![CI](https://github.com/PeronSlayer/lockbit-rescue/actions/workflows/ci.yml/badge.svg)](https://github.com/PeronSlayer/lockbit-rescue/actions/workflows/ci.yml)

Recover files encrypted by **LockBit 3.0 ("Black") / CriptomanGizmo** without paying the ransom, by exploiting the documented **keystream-reuse weakness** in its file-encryption routine.

This tool can decrypt a meaningful subset of files for free, **without the attacker's private key**, provided your encrypted batch contains at least one file whose original filename was long enough to act as a *known-plaintext oracle*.

> **Bottom line.** Real-world coverage is typically 5–40% of all encrypted files (highly dependent on how long the original filenames were). Files outside groups with a long-named oracle remain unrecoverable.

---

## TL;DR — recover your files

```bash
# 1. Get the tool
git clone https://github.com/Saddytech/lockbit-rescue.git
cd lockbit-rescue

# 2. Build the C decryptor + install Python deps
bash install.sh

# 3. Run it
python3 lockbit-rescue.py /path/to/encrypted /path/to/recovered

# 4. Check the result
python3 verify-recovered.py /path/to/recovered
```

The tool will:
1. Auto-detect the random 9-character ransomware extension.
2. Walk the source recursively and group encrypted files by their RSA-encrypted KEK fingerprint (same group = same Salsa20 keystream).
3. Pick the longest-named file in each group as the "oracle".
4. Recover the keystream from the oracle (filename + footer metadata is known-plaintext).
5. Decrypt every other file in the group whose footer is short enough to fit under the recovered keystream coverage.
6. Save them under `OUTPUT/group_<kek>/<original_name>`.
7. Skip writes where libmagic reports raw `data` (a botched decryption).
8. Automatically run Phase 2 on remaining files in each decryptable batch (unless disabled).

It is **resumable** — re-run the same command if interrupted; it skips work already on disk.

---

## What is the vulnerability?

LockBit 3.0 ("Black") encrypts file contents with Salsa20 (modified — random 64-byte initial state, no Salsa20 sigma constants). For each encryption batch, the same Salsa20 key/keystream is reused across many files. Each file ends with a 134-byte footer:

```
[ -134 : -132 ]  fei_len      uint16 little-endian: footer-encryption-info length
[ -132 : -128 ]  checksum     uint32
[ -128 :      ]  KEK blob     128 bytes (the RSA-encrypted Key Encryption Key)
```

Since the **KEK blob is identical** for every file in the same batch, we can group files into batches by hashing that 128-byte blob.

The "fei" region of each file is encrypted with the same Salsa20 keystream. The plaintext under it includes the original filename (apLib-compressed, UTF-16LE) plus a few fixed-format fields. For a file with a *long* original filename, we know:

- The first ~N bytes of plaintext exactly (apLib-compressed filename)
- The 18 trailing bytes (`filename_size[2] || skipped_bytes[8] || before_chunk_count[4] || after_chunk_count[4]`)

XORing that known plaintext with the ciphertext at the corresponding positions **recovers that many bytes of the Salsa20 keystream**. Any *other* file in the same batch whose footer is small enough to fit within those recovered keystream bytes can then be decrypted directly.

This research is by [Calif.io](https://www.calif.io/blog/lockbit-3.0-decryptor) and implemented in [yohanes/lockbit-v3-linux-decryptor](https://github.com/yohanes/lockbit-v3-linux-decryptor) (`stream-reuse.c`), which this tool drives.

---

## Requirements

- Linux x86_64
- `gcc`, `make`, `git`, `python3` (3.8+), `pip`
- The `file` command (libmagic) — pre-installed on most distros
- Python: `tqdm` (installed by `install.sh`)

The `install.sh` script handles everything except the system packages above. On Debian/Ubuntu:

```bash
sudo apt install build-essential git python3 python3-pip file
bash install.sh
```

On Arch/CachyOS:

```bash
sudo pacman -S base-devel git python python-pip file
bash install.sh
```

## Quality checks

Run local checks before pushing changes:

```bash
python3 -m py_compile lockbit-rescue.py lockbit-extend.py verify-recovered.py manifest.py keystream_cache.py phase2.py output_layout.py report_utils.py
pytest -q
```

CI is configured with GitHub Actions in `.github/workflows/ci.yml` and runs compile checks plus the test suite on push/PR.

## Branch protection recommendations

For safer releases on the fork, configure branch protection on `main` with:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Mark `CI / test` (or the exact check name shown in your repository) as required.
- Require branches to be up to date before merging.
- Restrict direct pushes to `main` (optional but recommended).
- Require at least 1 approval for PRs (recommended for collaborative maintenance).

Suggested lightweight release flow:

1. Open PR from a feature branch.
2. Ensure CI is green.
3. Merge via squash commit.
4. Tag release (`vX.Y.Z`) and publish release notes from `CHANGELOG.md`.

## Automated build and release

The repository includes a release pipeline that runs on every push to `main`:

- Workflow: `.github/workflows/release-on-push.yml`
- Behavior: build Linux bundle + build Windows wizard executable + publish a full GitHub release
- Release assets: Linux `.tar.gz`, Windows `.zip`, standalone `lockbit-wizard.exe`, and `SHA256SUMS.txt`
- Tag format: `release-<YYYY.MM.DD>-<run_number>`
- Release title format: `LockBit Rescue <YYYY.MM.DD> build <run_number>`
- Guardrails: release job fails if one of `.tar.gz`/`.zip`/`.exe` is missing or checksum validation fails
- Re-run behavior: if a release with the same generated tag already exists, it is replaced
- Cleanup: removes legacy `auto-*` releases and keeps only the latest 10 generated `release-*` releases

Verify downloaded release assets with:

```bash
sha256sum -c SHA256SUMS.txt
```

Manual local bundle build:

```bash
bash scripts/build_release_bundle.sh
```

This generates `dist/lockbit-rescue-<version>.tar.gz` with scripts, docs, and compiled helper binaries.

## Windows CMD wizard (non-expert mode)

For simpler usage on Windows CMD, use the guided wizard:

- Script: `lockbit-wizard.py`
- CMD launcher: `lockbit-wizard.cmd`
- Windows executable (from release pipeline): `lockbit-wizard.exe`
- Windows release guide: `README-WINDOWS.txt`

Wizard flow:

1. Choose "Guided recovery".
2. Enter source/output folders.
3. Pick standard or aggressive mode.
4. Optionally enable plan-only and JSON report.

On Windows, the wizard can run through WSL backend (recommended), so non-expert users do not need to compose long command-line arguments manually.

---

## Usage

### Basic

```bash
python3 lockbit-rescue.py SOURCE_DIR OUTPUT_DIR
```

### Common flags

| Flag | Purpose | Default |
|---|---|---|
| `--ext .XYZxyzABC` | Force-set the ransomware extension instead of auto-detecting | auto |
| `--min-size N` | Skip files smaller than N bytes | 10240 (10 KiB) |
| `--max-size N` | Skip files larger than N bytes | 1073741824 (1 GiB) |
| `--no-extension-filter` | Don't filter by original file type — try EVERYTHING | off |
| `--restore-tree` | Preserve source subdirectories under each `group_<kek>/` | off |
| `--predict-names` | Append extension via libmagic for extensionless recovered files | off |
| `--aggressive` | Wider coverage attempts (`--no-extension-filter`, deeper Phase 2) | off |
| `--plan-only` | Scan and print recovery plan without decrypting | off |
| `--report-json PATH` | Export a JSON execution report (scan/plan/phase stats) | off |
| `--stream-reuse PATH` | Path to the `stream-reuse` binary | auto-search |
| `--scratch PATH` | Scratch dir for temp files | `OUTPUT/.scratch` |
| `--timeout N` | Per-file decryption timeout (seconds) | 600 |
| `--jobs N` | Phase 1 parallel groups | min(4, cpu_count) |
| `--no-phase2` | Disable automatic Phase 2 handoff | off |
| `--phase2-max-brute-bytes N` | Phase 2 per-file brute gap limit | 4 |
| `--phase2-brute-timeout N` | Phase 2 brute timeout seconds | 900 |
| `--phase2-brute-retry-timeout N` | Phase 2 retry timeout seconds | 1800 |
| `--phase2-jobs N` | Phase 2 parallel batches | min(4, cpu_count) |
| `--phase2-brute-threads N` | Threads per brute-extend process | cpu_count |
| `--phase2-no-fusion` | Disable multi-oracle keystream fusion | off |
| `--brute-extend PATH` | Phase 2 brute binary path | auto-search |
| `--direct-decrypt PATH` | Phase 2 direct decrypt binary path | auto-search |

### Output layout

```
OUTPUT_DIR/
├── group_a1b2c3d4e5f6/         # one folder per encryption batch
│   ├── photo1.jpg
│   ├── docs/report.pdf         # original sub-paths flattened — see note
│   └── ...
├── group_f0e9d8c7b6a5/
│   └── ...
└── .scratch/                   # temporary working files (safe to delete after)
```

> **Note**: filenames inside `group_*/` keep their original *basename*, not their original full path. If you need to map a recovered file back to the original directory tree, cross-reference by basename with your encrypted source. A future version may emit a `manifest.csv`.

Use `--restore-tree` to keep original subdirectories under each `group_<kek>/`.

### Verifying results

```bash
python3 verify-recovered.py OUTPUT_DIR
```

This runs `file -b` on every output and classifies them:

- **GOOD** — magic bytes match the file extension. Recovery succeeded.
- **MISMATCH** — recognized file, but the magic differs from the extension. **Almost always means the original file was user-renamed before encryption (e.g. a PDF saved as `.html`)**. Content is intact.
- **SUSPECT** — libmagic returned raw `data`, `empty`, or `corrupted`. The decryption may be wrong for this file; investigate.

A clean run should show ~0% SUSPECT.

---

## FAQ

**Q: My extension isn't `.MoHsVxKYI`. Does it still work?**
Yes. LockBit 3 generates a different 9-character extension per attack. The tool auto-detects it (or pass `--ext .YourExt`).

**Q: How much of my data will I get back?**
It depends on whether each encryption batch contained at least one file with a long original filename. If your filenames are short (e.g. `IMG_0001.jpg`), recovery may be 0% for that batch. If they're long (e.g. scientific paper titles, Italian document names, downloads with descriptive titles), recovery can exceed 80% of the targeted files.

**Q: What about files larger than 1 GiB?**
Skipped by default to keep runs finite (think VM disks). Raise `--max-size` if you want to attempt them — note that I/O cost scales with file size since the stream-reuse implementation reads the whole file.

**Q: Is this safe to run? Will it modify my encrypted files?**
No. The tool only reads from the source and writes to the output directory. Encrypted originals are untouched.

**Q: Why does the script split output by `group_<kek>` rather than restoring the original directory tree?**
Two reasons: (a) per-batch separation is the natural unit of the exploit and helps spot issues; (b) different batches can legitimately contain files with the same basename. You can rearrange afterwards using basename matching.

**Q: My system disk is small — output goes to a network share, can it fit?**
Yes. Point `OUTPUT_DIR` directly to a mounted network share (SMB/NFS). Use `--scratch /path/on/local/disk` if you want temporary files on local disk for speed. Note: very slow NAS hardware can cap throughput at ~10 MB/s regardless of CPU/network — this is a hardware limit, not a script limit.

**Q: My ransomware ID/decryption ID is X. Can I check if law enforcement has a key?**
Yes. Visit [No More Ransom](https://www.nomoreransom.org/) and use their "Crypto Sheriff" or "Decryption Tools → LockBit 3.0 Black" checker. If the FBI/Europol publishes the private RSA key for your decryption ID in the future, you can decrypt 100% of files.

---

## When this tool won't help

- **No long-named oracle in a batch.** The "fei_len" of every file in the batch is small (short original filenames) and there is no usable known-plaintext span. Cryptographically blocked.
- **Files larger than 4 GiB**. The Salsa20 keystream offset for chunked encryption exceeds the keystream we can recover from any oracle.
- **Different LockBit family / different ransomware.** This exploit is specific to LockBit 3.0 ("Black"). Variants like LockBit Green, LockBit Linux, or other families (Conti, Akira, etc.) have different cryptography.

---

## Files in this package
- `lockbit-rescue.py` — main recovery script (scan, group, decrypt, verify)
- `verify-recovered.py` — integrity sweep using libmagic
- `brute-extend` (+ `src/_brute_extend.c`) — *Phase 2 tool*: pure-C, segfault-free keystream extension via known-plaintext brute force. See [BRUTEFORCE.md](docs/BRUTEFORCE.md).
- `direct-decrypt` (+ `src/_direct_decrypt.c`) — *Phase 2 tool*: decrypts a single file body given a recovered `file_encryption_key` and the batch's chunking parameters.
- `install.sh` — clones upstream stream-reuse and builds `stream-reuse`, `brute-extend`, `direct-decrypt`; installs `tqdm`
- `docs/TECHNICAL.md` — in-depth explanation of footer layout, keystream recovery, coverage math
- `docs/BRUTEFORCE.md` — segfault diagnosis, pure-C fix, false-positive lesson, end-to-end Phase 2 workflow
- `docs/STORY.md` — chronicle of the recovery operation this tool was built from (now includes Phase 11)
- `LICENSE` / credits — see end of this file
## Advanced: recovering files the main flow had to skip
`lockbit-rescue.py` now chains Phase 1 and Phase 2 automatically by default. If you want to run Phase 2 manually, or tune it for slow hardware/time budgets:
1. Use `brute-extend` to extend the keystream byte-by-byte, climbing a ladder of intermediate-fei_len files in the same batch. 1–3 byte extensions are essentially instant; a 4-byte extension takes ~9 minutes at 2³² iterations.
2. With each successful extension you also recover that target's `file_encryption_key` (the 64-byte Salsa20 state for its body).
3. Use `direct-decrypt` with that key plus the batch's `before/after/skipped` parameters to recover the full file body.
4. The standalone `lockbit-extend.py` entrypoint uses the same shared Phase 2 module as `lockbit-rescue.py`, so behavior is consistent between automatic and manual workflows.

### Performance notes (Sprint 3)
- Inter-batch parallelization is now available in both phases (`--jobs`, `--phase2-jobs`).
- `brute-extend` now supports multithread brute force through `BRUTE_THREADS`; Python wrappers expose this as `--phase2-brute-threads` and `lockbit-extend.py --brute-threads`.
- Phase 2 no longer stages each target file to scratch before brute/direct decrypt: it reads the needed regions directly from source paths.
- Phase 1 copy path uses `os.sendfile()` when available for faster kernel-level file transfer.

### Coverage and UX notes (Sprint 4)
- `--plan-only` lets you estimate recoverable groups/targets before running decryption.
- `--predict-names` appends a guessed extension from libmagic when decrypted names have no suffix.
- `--restore-tree` preserves source hierarchy under each group output folder.
- `--aggressive` expands attempts in both phases (all extensions, lower Phase 2 oracle threshold, fallback magic signatures).
- `--report-json` writes a machine-readable run report with scan stats, per-group Phase 1 summary, and per-batch Phase 2 outcomes.
See [BRUTEFORCE.md](docs/BRUTEFORCE.md) for a complete worked example (including the false-positive trap with short magic strings and the chunking-parameter requirements).

---

## Credits

- **Calif.io** for [the LockBit 3.0 decryptor research and write-up](https://www.calif.io/blog/lockbit-3.0-decryptor) that documents the keystream-reuse weakness.
- **yohanes** for the C/Python implementation in [lockbit-v3-linux-decryptor](https://github.com/yohanes/lockbit-v3-linux-decryptor) — `stream-reuse.c` does the actual cryptographic work; this package wraps it with discovery, batching, resume, and verification.
- This package: lockbit-rescue — pipeline, integrity sweep, install scripts, documentation.

---

## Disclaimer

This tool is for legitimate recovery of files on systems you own, by victims of LockBit 3.0 ransomware. Do not use to bypass legitimate security mechanisms. The author makes no warranty as to fitness or completeness.
