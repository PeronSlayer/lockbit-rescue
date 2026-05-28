#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  VERSION="$(date -u +%Y.%m.%d)-$(git rev-parse --short HEAD)"
fi

DIST_DIR="${ROOT_DIR}/dist"
BUNDLE_DIR="${DIST_DIR}/lockbit-rescue-${VERSION}"
TARBALL="${DIST_DIR}/lockbit-rescue-${VERSION}.tar.gz"

rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}" "${DIST_DIR}"

# Build binaries and runtime dependencies.
bash "${ROOT_DIR}/install.sh"

# Run compile checks for shipped Python entrypoints/modules.
python3 -m py_compile \
  lockbit-rescue.py \
  lockbit-extend.py \
  lockbit-wizard.py \
  verify-recovered.py \
  manifest.py \
  keystream_cache.py \
  phase2.py \
  output_layout.py \
  report_utils.py

# Package distribution files.
cp -f LICENSE README.md CHANGELOG.md requirements.txt install.sh "${BUNDLE_DIR}/"
cp -f lockbit-rescue.py lockbit-extend.py verify-recovered.py "${BUNDLE_DIR}/"
cp -f lockbit-wizard.py lockbit-wizard.cmd "${BUNDLE_DIR}/"
cp -f manifest.py keystream_cache.py phase2.py output_layout.py report_utils.py "${BUNDLE_DIR}/"
cp -f brute-extend direct-decrypt stream-reuse "${BUNDLE_DIR}/"
cp -rf docs src "${BUNDLE_DIR}/"

rm -f "${TARBALL}"
tar -czf "${TARBALL}" -C "${DIST_DIR}" "lockbit-rescue-${VERSION}"

# Emit machine-friendly paths for CI steps.
echo "VERSION=${VERSION}"
echo "BUNDLE_DIR=${BUNDLE_DIR}"
echo "TARBALL=${TARBALL}"
