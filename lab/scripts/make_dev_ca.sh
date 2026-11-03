#!/usr/bin/env bash
# Generate development CA and mTLS client certificates for BitGuard lab (Milestone S12)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${REPO_ROOT}/lab/certs"

echo "Generating BitGuard Dev CA and client certificates into ${CERTS_DIR}..."
python3 "${SCRIPT_DIR}/make_dev_ca.py" --output-dir "${CERTS_DIR}"
echo "Dev PKI setup complete."
