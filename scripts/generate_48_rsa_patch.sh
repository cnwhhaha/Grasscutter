#!/usr/bin/env bash
set -euo pipefail

# Generates a 4.8 RSA patch DLL for launchers expecting patch/48version.dll.
# Source: latest known Cultivation patch bundle.

OUT_DIR="${1:-patch}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ZIP_URL="https://github.com/Grasscutters/Cultivation/releases/download/v1.7.2/Cultivation.zip"

mkdir -p "$OUT_DIR"

curl -L -o "$TMP_DIR/Cultivation.zip" "$ZIP_URL"

python - "$TMP_DIR/Cultivation.zip" "$OUT_DIR/48version.dll" <<'PY'
import os, shutil, sys, zipfile
zip_path, out_path = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path) as zf:
    candidate = "patch/48version.dll" if "patch/48version.dll" in zf.namelist() else "patch/47version.dll"
    zf.extract(candidate, os.path.dirname(zip_path))
    shutil.copy2(os.path.join(os.path.dirname(zip_path), candidate), out_path)
    print(f"[info] source patch: {candidate}")
PY

sha256sum "$OUT_DIR/48version.dll" > "$OUT_DIR/48version.dll.sha256"
echo "[ok] generated $OUT_DIR/48version.dll"
cat "$OUT_DIR/48version.dll.sha256"
