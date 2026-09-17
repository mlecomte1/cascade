#!/usr/bin/env bash
# Build Cascade on Debian: PyInstaller binary + .deb (requires dpkg-deb).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -U pip
pip install -e ".[packaging]"
pyinstaller --noconfirm --clean packaging/cascade.spec

STAGE="$ROOT/packaging/deb-root"
rm -rf "$STAGE"
mkdir -p "$STAGE/usr/local/bin" "$STAGE/DEBIAN"
cp "$ROOT/dist/Cascade" "$STAGE/usr/local/bin/cascade"
chmod 755 "$STAGE/usr/local/bin/cascade"
cat > "$STAGE/DEBIAN/control" <<'EOF'
Package: cascade
Version: 0.2.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: local <cascade@localhost>
Depends: libxcb-cursor0, libegl1
Description: Offline desktop decoder (no network, in-memory session)
EOF
dpkg-deb --build "$STAGE" "$ROOT/dist/cascade_0.2.0_amd64.deb"
echo "Output: dist/Cascade and dist/cascade_0.2.0_amd64.deb"
