#!/usr/bin/env bash
#
# build.sh -- build standalone Linux/macOS executables for the ip-finder toolkit.
#
# Usage:
#   ./build.sh                 # one-file binaries into dist/<os>/
#   ONEDIR=1 ./build.sh        # folder bundles instead of single files
#   PYTHON=/path/to/python ./build.sh
#
# Requires PyInstaller in the selected Python:
#   pip install -r requirements.txt pyinstaller
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# dist/linux on Linux, dist/macos on macOS.
case "$(uname -s)" in
    Darwin) OSDIR="macos" ;;
    *)      OSDIR="linux" ;;
esac
DIST="dist/${OSDIR}"
WORK="build/${OSDIR}"
MODE="--onefile"
[ "${ONEDIR:-0}" = "1" ] && MODE="--onedir"

echo "Python : $("$PYTHON" -c 'import sys; print(sys.executable)')"
echo "Output : ${DIST}"
echo

build() {
    local name="$1" script="$2"
    echo "==> Building ${name} (${script})"
    "$PYTHON" -m PyInstaller --noconfirm --clean "$MODE" \
        --name "$name" \
        --distpath "$DIST" \
        --workpath "$WORK" \
        --specpath "$WORK" \
        "$script"
}

build finder            finder.py
build scan-devices      scan-devices.py
build scannet-fastV2    scannet-fastV2.py
build passive-finder    passive-finder.py
build oui-lookup        oui_lookup.py
build lan-multitool-gui lan_multitool_gui.py
# scannet-fast.py is Windows-only (uses icmp.dll); build it with build.ps1.

echo
echo "Done. Executables are in ${DIST}"
ls -lh "${DIST}"
