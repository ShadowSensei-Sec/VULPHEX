#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo
echo "======================================"
echo "          VULPHEX Installer"
echo "======================================"
echo

# --------------------------------------------------
# Find Python 3
# --------------------------------------------------

PYTHON=""

if command -v python3 >/dev/null 2>&1; then
    CANDIDATE="$(command -v python3)"

    # Reject Windows Store execution aliases.
    if [[ "$CANDIDATE" != *"/WindowsApps/"* ]]; then
        PYTHON="$CANDIDATE"
    fi
fi

if [[ -z "$PYTHON" ]] && command -v python >/dev/null 2>&1; then
    CANDIDATE="$(command -v python)"

    if [[ "$CANDIDATE" != *"/WindowsApps/"* ]]; then
        PYTHON="$CANDIDATE"
    fi
fi

if [[ -z "$PYTHON" ]]; then
    echo "Error: Python 3 was not found."
    echo
    echo "VULPHEX requires Python 3.13 or newer."
    echo "Install Python 3.13+ and run ./install.sh again."
    exit 1
fi

# --------------------------------------------------
# Check Python version
# --------------------------------------------------

PYTHON_MAJOR="$("$PYTHON" -c 'import sys; print(sys.version_info.major)')"
PYTHON_MINOR="$("$PYTHON" -c 'import sys; print(sys.version_info.minor)')"
PYTHON_VERSION="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"

if [[ "$PYTHON_MAJOR" -lt 3 || \
      ( "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 13 ) ]]; then

    echo "Error: VULPHEX requires Python 3.13 or newer."
    echo "Detected Python: $PYTHON_VERSION"
    exit 1
fi

echo "[+] Python $PYTHON_VERSION detected."

# --------------------------------------------------
# Create private VULPHEX runtime
# --------------------------------------------------

VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

if [[ ! -x "$VENV_PYTHON" ]]; then
    echo "[+] Creating VULPHEX runtime..."

    "$PYTHON" -m venv "$SCRIPT_DIR/.venv"
else
    echo "[+] VULPHEX runtime already exists."
fi

# --------------------------------------------------
# Install packaging tools
# --------------------------------------------------

echo "[+] Preparing package installer..."

"$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel

# --------------------------------------------------
# Install VULPHEX
# --------------------------------------------------

echo "[+] Installing VULPHEX..."

"$VENV_PYTHON" -m pip install .

# --------------------------------------------------
# Make launcher executable
# --------------------------------------------------

chmod +x "$SCRIPT_DIR/vulphex"

# --------------------------------------------------
# Complete
# --------------------------------------------------

echo
echo "======================================"
echo "       VULPHEX installation complete"
echo "======================================"
echo
echo "Start VULPHEX with:"
echo
echo "    ./vulphex"
echo
echo "No Python environment activation is required."
echo