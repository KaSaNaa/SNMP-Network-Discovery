#!/bin/bash
set -e

# Use venv
source venv/bin/activate

# Install dependencies if needed
python3 -m pip install -r requirements.txt
python3 -m pip install pyinstaller

# Clean previous builds
rm -rf build dist *.spec

# Build the binary
echo "Building binary..."
pyinstaller --onefile --name snmp-discovery-linux main.py

echo "Build complete. Binary is in dist/snmp-discovery-linux"
chmod +x dist/snmp-discovery-linux
