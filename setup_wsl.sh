#!/bin/bash
# Setup script for WSL Ubuntu to install Python and dependencies for Computer Networks Project

set -e

echo "=========================================="
echo "WSL Ubuntu Setup for IoT Telemetry Project"
echo "=========================================="

# Update package list
echo "[1/6] Updating package list..."
sudo apt-get update

# Install Python 3 and pip if not already installed
echo "[2/6] Installing Python 3 and pip..."
sudo apt-get install -y python3 python3-pip python3-venv

# Install system dependencies for network tools
echo "[3/6] Installing network tools (tcpdump, tc, netem)..."
sudo apt-get install -y tcpdump iproute2

# Install Python dependencies
echo "[4/6] Installing Python dependencies..."
# Use --break-system-packages flag for Ubuntu's externally-managed environment
# This is safe for development/testing purposes
echo "  Installing psutil (this may require --break-system-packages flag)..."
pip3 install --user --break-system-packages psutil || {
    echo "  Warning: pip install failed. Trying alternative method..."
    # Alternative: install via apt if available
    sudo apt-get install -y python3-psutil 2>/dev/null || {
        echo "  Error: Could not install psutil. You may need to install it manually."
        echo "  Try: pip3 install --user --break-system-packages psutil"
    }
}

# Verify installations
echo "[5/6] Verifying installations..."
python3 --version
pip3 --version
tcpdump --version | head -1
tc -V

# Make scripts executable
echo "[6/6] Making scripts executable..."
chmod +x collector.py sensor.py testphase2.py

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Run tests with: python3 testphase2.py"
echo "2. Or run individual scenarios with: python3 run_all_tests.py"
echo ""
echo "Note: Some commands require sudo (tcpdump, tc/netem)"
echo "You may need to configure passwordless sudo or enter password when prompted"
echo ""

