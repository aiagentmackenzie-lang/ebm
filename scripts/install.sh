#!/bin/bash
set -e

# Endpoint Behavior Monitor — Linux/macOS Installation Script

echo "[EBM] Installing Endpoint Behavior Monitor..."

OS=$(uname -s)
ARCH=$(uname -m)
INSTALL_DIR="/opt/ebm"
CONFIG_DIR="/etc/ebm"
RULES_DIR="$CONFIG_DIR/rules"
SERVICE_NAME="ebm"

# Detect platform
if [ "$OS" == "Linux" ]; then
    BINARY="ebm-linux-${ARCH}"
elif [ "$OS" == "Darwin" ]; then
    BINARY="ebm-darwin-${ARCH}"
else
    echo "[EBM] Unsupported OS: $OS"
    exit 1
fi

# Create directories
sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$RULES_DIR"

# Copy binary
if [ -f "dist/$BINARY" ]; then
    sudo cp "dist/$BINARY" "$INSTALL_DIR/ebm"
    sudo chmod +x "$INSTALL_DIR/ebm"
else
    echo "[EBM] Binary not found: dist/$BINARY"
    echo "[EBM] Please build first: make build-$OS"
    exit 1
fi

# Copy config
cp config.yaml.example "$CONFIG_DIR/config.yaml"

# Copy rules
cp -r rules/* "$RULES_DIR/"

sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<-EOF
[Unit]
Description=Endpoint Behavior Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/ebm -config $CONFIG_DIR/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
echo "[EBM] Installation complete. Start with: sudo systemctl start $SERVICE_NAME"
