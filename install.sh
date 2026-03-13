#!/bin/bash
# ForgeAI Local Connector — Quick Install Script
#
# Downloads a pre-built binary from GitHub Releases and installs
# it as a systemd service.
#
# Usage (recommended — API token auth):
#   curl -fsSL https://raw.githubusercontent.com/kravitzai/forge-flow-friend/main/install.sh \
#     | bash -s -- \
#     --token 'fgc_...' \
#     --proxmox-url 'https://192.168.1.100:8006' \
#     --proxmox-token-id 'monitoring@pve!forgeai' \
#     --proxmox-token-secret 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
#
# Password auth (fallback — prompted securely, never passed on CLI):
#   curl -fsSL ... | bash -s -- \
#     --token "fgc_..." \
#     --proxmox-url "https://192.168.1.100:8006" \
#     --proxmox-user "root@pam"
#   # The script will securely prompt for the password.

set -euo pipefail

REPO="kravitzai/forge-flow-friend"
CONNECTOR_TOKEN=""
PROXMOX_BASE_URL=""
PROXMOX_USERNAME=""
PROXMOX_PASSWORD=""
PROXMOX_TOKEN_ID=""
PROXMOX_TOKEN_SECRET=""
INSECURE_SKIP_VERIFY="false"
POLL_INTERVAL_SECONDS="30"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/forgeai"
SERVICE_USER="forgeai"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --token) CONNECTOR_TOKEN="$2"; shift 2 ;;
    --proxmox-url) PROXMOX_BASE_URL="$2"; shift 2 ;;
    --proxmox-user) PROXMOX_USERNAME="$2"; shift 2 ;;
    --proxmox-token-id) PROXMOX_TOKEN_ID="$2"; shift 2 ;;
    --proxmox-token-secret) PROXMOX_TOKEN_SECRET="$2"; shift 2 ;;
    --insecure) INSECURE_SKIP_VERIFY="true"; shift ;;
    --poll-interval) POLL_INTERVAL_SECONDS="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [ -z "$CONNECTOR_TOKEN" ]; then
  echo "Error: --token is required"
  exit 1
fi

echo "╔══════════════════════════════════════════╗"
echo "║  ForgeAI Local Connector — Installer     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Credential handling ──
# If no API token provided, fall back to username + interactive password prompt.
# Passwords are NEVER accepted as command-line arguments.
if [ -n "$PROXMOX_TOKEN_ID" ] && [ -n "$PROXMOX_TOKEN_SECRET" ]; then
  echo "→ Auth: Proxmox API token"
elif [ -n "$PROXMOX_USERNAME" ]; then
  echo "→ Auth: Username/password (password will be prompted)"
  # Check if password is already set via environment variable
  if [ -z "$PROXMOX_PASSWORD" ]; then
    if [ -t 0 ]; then
      # Interactive terminal — prompt securely
      echo ""
      read -s -p "  Enter Proxmox password for ${PROXMOX_USERNAME}: " PROXMOX_PASSWORD
      echo ""
    else
      # Non-interactive (piped) — check env
      echo "  ⚠️  No interactive terminal detected."
      echo "  Set PROXMOX_PASSWORD as an environment variable before running:"
      echo "    export PROXMOX_PASSWORD='...'"
      echo "    curl -fsSL ... | bash -s -- ..."
      exit 1
    fi
  else
    echo "  (using PROXMOX_PASSWORD from environment)"
  fi
  if [ -z "$PROXMOX_PASSWORD" ]; then
    echo "Error: password cannot be empty"
    exit 1
  fi
elif [ -n "$PROXMOX_BASE_URL" ]; then
  echo "Error: Proxmox URL provided but no auth credentials."
  echo "  Use --proxmox-token-id and --proxmox-token-secret (recommended)"
  echo "  Or  --proxmox-user to be prompted for a password"
  exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
echo "→ Detected: ${OS}/${ARCH}"

# Download binary from latest GitHub Release
ASSET_NAME="connector-agent-${OS}-${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
RELEASES_URL="https://github.com/${REPO}/releases"

# ── Pre-flight: verify release exists before downloading ──
echo "→ Checking release availability..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -L "$DOWNLOAD_URL" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "000" ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║  ❌ Release not found (HTTP ${HTTP_CODE})                        ║"
  echo "╚══════════════════════════════════════════════════════════╝"
  echo ""
  echo "  URL: ${DOWNLOAD_URL}"
  echo ""
  echo "  This usually means one of:"
  echo "    • No release has been published yet"
  echo "    • The repository is empty or private"
  echo "    • The architecture (${OS}/${ARCH}) has no pre-built binary"
  echo ""
  echo "  To fix:"
  echo "    1. Verify releases exist: ${RELEASES_URL}"
  echo "    2. Or use Docker instead (recommended):"
  echo "       docker run -d --name forgeai-connector \\"
  echo "         -e CONNECTOR_TOKEN='${CONNECTOR_TOKEN}' \\"
  echo "         ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest"
  echo "    3. Or build from source:"
  echo "       git clone https://github.com/${REPO}.git"
  echo "       cd forge-flow-friend"
  echo "       go build -o connector-agent ."
  echo ""
  exit 1
fi

echo "→ Downloading connector agent from GitHub Releases..."
echo "  ${DOWNLOAD_URL}"
curl -fsSL -o "/tmp/${ASSET_NAME}" "$DOWNLOAD_URL" || {
  echo ""
  echo "Download failed unexpectedly (HTTP ${HTTP_CODE} on pre-flight)."
  echo "Check: ${RELEASES_URL}"
  echo ""
  echo "Fallback — build from source:"
  echo "  git clone https://github.com/${REPO}.git"
  echo "  cd forge-flow-friend"
  echo "  go build -o connector-agent ."
  exit 1
}

# Extract
echo "→ Extracting..."
tar xzf "/tmp/${ASSET_NAME}" -C /tmp/
chmod +x "/tmp/connector-agent-${OS}-${ARCH}"

# Install binary
echo "→ Installing to ${INSTALL_DIR}..."
sudo mv "/tmp/connector-agent-${OS}-${ARCH}" "${INSTALL_DIR}/forgeai-connector"
rm -f "/tmp/${ASSET_NAME}"

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
  echo "→ Creating service user: ${SERVICE_USER}"
  sudo useradd -r -s /bin/false "$SERVICE_USER" 2>/dev/null || true
fi

# Create config directory
echo "→ Creating config directory..."
sudo mkdir -p "$CONFIG_DIR"
sudo chmod 700 "$CONFIG_DIR"

# Write environment file (secrets stored in file, never in CLI args or logs)
cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
CONNECTOR_TOKEN=${CONNECTOR_TOKEN}
PROXMOX_BASE_URL=${PROXMOX_BASE_URL}
PROXMOX_USERNAME=${PROXMOX_USERNAME}
PROXMOX_PASSWORD=${PROXMOX_PASSWORD}
PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS}
EOF
sudo chmod 600 "${CONFIG_DIR}/connector.env"
sudo chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/connector.env"

# Create systemd unit
echo "→ Creating systemd service..."
cat <<EOF | sudo tee /etc/systemd/system/forgeai-connector.service > /dev/null
[Unit]
Description=ForgeAI Local Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
EnvironmentFile=${CONFIG_DIR}/connector.env
ExecStart=${INSTALL_DIR}/forgeai-connector
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
echo "→ Starting connector..."
sudo systemctl daemon-reload
sudo systemctl enable forgeai-connector
sudo systemctl start forgeai-connector

echo ""
echo "✅ ForgeAI Local Connector installed and running!"
echo ""
echo "Useful commands:"
echo "  Status:    sudo systemctl status forgeai-connector"
echo "  Logs:      sudo journalctl -u forgeai-connector -f"
echo "  Stop:      sudo systemctl stop forgeai-connector"
echo "  Uninstall: sudo systemctl stop forgeai-connector && sudo rm ${INSTALL_DIR}/forgeai-connector /etc/systemd/system/forgeai-connector.service ${CONFIG_DIR}/connector.env"
