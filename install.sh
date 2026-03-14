#!/bin/bash
# ForgeAI Connector Host — Quick Install Script
#
# Installs the connector host as a systemd service that can manage
# multiple infrastructure targets simultaneously.
#
# Usage — Enrollment (recommended):
#   curl -fsSL https://raw.githubusercontent.com/kravitzai/forge-flow-friend/main/install.sh \
#     | bash -s -- --enroll-token 'fgc_...'
#
# Usage — Enrollment + initial target:
#   curl -fsSL https://raw.githubusercontent.com/kravitzai/forge-flow-friend/main/install.sh \
#     | bash -s -- \
#     --enroll-token 'fgbt_...' \
#     --target-type 'proxmox' \
#     --proxmox-url 'https://192.168.1.100:8006' \
#     --proxmox-token-id 'monitoring@pve!forgeai' \
#     --proxmox-token-secret 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
#
# Usage — Legacy mode (backward compatible):
#   curl -fsSL ... | bash -s -- --token 'fgc_...' --target-type 'proxmox' ...
#
# The host supports adding more targets later without reinstalling.

set -euo pipefail

REPO="kravitzai/forge-flow-friend"
ENROLLMENT_TOKEN=""
CONNECTOR_TOKEN=""
TARGET_TYPE=""
HOST_LABEL=""

# Proxmox
PROXMOX_BASE_URL=""
PROXMOX_USERNAME=""
PROXMOX_PASSWORD=""
PROXMOX_TOKEN_ID=""
PROXMOX_TOKEN_SECRET=""

# TrueNAS
TRUENAS_URL=""
TRUENAS_API_KEY=""

# Nutanix
NUTANIX_URL=""
NUTANIX_USERNAME=""
NUTANIX_PASSWORD=""

INSECURE_SKIP_VERIFY="false"
POLL_INTERVAL_SECONDS="30"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/forgeai"
SERVICE_USER="forgeai"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --enroll-token)         ENROLLMENT_TOKEN="$2";      shift 2 ;;
    --token)                CONNECTOR_TOKEN="$2";       shift 2 ;;
    --target-type)          TARGET_TYPE="$2";           shift 2 ;;
    --label)                HOST_LABEL="$2";            shift 2 ;;
    --proxmox-url)          PROXMOX_BASE_URL="$2";      shift 2 ;;
    --proxmox-user)         PROXMOX_USERNAME="$2";      shift 2 ;;
    --proxmox-token-id)     PROXMOX_TOKEN_ID="$2";      shift 2 ;;
    --proxmox-token-secret) PROXMOX_TOKEN_SECRET="$2";  shift 2 ;;
    --truenas-url)          TRUENAS_URL="$2";           shift 2 ;;
    --truenas-api-key)      TRUENAS_API_KEY="$2";       shift 2 ;;
    --nutanix-url)          NUTANIX_URL="$2";           shift 2 ;;
    --nutanix-username)     NUTANIX_USERNAME="$2";      shift 2 ;;
    --insecure)             INSECURE_SKIP_VERIFY="true"; shift ;;
    --poll-interval)        POLL_INTERVAL_SECONDS="$2"; shift 2 ;;
    --config-dir)           CONFIG_DIR="$2";            shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Require at least one auth token
if [ -z "$ENROLLMENT_TOKEN" ] && [ -z "$CONNECTOR_TOKEN" ]; then
  echo "Error: --enroll-token (recommended) or --token (legacy) is required"
  echo ""
  echo "  Enrollment mode:  --enroll-token 'fgbt_...'"
  echo "  Legacy mode:      --token 'fgc_...' --target-type 'proxmox' ..."
  exit 1
fi

echo "╔══════════════════════════════════════════╗"
echo "║  ForgeAI Connector Host — Installer      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "→ Mode: Host enrollment"
else
  echo "→ Mode: Legacy single-target"
fi

# ── Check for existing installation ──

EXISTING_INSTALL=false
if [ -f "${CONFIG_DIR}/host.json.enc" ] || [ -f "${CONFIG_DIR}/host.key" ]; then
  EXISTING_INSTALL=true
  echo "→ Existing host installation detected at ${CONFIG_DIR}"
  echo "  Upgrading binary without overwriting existing configuration."
  echo ""
fi

# ── Credential validation (only for new installs with a target type) ──

if [ -n "$TARGET_TYPE" ]; then
  echo "→ Initial target type: ${TARGET_TYPE}"

  case "$TARGET_TYPE" in
    proxmox)
      if [ -n "$PROXMOX_TOKEN_ID" ] && [ -n "$PROXMOX_TOKEN_SECRET" ]; then
        echo "→ Auth: Proxmox API token"
      elif [ -n "$PROXMOX_USERNAME" ]; then
        echo "→ Auth: Proxmox username/password (password will be prompted)"
        if [ -z "$PROXMOX_PASSWORD" ]; then
          if [ -t 0 ]; then
            echo ""
            read -s -p "  Enter Proxmox password for ${PROXMOX_USERNAME}: " PROXMOX_PASSWORD
            echo ""
          else
            echo "  ⚠️  No interactive terminal detected."
            echo "  Set PROXMOX_PASSWORD as an environment variable before running:"
            echo "    export PROXMOX_PASSWORD='...'"
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
      ;;

    truenas)
      if [ -z "$TRUENAS_URL" ]; then
        echo "Error: --truenas-url is required for TrueNAS targets"
        exit 1
      fi
      if [ -z "$TRUENAS_API_KEY" ]; then
        echo "Error: --truenas-api-key is required for TrueNAS targets"
        echo "  Generate one in TrueNAS: Settings → API Keys → Add"
        exit 1
      fi
      echo "→ Auth: TrueNAS API key"
      ;;

    nutanix)
      if [ -z "$NUTANIX_URL" ]; then
        echo "Error: --nutanix-url is required for Nutanix targets"
        exit 1
      fi
      if [ -z "$NUTANIX_USERNAME" ]; then
        echo "Error: --nutanix-username is required for Nutanix targets"
        exit 1
      fi
      if [ -z "$NUTANIX_PASSWORD" ]; then
        if [ -t 0 ]; then
          echo "→ Auth: Nutanix username/password (password will be prompted)"
          echo ""
          read -s -p "  Enter Nutanix password for ${NUTANIX_USERNAME}: " NUTANIX_PASSWORD
          echo ""
        else
          echo "  ⚠️  No interactive terminal detected."
          echo "  Set NUTANIX_PASSWORD as an environment variable before running:"
          echo "    export NUTANIX_PASSWORD='...'"
          exit 1
        fi
      else
        echo "→ Auth: Nutanix username/password (from environment)"
      fi
      if [ -z "$NUTANIX_PASSWORD" ]; then
        echo "Error: password cannot be empty"
        exit 1
      fi
      ;;

    *)
      echo "Error: unsupported --target-type '${TARGET_TYPE}'"
      echo "  Supported: proxmox, truenas, nutanix, prometheus, grafana, ollama,"
      echo "             generic-http, pure-storage, netapp-ontap, powerstore, powermax, powerflex"
      echo ""
      echo "  Tip: Use --enroll-token instead of --token to enroll a multi-target host."
      echo "  Targets are then assigned remotely from the ForgeAI dashboard."
      exit 1
      ;;
  esac
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
  echo "  Fallback — use Docker:"
  echo "    docker run -d --name forgeai-host \\"
  echo "      --pull always \\"
  echo "      -v /etc/forgeai:/etc/forgeai \\"
  if [ -n "$ENROLLMENT_TOKEN" ]; then
    echo "      -e FORGEAI_ENROLLMENT_TOKEN='${ENROLLMENT_TOKEN}' \\"
  else
    echo "      -e CONNECTOR_TOKEN='${CONNECTOR_TOKEN}' \\"
  fi
  [ -n "$TARGET_TYPE" ] && echo "      -e TARGET_TYPE='${TARGET_TYPE}' \\"
  case "$TARGET_TYPE" in
    proxmox)
      [ -n "$PROXMOX_BASE_URL" ]     && echo "      -e PROXMOX_BASE_URL='${PROXMOX_BASE_URL}' \\"
      [ -n "$PROXMOX_TOKEN_ID" ]     && echo "      -e PROXMOX_TOKEN_ID='${PROXMOX_TOKEN_ID}' \\"
      [ -n "$PROXMOX_TOKEN_SECRET" ] && echo "      -e PROXMOX_TOKEN_SECRET='${PROXMOX_TOKEN_SECRET}' \\"
      [ -n "$PROXMOX_USERNAME" ]     && echo "      -e PROXMOX_USERNAME='${PROXMOX_USERNAME}' \\"
      ;;
    truenas)
      echo "      -e TRUENAS_URL='${TRUENAS_URL}' \\"
      echo "      -e TRUENAS_API_KEY='${TRUENAS_API_KEY}' \\"
      ;;
    nutanix)
      echo "      -e NUTANIX_URL='${NUTANIX_URL}' \\"
      echo "      -e NUTANIX_USERNAME='${NUTANIX_USERNAME}' \\"
      ;;
  esac
  [ "$INSECURE_SKIP_VERIFY" = "true" ] && echo "      -e INSECURE_SKIP_VERIFY=true \\"
  echo "      ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest"
  echo ""
  exit 1
fi

echo "→ Downloading connector host from GitHub Releases..."
echo "  ${DOWNLOAD_URL}"
curl -fsSL -o "/tmp/${ASSET_NAME}" "$DOWNLOAD_URL" || {
  echo "Download failed. Check: ${RELEASES_URL}"
  exit 1
}

# Extract
echo "→ Extracting..."
tar xzf "/tmp/${ASSET_NAME}" -C /tmp/
chmod +x "/tmp/connector-agent-${OS}-${ARCH}"

# Stop existing service before replacing binary
if systemctl is-active --quiet forgeai-host 2>/dev/null; then
  echo "→ Stopping existing host service..."
  sudo systemctl stop forgeai-host
fi

# Install binary
echo "→ Installing to ${INSTALL_DIR}..."
sudo mv "/tmp/connector-agent-${OS}-${ARCH}" "${INSTALL_DIR}/forgeai-host"
rm -f "/tmp/${ASSET_NAME}"

# Also create symlink for backward compatibility
sudo ln -sf "${INSTALL_DIR}/forgeai-host" "${INSTALL_DIR}/forgeai-connector"

# Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
  echo "→ Creating service user: ${SERVICE_USER}"
  sudo useradd -r -s /bin/false "$SERVICE_USER" 2>/dev/null || true
fi

# Create config directory with proper permissions
echo "→ Creating config directory..."
sudo mkdir -p "${CONFIG_DIR}/secrets"
sudo chmod 700 "${CONFIG_DIR}"
sudo chmod 700 "${CONFIG_DIR}/secrets"
sudo chown -R "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}"

# Write environment file
if [ "$EXISTING_INSTALL" = false ]; then
  echo "→ Writing configuration..."

  if [ -n "$ENROLLMENT_TOKEN" ]; then
    # Enrollment mode — minimal env, host enrolls on first run
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
FORGEAI_ENROLLMENT_TOKEN=${ENROLLMENT_TOKEN}
CONFIG_DIR=${CONFIG_DIR}
HOST_LABEL=${HOST_LABEL}
EOF

    # If initial target provided, also include legacy vars for migration
    if [ -n "$TARGET_TYPE" ]; then
      cat <<EOF | sudo tee -a "${CONFIG_DIR}/connector.env" > /dev/null
CONNECTOR_TOKEN=${ENROLLMENT_TOKEN}
TARGET_TYPE=${TARGET_TYPE}
PROXMOX_BASE_URL=${PROXMOX_BASE_URL}
PROXMOX_USERNAME=${PROXMOX_USERNAME}
PROXMOX_PASSWORD=${PROXMOX_PASSWORD}
PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
TRUENAS_URL=${TRUENAS_URL}
TRUENAS_API_KEY=${TRUENAS_API_KEY}
NUTANIX_URL=${NUTANIX_URL}
NUTANIX_USERNAME=${NUTANIX_USERNAME}
NUTANIX_PASSWORD=${NUTANIX_PASSWORD}
INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS}
EOF
    fi
  else
    # Legacy mode
    cat <<EOF | sudo tee "${CONFIG_DIR}/connector.env" > /dev/null
CONNECTOR_TOKEN=${CONNECTOR_TOKEN}
TARGET_TYPE=${TARGET_TYPE}
CONFIG_DIR=${CONFIG_DIR}
PROXMOX_BASE_URL=${PROXMOX_BASE_URL}
PROXMOX_USERNAME=${PROXMOX_USERNAME}
PROXMOX_PASSWORD=${PROXMOX_PASSWORD}
PROXMOX_TOKEN_ID=${PROXMOX_TOKEN_ID}
PROXMOX_TOKEN_SECRET=${PROXMOX_TOKEN_SECRET}
TRUENAS_URL=${TRUENAS_URL}
TRUENAS_API_KEY=${TRUENAS_API_KEY}
NUTANIX_URL=${NUTANIX_URL}
NUTANIX_USERNAME=${NUTANIX_USERNAME}
NUTANIX_PASSWORD=${NUTANIX_PASSWORD}
INSECURE_SKIP_VERIFY=${INSECURE_SKIP_VERIFY}
POLL_INTERVAL_SECONDS=${POLL_INTERVAL_SECONDS}
EOF
  fi

  sudo chmod 600 "${CONFIG_DIR}/connector.env"
  sudo chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/connector.env"
else
  echo "→ Preserving existing configuration"
fi

# Create systemd unit
echo "→ Creating systemd service..."
cat <<EOF | sudo tee /etc/systemd/system/forgeai-host.service > /dev/null
[Unit]
Description=ForgeAI Connector Host
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
EnvironmentFile=${CONFIG_DIR}/connector.env
ExecStart=${INSTALL_DIR}/forgeai-host
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR}
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Remove old single-target service if it exists
if systemctl is-enabled --quiet forgeai-connector 2>/dev/null; then
  echo "→ Migrating from legacy single-target service..."
  sudo systemctl stop forgeai-connector 2>/dev/null || true
  sudo systemctl disable forgeai-connector 2>/dev/null || true
  sudo rm -f /etc/systemd/system/forgeai-connector.service
fi

# Enable and start
echo "→ Starting connector host..."
sudo systemctl daemon-reload
sudo systemctl enable forgeai-host
sudo systemctl restart forgeai-host

echo ""
echo "✅ ForgeAI Connector Host installed and running!"
if [ -n "$ENROLLMENT_TOKEN" ]; then
  echo "   Mode: Enrollment (host will self-register with backend)"
fi
if [ -n "$TARGET_TYPE" ]; then
  echo "   Initial target: ${TARGET_TYPE}"
fi
echo "   Config dir: ${CONFIG_DIR}"
echo ""
echo "Useful commands:"
echo "  Status:    sudo systemctl status forgeai-host"
echo "  Logs:      sudo journalctl -u forgeai-host -f"
echo "  Stop:      sudo systemctl stop forgeai-host"
echo "  Uninstall: sudo systemctl stop forgeai-host && sudo systemctl disable forgeai-host && sudo rm ${INSTALL_DIR}/forgeai-host /etc/systemd/system/forgeai-host.service && sudo rm -rf ${CONFIG_DIR}"
echo ""
echo "After enrollment, targets are managed from the ForgeAI dashboard."
echo "No reinstall needed to add, update, or remove targets."
