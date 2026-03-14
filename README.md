# ForgeAI Local Connector Agent

> **This repository is the public release surface for the ForgeAI Connector Agent.**
> It is automatically synced from the private application source repository.
> The full ForgeAI platform lives in a separate, private repo.

A lightweight, outbound-only agent that bridges your local infrastructure with the ForgeAI platform. Supports **Proxmox VE** and **TrueNAS**. No inbound firewall ports needed.

## Install

### Docker (Recommended)

#### Proxmox

```bash
docker run -d --name forgeai-connector \
  --restart unless-stopped \
  -e CONNECTOR_TOKEN='fgc_your_token_here' \
  -e TARGET_TYPE='proxmox' \
  -e PROXMOX_BASE_URL='https://192.168.1.100:8006' \
  -e PROXMOX_TOKEN_ID='monitoring@pve!forgeai' \
  -e PROXMOX_TOKEN_SECRET='your_token_secret' \
  -e INSECURE_SKIP_VERIFY='true' \
  ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest
```

#### TrueNAS

```bash
docker run -d --name forgeai-connector-truenas \
  --restart unless-stopped \
  -e CONNECTOR_TOKEN='fgc_your_token_here' \
  -e TARGET_TYPE='truenas' \
  -e TRUENAS_URL='https://192.168.1.50/api/v2.0' \
  -e TRUENAS_API_KEY='1-xxxxxxxxxxxx' \
  -e INSECURE_SKIP_VERIFY='true' \
  ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest
```

### Linux Service (install.sh)

```bash
# Proxmox
curl -fsSL https://raw.githubusercontent.com/kravitzai/forge-flow-friend/main/install.sh \
  | bash -s -- \
  --token 'fgc_...' \
  --target-type 'proxmox' \
  --proxmox-url 'https://192.168.1.100:8006' \
  --proxmox-token-id 'monitoring@pve!forgeai' \
  --proxmox-token-secret 'your_token_secret'

# TrueNAS
curl -fsSL https://raw.githubusercontent.com/kravitzai/forge-flow-friend/main/install.sh \
  | bash -s -- \
  --token 'fgc_...' \
  --target-type 'truenas' \
  --truenas-url 'https://192.168.1.50/api/v2.0' \
  --truenas-api-key '1-xxxxxxxxxxxx'
```

### Build from Source

```bash
git clone https://github.com/kravitzai/forge-flow-friend.git
cd forge-flow-friend
go build -o connector-agent .
```

## Configuration

| Variable | Required | Description |
|---|---|---|
| `CONNECTOR_TOKEN` | ✅ | ForgeAI connector token (`fgc_...`) |
| `TARGET_TYPE` | | Target platform: `proxmox` (default) or `truenas` |
| `INSECURE_SKIP_VERIFY` | | Accept self-signed certs |
| `POLL_INTERVAL_SECONDS` | | Collection interval (default: 30) |

### Proxmox Variables

| Variable | Required | Description |
|---|---|---|
| `PROXMOX_BASE_URL` | ✅ | Proxmox API URL |
| `PROXMOX_TOKEN_ID` | ✅* | API token ID (recommended auth) |
| `PROXMOX_TOKEN_SECRET` | ✅* | API token secret |
| `PROXMOX_USERNAME` | | Username (fallback auth) |
| `PROXMOX_PASSWORD` | | Password (env var or secure prompt only) |
| `PROXMOX_NODE` | | Limit to specific node |

### TrueNAS Variables

| Variable | Required | Description |
|---|---|---|
| `TRUENAS_URL` | ✅ | TrueNAS API URL (e.g. `https://truenas.local/api/v2.0`) |
| `TRUENAS_API_KEY` | ✅ | API key from Settings → API Keys → Add |

## What It Collects (Read-Only)

### Proxmox
- **Nodes**: status, CPU, RAM, disk, uptime, PVE version
- **Workloads**: VM/LXC inventory, status, resource usage
- **Storage**: backends, type, capacity, usage
- **Cluster**: membership, quorum status

### TrueNAS
- **ZFS Pools**: health, capacity, fragmentation, scrub/resilver status
- **Datasets**: quotas, compression, deduplication properties
- **Replication**: task status and schedules
- **Shares**: SMB/NFS share configurations
- **Alerts**: native alerts plus edge-side warnings for pool degradation and capacity > 90%

## Multiple Targets

To monitor both Proxmox and TrueNAS, run separate agent instances side by side:

```bash
# Proxmox connector
docker run -d --name forgeai-proxmox \
  -e CONNECTOR_TOKEN='fgc_proxmox_token' \
  -e TARGET_TYPE='proxmox' \
  -e PROXMOX_BASE_URL='https://192.168.1.100:8006' \
  ...

# TrueNAS connector
docker run -d --name forgeai-truenas \
  -e CONNECTOR_TOKEN='fgc_truenas_token' \
  -e TARGET_TYPE='truenas' \
  -e TRUENAS_URL='https://192.168.1.50/api/v2.0' \
  ...
```

Each connector registration maps to a single target. Register each target separately in the ForgeAI dashboard.

## Releases & Docker Images

- **GitHub Releases**: Pre-built binaries for linux/amd64 and linux/arm64
- **GHCR**: `ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest`

Releases are built automatically when a version tag (e.g. `v0.1.0`) is pushed.

## Security

- Outbound-only — no inbound ports needed
- Token-scoped — each connector has a unique, revocable token
- No plaintext passwords — API tokens recommended; passwords prompted securely
- Credentials stay local — Proxmox/TrueNAS credentials never leave the connector host
- Non-root — runs as unprivileged user

## License

MIT
