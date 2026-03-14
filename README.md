# ForgeAI Local Connector Agent

> **This repository is the public release surface for the ForgeAI Connector Agent.**
> It is automatically synced from the private application source repository.
> The full ForgeAI platform lives in a separate, private repo.

A lightweight, outbound-only agent that bridges your local Proxmox VE environment with the ForgeAI platform. No inbound firewall ports needed.

## Install

### Docker (Recommended)

```bash
docker run -d --name forgeai-connector \
  --restart unless-stopped \
  -e CONNECTOR_TOKEN='fgc_your_token_here' \
  -e PROXMOX_BASE_URL='https://192.168.1.100:8006' \
  -e PROXMOX_TOKEN_ID='monitoring@pve!forgeai' \
  -e PROXMOX_TOKEN_SECRET='your_token_secret' \
  -e INSECURE_SKIP_VERIFY='true' \
  ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest
```

### Linux Service (install.sh)

```bash
curl -fsSL https://raw.githubusercontent.com/kravitzai/forge-flow-friend/main/connector-agent/install.sh \
  | bash -s -- \
  --token 'fgc_...' \
  --proxmox-url 'https://192.168.1.100:8006' \
  --proxmox-token-id 'monitoring@pve!forgeai' \
  --proxmox-token-secret 'your_token_secret'
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
| `PROXMOX_BASE_URL` | ✅ | Proxmox API URL |
| `PROXMOX_TOKEN_ID` | ✅* | API token ID (recommended auth) |
| `PROXMOX_TOKEN_SECRET` | ✅* | API token secret |
| `PROXMOX_USERNAME` | | Username (fallback auth) |
| `PROXMOX_PASSWORD` | | Password (env var or secure prompt only) |
| `PROXMOX_NODE` | | Limit to specific node |
| `POLL_INTERVAL_SECONDS` | | Collection interval (default: 30) |
| `INSECURE_SKIP_VERIFY` | | Accept self-signed certs |

## What It Collects (Read-Only)

- **Nodes**: status, CPU, RAM, disk, uptime, PVE version
- **Workloads**: VM/LXC inventory, status, resource usage
- **Storage**: backends, type, capacity, usage
- **Cluster**: membership, quorum status

## Releases & Docker Images

- **GitHub Releases**: Pre-built binaries for linux/amd64 and linux/arm64
- **GHCR**: `ghcr.io/kravitzai/forge-flow-friend/connector-agent:latest`

Releases are built automatically when a version tag (e.g. `v0.1.0`) is pushed.

## Security

- Outbound-only — no inbound ports needed
- Token-scoped — each connector has a unique, revocable token
- No plaintext passwords — API tokens recommended; passwords prompted securely
- Credentials stay local — Proxmox credentials never leave the connector host
- Non-root — runs as unprivileged user

## License

MIT
