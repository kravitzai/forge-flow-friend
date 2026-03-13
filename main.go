// ForgeAI Local Connector Agent — MVP
//
// A lightweight, outbound-only agent that polls a local infrastructure target
// (Proxmox, TrueNAS, or Nutanix) and sends normalized heartbeat + snapshot
// data to the ForgeAI backend.
//
// Usage (Proxmox):
//   CONNECTOR_TOKEN=fgc_... TARGET_TYPE=proxmox PROXMOX_BASE_URL=https://192.168.1.100:8006 \
//     PROXMOX_USERNAME=root@pam PROXMOX_PASSWORD=secret ./connector-agent
//
// Usage (TrueNAS):
//   CONNECTOR_TOKEN=fgc_... TARGET_TYPE=truenas TRUENAS_URL=https://192.168.1.50/api/v2.0 \
//     TRUENAS_API_KEY=1-xxxxxxxxxxxx ./connector-agent

package main

import (
	"bytes"
	
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPollInterval    = 30
	defaultHeartbeatSecs   = 30
	agentVersion           = "0.1.0"
	defaultBackendEndpoint = "https://yvtszwgcmgmqylmmybrh.supabase.co/functions/v1/connector-heartbeat"
)

// Config holds all runtime configuration
type Config struct {
	ConnectorToken     string
	BackendURL         string
	TargetType         string // "proxmox", "truenas", "nutanix"

	// Proxmox
	ProxmoxBaseURL     string
	ProxmoxUsername     string
	ProxmoxPassword    string
	ProxmoxTokenID     string
	ProxmoxTokenSecret string
	ProxmoxNode        string

	// TrueNAS
	TrueNASURL         string
	TrueNASAPIKey      string

	// Common
	PollIntervalSecs   int
	InsecureSkipVerify bool
	LogLevel           string
}

func loadConfig() (*Config, error) {
	c := &Config{
		ConnectorToken:     os.Getenv("CONNECTOR_TOKEN"),
		BackendURL:         os.Getenv("BACKEND_URL"),
		TargetType:         strings.ToLower(os.Getenv("TARGET_TYPE")),

		// Proxmox
		ProxmoxBaseURL:     strings.TrimRight(os.Getenv("PROXMOX_BASE_URL"), "/"),
		ProxmoxUsername:     os.Getenv("PROXMOX_USERNAME"),
		ProxmoxPassword:    os.Getenv("PROXMOX_PASSWORD"),
		ProxmoxTokenID:     os.Getenv("PROXMOX_TOKEN_ID"),
		ProxmoxTokenSecret: os.Getenv("PROXMOX_TOKEN_SECRET"),
		ProxmoxNode:        os.Getenv("PROXMOX_NODE"),

		// TrueNAS
		TrueNASURL:         strings.TrimRight(os.Getenv("TRUENAS_URL"), "/"),
		TrueNASAPIKey:      os.Getenv("TRUENAS_API_KEY"),

		LogLevel:           os.Getenv("LOG_LEVEL"),
	}

	if c.ConnectorToken == "" {
		return nil, fmt.Errorf("CONNECTOR_TOKEN is required")
	}
	if !strings.HasPrefix(c.ConnectorToken, "fgc_") {
		return nil, fmt.Errorf("CONNECTOR_TOKEN must start with fgc_")
	}

	// Default to proxmox for backward compatibility
	if c.TargetType == "" {
		c.TargetType = "proxmox"
	}

	// Validate per target type
	switch c.TargetType {
	case "proxmox":
		if c.ProxmoxBaseURL == "" {
			return nil, fmt.Errorf("PROXMOX_BASE_URL is required (e.g. https://192.168.1.100:8006)")
		}
		if c.ProxmoxUsername == "" && c.ProxmoxTokenID == "" {
			return nil, fmt.Errorf("PROXMOX_USERNAME or PROXMOX_TOKEN_ID is required")
		}
		if c.ProxmoxUsername != "" && c.ProxmoxPassword == "" {
			return nil, fmt.Errorf("PROXMOX_PASSWORD is required when using PROXMOX_USERNAME")
		}
		if c.ProxmoxTokenID != "" && c.ProxmoxTokenSecret == "" {
			return nil, fmt.Errorf("PROXMOX_TOKEN_SECRET is required when using PROXMOX_TOKEN_ID")
		}

	case "truenas":
		if c.TrueNASURL == "" {
			return nil, fmt.Errorf("TRUENAS_URL is required (e.g. https://192.168.1.50/api/v2.0)")
		}
		if c.TrueNASAPIKey == "" {
			return nil, fmt.Errorf("TRUENAS_API_KEY is required (generate in TrueNAS: Settings → API Keys → Add)")
		}

	case "nutanix":
		return nil, fmt.Errorf("nutanix target type is not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported TARGET_TYPE '%s' (supported: proxmox, truenas)", c.TargetType)
	}

	if c.BackendURL == "" {
		c.BackendURL = defaultBackendEndpoint
	}

	c.PollIntervalSecs = defaultPollInterval
	if v := os.Getenv("POLL_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 {
			c.PollIntervalSecs = n
		}
	}

	if v := os.Getenv("INSECURE_SKIP_VERIFY"); v == "true" || v == "1" {
		c.InsecureSkipVerify = true
	}

	return c, nil
}

// ── Collector interface ──

// Collector abstracts platform-specific snapshot collection
type Collector interface {
	// CollectAndSend collects a snapshot and sends it to the backend
	CollectAndSend(cfg *Config) error
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("[agent] ForgeAI Local Connector v%s starting", agentVersion)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("[config] %v", err)
	}

	log.Printf("[config] Backend URL: %s", cfg.BackendURL)
	log.Printf("[config] Target type: %s", cfg.TargetType)
	log.Printf("[config] Poll interval: %ds", cfg.PollIntervalSecs)
	if cfg.InsecureSkipVerify {
		log.Printf("[config] TLS verification DISABLED (self-signed)")
	}

	// Dispatch based on target type
	switch cfg.TargetType {
	case "proxmox":
		runProxmox(cfg)
	case "truenas":
		runTrueNAS(cfg)
	default:
		log.Fatalf("[config] unsupported target type: %s", cfg.TargetType)
	}
}

// ── Proxmox runner ──

func runProxmox(cfg *Config) {
	log.Printf("[config] Proxmox URL: %s", cfg.ProxmoxBaseURL)
	if cfg.ProxmoxNode != "" {
		log.Printf("[config] Limiting to node: %s", cfg.ProxmoxNode)
	}

	pve := NewProxmoxClient(cfg)

	if cfg.ProxmoxTokenID == "" {
		log.Printf("[proxmox] Authenticating as %s...", cfg.ProxmoxUsername)
		if err := pve.Authenticate(); err != nil {
			log.Fatalf("[proxmox] Authentication failed: %v", err)
		}
		log.Printf("[proxmox] Authentication successful")
	} else {
		log.Printf("[proxmox] Using API token: %s", cfg.ProxmoxTokenID)
	}

	sendInitialHeartbeat(cfg, proxmoxCapabilities())
	runLoop(cfg, func() { collectAndSendProxmox(cfg, pve) })
}

func proxmoxCapabilities() []string {
	return []string{
		"proxmox.read.health",
		"proxmox.read.workloads",
		"proxmox.read.storage",
		"proxmox.read.cluster",
	}
}

func collectAndSendProxmox(cfg *Config, pve *ProxmoxClient) {
	if cfg.ProxmoxTokenID == "" && pve.IsTicketExpired() {
		log.Printf("[proxmox] Ticket expired, re-authenticating...")
		if err := pve.Authenticate(); err != nil {
			log.Printf("[proxmox] Re-authentication failed: %v", err)
			_ = sendHeartbeat(cfg, proxmoxCapabilities())
			return
		}
	}

	snapshot, err := pve.CollectSnapshot()
	if err != nil {
		log.Printf("[collect] Snapshot collection failed: %v", err)
		_ = sendHeartbeat(cfg, proxmoxCapabilities())
		return
	}

	if err := sendProxmoxSnapshot(cfg, snapshot); err != nil {
		log.Printf("[send] Snapshot delivery failed: %v", err)
	} else {
		log.Printf("[send] Snapshot delivered: %d nodes, %d workloads, %d storage",
			len(snapshot.Nodes), len(snapshot.Workloads), len(snapshot.Storage))
	}
}

func sendProxmoxSnapshot(cfg *Config, data *SnapshotData) error {
	payload := map[string]interface{}{
		"type":          "snapshot",
		"schemaVersion": 1,
		"capabilities":  proxmoxCapabilities(),
		"snapshotData": map[string]interface{}{
			"nodes":     data.Nodes,
			"workloads": data.Workloads,
			"storage":   data.Storage,
			"cluster":   data.Cluster,
		},
		"alerts":       data.Alerts,
		"collectedAt":  data.CollectedAt,
		"agentVersion": agentVersion,
	}
	return postToBackend(cfg, payload)
}

// ── TrueNAS runner ──

func runTrueNAS(cfg *Config) {
	log.Printf("[config] TrueNAS URL: %s", cfg.TrueNASURL)

	tnas := NewTrueNASClient(cfg)

	// Verify connectivity
	log.Printf("[truenas] Verifying API access...")
	sysInfo, err := tnas.collectSystemInfo()
	if err != nil {
		log.Fatalf("[truenas] API access failed: %v", err)
	}
	log.Printf("[truenas] Connected to %s (%s) — %s", sysInfo.Hostname, sysInfo.SystemType, sysInfo.Version)

	sendInitialHeartbeat(cfg, truenasCapabilities())
	runLoop(cfg, func() { collectAndSendTrueNAS(cfg, tnas) })
}

func truenasCapabilities() []string {
	return []string{
		"truenas.read.health",
		"truenas.read.pools",
		"truenas.read.datasets",
		"truenas.read.snapshots",
		"truenas.read.replication",
		"truenas.read.shares",
		"truenas.read.alerts",
	}
}

func collectAndSendTrueNAS(cfg *Config, tnas *TrueNASClient) {
	snapshot, err := tnas.CollectSnapshot()
	if err != nil {
		log.Printf("[collect] Snapshot collection failed: %v", err)
		_ = sendHeartbeat(cfg, truenasCapabilities())
		return
	}

	if err := sendTrueNASSnapshot(cfg, snapshot); err != nil {
		log.Printf("[send] Snapshot delivery failed: %v", err)
	} else {
		poolCount := len(snapshot.Pools)
		dsCount := len(snapshot.Datasets)
		shareCount := len(snapshot.Shares)
		alertCount := len(snapshot.Alerts)
		log.Printf("[send] Snapshot delivered: %d pools, %d datasets, %d shares, %d alerts",
			poolCount, dsCount, shareCount, alertCount)
	}
}

func sendTrueNASSnapshot(cfg *Config, data *TrueNASSnapshotData) error {
	payload := map[string]interface{}{
		"type":          "snapshot",
		"schemaVersion": 1,
		"capabilities":  truenasCapabilities(),
		"snapshotData": map[string]interface{}{
			"system":      data.System,
			"pools":       data.Pools,
			"datasets":    data.Datasets,
			"snapshots":   data.Snapshots,
			"replication": data.Replication,
			"shares":      data.Shares,
		},
		"alerts":       data.Alerts,
		"collectedAt":  data.CollectedAt,
		"agentVersion": agentVersion,
	}
	return postToBackend(cfg, payload)
}

// ── Shared lifecycle ──

func sendInitialHeartbeat(cfg *Config, capabilities []string) {
	log.Printf("[agent] Sending initial heartbeat...")
	if err := sendHeartbeat(cfg, capabilities); err != nil {
		log.Printf("[agent] WARNING: Initial heartbeat failed: %v", err)
		log.Printf("[agent] Will retry on next cycle")
	} else {
		log.Printf("[agent] Initial heartbeat acknowledged")
	}
}

func runLoop(cfg *Config, collectFn func()) {
	ticker := time.NewTicker(time.Duration(cfg.PollIntervalSecs) * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Collect immediately
	go collectFn()

	for {
		select {
		case <-ticker.C:
			go collectFn()
		case sig := <-sigCh:
			log.Printf("[agent] Received %v, shutting down gracefully", sig)
			return
		}
	}
}

// ── Backend communication ──

func sendHeartbeat(cfg *Config, capabilities []string) error {
	payload := map[string]interface{}{
		"type":         "heartbeat",
		"agentVersion": agentVersion,
		"capabilities": capabilities,
	}
	return postToBackend(cfg, payload)
}

func postToBackend(cfg *Config, payload map[string]interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.BackendURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", cfg.ConnectorToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 {
		return fmt.Errorf("authentication failed — token may be invalid or revoked")
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("connector has been revoked by administrator")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
