// ForgeAI Local Connector Agent — MVP
//
// A lightweight, outbound-only agent that polls a local Proxmox VE instance
// and sends normalized heartbeat + snapshot data to the ForgeAI backend.
//
// Usage:
//   CONNECTOR_TOKEN=fgc_... PROXMOX_BASE_URL=https://192.168.1.100:8006 \
//     PROXMOX_USERNAME=root@pam PROXMOX_PASSWORD=secret ./connector-agent

package main

import (
	"bytes"
	"crypto/tls"
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
	ProxmoxBaseURL     string
	ProxmoxUsername     string
	ProxmoxPassword    string
	ProxmoxTokenID     string // alternative: API token auth
	ProxmoxTokenSecret string
	ProxmoxNode        string // optional: limit to single node
	PollIntervalSecs   int
	InsecureSkipVerify bool
	LogLevel           string
}

func loadConfig() (*Config, error) {
	c := &Config{
		ConnectorToken:     os.Getenv("CONNECTOR_TOKEN"),
		BackendURL:         os.Getenv("BACKEND_URL"),
		ProxmoxBaseURL:     strings.TrimRight(os.Getenv("PROXMOX_BASE_URL"), "/"),
		ProxmoxUsername:     os.Getenv("PROXMOX_USERNAME"),
		ProxmoxPassword:    os.Getenv("PROXMOX_PASSWORD"),
		ProxmoxTokenID:     os.Getenv("PROXMOX_TOKEN_ID"),
		ProxmoxTokenSecret: os.Getenv("PROXMOX_TOKEN_SECRET"),
		ProxmoxNode:        os.Getenv("PROXMOX_NODE"),
		LogLevel:           os.Getenv("LOG_LEVEL"),
	}

	if c.ConnectorToken == "" {
		return nil, fmt.Errorf("CONNECTOR_TOKEN is required")
	}
	if !strings.HasPrefix(c.ConnectorToken, "fgc_") {
		return nil, fmt.Errorf("CONNECTOR_TOKEN must start with fgc_")
	}
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

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("[agent] ForgeAI Local Connector v%s starting", agentVersion)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("[config] %v", err)
	}

	log.Printf("[config] Backend URL: %s", cfg.BackendURL)
	log.Printf("[config] Proxmox URL: %s", cfg.ProxmoxBaseURL)
	log.Printf("[config] Poll interval: %ds", cfg.PollIntervalSecs)
	if cfg.InsecureSkipVerify {
		log.Printf("[config] TLS verification DISABLED for Proxmox (self-signed)")
	}
	if cfg.ProxmoxNode != "" {
		log.Printf("[config] Limiting to node: %s", cfg.ProxmoxNode)
	}

	// Create Proxmox client
	pve := NewProxmoxClient(cfg)

	// Authenticate to Proxmox
	if cfg.ProxmoxTokenID == "" {
		log.Printf("[proxmox] Authenticating as %s...", cfg.ProxmoxUsername)
		if err := pve.Authenticate(); err != nil {
			log.Fatalf("[proxmox] Authentication failed: %v", err)
		}
		log.Printf("[proxmox] Authentication successful")
	} else {
		log.Printf("[proxmox] Using API token: %s", cfg.ProxmoxTokenID)
	}

	// Send initial heartbeat
	log.Printf("[agent] Sending initial heartbeat...")
	if err := sendHeartbeat(cfg); err != nil {
		log.Printf("[agent] WARNING: Initial heartbeat failed: %v", err)
		log.Printf("[agent] Will retry on next cycle")
	} else {
		log.Printf("[agent] Initial heartbeat acknowledged")
	}

	// Main loop
	ticker := time.NewTicker(time.Duration(cfg.PollIntervalSecs) * time.Second)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Collect immediately, then on ticker
	go collectAndSend(cfg, pve)

	for {
		select {
		case <-ticker.C:
			go collectAndSend(cfg, pve)
		case sig := <-sigCh:
			log.Printf("[agent] Received %v, shutting down gracefully", sig)
			return
		}
	}
}

func collectAndSend(cfg *Config, pve *ProxmoxClient) {
	// Re-authenticate if using password auth and ticket expired
	if cfg.ProxmoxTokenID == "" && pve.IsTicketExpired() {
		log.Printf("[proxmox] Ticket expired, re-authenticating...")
		if err := pve.Authenticate(); err != nil {
			log.Printf("[proxmox] Re-authentication failed: %v", err)
			_ = sendHeartbeat(cfg) // still heartbeat even if collection fails
			return
		}
	}

	snapshot, err := pve.CollectSnapshot()
	if err != nil {
		log.Printf("[collect] Snapshot collection failed: %v", err)
		_ = sendHeartbeat(cfg)
		return
	}

	if err := sendSnapshot(cfg, snapshot); err != nil {
		log.Printf("[send] Snapshot delivery failed: %v", err)
	} else {
		nodeCount := len(snapshot.Nodes)
		workloadCount := len(snapshot.Workloads)
		log.Printf("[send] Snapshot delivered: %d nodes, %d workloads, %d storage",
			nodeCount, workloadCount, len(snapshot.Storage))
	}
}

// ── Backend communication ──

func sendHeartbeat(cfg *Config) error {
	payload := map[string]interface{}{
		"type":         "heartbeat",
		"agentVersion": agentVersion,
		"capabilities": []string{
			"proxmox.read.health",
			"proxmox.read.workloads",
			"proxmox.read.storage",
			"proxmox.read.cluster",
		},
	}
	return postToBackend(cfg, payload)
}

func sendSnapshot(cfg *Config, data *SnapshotData) error {
	payload := map[string]interface{}{
		"type":          "snapshot",
		"schemaVersion": 1,
		"capabilities": []string{
			"proxmox.read.health",
			"proxmox.read.workloads",
			"proxmox.read.storage",
			"proxmox.read.cluster",
		},
		"snapshotData": map[string]interface{}{
			"nodes":     data.Nodes,
			"workloads": data.Workloads,
			"storage":   data.Storage,
			"cluster":   data.Cluster,
		},
		"alerts":      data.Alerts,
		"collectedAt": data.CollectedAt,
		"agentVersion": agentVersion,
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
