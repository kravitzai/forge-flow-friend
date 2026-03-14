// ForgeAI Connector Host — Entrypoint
//
// The Connector Host is a long-running supervisor process that manages
// per-target workers. It supports:
//   - Multiple concurrent targets (proxmox, truenas, etc.)
//   - Independent worker lifecycle per target
//   - Encrypted local config/secret storage
//   - Legacy single-target env-var mode for backward compatibility
//
// Usage (Host mode — multi-target):
//   ./connector-agent --config-dir /etc/forgeai
//
// Usage (Legacy mode — single target via env vars):
//   CONNECTOR_TOKEN=fgc_... TARGET_TYPE=proxmox PROXMOX_BASE_URL=... ./connector-agent

package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("[host] ForgeAI Connector Host v%s starting", HostVersion)

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = defaultConfigDir
	}

	// Initialize encrypted store
	store, err := NewStore(configDir)
	if err != nil {
		log.Fatalf("[store] Initialization failed: %v", err)
	}

	// Detect mode: check if there's existing host state, or fall back to legacy env
	legacyCfg := detectLegacyEnvConfig()

	// Initialize backend client
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" && legacyCfg != nil {
		backendURL = legacyCfg.BackendURL
	}
	backend := NewBackendClient(backendURL)

	// Create supervisor
	supervisor := NewSupervisor(store, backend)

	// Register available adapters
	supervisor.RegisterAdapter("proxmox", NewProxmoxAdapter)
	supervisor.RegisterAdapter("truenas", NewTrueNASAdapter)

	// Initialize (loads state or migrates legacy config)
	if err := supervisor.Initialize(legacyCfg); err != nil {
		log.Fatalf("[supervisor] Initialization failed: %v", err)
	}

	log.Printf("[host] Configured targets: %d", supervisor.TargetCount())

	// Reconcile — starts workers for all enabled targets
	if err := supervisor.Reconcile(); err != nil {
		log.Fatalf("[supervisor] Reconciliation failed: %v", err)
	}

	log.Printf("[host] Active workers: %d", supervisor.WorkerCount())

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("[host] Received %v, shutting down gracefully...", sig)
	supervisor.Shutdown()
	log.Printf("[host] Shutdown complete")
}

// detectLegacyEnvConfig checks for the old single-target environment
// variable configuration and returns a Config if found.
// Returns nil if no legacy config is detected.
func detectLegacyEnvConfig() *Config {
	token := os.Getenv("CONNECTOR_TOKEN")
	if token == "" {
		return nil
	}

	if !strings.HasPrefix(token, "fgc_") {
		log.Printf("[config] WARNING: CONNECTOR_TOKEN does not start with fgc_")
	}

	targetType := strings.ToLower(os.Getenv("TARGET_TYPE"))
	if targetType == "" {
		targetType = "proxmox"
	}

	c := &Config{
		ConnectorToken:     token,
		BackendURL:         os.Getenv("BACKEND_URL"),
		TargetType:         targetType,

		ProxmoxBaseURL:     strings.TrimRight(os.Getenv("PROXMOX_BASE_URL"), "/"),
		ProxmoxUsername:    os.Getenv("PROXMOX_USERNAME"),
		ProxmoxPassword:   os.Getenv("PROXMOX_PASSWORD"),
		ProxmoxTokenID:    os.Getenv("PROXMOX_TOKEN_ID"),
		ProxmoxTokenSecret: os.Getenv("PROXMOX_TOKEN_SECRET"),
		ProxmoxNode:       os.Getenv("PROXMOX_NODE"),

		TrueNASURL:    strings.TrimRight(os.Getenv("TRUENAS_URL"), "/"),
		TrueNASAPIKey: os.Getenv("TRUENAS_API_KEY"),

		LogLevel: os.Getenv("LOG_LEVEL"),
	}

	if c.BackendURL == "" {
		c.BackendURL = defaultBackendEndpoint
	}

	c.PollIntervalSecs = 30
	if v := os.Getenv("POLL_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 {
			c.PollIntervalSecs = n
		}
	}

	if v := os.Getenv("INSECURE_SKIP_VERIFY"); v == "true" || v == "1" {
		c.InsecureSkipVerify = true
	}

	// Validate basic requirements per target type
	switch targetType {
	case "proxmox":
		if c.ProxmoxBaseURL == "" {
			log.Printf("[config] WARNING: PROXMOX_BASE_URL not set for proxmox target")
			return nil
		}
	case "truenas":
		if c.TrueNASURL == "" || c.TrueNASAPIKey == "" {
			log.Printf("[config] WARNING: TRUENAS_URL or TRUENAS_API_KEY not set")
			return nil
		}
	default:
		if !IsValidTargetType(targetType) {
			log.Printf("[config] WARNING: Unsupported TARGET_TYPE: %s", targetType)
			return nil
		}
	}

	log.Printf("[config] Legacy env config detected: target_type=%s", targetType)

	// Only print non-secret config
	switch targetType {
	case "proxmox":
		log.Printf("[config] Proxmox URL: %s", c.ProxmoxBaseURL)
		if c.ProxmoxNode != "" {
			log.Printf("[config] Limiting to node: %s", c.ProxmoxNode)
		}
	case "truenas":
		log.Printf("[config] TrueNAS URL: %s", c.TrueNASURL)
	}

	if c.InsecureSkipVerify {
		log.Printf("[config] TLS verification DISABLED (self-signed)")
	}

	return c
}
