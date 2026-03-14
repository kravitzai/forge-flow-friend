// ForgeAI Connector Host — Entrypoint
//
// The Connector Host is a long-running supervisor process that manages
// per-target workers. It supports:
//   - Secure host enrollment with bootstrap token
//   - Desired-state sync from ForgeAI backend
//   - Multiple concurrent targets (proxmox, truenas, etc.)
//   - Independent worker lifecycle per target
//   - Encrypted local config/secret storage
//   - Legacy single-target env-var mode for backward compatibility
//
// Usage (Enrollment — recommended):
//   FORGEAI_ENROLLMENT_TOKEN=fgbt_... ./connector-agent
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
	"time"
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

	// Determine backend URL
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = defaultBackendBase
	}
	backend := NewBackendClient(backendURL)

	// Create supervisor
	supervisor := NewSupervisor(store, backend)

	// Register available adapters
	supervisor.RegisterAdapter("proxmox", NewProxmoxAdapter)
	supervisor.RegisterAdapter("truenas", NewTrueNASAdapter)

	// ── Enrollment / State Loading ──
	// Priority:
	//   1. Existing enrolled state (host.json.enc)
	//   2. Enrollment via FORGEAI_ENROLLMENT_TOKEN
	//   3. Legacy env-var migration (CONNECTOR_TOKEN + TARGET_TYPE)
	//   4. Bare enrollment via CONNECTOR_TOKEN (no target type = enroll-only)

	enrollmentToken := os.Getenv("FORGEAI_ENROLLMENT_TOKEN")
	legacyCfg := detectLegacyEnvConfig()

	if enrollmentToken != "" {
		// Enrollment flow
		state, err := MustEnroll(store, backendURL)
		if err != nil {
			log.Fatalf("[enrollment] %v", err)
		}
		supervisor.InitializeWithState(state)
		log.Printf("[host] Enrolled host: %s (%s)", state.Identity.Label, state.Identity.HostID[:12])
	} else {
		// Legacy / existing state flow
		if err := supervisor.Initialize(legacyCfg); err != nil {
			log.Fatalf("[supervisor] Initialization failed: %v", err)
		}
	}

	log.Printf("[host] Configured targets: %d", supervisor.TargetCount())

	// Reconcile — starts workers for all enabled targets
	if err := supervisor.Reconcile(); err != nil {
		log.Fatalf("[supervisor] Reconciliation failed: %v", err)
	}

	log.Printf("[host] Active workers: %d", supervisor.WorkerCount())

	// ── Desired-State Sync Loop ──
	// Only start if the host is enrolled with a valid connector token
	var syncManager *SyncManager
	if token := supervisor.GetConnectorToken(); token != "" {
		syncInterval := 60 * time.Second
		if state := supervisor.GetState(); state != nil && state.Config.SyncIntervalSecs > 0 {
			syncInterval = time.Duration(state.Config.SyncIntervalSecs) * time.Second
		}

		syncManager = NewSyncManager(backend, store, supervisor)
		syncManager.Start(syncInterval)
		log.Printf("[host] Desired-state sync enabled (interval: %v)", syncInterval)
	} else {
		log.Printf("[host] No connector token — desired-state sync disabled")
		log.Printf("[host] Enroll the host to enable remote management")
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("[host] Received %v, shutting down gracefully...", sig)

	if syncManager != nil {
		syncManager.Stop()
	}
	supervisor.Shutdown()
	log.Printf("[host] Shutdown complete")
}

// detectLegacyEnvConfig checks for the old single-target environment
// variable configuration and returns a Config if found.
func detectLegacyEnvConfig() *Config {
	token := os.Getenv("CONNECTOR_TOKEN")
	if token == "" {
		return nil
	}

	// If FORGEAI_ENROLLMENT_TOKEN is set, don't treat CONNECTOR_TOKEN as legacy
	if os.Getenv("FORGEAI_ENROLLMENT_TOKEN") != "" {
		return nil
	}

	if !strings.HasPrefix(token, "fgc_") {
		log.Printf("[config] WARNING: CONNECTOR_TOKEN does not start with fgc_")
	}

	targetType := strings.ToLower(os.Getenv("TARGET_TYPE"))
	if targetType == "" {
		// No target type = just a token for enrollment, not legacy mode
		return nil
	}

	c := &Config{
		ConnectorToken:      token,
		BackendURL:          os.Getenv("BACKEND_URL"),
		TargetType:          targetType,
		ProxmoxBaseURL:      strings.TrimRight(os.Getenv("PROXMOX_BASE_URL"), "/"),
		ProxmoxUsername:     os.Getenv("PROXMOX_USERNAME"),
		ProxmoxPassword:    os.Getenv("PROXMOX_PASSWORD"),
		ProxmoxTokenID:     os.Getenv("PROXMOX_TOKEN_ID"),
		ProxmoxTokenSecret: os.Getenv("PROXMOX_TOKEN_SECRET"),
		ProxmoxNode:        os.Getenv("PROXMOX_NODE"),
		TrueNASURL:         strings.TrimRight(os.Getenv("TRUENAS_URL"), "/"),
		TrueNASAPIKey:      os.Getenv("TRUENAS_API_KEY"),
		LogLevel:           os.Getenv("LOG_LEVEL"),
	}

	if c.BackendURL == "" {
		c.BackendURL = defaultBackendBase + defaultHeartbeatPath
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
