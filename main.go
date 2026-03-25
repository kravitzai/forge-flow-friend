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
	"path/filepath"
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

	// ── Check for --force-reset-state flag ──
	forceReset := false
	for _, arg := range os.Args[1:] {
		if arg == "--force-reset-state" {
			forceReset = true
		}
	}

	if forceReset {
		log.Printf("[host] ⚠️  --force-reset-state: Clearing persisted enrollment state...")
		resetFiles := []string{
			filepath.Join(configDir, stateFileName),
			filepath.Join(configDir, keyFileName),
		}
		for _, f := range resetFiles {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				log.Printf("[host]   Failed to remove %s: %v", f, err)
			} else if err == nil {
				log.Printf("[host]   Removed: %s", f)
			}
		}
		// Remove all secret files
		secretsDir := filepath.Join(configDir, secretsDirName)
		entries, _ := os.ReadDir(secretsDir)
		for _, e := range entries {
			p := filepath.Join(secretsDir, e.Name())
			if err := os.Remove(p); err == nil {
				log.Printf("[host]   Removed: %s", p)
			}
		}
		log.Printf("[host] State reset complete. Host will re-enroll on this run.")
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

	// Register available adapters — built-in only, no dynamic plugins
	supervisor.RegisterAdapter("proxmox", NewProxmoxAdapter)
	supervisor.RegisterAdapter("truenas", NewTrueNASAdapter)
	supervisor.RegisterAdapter("nutanix", NewNutanixAdapter)
	supervisor.RegisterAdapter("prometheus", NewPrometheusAdapter)
	supervisor.RegisterAdapter("grafana", NewGrafanaAdapter)
	supervisor.RegisterAdapter("ollama", NewOllamaAdapter)
	supervisor.RegisterAdapter("generic-http", NewGenericHTTPAdapter)
	supervisor.RegisterAdapter("open-webui", NewOpenwebuiAdapter)
	supervisor.RegisterAdapter("pure-storage", NewPureStorageAdapter)
	supervisor.RegisterAdapter("netapp-ontap", NewNetAppONTAPAdapter)
	supervisor.RegisterAdapter("powerstore", NewPowerStoreAdapter)
	supervisor.RegisterAdapter("powermax", NewPowerMaxAdapter)
	supervisor.RegisterAdapter("powerflex", NewPowerFlexAdapter)
	supervisor.RegisterAdapter("kubernetes", NewKubernetesAdapter)
	supervisor.RegisterAdapter("nexus", NewNexusAdapter)
	supervisor.RegisterAdapter("ndfc", NewNdfcAdapter)
	supervisor.RegisterAdapter("brocade", NewBrocadeAdapter)
	supervisor.RegisterAdapter("powerswitch", NewPowerSwitchAdapter)
	supervisor.RegisterAdapter("infiniband", NewInfiniBandAdapter)

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
	// Set up signal channel early for use by update goroutine
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── Desired-State Sync Loop ──
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

	// ── Update Manager ──
	var updateManager *UpdateManager
	updateMgr, err := NewUpdateManager(store, backend, supervisor, configDir)
	if err != nil {
		log.Printf("[host] WARNING: Update manager init failed: %v", err)
	} else {
		updateManager = updateMgr

		// Check for pending rollback from a previous failed update
		if updateManager.CheckRollbackNeeded() {
			log.Printf("[host] Pending rollback detected — initiating automatic rollback")
			if err := updateManager.Rollback(); err != nil {
				log.Printf("[host] WARNING: Rollback failed: %v", err)
			}
		} else {
			// Confirm health if this is a new version that just started
			updateManager.ConfirmHealth()
		}

		// Start periodic update checks if policy allows
		hostState := supervisor.GetState()
		updatePolicy := UpdatePolicy("none")
		if hostState != nil && hostState.Update.UpdatePolicy != "" {
			updatePolicy = UpdatePolicy(hostState.Update.UpdatePolicy)
		}

		if updatePolicy != UpdatePolicyNone {
			go func() {
				checkInterval := 6 * time.Hour
				ticker := time.NewTicker(checkInterval)
				defer ticker.Stop()

				for {
					select {
					case <-sigCh:
						return
					case <-ticker.C:
						manifest, err := updateManager.CheckForUpdate(updatePolicy)
						if err != nil {
							log.Printf("[updater] Update check error: %v", err)
							continue
						}
						if manifest != nil {
							log.Printf("[updater] Update available: %s (channel: %s)", manifest.Version, manifest.Channel)
							if err := updateManager.StageUpdate(manifest); err != nil {
								log.Printf("[updater] Stage failed: %v", err)
							}
						}
					}
				}
			}()
			log.Printf("[host] Update checks enabled (policy: %s)", updatePolicy)
		} else {
			log.Printf("[host] Auto-updates disabled (policy: none)")
		}
	}

	// Wait for shutdown signal
	sig := <-sigCh

	log.Printf("[host] Received %v, shutting down gracefully...", sig)

	if syncManager != nil {
		syncManager.Stop()
	}
	if updateManager != nil {
		// Drain workers before potential update apply
		updateManager.DrainWorkers(10 * time.Second)
	} else {
		supervisor.Shutdown()
	}
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
