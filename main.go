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
	"context"
	"fmt"
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
	// Handle --version flag before any other initialization
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Printf("ForgeAI Connector Host %s\n", HostVersion)
			os.Exit(0)
		}
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	// Initialize audit logger early — use env LOG_LEVEL or default "info"
	configLevel := os.Getenv("LOG_LEVEL")
	if configLevel == "" {
		configLevel = "info"
	}
	InitAuditLogger(configLevel)

	execPath, _ := os.Executable()
	audit.Info("host.startup", fmt.Sprintf("ForgeAI Connector Host v%s starting", HostVersion),
		F("executable", execPath),
		F("pid", os.Getpid()))

	// ── Read remote action opt-in flags from environment ──
	remoteLiveQuery := envBool("FORGEAI_REMOTE_LIVE_QUERY")
	remoteRestart := envBool("FORGEAI_REMOTE_RESTART")
	// Convenience flag: --enable-remote-actions sets both
	if envBool("FORGEAI_REMOTE_ACTIONS") {
		remoteLiveQuery = true
		remoteRestart = true
	}

	hybridMode := envBool("FORGEAI_HYBRID_MODE")
	if hybridMode {
		audit.Info("host.startup",
			"Hybrid Mode enabled — local DB will be activated")
	}

	// ── Local API token ──
	localAPIToken := os.Getenv("FORGEAI_LOCAL_API_TOKEN")
	if localAPIToken == "" && hybridMode {
		localAPIToken = generateID() // random per startup
		audit.Info("local_api.start",
			"Local API token generated (set FORGEAI_LOCAL_API_TOKEN to pin)",
			F("token", localAPIToken))
	}

	// ── Parse change-operation policy from environment ──
	changePolicyConfig := ParseChangePolicyFromEnv()
	changePolicyConfig.LogStartupSummary()

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
		audit.Warn("host.config_loaded", "Force-reset: Clearing persisted enrollment state")
		resetFiles := []string{
			filepath.Join(configDir, stateFileName),
			filepath.Join(configDir, keyFileName),
		}
		for _, f := range resetFiles {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				audit.Error("host.config_loaded", "Failed to remove file", F("path", f), Err(err))
			} else if err == nil {
				audit.Info("host.config_loaded", "Removed file", F("path", f))
			}
		}
		// Remove all secret files
		secretsDir := filepath.Join(configDir, secretsDirName)
		entries, _ := os.ReadDir(secretsDir)
		for _, e := range entries {
			p := filepath.Join(secretsDir, e.Name())
			if err := os.Remove(p); err == nil {
				audit.Info("host.config_loaded", "Removed secret file", F("path", p))
			}
		}
		audit.Info("host.config_loaded", "State reset complete — host will re-enroll on this run")
	}

	// Initialize encrypted store
	store, err := NewStore(configDir, hybridMode)
	if err != nil {
		audit.Critical("host.startup", "Store initialization failed", Err(err))
		os.Exit(1)
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
	supervisor.RegisterAdapter("bluefield", NewBlueFieldAdapter)
	supervisor.RegisterAdapter("dell-idrac", NewIdracAdapter)

	// ── Enrollment / State Loading ──
	enrollmentToken := os.Getenv("FORGEAI_ENROLLMENT_TOKEN")
	legacyCfg := detectLegacyEnvConfig()

	if enrollmentToken != "" {
		// Enrollment flow
		state, err := MustEnroll(store, backendURL)
		if err != nil {
			audit.Critical("enrollment.failed", "Enrollment failed", Err(err))
			os.Exit(1)
		}
		supervisor.InitializeWithState(state)
		audit.SetHostID(state.Identity.HostID)
		audit.Info("enrollment.success", "Host enrolled",
			F("label", state.Identity.Label), F("host_id_short", state.Identity.HostID[:12]))
	} else {
		// Legacy / existing state flow
		if err := supervisor.Initialize(legacyCfg); err != nil {
			audit.Critical("host.startup", "Supervisor initialization failed", Err(err))
			os.Exit(1)
		}
		// Set host ID if state was loaded
		if state := supervisor.GetState(); state != nil && state.Identity.HostID != "" {
			audit.SetHostID(state.Identity.HostID)
		}
	}

	audit.Info("host.config_loaded", "Targets configured", F("count", supervisor.TargetCount()))

	// Apply remote action flags to host config
	if state := supervisor.GetState(); state != nil {
		if remoteLiveQuery {
			state.Config.RemoteLiveQueryEnabled = true
		}
		if remoteRestart {
			state.Config.RemoteRestartEnabled = true
		}
		if remoteLiveQuery || remoteRestart {
			audit.Info("host.config_loaded", "Remote actions configured",
				F("live_query", state.Config.RemoteLiveQueryEnabled),
				F("restart", state.Config.RemoteRestartEnabled))
		} else {
			audit.Info("host.config_loaded", "Remote actions disabled (set FORGEAI_REMOTE_LIVE_QUERY=true and/or FORGEAI_REMOTE_RESTART=true to enable)")
		}

		// Update audit logger level from persisted config
		audit.SetLevel(parseLogLevel(state.Config.LogLevel))
	}

	// ── Upload Queue ──
	uqCfg := DefaultUploadQueueConfig()
	uqCfg.LocalDB = store.LocalDB()
	uploadQueue := NewUploadQueue(backend, uqCfg)
	uploadQueue.Start()
	supervisor.SetUploadQueue(uploadQueue)

	// ── Metrics Logger ──
	metricsStopCh := make(chan struct{})
	StartMetricsLogger(5*time.Minute, metricsStopCh)

	// ── Hybrid Mode: local DB retention goroutine ──
	var retentionStopCh chan struct{}
	if ldb := store.LocalDB(); ldb != nil {
		retentionStopCh = make(chan struct{})
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-retentionStopCh:
					return
				case <-ticker.C:
					maxDays := 7
					if st := supervisor.GetState(); st != nil {
						if d := st.Config.LocalRetentionDays; d > 0 {
							maxDays = d
						}
					}
					if _, err := ldb.RunRetention(maxDays); err != nil {
						audit.Error("local_db.retention",
							"Retention run failed", Err(err))
					}
				}
			}
		}()
		audit.Info("local_db.retention",
			"Retention goroutine started",
			F("default_days", 7))
	}

	// Reconcile — starts workers for all enabled targets
	if err := supervisor.Reconcile(); err != nil {
		audit.Critical("host.startup", "Reconciliation failed", Err(err))
		os.Exit(1)
	}

	if ldb := store.LocalDB(); ldb != nil {
		stats := ldb.Stats()
		audit.Info("local_db.stats", "Local DB ready",
			F("snapshot_count", stats["snapshot_count"]),
			F("unsynced_count", stats["unsynced_count"]))
	}

	// ── Local API Server (Hybrid Mode) ──
	var localAPI *LocalAPIServer
	if ldb := store.LocalDB(); ldb != nil {
		bind := os.Getenv("FORGEAI_LOCAL_API_BIND")
		if bind == "" {
			bind = defaultLocalAPIBind
		}
		localAPI = NewLocalAPIServer(
			ldb, supervisor, localAPIToken, bind)
		localAPI.Start()
	}

	if localAPI != nil {
		supervisor.SetLocalAPIURL(localAPI.LANURL())
	}

	audit.Info("host.startup", "Active workers started", F("count", supervisor.WorkerCount()))

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

		syncManager = NewSyncManager(backend, store, supervisor, changePolicyConfig)
		syncManager.Start(syncInterval)
		audit.Info("sync.reconciled", "Desired-state sync enabled", F("interval", syncInterval.String()))
	} else {
		audit.Warn("sync.error", "No connector token — desired-state sync disabled")
		audit.Info("host.config_loaded", "Enroll the host to enable remote management")
	}

	// ── Update Manager ──
	var updateManager *UpdateManager
	updateMgr, err := NewUpdateManager(store, backend, supervisor, configDir)
	if err != nil {
		audit.Warn("update.check", "Update manager init failed", Err(err))
	} else {
		updateManager = updateMgr

		// Check for pending rollback from a previous failed update
		if updateManager.CheckRollbackNeeded() {
			audit.Warn("update.rollback", "Pending rollback detected — initiating automatic rollback")
			if err := updateManager.Rollback(); err != nil {
				audit.Error("update.rollback", "Rollback failed", Err(err))
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
			updateCtx, updateCancel := context.WithCancel(context.Background())
			defer updateCancel()

			go func() {
				checkInterval := 6 * time.Hour
				ticker := time.NewTicker(checkInterval)
				defer ticker.Stop()

				for {
					select {
					case <-updateCtx.Done():
						return
					case <-ticker.C:
						manifest, err := updateManager.CheckForUpdate(updatePolicy)
						if err != nil {
							audit.Error("update.check", "Update check error", Err(err))
							continue
						}
						if manifest != nil {
							audit.Info("update.available", "Update available",
								F("version", manifest.Version), F("channel", manifest.Channel))
							if err := updateManager.StageUpdate(manifest); err != nil {
								audit.Error("update.staged", "Stage failed", Err(err))
							}
						}
					}
				}
			}()
			audit.Info("update.check", "Update checks enabled", F("policy", string(updatePolicy)))
		} else {
			audit.Info("update.check", "Auto-updates disabled (policy: none)")
		}
	}

	// Wait for shutdown signal
	sig := <-sigCh

	audit.Info("host.shutdown", fmt.Sprintf("Received %v, shutting down gracefully...", sig))

	// Stop metrics logger
	close(metricsStopCh)

	// Final metrics dump
	agentMetrics.DumpToLog()

	if syncManager != nil {
		syncManager.Stop()
	}
	if updateManager != nil {
		updateManager.DrainWorkers(10 * time.Second)
	} else {
		supervisor.Shutdown()
	}

	// Stop upload queue after workers are done
	uploadQueue.Stop()

	if localAPI != nil {
		localAPI.Stop()
	}

	if retentionStopCh != nil {
		close(retentionStopCh)
	}
	if ldb := store.LocalDB(); ldb != nil {
		if err := ldb.Close(); err != nil {
			audit.Warn("local_db.shutdown",
				"Local DB close error", Err(err))
		} else {
			audit.Info("local_db.shutdown",
				"Local DB closed cleanly")
		}
	}

	audit.Info("host.shutdown", "Shutdown complete")
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
		audit.Warn("host.config_loaded", "CONNECTOR_TOKEN does not start with fgc_")
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
			audit.Warn("host.config_loaded", "PROXMOX_BASE_URL not set for proxmox target")
			return nil
		}
	case "truenas":
		if c.TrueNASURL == "" || c.TrueNASAPIKey == "" {
			audit.Warn("host.config_loaded", "TRUENAS_URL or TRUENAS_API_KEY not set")
			return nil
		}
	default:
		if !IsValidTargetType(targetType) {
			audit.Warn("host.config_loaded", "Unsupported TARGET_TYPE", F("target_type", targetType))
			return nil
		}
	}

	audit.Info("host.config_loaded", "Legacy env config detected", F("target_type", targetType))

	switch targetType {
	case "proxmox":
		audit.Info("host.config_loaded", "Proxmox endpoint", F("url", c.ProxmoxBaseURL))
		if c.ProxmoxNode != "" {
			audit.Info("host.config_loaded", "Limiting to node", F("node", c.ProxmoxNode))
		}
	case "truenas":
		audit.Info("host.config_loaded", "TrueNAS endpoint", F("url", c.TrueNASURL))
	}

	if c.InsecureSkipVerify {
		audit.Warn("host.config_loaded", "TLS verification DISABLED (self-signed)")
	}

	return c
}

// envBool returns true if the named environment variable is set to "true" or "1".
func envBool(name string) bool {
	v := os.Getenv(name)
	return v == "true" || v == "1"
}
