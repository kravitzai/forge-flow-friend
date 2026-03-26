// ForgeAI Connector Host — Desired-State Sync
//
// Implements polling-based desired-state synchronization from the
// ForgeAI backend. The host periodically fetches its desired target
// profiles and reconciles them against running workers.
//
// The sync payload is config-only — no executable code, no task
// payloads, no arbitrary plugin references.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// contains is a case-insensitive substring check for error classification.
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// ── Desired-State Payload Model ──

// DesiredStatePayload is the backend → host config-only payload.
// It is declarative: describes what should be, not what to do.
type DesiredStatePayload struct {
	// Revision for diffing desired vs current
	Revision     int64  `json:"revision"`
	RevisionHash string `json:"revision_hash,omitempty"`

	// Host-level config overrides
	HostConfig *HostConfigOverride `json:"host_config,omitempty"`

	// Desired target profiles
	Targets []DesiredTargetProfile `json:"targets"`

	// Host-level policy
	Policy *HostPolicy `json:"policy,omitempty"`

	// Wipe instruction — explicit control-plane command for credential cleanup
	WipeInstruction *WipeInstruction `json:"wipe_instruction,omitempty"`

	// Pending relay commands — live API queries from users to execute locally
	PendingCommands []RelayCommand `json:"pending_commands,omitempty"`
}

// WipeInstruction is the control-plane command to wipe local credentials/state.
// Only processed on explicit instruction — never on transient errors.
type WipeInstruction struct {
	Action      string `json:"action"`       // "wipe_local_credentials"
	RequestedAt string `json:"requested_at"`
	RequestedBy string `json:"requested_by"`
}

// HostConfigOverride allows backend to push safe config updates.
// Only config knobs — never executable content.
type HostConfigOverride struct {
	LogLevel            string `json:"log_level,omitempty"`
	SyncIntervalSecs    int    `json:"sync_interval_secs,omitempty"`
	MaxConcurrentWorkers int   `json:"max_concurrent_workers,omitempty"`
}

// HostPolicy contains host-level policy settings from the control plane.
type HostPolicy struct {
	AutoUpdatePolicy       string `json:"auto_update_policy,omitempty"`
	CredentialRotationDays int    `json:"credential_rotation_days,omitempty"`
	MaintenanceWindow      string `json:"maintenance_window,omitempty"`
}

// DesiredTargetProfile is a backend-declared target profile.
// It includes the common profile envelope + any target-specific config.
type DesiredTargetProfile struct {
	// Identity
	TargetID string `json:"target_id"`
	Name     string `json:"name"`

	// Type & mode
	TargetType string     `json:"target_type"`
	Mode       ProfileMode `json:"mode"`

	// State control
	Enabled bool         `json:"enabled"`
	Status  TargetStatus `json:"status,omitempty"`

	// Endpoint
	Endpoint string    `json:"endpoint"`
	TLS      TLSConfig `json:"tls"`

	// Polling
	PollIntervalSecs int `json:"poll_interval_secs"`

	// Labels & capabilities
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`

	// Resource limits
	ResourceLimits ResourceLimits `json:"resource_limits,omitempty"`

	// Maintenance
	Paused            bool   `json:"paused"`
	MaintenanceReason string `json:"maintenance_reason,omitempty"`

	// Auth config — declares expected auth type, not the secret itself
	AuthType string `json:"auth_type"`

	// Credential delivery — encrypted secret payload from backend
	// These are transit-encrypted and stored locally by the host.
	CredentialPayload *CredentialPayload `json:"credential_payload,omitempty"`

	// Credential policy
	CredentialRotationDays int `json:"credential_rotation_days,omitempty"`

	// Target-specific config (opaque to host, interpreted by adapter)
	TargetConfig map[string]interface{} `json:"target_config,omitempty"`

	// Versioning
	ConfigVersion int `json:"config_version"`
}

// CredentialPayload carries encrypted per-target secrets from backend → host.
// Standard path: "host-keypair" with NaCl box encryption.
// Deprecated: "token-scoped" (Phase 2 legacy, disabled for new hosts).
type CredentialPayload struct {
	// EncryptionMethod: "host-keypair" (standard), "token-scoped" (deprecated),
	// "unavailable" (host missing public key), "error" (encryption failure)
	EncryptionMethod string            `json:"encryption_method"`

	// Token-scoped (DEPRECATED — migration only, will be removed)
	Credentials      map[string]string `json:"credentials,omitempty"`

	// Host-keypair encrypted blob (senderPub + nonce + ciphertext, base64)
	EncryptedBlob    string            `json:"encrypted_blob,omitempty"`

	// Versioned envelope (Phase 4+) — preferred over raw blob
	Envelope         *CredentialEnvelope `json:"envelope,omitempty"`
}

// CredentialEnvelope is the versioned encrypted credential payload format.
// Format version "ecpv1": X25519-XSalsa20-Poly1305 (NaCl box)
type CredentialEnvelope struct {
	Format          string `json:"format"`            // "ecpv1"
	TargetID        string `json:"target_id"`
	Algorithm       string `json:"algorithm"`         // "x25519-xsalsa20-poly1305"
	SenderPublicKey string `json:"sender_public_key"` // base64, 32 bytes
	Nonce           string `json:"nonce"`             // base64, 24 bytes
	Ciphertext      string `json:"ciphertext"`        // base64
}

// WipeAckPayload reports wipe result back to control plane.
type WipeAckPayload struct {
	Status       string `json:"status"`         // completed, failed
	Error        string `json:"error,omitempty"`
	WipedTargets int    `json:"wiped_targets"`
}

// ── Desired-State Sync Loop ──

// SyncManager handles periodic desired-state fetching and reconciliation.
type SyncManager struct {
	backend      *BackendClient
	store        *Store
	supervisor   *Supervisor
	validator    *ProfileValidator
	hostKeyPair  *HostKeyPair
	relayHandler *RelayHandler
	interval     time.Duration
	fastInterval time.Duration // shorter interval when relay commands were received
	cancel       context.CancelFunc
	done         chan struct{}
	// fastPollUntil: when set to a future time, use fastInterval instead of interval
	fastPollUntil time.Time
	// lastRejected tracks profiles rejected during the most recent sync cycle,
	// so sendAck can report them with error status to the control plane.
	lastRejected []RejectedProfile
}

// NewSyncManager creates a sync manager.
func NewSyncManager(backend *BackendClient, store *Store, supervisor *Supervisor) *SyncManager {
	// Load host keypair for credential decryption
	kp, err := store.LoadKeyPair()
	if err != nil {
		log.Printf("[sync] WARNING: Failed to load host keypair: %v", err)
	}
	if kp != nil {
		log.Printf("[sync] Host keypair loaded for credential decryption")
	}

	return &SyncManager{
		backend:      backend,
		store:        store,
		supervisor:   supervisor,
		validator:    NewProfileValidator(),
		hostKeyPair:  kp,
		relayHandler: NewRelayHandler(supervisor, backend, store),
		interval:     60 * time.Second,
		fastInterval: 5 * time.Second,
		done:         make(chan struct{}),
	}
}

// Start begins the sync loop.
func (sm *SyncManager) Start(interval time.Duration) {
	if interval > 0 {
		sm.interval = interval
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm.cancel = cancel

	go sm.run(ctx)
	go sm.commandPollLoop(ctx)
	log.Printf("[sync] Desired-state sync started (interval: %v, fast: %v, cmd-poll: 3s)", sm.interval, sm.fastInterval)
}

// Stop halts the sync loop.
func (sm *SyncManager) Stop() {
	if sm.cancel != nil {
		sm.cancel()
		<-sm.done
	}
}

// commandPollLoop is a dedicated fast-polling goroutine for relay commands.
// Runs independently of the 60s config sync to achieve <5s command pickup latency.
func (sm *SyncManager) commandPollLoop(ctx context.Context) {
	log.Printf("[cmd-poll] Command poll loop started (idle: 3s, fast: 1s)")

	const idleInterval = 3 * time.Second
	const fastInterval = 1 * time.Second
	const fastDuration = 15 * time.Second

	pollInterval := idleInterval
	var fastUntil time.Time
	var lastErrLog time.Time

	for {
		select {
		case <-ctx.Done():
			log.Printf("[cmd-poll] Command poll loop stopped")
			return
		case <-time.After(pollInterval):
		}

		token := sm.supervisor.GetConnectorToken()
		if token == "" {
			continue
		}

		commands, err := sm.backend.CheckCommands(token)
		if err != nil {
			// Throttled error logging — at most once per 30s to avoid spam
			if time.Since(lastErrLog) > 30*time.Second {
				log.Printf("[cmd-poll] CheckCommands error: %v", err)
				lastErrLog = time.Now()
			}
			continue
		}

		if len(commands) > 0 {
			log.Printf("[cmd-poll] Found %d pending command(s)", len(commands))
			sm.relayHandler.ProcessCommands(commands)
			fastUntil = time.Now().Add(fastDuration)
		}

		if time.Now().Before(fastUntil) {
			pollInterval = fastInterval
		} else {
			pollInterval = idleInterval
		}
	}
}

func (sm *SyncManager) run(ctx context.Context) {
	defer close(sm.done)

	// Fetch immediately on start
	sm.fetchAndReconcile()

	for {
		// Use fast interval if we recently processed relay commands
		pollInterval := sm.interval
		if time.Now().Before(sm.fastPollUntil) {
			pollInterval = sm.fastInterval
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
			sm.fetchAndReconcile()
		}
	}
}

// fetchAndReconcile fetches desired state and reconciles.
func (sm *SyncManager) fetchAndReconcile() {
	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		log.Printf("[sync] No connector token — skipping sync")
		return
	}

	// Build capability manifest JSON for control-plane reporting
	manifest := sm.supervisor.BuildCapabilityManifest()
	manifestJSON, _ := json.Marshal(manifest)

	payload, err := sm.backend.FetchDesiredState(token, string(manifestJSON))
	if err != nil {
		log.Printf("[sync] Desired-state fetch failed: %v", err)

		// Provide actionable guidance for auth failures vs transient errors
		errStr := err.Error()
		if contains(errStr, "token invalid") || contains(errStr, "revoked") || contains(errStr, "authentication failed") {
			log.Printf("[sync] ── Likely cause ──")
			log.Printf("[sync]   The stored connector token appears invalid or revoked.")
			log.Printf("[sync]   This commonly happens when:")
			log.Printf("[sync]     1. The host registration was deleted from the ForgeAI dashboard")
			log.Printf("[sync]     2. The connector token was revoked")
			log.Printf("[sync]     3. This container/service was reinstalled with an existing volume")
			log.Printf("[sync]        that contains stale enrollment state from a previous host")
			log.Printf("[sync] ── Recovery steps ──")
			log.Printf("[sync]   Docker named volume:")
			log.Printf("[sync]     docker stop forgeai-host && docker rm forgeai-host")
			log.Printf("[sync]     docker volume rm forgeai-config")
			log.Printf("[sync]     docker run ... -e FORGEAI_ENROLLMENT_TOKEN='fgbt_new_token' ...")
			log.Printf("[sync]   Bind mount / systemd:")
			log.Printf("[sync]     sudo systemctl stop forgeai-host")
			log.Printf("[sync]     sudo rm -rf /etc/forgeai/host.json.enc /etc/forgeai/host.key /etc/forgeai/secrets/")
			log.Printf("[sync]     # Update FORGEAI_ENROLLMENT_TOKEN in /etc/forgeai/connector.env")
			log.Printf("[sync]     sudo systemctl start forgeai-host")
			log.Printf("[sync]   Or run with --force-reset-state to clear persisted state automatically.")
			log.Printf("[sync] ────────────────────")
		} else {
			log.Printf("[sync] Preserving existing local state (safe degradation)")
		}
		return
	}

	if payload == nil {
		log.Printf("[sync] Empty desired-state — no changes")
		return
	}

	// ── Check for wipe instruction BEFORE normal reconciliation ──
	if payload.WipeInstruction != nil && payload.WipeInstruction.Action == "wipe_local_credentials" {
		log.Printf("[sync] ⚠️  WIPE INSTRUCTION received from control plane (requested at: %s)", payload.WipeInstruction.RequestedAt)
		wipeAck := sm.executeLocalWipe()
		sm.sendWipeAck(payload.Revision, wipeAck)
		// After wipe, send the normal ack too
		sm.sendAck(payload.Revision, "applied")
		return
	}

	// ── Process pending relay commands (live API queries from users) ──
	if len(payload.PendingCommands) > 0 {
		log.Printf("[sync] Received %d pending relay command(s) — entering fast-poll mode", len(payload.PendingCommands))
		// Enter fast-poll mode for 30 seconds to pick up follow-up commands quickly
		sm.fastPollUntil = time.Now().Add(30 * time.Second)
		go sm.relayHandler.ProcessCommands(payload.PendingCommands)
	}

	// Validate all target profiles before applying any
	validTargets, rejected := sm.validateProfiles(payload.Targets)
	if len(rejected) > 0 {
		log.Printf("[sync] Rejected %d invalid target profiles", len(rejected))
		for _, r := range rejected {
			log.Printf("[sync]   ✗ %s (%s): %s", r.Name, r.TargetID, r.Reason)
		}
	}

	// Store rejected profiles so sendAck can include them in target_statuses
	sm.lastRejected = rejected

	// Apply host config overrides if provided
	if payload.HostConfig != nil {
		sm.applyHostConfig(payload.HostConfig)
	}

	// Apply policy if provided
	if payload.Policy != nil {
		sm.applyHostPolicy(payload.Policy)
	}

	// Process credential payloads for valid targets
	for i := range validTargets {
		if validTargets[i].CredentialPayload != nil {
			if err := sm.processCredentials(&validTargets[i]); err != nil {
				log.Printf("[sync] Credential processing failed for %s: %v",
					validTargets[i].Name, err)
				// Don't fail the whole sync — this target just won't have updated creds
			}
		}
	}

	// Convert desired profiles to internal TargetProfile and reconcile
	ackStatus := sm.applyDesiredTargets(validTargets, payload.Revision)

	// Send acknowledgement
	sm.sendAck(payload.Revision, ackStatus)
}

// validateProfiles validates each profile and returns valid + rejected lists.
func (sm *SyncManager) validateProfiles(profiles []DesiredTargetProfile) ([]DesiredTargetProfile, []RejectedProfile) {
	var valid []DesiredTargetProfile
	var rejected []RejectedProfile

	for _, p := range profiles {
		if err := sm.validator.Validate(&p); err != nil {
			rejected = append(rejected, RejectedProfile{
				TargetID: p.TargetID,
				Name:     p.Name,
				Reason:   err.Error(),
			})
			continue
		}
		valid = append(valid, p)
	}

	return valid, rejected
}

// RejectedProfile records why a profile was rejected.
type RejectedProfile struct {
	TargetID string
	Name     string
	Reason   string
}

// processCredentials handles a credential payload for a target.
func (sm *SyncManager) processCredentials(target *DesiredTargetProfile) error {
	cp := target.CredentialPayload
	if cp == nil {
		return nil
	}

	switch cp.EncryptionMethod {
	case "host-keypair":
		// Standard path: decrypt using host's NaCl private key
		if sm.hostKeyPair == nil {
			return fmt.Errorf("host keypair not available for decryption")
		}

		// Prefer versioned envelope if present
		if cp.Envelope != nil {
			return sm.processEnvelope(cp.Envelope, target.TargetID)
		}

		// Fall back to raw blob format
		if cp.EncryptedBlob == "" {
			return fmt.Errorf("empty encrypted blob and no envelope")
		}
		plaintext, err := DecryptCredentialPayload(cp.EncryptedBlob, sm.hostKeyPair)
		if err != nil {
			return fmt.Errorf("decrypt credentials: %w", err)
		}
		var creds map[string]string
		if err := json.Unmarshal(plaintext, &creds); err != nil {
			return fmt.Errorf("unmarshal decrypted credentials: %w", err)
		}
		return sm.store.SaveSecret(target.TargetID, creds)

	case "token-scoped", "plaintext":
		// DEPRECATED — migration path only for pre-Phase 4 hosts.
		// Will be removed in a future version.
		log.Printf("[sync] WARNING: Received deprecated token-scoped credentials for %s — migrate host to enable encrypted delivery", target.Name)
		if len(cp.Credentials) == 0 {
			return fmt.Errorf("empty credential payload")
		}
		return sm.store.SaveSecret(target.TargetID, cp.Credentials)

	case "unavailable":
		log.Printf("[sync] WARNING: Backend withheld credentials for %s — host public key not registered", target.Name)
		return fmt.Errorf("credentials unavailable: %s", cp.EncryptionMethod)

	case "error":
		log.Printf("[sync] WARNING: Backend credential encryption error for %s", target.Name)
		return fmt.Errorf("backend credential encryption error")

	default:
		return fmt.Errorf("unknown encryption method: %s", cp.EncryptionMethod)
	}
}

// processEnvelope decrypts a versioned CredentialEnvelope.
func (sm *SyncManager) processEnvelope(env *CredentialEnvelope, targetID string) error {
	// Validate envelope format
	if env.Format != "ecpv1" {
		return fmt.Errorf("unsupported credential envelope format: %s", env.Format)
	}
	if env.Algorithm != "x25519-xsalsa20-poly1305" {
		return fmt.Errorf("unsupported envelope algorithm: %s", env.Algorithm)
	}

	// Reconstruct the raw blob from envelope fields for DecryptCredentialPayload
	// Blob format: senderPub(32) + nonce(24) + ciphertext
	senderPub, err := base64Decode(env.SenderPublicKey)
	if err != nil {
		return fmt.Errorf("decode sender public key: %w", err)
	}
	nonce, err := base64Decode(env.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64Decode(env.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	if len(senderPub) != 32 {
		return fmt.Errorf("invalid sender public key length: %d", len(senderPub))
	}
	if len(nonce) != 24 {
		return fmt.Errorf("invalid nonce length: %d", len(nonce))
	}

	// Reconstruct blob and decrypt
	blob := make([]byte, 0, 32+24+len(ciphertext))
	blob = append(blob, senderPub...)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	blobB64 := base64Encode(blob)
	plaintext, err := DecryptCredentialPayload(blobB64, sm.hostKeyPair)
	if err != nil {
		return fmt.Errorf("decrypt envelope: %w", err)
	}

	var creds map[string]string
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return fmt.Errorf("unmarshal envelope credentials: %w", err)
	}

	log.Printf("[sync] ✓ Decrypted credentials via ecpv1 envelope for target %s", targetID)
	return sm.store.SaveSecret(targetID, creds)
}

// base64Decode decodes a standard base64 string.
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// base64Encode encodes bytes to standard base64.
func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// sendAck sends a revision acknowledgement to the backend.
func (sm *SyncManager) sendAck(revision int64, status string) {
	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		return
	}

	// Build per-target status map from running targets
	targetStatuses := make(map[string]TargetAckStatus)
	for _, t := range sm.supervisor.GetTargets() {
		ts := TargetAckStatus{Status: string(t.Status)}
		if t.Status == TargetStatusError || t.Status == TargetStatusDegraded {
			// Get worker state for error info
			for _, ws := range sm.supervisor.Status() {
				if ws.TargetID == t.TargetID && ws.LastError != "" {
					ts.Error = ws.LastError
					break
				}
			}
		}
		targetStatuses[t.TargetID] = ts
	}

	// Include rejected targets so the control plane knows they failed
	for _, r := range sm.lastRejected {
		targetStatuses[r.TargetID] = TargetAckStatus{
			Status: "error",
			Error:  fmt.Sprintf("rejected: %s", r.Reason),
		}
	}

	// Downgrade overall status if any targets were rejected
	if len(sm.lastRejected) > 0 && status == "applied" {
		if len(sm.supervisor.GetTargets()) > 0 {
			status = "partial"
		} else {
			status = "failed"
		}
	}

	ack := AckPayload{
		Revision:       revision,
		Status:         status,
		AgentVersion:   HostVersion,
		TargetStatuses: targetStatuses,
	}

	sm.backend.SendAcknowledgement(token, ack)

	// Update local tracking
	if state := sm.supervisor.GetState(); state != nil {
		state.LastSyncRevision = revision
		state.LastSyncAt = time.Now()
		state.LastAckStatus = status
		sm.store.SaveState(state)
	}
}

// executeLocalWipe stops all workers, deletes per-target credentials and state.
// Preserves host identity so the wipe acknowledgement can be sent.
func (sm *SyncManager) executeLocalWipe() WipeAckPayload {
	targets := sm.supervisor.GetTargets()
	wipedCount := 0

	log.Printf("[wipe] Stopping all workers...")
	sm.supervisor.Shutdown()

	log.Printf("[wipe] Removing per-target credentials and state...")
	for _, t := range targets {
		// Delete credentials
		if err := sm.store.DeleteSecret(t.CredentialRef); err != nil {
			log.Printf("[wipe] Failed to delete credentials for %s: %v", t.Name, err)
		} else {
			log.Printf("[wipe] ✓ Deleted credentials for target: %s", t.Name)
			wipedCount++
		}
	}

	// Clear targets from state but keep host identity
	state := sm.supervisor.GetState()
	if state != nil {
		state.Targets = []TargetProfile{}
		if err := sm.store.SaveState(state); err != nil {
			log.Printf("[wipe] Failed to save cleared state: %v", err)
			return WipeAckPayload{Status: "failed", Error: fmt.Sprintf("state save failed: %v", err), WipedTargets: wipedCount}
		}
		log.Printf("[wipe] ✓ Cleared target profiles from local state")
	}

	log.Printf("[wipe] ✓ Local wipe complete — %d target credentials removed", wipedCount)
	return WipeAckPayload{Status: "completed", WipedTargets: wipedCount}
}

// sendWipeAck sends a wipe acknowledgement to the backend.
func (sm *SyncManager) sendWipeAck(revision int64, wipeResult WipeAckPayload) {
	token := sm.supervisor.GetConnectorToken()
	if token == "" {
		log.Printf("[wipe] Cannot send wipe ack — no connector token")
		return
	}

	ack := AckPayload{
		Revision:     revision,
		Status:       "applied",
		AgentVersion: HostVersion,
		WipeAck:      &wipeResult,
	}

	if err := sm.backend.SendAcknowledgement(token, ack); err != nil {
		log.Printf("[wipe] Failed to send wipe ack: %v", err)
	} else {
		log.Printf("[wipe] ✓ Wipe acknowledgement sent to control plane")
	}
}

// applyHostConfig applies safe host-level config overrides.
func (sm *SyncManager) applyHostConfig(override *HostConfigOverride) {
	state := sm.supervisor.GetState()
	if state == nil {
		return
	}

	changed := false
	if override.LogLevel != "" && isValidLogLevel(override.LogLevel) {
		state.Config.LogLevel = override.LogLevel
		changed = true
	}
	if override.SyncIntervalSecs > 0 && override.SyncIntervalSecs >= 15 {
		state.Config.SyncIntervalSecs = override.SyncIntervalSecs
		changed = true
	}
	if override.MaxConcurrentWorkers >= 0 {
		state.Config.MaxConcurrentWorkers = override.MaxConcurrentWorkers
		changed = true
	}

	if changed {
		log.Printf("[sync] Applied host config overrides")
	}
}

// applyHostPolicy applies host-level policy settings.
func (sm *SyncManager) applyHostPolicy(policy *HostPolicy) {
	state := sm.supervisor.GetState()
	if state == nil {
		return
	}

	if policy.AutoUpdatePolicy != "" {
		state.Config.AutoUpdatePolicy = policy.AutoUpdatePolicy
	}
	log.Printf("[sync] Applied host policy")
}

// applyDesiredTargets converts desired profiles to internal profiles and updates supervisor.
// Returns an ack status: "applied", "partial", or "failed".
func (sm *SyncManager) applyDesiredTargets(desired []DesiredTargetProfile, revision int64) string {
	// Build set of desired target IDs
	desiredIDs := make(map[string]bool)
	for _, d := range desired {
		desiredIDs[d.TargetID] = true
	}

	// Get current targets
	currentTargets := sm.supervisor.GetTargets()
	currentMap := make(map[string]*TargetProfile)
	for i := range currentTargets {
		currentMap[currentTargets[i].TargetID] = &currentTargets[i]
	}

	errors := 0
	applied := 0

	// Process each desired target
	for _, d := range desired {
		profile := desiredToInternal(d)

		current, exists := currentMap[d.TargetID]
		if !exists {
			// New target — add it
			log.Printf("[sync] Adding new target: %s (%s)", d.Name, d.TargetType)
			creds := extractCredsFromPayload(d.CredentialPayload)
			if err := sm.supervisor.AddTarget(profile, creds); err != nil {
				log.Printf("[sync] Failed to add target %s: %v", d.Name, err)
				errors++
			} else {
				applied++
			}
			continue
		}

		// Existing target — check if update needed
		if d.ConfigVersion > current.ConfigVersion || profileChanged(current, &profile) {
			log.Printf("[sync] Updating target: %s (v%d → v%d)", d.Name,
				current.ConfigVersion, d.ConfigVersion)
			sm.supervisor.UpdateTarget(profile)
			applied++
			continue
		}

		// Check enable/disable state change
		if d.Enabled != current.Enabled || d.Paused != current.Paused {
			log.Printf("[sync] State change for %s: enabled=%v paused=%v", d.Name, d.Enabled, d.Paused)
			sm.supervisor.UpdateTarget(profile)
			applied++
		} else {
			applied++ // no change needed = success
		}
	}

	// Remove targets no longer in desired state
	for id, current := range currentMap {
		if !desiredIDs[id] {
			log.Printf("[sync] Removing target no longer in desired state: %s", current.Name)
			if err := sm.supervisor.RemoveTarget(id); err != nil {
				log.Printf("[sync] Failed to remove target %s: %v", current.Name, err)
				errors++
			} else {
				applied++
			}
		}
	}

	log.Printf("[sync] Reconciliation complete (revision: %d, targets: %d, errors: %d)", revision, len(desired), errors)

	if errors > 0 && applied > 0 {
		return "partial"
	}
	if errors > 0 {
		return "failed"
	}
	return "applied"
}

// desiredToInternal converts a DesiredTargetProfile to an internal TargetProfile.
func desiredToInternal(d DesiredTargetProfile) TargetProfile {
	return TargetProfile{
		TargetID:               d.TargetID,
		Name:                   d.Name,
		TargetType:             d.TargetType,
		Mode:                   string(d.Mode),
		Enabled:                d.Enabled,
		Status:                 d.Status,
		Endpoint:               d.Endpoint,
		TLS:                    d.TLS,
		Labels:                 d.Labels,
		Capabilities:           d.Capabilities,
		PollIntervalSecs:       d.PollIntervalSecs,
		ResourceLimits:         d.ResourceLimits,
		Paused:                 d.Paused,
		MaintenanceReason:      d.MaintenanceReason,
		CredentialRef:          d.TargetID, // credential ref = target ID
		CredentialRotationDays: d.CredentialRotationDays,
		ConfigVersion:          d.ConfigVersion,
		UpdatedAt:              time.Now(),
		TargetConfig:           d.TargetConfig,
		AuthType:               d.AuthType,
	}
}

// extractCredsFromPayload extracts credentials from a payload, returning
// an empty map if the payload is nil or encrypted with unsupported method.
func extractCredsFromPayload(cp *CredentialPayload) map[string]string {
	if cp == nil {
		return map[string]string{}
	}
	if cp.EncryptionMethod == "token-scoped" || cp.EncryptionMethod == "plaintext" {
		return cp.Credentials
	}
	return map[string]string{}
}

// profileChanged checks if a profile needs updating (beyond config version).
func profileChanged(current *TargetProfile, desired *TargetProfile) bool {
	if current.Endpoint != desired.Endpoint {
		return true
	}
	if current.PollIntervalSecs != desired.PollIntervalSecs {
		return true
	}
	if current.Mode != desired.Mode {
		return true
	}
	if current.AuthType != desired.AuthType {
		return true
	}
	return false
}

// isValidLogLevel checks if a log level is recognized.
func isValidLogLevel(level string) bool {
	switch level {
	case "debug", "info", "warn", "error":
		return true
	}
	return false
}

// ── JSON helpers for backend response parsing ──

// parseDesiredState parses a JSON response into a DesiredStatePayload.
func parseDesiredState(data []byte) (*DesiredStatePayload, error) {
	var payload DesiredStatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse desired state: %w", err)
	}
	return &payload, nil
}
