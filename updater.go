// ForgeAI Connector Host — Signed Update Verification & Staged Rollout
//
// Implements the update lifecycle:
//   1. Discover update metadata from backend
//   2. Download artifact
//   3. Verify Ed25519 signature + SHA-256 hash
//   4. Stage as candidate binary
//   5. Drain workers, switch execution
//   6. Health check with bounded timeout
//   7. Automatic rollback on failure
//
// Trust model:
//   - Pinned Ed25519 public key compiled into the binary
//   - Update manifests must be signed with the corresponding private key
//   - Verification does NOT depend solely on TLS/transport trust
//   - No unsigned or incorrectly signed binaries can be installed

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ── Trust Root ──
// This is the pinned Ed25519 public key for verifying update signatures.
// It is embedded at build time and MUST NOT be fetched dynamically.
// To rotate: rebuild and distribute a new agent version with the new key.
const pinnedUpdatePublicKeyBase64 = "FORGEAI_UPDATE_SIGNING_KEY_PLACEHOLDER"

// ── Update Policy ──

type UpdatePolicy string

const (
	UpdatePolicyNone     UpdatePolicy = "none"     // no auto-updates
	UpdatePolicySecurity UpdatePolicy = "security" // security patches only
	UpdatePolicyStable   UpdatePolicy = "stable"   // stable releases
	UpdatePolicyBeta     UpdatePolicy = "beta"     // beta + stable
)

func IsValidUpdatePolicy(p string) bool {
	switch UpdatePolicy(p) {
	case UpdatePolicyNone, UpdatePolicySecurity, UpdatePolicyStable, UpdatePolicyBeta:
		return true
	}
	return false
}

// ── Update Channel Matching ──

type ReleaseChannel string

const (
	ChannelSecurity ReleaseChannel = "security"
	ChannelStable   ReleaseChannel = "stable"
	ChannelBeta     ReleaseChannel = "beta"
)

// PolicyAllowsChannel returns true if the update policy permits a given channel.
func PolicyAllowsChannel(policy UpdatePolicy, channel ReleaseChannel) bool {
	switch policy {
	case UpdatePolicyNone:
		return false
	case UpdatePolicySecurity:
		return channel == ChannelSecurity
	case UpdatePolicyStable:
		return channel == ChannelSecurity || channel == ChannelStable
	case UpdatePolicyBeta:
		return true
	}
	return false
}

// ── Versioned Update Manifest ──
// Extends the Phase 1 UpdateManifest with fields for signed verification.

type SignedUpdateManifest struct {
	// Identity
	Version        string `json:"version"`
	Channel        string `json:"channel"` // security, stable, beta
	MinHostVersion string `json:"min_host_version,omitempty"`

	// Artifact
	ArtifactURL  string `json:"artifact_url"`
	ArtifactName string `json:"artifact_name"` // e.g. "forgeai-host-linux-amd64"
	ArtifactSize int64  `json:"artifact_size"`

	// Integrity
	SHA256       string `json:"sha256"`        // hex-encoded hash of the artifact
	Signature    string `json:"signature"`     // base64 Ed25519 signature over canonical manifest

	// Metadata
	ReleasedAt   string `json:"released_at"`
	ReleaseNotes string `json:"release_notes,omitempty"`
}

// CanonicalBytes returns the deterministic byte representation used for signing.
// Only identity + integrity fields are included — not release notes or metadata.
func (m *SignedUpdateManifest) CanonicalBytes() []byte {
	canonical := fmt.Sprintf("forgeai-update-v1\nversion=%s\nchannel=%s\nartifact=%s\nsha256=%s\nsize=%d",
		m.Version, m.Channel, m.ArtifactName, m.SHA256, m.ArtifactSize)
	return []byte(canonical)
}

// ── Staged Update State (persisted) ──

type StagedUpdateState struct {
	// Candidate
	CandidateVersion string `json:"candidate_version,omitempty"`
	CandidatePath    string `json:"candidate_path,omitempty"`
	CandidateSHA256  string `json:"candidate_sha256,omitempty"`
	StagedAt         string `json:"staged_at,omitempty"`

	// Rollback
	PreviousVersion string `json:"previous_version,omitempty"`
	PreviousPath    string `json:"previous_path,omitempty"`
	RollbackCount   int    `json:"rollback_count"`

	// Health check
	HealthDeadline string `json:"health_deadline,omitempty"` // ISO 8601
	Confirmed      bool   `json:"confirmed"`

	// Update history
	LastCheckAt     string `json:"last_check_at,omitempty"`
	LastUpdateAt    string `json:"last_update_at,omitempty"`
	LastRollbackAt  string `json:"last_rollback_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	ConsecutiveFails int   `json:"consecutive_fails"`
}

const (
	updateStateFile     = "update_state.json.enc"
	stagedBinaryDir     = "staged"
	rollbackBinaryDir   = "rollback"
	healthCheckTimeout  = 60 * time.Second
	maxConsecutiveFails = 3 // stop trying after 3 failed updates
)

// ── Update Manager ──

type UpdateManager struct {
	mu         sync.Mutex
	store      *Store
	backend    *BackendClient
	supervisor *Supervisor
	configDir  string
	publicKey  ed25519.PublicKey
	state      *StagedUpdateState
}

func NewUpdateManager(store *Store, backend *BackendClient, supervisor *Supervisor, configDir string) (*UpdateManager, error) {
	um := &UpdateManager{
		store:     store,
		backend:   backend,
		supervisor: supervisor,
		configDir: configDir,
		state:     &StagedUpdateState{},
	}

	// Parse pinned public key
	if pinnedUpdatePublicKeyBase64 != "FORGEAI_UPDATE_SIGNING_KEY_PLACEHOLDER" {
		pubBytes, err := base64.StdEncoding.DecodeString(pinnedUpdatePublicKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("decode pinned update public key: %w", err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pinned update public key wrong size: %d (expected %d)", len(pubBytes), ed25519.PublicKeySize)
		}
		um.publicKey = ed25519.PublicKey(pubBytes)
	} else {
		log.Printf("[updater] WARNING: No update signing key configured — update verification disabled")
	}

	// Ensure staging directories exist
	for _, dir := range []string{
		filepath.Join(configDir, stagedBinaryDir),
		filepath.Join(configDir, rollbackBinaryDir),
	} {
		os.MkdirAll(dir, 0700)
	}

	// Load persisted update state
	um.loadState()

	return um, nil
}

// ── Signature Verification ──

// VerifyManifest checks the Ed25519 signature on an update manifest.
func (um *UpdateManager) VerifyManifest(manifest *SignedUpdateManifest) error {
	if um.publicKey == nil {
		return fmt.Errorf("no update signing key configured")
	}

	if manifest.Signature == "" {
		return fmt.Errorf("manifest has no signature")
	}

	sig, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d", len(sig))
	}

	canonical := manifest.CanonicalBytes()

	if !ed25519.Verify(um.publicKey, canonical, sig) {
		return fmt.Errorf("signature verification FAILED — manifest is not trusted")
	}

	return nil
}

// VerifyArtifact checks that a downloaded artifact matches the manifest hash.
func (um *UpdateManager) VerifyArtifact(artifactPath string, expectedSHA256 string) error {
	f, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("open artifact: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash artifact: %w", err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expectedSHA256 {
		return fmt.Errorf("SHA-256 mismatch: expected %s, got %s", expectedSHA256, actual)
	}

	return nil
}

// ── Staged Update Flow ──

// CheckForUpdate queries the backend for available updates and returns
// a manifest if one is available and permitted by policy.
func (um *UpdateManager) CheckForUpdate(policy UpdatePolicy) (*SignedUpdateManifest, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if policy == UpdatePolicyNone {
		return nil, nil
	}

	// Don't check if too many consecutive failures
	if um.state.ConsecutiveFails >= maxConsecutiveFails {
		return nil, fmt.Errorf("update checks suspended after %d consecutive failures", maxConsecutiveFails)
	}

	um.state.LastCheckAt = time.Now().UTC().Format(time.RFC3339)
	um.saveState()

	// Fetch update manifest from backend
	token := um.supervisor.GetConnectorToken()
	if token == "" {
		return nil, fmt.Errorf("no connector token for update check")
	}

	manifest, err := um.backend.FetchUpdateManifest(token)
	if err != nil {
		return nil, fmt.Errorf("fetch update manifest: %w", err)
	}

	if manifest == nil {
		return nil, nil // no update available
	}

	// Check channel policy
	if !PolicyAllowsChannel(policy, ReleaseChannel(manifest.Channel)) {
		log.Printf("[updater] Update %s available on channel '%s' but policy '%s' does not allow it",
			manifest.Version, manifest.Channel, policy)
		return nil, nil
	}

	// Check minimum host version
	if manifest.MinHostVersion != "" && manifest.MinHostVersion > HostVersion {
		return nil, fmt.Errorf("update %s requires host >= %s (current: %s)",
			manifest.Version, manifest.MinHostVersion, HostVersion)
	}

	// Don't re-stage same version
	if manifest.Version == HostVersion {
		return nil, nil
	}

	return manifest, nil
}

// StageUpdate downloads and verifies an update artifact without applying it.
func (um *UpdateManager) StageUpdate(manifest *SignedUpdateManifest) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	log.Printf("[updater] Staging update: %s → %s", HostVersion, manifest.Version)

	// Step 1: Verify manifest signature
	if err := um.VerifyManifest(manifest); err != nil {
		um.state.LastError = fmt.Sprintf("manifest verification failed: %v", err)
		um.state.ConsecutiveFails++
		um.saveState()
		return fmt.Errorf("manifest verification: %w", err)
	}
	log.Printf("[updater] ✓ Manifest signature verified")

	// Step 2: Download artifact to staging directory
	stagedPath := filepath.Join(um.configDir, stagedBinaryDir, manifest.ArtifactName)
	if err := um.downloadArtifact(manifest.ArtifactURL, stagedPath); err != nil {
		um.state.LastError = fmt.Sprintf("download failed: %v", err)
		um.state.ConsecutiveFails++
		um.saveState()
		return fmt.Errorf("download artifact: %w", err)
	}
	log.Printf("[updater] ✓ Artifact downloaded to staging")

	// Step 3: Verify artifact hash
	if err := um.VerifyArtifact(stagedPath, manifest.SHA256); err != nil {
		os.Remove(stagedPath)
		um.state.LastError = fmt.Sprintf("hash verification failed: %v", err)
		um.state.ConsecutiveFails++
		um.saveState()
		return fmt.Errorf("artifact verification: %w", err)
	}
	log.Printf("[updater] ✓ Artifact SHA-256 verified")

	// Step 4: Make executable
	if err := os.Chmod(stagedPath, 0755); err != nil {
		os.Remove(stagedPath)
		return fmt.Errorf("chmod staged binary: %w", err)
	}

	// Step 5: Update staged state
	um.state.CandidateVersion = manifest.Version
	um.state.CandidatePath = stagedPath
	um.state.CandidateSHA256 = manifest.SHA256
	um.state.StagedAt = time.Now().UTC().Format(time.RFC3339)
	um.saveState()

	log.Printf("[updater] ✓ Update %s staged and ready for activation", manifest.Version)
	return nil
}

// ApplyUpdate activates the staged candidate:
//   1. Drains workers gracefully
//   2. Backs up current binary for rollback
//   3. Swaps to new binary
//   4. Sets health deadline
//
// The caller (main/supervisor) is responsible for restarting the process.
func (um *UpdateManager) ApplyUpdate() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.state.CandidatePath == "" {
		return fmt.Errorf("no staged update to apply")
	}

	// Verify the staged artifact hasn't been tampered with since staging
	if err := um.VerifyArtifact(um.state.CandidatePath, um.state.CandidateSHA256); err != nil {
		return fmt.Errorf("staged artifact re-verification failed (possible tampering): %w", err)
	}

	log.Printf("[updater] Applying update: %s → %s", HostVersion, um.state.CandidateVersion)

	// Step 1: Back up current binary for rollback
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current binary path: %w", err)
	}

	rollbackPath := filepath.Join(um.configDir, rollbackBinaryDir,
		fmt.Sprintf("forgeai-host-%s", HostVersion))

	if err := copyFile(currentBinary, rollbackPath); err != nil {
		log.Printf("[updater] WARNING: Failed to create rollback copy: %v", err)
		// Continue — rollback may not work but update should still proceed
	} else {
		os.Chmod(rollbackPath, 0755)
		um.state.PreviousVersion = HostVersion
		um.state.PreviousPath = rollbackPath
		log.Printf("[updater] ✓ Rollback binary saved: %s", rollbackPath)
	}

	// Step 2: Replace current binary with staged candidate
	if err := replaceFile(um.state.CandidatePath, currentBinary); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	// Step 3: Set health check deadline
	deadline := time.Now().Add(healthCheckTimeout).UTC().Format(time.RFC3339)
	um.state.HealthDeadline = deadline
	um.state.Confirmed = false
	um.state.LastUpdateAt = time.Now().UTC().Format(time.RFC3339)
	um.saveState()

	log.Printf("[updater] ✓ Binary replaced. Health deadline: %s", deadline)
	log.Printf("[updater] Process must confirm health within %v or rollback will trigger", healthCheckTimeout)

	return nil
}

// ConfirmHealth marks the current version as healthy after an update.
// Should be called by the supervisor after successful startup + heartbeat.
func (um *UpdateManager) ConfirmHealth() {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.state.HealthDeadline == "" || um.state.Confirmed {
		return
	}

	um.state.Confirmed = true
	um.state.CandidateVersion = ""
	um.state.CandidatePath = ""
	um.state.CandidateSHA256 = ""
	um.state.ConsecutiveFails = 0
	um.state.LastError = ""
	um.saveState()

	log.Printf("[updater] ✓ Health confirmed — update finalized")
}

// CheckRollbackNeeded examines whether a rollback is required.
// Returns true if the health deadline has passed without confirmation.
func (um *UpdateManager) CheckRollbackNeeded() bool {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.state.HealthDeadline == "" || um.state.Confirmed {
		return false
	}

	deadline, err := time.Parse(time.RFC3339, um.state.HealthDeadline)
	if err != nil {
		return false
	}

	return time.Now().After(deadline)
}

// Rollback reverts to the previous binary version.
func (um *UpdateManager) Rollback() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.state.PreviousPath == "" {
		return fmt.Errorf("no previous version available for rollback")
	}

	log.Printf("[updater] ROLLING BACK from %s to %s", um.state.CandidateVersion, um.state.PreviousVersion)

	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current binary: %w", err)
	}

	// Verify rollback binary still exists
	if _, err := os.Stat(um.state.PreviousPath); err != nil {
		return fmt.Errorf("rollback binary not found at %s: %w", um.state.PreviousPath, err)
	}

	if err := replaceFile(um.state.PreviousPath, currentBinary); err != nil {
		return fmt.Errorf("rollback replace failed: %w", err)
	}

	um.state.RollbackCount++
	um.state.LastRollbackAt = time.Now().UTC().Format(time.RFC3339)
	um.state.HealthDeadline = ""
	um.state.CandidateVersion = ""
	um.state.CandidatePath = ""
	um.state.ConsecutiveFails++
	um.saveState()

	log.Printf("[updater] ✓ Rollback complete to version %s", um.state.PreviousVersion)
	return nil
}

// GetUpdateState returns the current update state for reporting.
func (um *UpdateManager) GetUpdateState() StagedUpdateState {
	um.mu.Lock()
	defer um.mu.Unlock()
	return *um.state
}

// ── Worker Drain Support ──

// DrainWorkers asks the supervisor to gracefully stop all workers
// before a binary swap. Workers are given a bounded time to finish.
func (um *UpdateManager) DrainWorkers(timeout time.Duration) {
	log.Printf("[updater] Draining workers (timeout: %v)...", timeout)

	done := make(chan struct{})
	go func() {
		um.supervisor.Shutdown()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[updater] ✓ All workers drained")
	case <-time.After(timeout):
		log.Printf("[updater] WARNING: Worker drain timed out after %v", timeout)
	}
}

// ── Persistence ──

func (um *UpdateManager) loadState() {
	path := filepath.Join(um.configDir, updateStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return // no state yet
	}

	plaintext, err := um.store.decrypt(data)
	if err != nil {
		log.Printf("[updater] WARNING: Failed to decrypt update state: %v", err)
		return
	}

	json.Unmarshal(plaintext, um.state)
}

func (um *UpdateManager) saveState() {
	data, err := json.Marshal(um.state)
	if err != nil {
		log.Printf("[updater] WARNING: Failed to marshal update state: %v", err)
		return
	}

	ciphertext, err := um.store.encrypt(data)
	if err != nil {
		log.Printf("[updater] WARNING: Failed to encrypt update state: %v", err)
		return
	}

	path := filepath.Join(um.configDir, updateStateFile)
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return
	}
	os.Rename(tmpPath, path)
}

// ── Download helper ──

func (um *UpdateManager) downloadArtifact(url, destPath string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmpPath := destPath + ".download"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write artifact: %w", err)
	}
	f.Close()

	return os.Rename(tmpPath, destPath)
}

// ── File helpers ──

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func replaceFile(src, dst string) error {
	tmpDst := dst + ".old"

	// Move current out of the way
	if err := os.Rename(dst, tmpDst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("move current binary: %w", err)
	}

	// Copy new binary into place
	if err := copyFile(src, dst); err != nil {
		// Try to restore
		os.Rename(tmpDst, dst)
		return fmt.Errorf("copy new binary: %w", err)
	}

	os.Chmod(dst, 0755)
	os.Remove(tmpDst)
	return nil
}
