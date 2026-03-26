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
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ── Trust Root ──
const pinnedUpdatePublicKeyBase64 = "FORGEAI_UPDATE_SIGNING_KEY_PLACEHOLDER"

// ── Update Policy ──

type UpdatePolicy string

const (
	UpdatePolicyNone     UpdatePolicy = "none"
	UpdatePolicySecurity UpdatePolicy = "security"
	UpdatePolicyStable   UpdatePolicy = "stable"
	UpdatePolicyBeta     UpdatePolicy = "beta"
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

type SignedUpdateManifest struct {
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	MinHostVersion string `json:"min_host_version,omitempty"`
	ArtifactURL    string `json:"artifact_url"`
	ArtifactName   string `json:"artifact_name"`
	ArtifactSize   int64  `json:"artifact_size"`
	SHA256         string `json:"sha256"`
	Signature      string `json:"signature"`
	ReleasedAt     string `json:"released_at"`
	ReleaseNotes   string `json:"release_notes,omitempty"`
}

func (m *SignedUpdateManifest) CanonicalBytes() []byte {
	canonical := fmt.Sprintf("forgeai-update-v1\nversion=%s\nchannel=%s\nartifact=%s\nsha256=%s\nsize=%d",
		m.Version, m.Channel, m.ArtifactName, m.SHA256, m.ArtifactSize)
	return []byte(canonical)
}

// ── Staged Update State (persisted) ──

type StagedUpdateState struct {
	CandidateVersion  string `json:"candidate_version,omitempty"`
	CandidatePath     string `json:"candidate_path,omitempty"`
	CandidateSHA256   string `json:"candidate_sha256,omitempty"`
	StagedAt          string `json:"staged_at,omitempty"`
	PreviousVersion   string `json:"previous_version,omitempty"`
	PreviousPath      string `json:"previous_path,omitempty"`
	RollbackCount     int    `json:"rollback_count"`
	HealthDeadline    string `json:"health_deadline,omitempty"`
	Confirmed         bool   `json:"confirmed"`
	LastCheckAt       string `json:"last_check_at,omitempty"`
	LastUpdateAt      string `json:"last_update_at,omitempty"`
	LastRollbackAt    string `json:"last_rollback_at,omitempty"`
	LastError         string `json:"last_error,omitempty"`
	ConsecutiveFails  int    `json:"consecutive_fails"`
}

const (
	updateStateFile     = "update_state.json.enc"
	stagedBinaryDir     = "staged"
	rollbackBinaryDir   = "rollback"
	healthCheckTimeout  = 60 * time.Second
	maxConsecutiveFails = 3
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
		audit.Warn("update.check", "No update signing key configured — update verification disabled")
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

func (um *UpdateManager) CheckForUpdate(policy UpdatePolicy) (*SignedUpdateManifest, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if policy == UpdatePolicyNone {
		return nil, nil
	}

	if um.state.ConsecutiveFails >= maxConsecutiveFails {
		return nil, fmt.Errorf("update checks suspended after %d consecutive failures", maxConsecutiveFails)
	}

	um.state.LastCheckAt = time.Now().UTC().Format(time.RFC3339)
	um.saveState()

	token := um.supervisor.GetConnectorToken()
	if token == "" {
		return nil, fmt.Errorf("no connector token for update check")
	}

	audit.Info("update.check", "Checking for updates", F("policy", string(policy)))

	manifest, err := um.backend.FetchUpdateManifest(token)
	if err != nil {
		return nil, fmt.Errorf("fetch update manifest: %w", err)
	}

	if manifest == nil {
		return nil, nil
	}

	if !PolicyAllowsChannel(policy, ReleaseChannel(manifest.Channel)) {
		audit.Info("update.check", "Update available but policy does not allow",
			F("version", manifest.Version), F("channel", manifest.Channel), F("policy", string(policy)))
		return nil, nil
	}

	if manifest.MinHostVersion != "" && manifest.MinHostVersion > HostVersion {
		return nil, fmt.Errorf("update %s requires host >= %s (current: %s)",
			manifest.Version, manifest.MinHostVersion, HostVersion)
	}

	if manifest.Version == HostVersion {
		return nil, nil
	}

	return manifest, nil
}

func (um *UpdateManager) StageUpdate(manifest *SignedUpdateManifest) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	audit.Info("update.staged", fmt.Sprintf("Staging update: %s → %s", HostVersion, manifest.Version))

	// Step 1: Verify manifest signature
	if err := um.VerifyManifest(manifest); err != nil {
		um.state.LastError = fmt.Sprintf("manifest verification failed: %v", err)
		um.state.ConsecutiveFails++
		um.saveState()
		return fmt.Errorf("manifest verification: %w", err)
	}
	audit.Info("update.staged", "Manifest signature verified")

	// Step 2: Download artifact
	stagedPath := filepath.Join(um.configDir, stagedBinaryDir, manifest.ArtifactName)
	if err := um.downloadArtifact(manifest.ArtifactURL, stagedPath); err != nil {
		um.state.LastError = fmt.Sprintf("download failed: %v", err)
		um.state.ConsecutiveFails++
		um.saveState()
		return fmt.Errorf("download artifact: %w", err)
	}
	audit.Info("update.staged", "Artifact downloaded to staging")

	// Step 3: Verify artifact hash
	if err := um.VerifyArtifact(stagedPath, manifest.SHA256); err != nil {
		os.Remove(stagedPath)
		um.state.LastError = fmt.Sprintf("hash verification failed: %v", err)
		um.state.ConsecutiveFails++
		um.saveState()
		return fmt.Errorf("artifact verification: %w", err)
	}
	audit.Info("update.staged", "Artifact SHA-256 verified")

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

	audit.Info("update.staged", "Update staged and ready for activation", F("version", manifest.Version))
	return nil
}

func (um *UpdateManager) ApplyUpdate() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.state.CandidatePath == "" {
		return fmt.Errorf("no staged update to apply")
	}

	if err := um.VerifyArtifact(um.state.CandidatePath, um.state.CandidateSHA256); err != nil {
		return fmt.Errorf("staged artifact re-verification failed (possible tampering): %w", err)
	}

	audit.Info("update.staged", fmt.Sprintf("Applying update: %s → %s", HostVersion, um.state.CandidateVersion))

	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current binary path: %w", err)
	}

	rollbackPath := filepath.Join(um.configDir, rollbackBinaryDir,
		fmt.Sprintf("forgeai-host-%s", HostVersion))

	if err := copyFile(currentBinary, rollbackPath); err != nil {
		audit.Warn("update.rollback", "Failed to create rollback copy", Err(err))
	} else {
		os.Chmod(rollbackPath, 0755)
		um.state.PreviousVersion = HostVersion
		um.state.PreviousPath = rollbackPath
		audit.Info("update.staged", "Rollback binary saved", F("path", rollbackPath))
	}

	if err := replaceFile(um.state.CandidatePath, currentBinary); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	deadline := time.Now().Add(healthCheckTimeout).UTC().Format(time.RFC3339)
	um.state.HealthDeadline = deadline
	um.state.Confirmed = false
	um.state.LastUpdateAt = time.Now().UTC().Format(time.RFC3339)
	um.saveState()

	audit.Info("update.staged", "Binary replaced — health check deadline set",
		F("deadline", deadline), F("timeout", healthCheckTimeout.String()))

	return nil
}

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

	audit.Info("update.staged", "Health confirmed — update finalized")
}

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

func (um *UpdateManager) Rollback() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if um.state.PreviousPath == "" {
		return fmt.Errorf("no previous version available for rollback")
	}

	audit.Warn("update.rollback", fmt.Sprintf("ROLLING BACK from %s to %s",
		um.state.CandidateVersion, um.state.PreviousVersion))

	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current binary: %w", err)
	}

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

	audit.Info("update.rollback", "Rollback complete", F("version", um.state.PreviousVersion))
	return nil
}

func (um *UpdateManager) GetUpdateState() StagedUpdateState {
	um.mu.Lock()
	defer um.mu.Unlock()
	return *um.state
}

// ── Worker Drain Support ──

func (um *UpdateManager) DrainWorkers(timeout time.Duration) {
	audit.Info("host.shutdown", "Draining workers", F("timeout", timeout.String()))

	done := make(chan struct{})
	go func() {
		um.supervisor.Shutdown()
		close(done)
	}()

	select {
	case <-done:
		audit.Info("host.shutdown", "All workers drained")
	case <-time.After(timeout):
		audit.Warn("host.shutdown", "Worker drain timed out", F("timeout", timeout.String()))
	}
}

// ── Persistence ──

func (um *UpdateManager) loadState() {
	path := filepath.Join(um.configDir, updateStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	plaintext, err := um.store.decrypt(data)
	if err != nil {
		audit.Warn("update.check", "Failed to decrypt update state", Err(err))
		return
	}

	json.Unmarshal(plaintext, um.state)
}

func (um *UpdateManager) saveState() {
	data, err := json.Marshal(um.state)
	if err != nil {
		audit.Warn("update.check", "Failed to marshal update state", Err(err))
		return
	}

	ciphertext, err := um.store.encrypt(data)
	if err != nil {
		audit.Warn("update.check", "Failed to encrypt update state", Err(err))
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

	if err := os.Rename(dst, tmpDst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("move current binary: %w", err)
	}

	if err := copyFile(src, dst); err != nil {
		os.Rename(tmpDst, dst)
		return fmt.Errorf("copy new binary: %w", err)
	}

	os.Chmod(dst, 0755)
	os.Remove(tmpDst)
	return nil
}
