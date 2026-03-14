// ForgeAI Connector Host — Encrypted Local Store
//
// Provides a secure local store for host state, target profiles,
// and encrypted credentials. Uses AES-256-GCM with a machine-derived key.
//
// Layout:
//   /etc/forgeai/
//     host.json.enc      — encrypted host state (identity + config + targets)
//     secrets/            — per-target encrypted credential files
//       <target_id>.enc  — encrypted credentials for one target
//     host.key           — key derivation material (mode 0600)

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	defaultConfigDir = "/etc/forgeai"
	stateFileName    = "host.json.enc"
	keyFileName      = "host.key"
	secretsDirName   = "secrets"
	keySize          = 32 // AES-256
)

// Store provides encrypted persistence for host state and secrets.
type Store struct {
	mu        sync.RWMutex
	configDir string
	key       []byte // derived encryption key
}

// NewStore creates a store rooted at the given directory.
// If the directory does not exist, it will be created with mode 0700.
func NewStore(configDir string) (*Store, error) {
	if configDir == "" {
		configDir = defaultConfigDir
	}

	s := &Store{configDir: configDir}

	// Ensure directory structure
	for _, dir := range []string{configDir, filepath.Join(configDir, secretsDirName)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	// Load or generate encryption key
	if err := s.loadOrCreateKey(); err != nil {
		return nil, fmt.Errorf("key init: %w", err)
	}

	return s, nil
}

// loadOrCreateKey loads the key file or generates a new one.
func (s *Store) loadOrCreateKey() error {
	keyPath := filepath.Join(s.configDir, keyFileName)

	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) >= keySize {
		// Derive key from stored material
		s.key = deriveKey(data)
		return nil
	}

	// Generate new key material
	material := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return fmt.Errorf("generate key material: %w", err)
	}

	if err := os.WriteFile(keyPath, material, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	s.key = deriveKey(material)
	return nil
}

// deriveKey uses SHA-256 to derive a fixed-size key from material.
func deriveKey(material []byte) []byte {
	h := sha256.Sum256(material)
	return h[:]
}

// ── Host State ──

// LoadState reads and decrypts the host state.
// Returns nil (not an error) if no state file exists yet.
func (s *Store) LoadState() (*HostState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.configDir, stateFileName)
	ciphertext, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil // fresh install
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}

	plaintext, err := s.decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt state: %w", err)
	}

	var state HostState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}

	return &state, nil
}

// SaveState encrypts and writes the host state.
func (s *Store) SaveState(state *HostState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	ciphertext, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt state: %w", err)
	}

	path := filepath.Join(s.configDir, stateFileName)
	tmpPath := path + ".tmp"

	// Atomic write: write to temp, then rename
	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename state: %w", err)
	}

	return nil
}

// ── Per-Target Secrets ──

// LoadSecret reads encrypted credentials for a target.
func (s *Store) LoadSecret(targetID string) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := filepath.Join(s.configDir, secretsDirName, targetID+".enc")
	ciphertext, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secret %s: %w", targetID, err)
	}

	plaintext, err := s.decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret %s: %w", targetID, err)
	}

	var creds map[string]string
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal secret %s: %w", targetID, err)
	}

	return creds, nil
}

// SaveSecret encrypts and writes credentials for a target.
func (s *Store) SaveSecret(targetID string, creds map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal secret: %w", err)
	}

	ciphertext, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}

	path := filepath.Join(s.configDir, secretsDirName, targetID+".enc")
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename secret: %w", err)
	}

	return nil
}

// DeleteSecret removes credentials for a target.
func (s *Store) DeleteSecret(targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.configDir, secretsDirName, targetID+".enc")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete secret %s: %w", targetID, err)
	}
	return nil
}

// ── Encryption primitives (AES-256-GCM) ──

func (s *Store) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *Store) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ── Migration: import from legacy env-based config ──

// ImportLegacyEnvConfig creates a HostState from the old single-target
// environment variable configuration. This enables backward compatibility
// during the transition to the multi-target model.
func ImportLegacyEnvConfig(cfg *Config) (*HostState, map[string]string) {
	state := &HostState{
		Identity: HostIdentity{
			HostID:         generateID(),
			Label:          fmt.Sprintf("legacy-%s-host", cfg.TargetType),
			ConnectorToken: cfg.ConnectorToken,
			BackendURL:     cfg.BackendURL,
		},
		Config:  DefaultHostConfig(),
		Targets: []TargetProfile{},
		Version: 1,
	}

	state.Config.InsecureSkipVerify = cfg.InsecureSkipVerify

	// Build the target profile from legacy config
	profile := TargetProfile{
		TargetID:         generateID(),
		Name:             fmt.Sprintf("Legacy %s target", cfg.TargetType),
		TargetType:       cfg.TargetType,
		Mode:             "read-only",
		Enabled:          true,
		Status:           TargetStatusPending,
		PollIntervalSecs: cfg.PollIntervalSecs,
		ConfigVersion:    1,
		TargetConfig:     map[string]interface{}{},
		CredentialRef:     "", // will be set after secret storage
	}

	creds := map[string]string{}

	switch cfg.TargetType {
	case "proxmox":
		profile.Endpoint = cfg.ProxmoxBaseURL
		profile.TLS.InsecureSkipVerify = cfg.InsecureSkipVerify
		if cfg.ProxmoxTokenID != "" {
			profile.TargetConfig["token_id"] = cfg.ProxmoxTokenID
			creds["token_secret"] = cfg.ProxmoxTokenSecret
		} else {
			profile.TargetConfig["username"] = cfg.ProxmoxUsername
			creds["password"] = cfg.ProxmoxPassword
		}
		if cfg.ProxmoxNode != "" {
			profile.TargetConfig["node"] = cfg.ProxmoxNode
		}

	case "truenas":
		profile.Endpoint = cfg.TrueNASURL
		profile.TLS.InsecureSkipVerify = cfg.InsecureSkipVerify
		creds["api_key"] = cfg.TrueNASAPIKey
	}

	profile.CredentialRef = profile.TargetID
	state.Targets = append(state.Targets, profile)

	return state, creds
}

// generateID creates a simple unique ID.
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
