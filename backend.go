// ForgeAI Connector Host — Backend Communication
//
// Handles all communication with the ForgeAI control plane:
//   - Heartbeat/snapshot delivery (per-target workers)
//   - Host enrollment (enrollment.go calls this)
//   - Desired-state fetch (sync manager polls this)
//   - Acknowledgements
//
// The backend client is deliberately separate from adapter logic.
// It knows nothing about Proxmox, TrueNAS, etc.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	defaultBackendBase       = "https://yvtszwgcmgmqylmmybrh.supabase.co"
	defaultHeartbeatPath     = "/functions/v1/connector-heartbeat"
	defaultEnrollPath        = "/functions/v1/connector-enroll"
	defaultDesiredStatePath  = "/functions/v1/connector-desired-state"
	defaultUpdateCheckPath   = "/functions/v1/connector-update-check"
)

// BackendClient handles communication with the ForgeAI backend.
type BackendClient struct {
	BaseURL string
	client  *http.Client
}

// NewBackendClient creates a backend client with the given base URL.
func NewBackendClient(baseURL string) *BackendClient {
	if baseURL == "" {
		baseURL = defaultBackendBase
	}
	return &BackendClient{
		BaseURL: baseURL,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Post sends a payload to the heartbeat endpoint with the given connector token.
func (b *BackendClient) Post(token string, payload map[string]interface{}) error {
	url := b.BaseURL + defaultHeartbeatPath
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", token)
	req.Header.Set("X-Agent-Version", HostVersion)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 200, 201, 202:
		return nil
	case 401:
		return fmt.Errorf("authentication failed — token may be invalid or revoked")
	case 403:
		return fmt.Errorf("connector has been revoked by administrator")
	default:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
}

// FetchDesiredState retrieves the desired target profile state from the backend.
// Returns nil payload (not error) if backend returns 204 (no changes).
// capManifestJSON is optional — if non-empty, sent as X-Host-Capabilities header.
func (b *BackendClient) FetchDesiredState(token string, capManifestJSON ...string) (*DesiredStatePayload, error) {
	url := b.BaseURL + defaultDesiredStatePath

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Connector-Token", token)
	req.Header.Set("X-Agent-Version", HostVersion)
	req.Header.Set("Accept", "application/json")

	// Include capability manifest if provided
	if len(capManifestJSON) > 0 && capManifestJSON[0] != "" {
		req.Header.Set("X-Host-Capabilities", capManifestJSON[0])
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch desired state: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 200:
		// Has desired state
	case 204:
		// No changes
		return nil, nil
	case 401:
		return nil, fmt.Errorf("authentication failed — token invalid or revoked")
	case 403:
		return nil, fmt.Errorf("host has been revoked")
	case 404:
		// Backend doesn't support desired-state yet — not an error
		log.Printf("[backend] Desired-state endpoint not available (404) — using local config only")
		return nil, nil
	case 429:
		return nil, fmt.Errorf("rate limited — will retry next cycle")
	default:
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	payload, err := parseDesiredState(body)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// AckPayload is sent to the desired-state endpoint as a POST to acknowledge a revision.
type AckPayload struct {
	Revision       int64                      `json:"revision"`
	Status         string                     `json:"status"`          // applied, partial, failed, rejected
	AgentVersion   string                     `json:"agent_version"`
	TargetStatuses map[string]TargetAckStatus `json:"target_statuses,omitempty"`
}

// TargetAckStatus reports per-target status in an acknowledgement.
type TargetAckStatus struct {
	Status string `json:"status"` // active, degraded, error, pending
	Error  string `json:"error,omitempty"`
}

// SendAcknowledgement sends a sync acknowledgement to the desired-state endpoint (POST).
func (b *BackendClient) SendAcknowledgement(token string, ack AckPayload) error {
	url := b.BaseURL + defaultDesiredStatePath

	body, err := json.Marshal(ack)
	if err != nil {
		return fmt.Errorf("marshal ack: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create ack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", token)
	req.Header.Set("X-Agent-Version", HostVersion)

	resp, err := b.client.Do(req)
	if err != nil {
		log.Printf("[backend] Ack delivery failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[backend] Ack returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// FetchUpdateManifest retrieves the latest update manifest from the backend.
// Returns nil (not error) if no update is available (204).
func (b *BackendClient) FetchUpdateManifest(token string) (*SignedUpdateManifest, error) {
	url := b.BaseURL + defaultUpdateCheckPath

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create update check request: %w", err)
	}
	req.Header.Set("X-Connector-Token", token)
	req.Header.Set("X-Agent-Version", HostVersion)
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch update manifest: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case 200:
		var manifest SignedUpdateManifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			return nil, fmt.Errorf("parse update manifest: %w", err)
		}
		return &manifest, nil
	case 204:
		return nil, nil // no update available
	case 404:
		// Endpoint not deployed yet
		return nil, nil
	default:
		return nil, fmt.Errorf("update check HTTP %d: %s", resp.StatusCode, string(body))
	}
}
