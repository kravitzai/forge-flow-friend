// ForgeAI Connector Host — Relay Execution Handler
//
// Handles live API relay commands received from the cloud via
// the desired-state polling loop. The agent executes the operation
// locally against the LAN-accessible target and posts the result
// back via the connector-api-response edge function.
//
// This file defines the relay handler, platform executor dispatch,
// and the response posting logic.

package main

import (
	"crypto/tls"
)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	defaultRelayResponsePath = "/functions/v1/connector-api-response"
)

// RelayCommand is a pending API execution command from the cloud.
type RelayCommand struct {
	ID              string                 `json:"id"`
	Method          string                 `json:"method"`
	Path            string                 `json:"path"`
	Body            map[string]interface{} `json:"body,omitempty"`
	Platform        string                 `json:"platform"`
	OperationID     string                 `json:"operation_id,omitempty"`
	TargetProfileID string                 `json:"target_profile_id"`
	SafetyLevel     string                 `json:"safety_level"`
}

// RelayResult is the response posted back to the cloud.
type RelayResult struct {
	ID             string                 `json:"id"`
	ResponseStatus int                    `json:"response_status"`
	ResponseData   map[string]interface{} `json:"response_data,omitempty"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	DurationMs     int64                  `json:"duration_ms,omitempty"`
}

// RelayHandler processes relay commands using local platform access.
type RelayHandler struct {
	supervisor *Supervisor
	backend    *BackendClient
	store      *Store

	// Safety allow-list: only read-only operations
	allowedSafetyLevels map[string]bool

	// Platform allow-list: only known platforms can be relayed
	allowedPlatforms map[string]bool
}

// NewRelayHandler creates a relay handler.
func NewRelayHandler(supervisor *Supervisor, backend *BackendClient, store *Store) *RelayHandler {
	return &RelayHandler{
		supervisor: supervisor,
		backend:    backend,
		store:      store,
		allowedSafetyLevels: map[string]bool{
			"read-only": true,
		},
		allowedPlatforms: map[string]bool{
			"proxmox":  true,
			"ollama":   true,
			"nutanix":  true,
			"truenas":  true,
			"openwebui": true,
		},
	}
}

// ProcessCommands handles a batch of relay commands.
// Called from the desired-state sync loop when pending_commands are present.
func (rh *RelayHandler) ProcessCommands(commands []RelayCommand) {
	if len(commands) == 0 {
		return
	}

	log.Printf("[relay] Processing %d pending command(s)", len(commands))

	results := make([]RelayResult, 0, len(commands))
	for _, cmd := range commands {
		log.Printf("[relay] Executing cmd=%s platform=%s op=%s path=%s safety=%s",
			cmd.ID, cmd.Platform, cmd.OperationID, cmd.Path, cmd.SafetyLevel)
		result := rh.executeCommand(cmd)
		if result.ErrorMessage != "" {
			log.Printf("[relay] cmd=%s FAILED: %s (duration=%dms)", cmd.ID, result.ErrorMessage, result.DurationMs)
		} else {
			log.Printf("[relay] cmd=%s OK: HTTP %d (duration=%dms)", cmd.ID, result.ResponseStatus, result.DurationMs)
		}
		results = append(results, result)
	}

	// Post all results back to the cloud
	rh.postResults(results)
}

// executeCommand runs a single relay command locally.
func (rh *RelayHandler) executeCommand(cmd RelayCommand) RelayResult {
	start := time.Now()

	// Platform allow-list check
	if !rh.allowedPlatforms[cmd.Platform] {
		log.Printf("[relay] REJECTED cmd=%s: unknown platform %q", cmd.ID, cmd.Platform)
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("platform %q not in agent allow-list", cmd.Platform),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Safety check — agent-side allow-list
	if !rh.allowedSafetyLevels[cmd.SafetyLevel] {
		log.Printf("[relay] REJECTED cmd=%s: safety level %q not allowed", cmd.ID, cmd.SafetyLevel)
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("safety level %q not allowed on agent", cmd.SafetyLevel),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Method allow-list
	method := strings.ToUpper(cmd.Method)
	if method != "GET" && method != "POST" {
		// POST is allowed for read-only operations (e.g., Nutanix list, Ollama show)
		if cmd.SafetyLevel != "read-only" {
			log.Printf("[relay] REJECTED cmd=%s: method %q not allowed for safety %q", cmd.ID, method, cmd.SafetyLevel)
			return RelayResult{
				ID:           cmd.ID,
				ErrorMessage: fmt.Sprintf("method %q not allowed for safety level %q", method, cmd.SafetyLevel),
				DurationMs:   time.Since(start).Milliseconds(),
			}
		}
	}

	// Path validation — reject suspicious paths
	if cmd.Path == "" || strings.Contains(cmd.Path, "..") {
		log.Printf("[relay] REJECTED cmd=%s: invalid path %q", cmd.ID, cmd.Path)
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: "invalid request path",
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Find the target profile
	target := rh.supervisor.FindTarget(cmd.TargetProfileID)
	if target == nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("target profile %q not found on this agent", cmd.TargetProfileID),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Load credentials
	creds, err := rh.store.LoadSecret(cmd.TargetProfileID)
	if err != nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("failed to load credentials for target: %v", err),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Execute the HTTP call against the local target
	result := rh.executeHTTP(cmd, target, creds)
	result.DurationMs = time.Since(start).Milliseconds()
	return result
}

// executeHTTP performs the actual HTTP request against the target endpoint.
func (rh *RelayHandler) executeHTTP(cmd RelayCommand, target *TargetProfile, creds map[string]string) RelayResult {
	fullURL := target.Endpoint + cmd.Path

	var bodyReader io.Reader
	if cmd.Body != nil && (strings.ToUpper(cmd.Method) == "POST" || strings.ToUpper(cmd.Method) == "PUT" || strings.ToUpper(cmd.Method) == "PATCH") {
		bodyBytes, err := json.Marshal(cmd.Body)
		if err != nil {
			return RelayResult{ID: cmd.ID, ErrorMessage: fmt.Sprintf("marshal request body: %v", err)}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(strings.ToUpper(cmd.Method), fullURL, bodyReader)
	if err != nil {
		return RelayResult{ID: cmd.ID, ErrorMessage: fmt.Sprintf("create request: %v", err)}
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Apply auth from credentials based on target auth type
	applyAuth(req, target, creds)

	// Use TLS-aware client from the target
	client := buildHTTPClient(target)

	resp, err := client.Do(req)
	if err != nil {
		return RelayResult{
			ID:           cmd.ID,
			ErrorMessage: fmt.Sprintf("execute request: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read response (cap at 5MB)
	limited := io.LimitReader(resp.Body, 5*1024*1024)
	respBytes, err := io.ReadAll(limited)
	if err != nil {
		return RelayResult{
			ID:             cmd.ID,
			ResponseStatus: resp.StatusCode,
			ErrorMessage:   fmt.Sprintf("read response: %v", err),
		}
	}

	var respData map[string]interface{}
	if err := json.Unmarshal(respBytes, &respData); err != nil {
		// Non-JSON response
		respData = map[string]interface{}{
			"rawText": string(respBytes),
		}
	}

	result := RelayResult{
		ID:             cmd.ID,
		ResponseStatus: resp.StatusCode,
		ResponseData:   respData,
	}

	if resp.StatusCode >= 400 {
		result.ErrorMessage = fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode)
	}

	return result
}

// applyAuth sets authentication headers based on target config.
func applyAuth(req *http.Request, target *TargetProfile, creds map[string]string) {
	switch target.AuthType {
	case "basic", "username_password":
		username := creds["username"]
		password := creds["password"]
		if username != "" && password != "" {
			req.SetBasicAuth(username, password)
		}
	case "bearer", "api_token", "api-key":
		token := creds["token"]
		if token == "" {
			token = creds["api_key"]
		}
		if token == "" {
			token = creds["service_token"]
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case "proxmox_api_token":
		// Proxmox PVE API token format: PVEAPIToken=user@realm!tokenid=secret
		tokenID := creds["token_id"]
		tokenSecret := creds["token_secret"]
		username := creds["username"]
		if tokenID != "" && tokenSecret != "" {
			req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s!%s=%s", username, tokenID, tokenSecret))
		} else if creds["api_key"] != "" {
			req.Header.Set("Authorization", "PVEAPIToken="+creds["api_key"])
		}
	}
}

// buildHTTPClient creates an HTTP client respecting TLS config.
func buildHTTPClient(target *TargetProfile) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: target.TLS.InsecureSkipVerify},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// postResults sends relay results back to the cloud.
func (rh *RelayHandler) postResults(results []RelayResult) {
	token := rh.supervisor.GetConnectorToken()
	if token == "" {
		log.Printf("[relay] No connector token — cannot post results")
		return
	}

	payload := map[string]interface{}{
		"results": results,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[relay] Failed to marshal results: %v", err)
		return
	}

	url := rh.backend.BaseURL + defaultRelayResponsePath
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[relay] Failed to create response request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Connector-Token", token)
	req.Header.Set("X-Agent-Version", HostVersion)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[relay] Failed to post results: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[relay] Response post returned HTTP %d: %s", resp.StatusCode, string(respBody))
	} else {
		log.Printf("[relay] Successfully posted %d result(s)", len(results))
	}
}
