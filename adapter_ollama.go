// ForgeAI Connector Host — Ollama Adapter (read-only)
//
// Collects model inventory, runtime health, and version info from
// a local Ollama instance. Designed for homelab AI server monitoring.
//
// Auth: typically none (local trusted). Optional header-based auth if
// Ollama is behind a reverse proxy.

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type OllamaAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	headers map[string]string
}

func NewOllamaAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &OllamaAdapter{profile: profile}, nil
}

func (a *OllamaAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint
	a.headers = make(map[string]string)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: profile.TLS.InsecureSkipVerify},
	}
	a.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}

	// Optional header auth (for proxied setups)
	if name := creds["header_name"]; name != "" {
		a.headers[name] = creds["header_value"]
	}

	log.Printf("[ollama:%s] Verifying at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/version")
	if err != nil {
		return fmt.Errorf("Ollama API verification failed: %w", err)
	}
	log.Printf("[ollama:%s] Connected", profile.Name)
	return nil
}

func (a *OllamaAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	version, _ := a.apiGet("/api/version")
	tags, _ := a.apiGet("/api/tags")
	ps, _ := a.apiGet("/api/ps")

	// Extract model list
	var models []interface{}
	if tags != nil {
		if m, ok := tags["models"].([]interface{}); ok {
			models = m
		}
	}

	// Extract running models
	var running []interface{}
	if ps != nil {
		if m, ok := ps["models"].([]interface{}); ok {
			running = m
		}
	}

	snapshotData := map[string]interface{}{
		"version":       version,
		"models":        models,
		"runningModels": running,
		"summary": map[string]interface{}{
			"model_count":   len(models),
			"running_count": len(running),
		},
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       []map[string]interface{}{},
		"collectedAt":  now,
	}, nil
}

func (a *OllamaAdapter) Capabilities() []string {
	return []string{
		"ollama.read.health",
		"ollama.read.models",
		"ollama.read.runtime",
	}
}

func (a *OllamaAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/version")
	return err
}

func (a *OllamaAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *OllamaAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}
