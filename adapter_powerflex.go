// ForgeAI Connector Host — PowerFlex Adapter (read-only)
//
// Collects cluster/system health, storage capacity, alerts, and
// inventory from Dell PowerFlex (VxFlex OS) Gateway REST API.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type PowerFlexAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authToken  string
}

func NewPowerFlexAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PowerFlexAdapter{profile: profile}, nil
}

func (a *PowerFlexAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: profile.TLS.InsecureSkipVerify},
	}
	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = &http.Client{Transport: transport, Timeout: timeout}

	// PowerFlex uses POST /api/login with Basic auth to get a token
	username := creds["username"]
	password := creds["password"]
	if username != "" && password != "" {
		if err := a.authenticate(username, password); err != nil {
			return fmt.Errorf("PowerFlex authentication failed: %w", err)
		}
	}

	log.Printf("[powerflex:%s] Verifying API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/version")
	if err != nil {
		return fmt.Errorf("PowerFlex API verification failed: %w", err)
	}
	log.Printf("[powerflex:%s] Connected", profile.Name)
	return nil
}

func (a *PowerFlexAdapter) authenticate(username, password string) error {
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req, err := http.NewRequest("POST", a.baseURL+"/api/login", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// PowerFlex Gateway uses Basic auth for login
	req.SetBasicAuth(username, password)

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	// Token is returned as a plain string in the response body
	token := string(bytes.Trim(body, "\""))
	if token != "" {
		a.authToken = token
	}
	return nil
}

func (a *PowerFlexAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	version, _ := a.apiGet("/api/version")
	systems, _ := a.apiGetList("/api/types/System/instances")
	sds, _ := a.apiGetList("/api/types/Sds/instances")
	pools, _ := a.apiGetList("/api/types/StoragePool/instances")
	alerts, _ := a.apiGetList("/api/types/Alert/instances")

	snapshotData := map[string]interface{}{
		"version":      version,
		"systems":      systems,
		"sds_nodes":    sds,
		"storagePools": pools,
	}

	alertList := extractPowerFlexAlerts(alerts)

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *PowerFlexAdapter) Capabilities() []string {
	return []string{
		"powerflex.read.health",
		"powerflex.read.capacity",
		"powerflex.read.alerts",
		"powerflex.read.inventory",
	}
}

func (a *PowerFlexAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/version")
	return err
}

func (a *PowerFlexAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PowerFlexAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
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

func (a *PowerFlexAdapter) apiGetList(path string) ([]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		var single map[string]interface{}
		if err2 := json.Unmarshal(body, &single); err2 == nil {
			return []interface{}{single}, nil
		}
		return nil, err
	}
	return result, nil
}

func extractPowerFlexAlerts(data []interface{}) []map[string]interface{} {
	if data == nil {
		return nil
	}
	var alerts []map[string]interface{}
	for _, item := range data {
		if a, ok := item.(map[string]interface{}); ok {
			severity := "warning"
			if s, ok := a["severityString"].(string); ok {
				severity = s
			} else if s, ok := a["severity"].(string); ok {
				severity = s
			}
			desc := ""
			if d, ok := a["alertTypeString"].(string); ok {
				desc = d
			}
			alerts = append(alerts, map[string]interface{}{
				"severity": severity,
				"source":   "powerflex",
				"message":  desc,
			})
		}
	}
	return alerts
}
