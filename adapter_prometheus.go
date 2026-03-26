// ForgeAI Connector Host — Prometheus Adapter (read-only)
//
// Collects target health, basic metadata, and runtime posture from
// a Prometheus server via its HTTP API. No admin mutations.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type PrometheusAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	headers map[string]string
}

func NewPrometheusAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &PrometheusAdapter{profile: profile}, nil
}

func (a *PrometheusAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint
	a.headers = make(map[string]string)

	timeout := 10 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	// Auth: header-based or username/password (basic auth)
	if name := creds["header_name"]; name != "" {
		a.headers[name] = creds["header_value"]
	}
	if user := creds["username"]; user != "" {
		// Basic auth handled per-request
		a.headers["_basic_user"] = user
		a.headers["_basic_pass"] = creds["password"]
	}

	log.Printf("[prometheus:%s] Verifying at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/api/v1/status/buildinfo")
	if err != nil {
		return fmt.Errorf("Prometheus API verification failed: %w", err)
	}
	log.Printf("[prometheus:%s] Connected", profile.Name)
	return nil
}

func (a *PrometheusAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	buildInfo, _ := a.apiGet("/api/v1/status/buildinfo")
	runtimeInfo, _ := a.apiGet("/api/v1/status/runtimeinfo")
	targets, _ := a.apiGet("/api/v1/targets?state=active")
	rules, _ := a.apiGet("/api/v1/rules?type=alert")

	// Summarize targets
	targetSummary := summarizeTargets(targets)

	// Summarize alerts from rules
	alertSummary := summarizeAlertRules(rules)

	snapshotData := map[string]interface{}{
		"buildInfo":     extractData(buildInfo),
		"runtimeInfo":   extractData(runtimeInfo),
		"targets":       extractData(targets),
		"targetSummary": targetSummary,
		"alertRules":    extractData(rules),
		"alertSummary":  alertSummary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertSummary["firingAlerts"],
		"collectedAt":  now,
	}, nil
}

func (a *PrometheusAdapter) Capabilities() []string {
	return []string{
		"prometheus.read.health",
		"prometheus.read.targets",
		"prometheus.read.alerts",
		"prometheus.read.metadata",
	}
}

func (a *PrometheusAdapter) HealthCheck() error {
	_, err := a.apiGet("/api/v1/status/buildinfo")
	return err
}

func (a *PrometheusAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *PrometheusAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range a.headers {
		if k[0] == '_' {
			continue // internal markers
		}
		req.Header.Set(k, v)
	}
	if user, ok := a.headers["_basic_user"]; ok && user != "" {
		req.SetBasicAuth(user, a.headers["_basic_pass"])
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
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

func extractData(resp map[string]interface{}) interface{} {
	if resp == nil {
		return nil
	}
	if d, ok := resp["data"]; ok {
		return d
	}
	return resp
}

func summarizeTargets(resp map[string]interface{}) map[string]interface{} {
	summary := map[string]interface{}{
		"total_up": 0, "total_down": 0, "total_unknown": 0,
	}
	if resp == nil {
		return summary
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return summary
	}
	active, _ := data["activeTargets"].([]interface{})
	up, down, unknown := 0, 0, 0
	for _, t := range active {
		if tm, ok := t.(map[string]interface{}); ok {
			switch tm["health"] {
			case "up":
				up++
			case "down":
				down++
			default:
				unknown++
			}
		}
	}
	summary["total_up"] = up
	summary["total_down"] = down
	summary["total_unknown"] = unknown
	return summary
}

func summarizeAlertRules(resp map[string]interface{}) map[string]interface{} {
	summary := map[string]interface{}{
		"totalRules": 0, "firingCount": 0, "firingAlerts": []map[string]interface{}{},
	}
	if resp == nil {
		return summary
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return summary
	}
	groups, _ := data["groups"].([]interface{})
	totalRules, firingCount := 0, 0
	var firingAlerts []map[string]interface{}

	for _, g := range groups {
		gm, _ := g.(map[string]interface{})
		if gm == nil {
			continue
		}
		rules, _ := gm["rules"].([]interface{})
		for _, r := range rules {
			rm, _ := r.(map[string]interface{})
			if rm == nil {
				continue
			}
			totalRules++
			state, _ := rm["state"].(string)
			if state == "firing" {
				firingCount++
				name, _ := rm["name"].(string)
				firingAlerts = append(firingAlerts, map[string]interface{}{
					"severity": "warning",
					"source":   "prometheus",
					"message":  fmt.Sprintf("Alert firing: %s", name),
				})
			}
		}
	}
	summary["totalRules"] = totalRules
	summary["firingCount"] = firingCount
	summary["firingAlerts"] = firingAlerts
	return summary
}
