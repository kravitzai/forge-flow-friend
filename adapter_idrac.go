// ForgeAI Connector Host — Dell iDRAC Adapter (read-only)
//
// Collects system health, hardware inventory, thermal status, power,
// and SEL logs from Dell iDRAC via the standard DMTF Redfish v1 API.

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type IdracAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	authHeader string
}

func NewIdracAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &IdracAdapter{profile: profile}, nil
}

func (a *IdracAdapter) Init(profile *TargetProfile, creds map[string]string) error {
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

	// Auth: Basic auth from username/password
	username := creds["username"]
	password := creds["password"]
	if username == "" || password == "" {
		return fmt.Errorf("iDRAC requires username and password credentials")
	}
	a.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

	log.Printf("[idrac:%s] Verifying Redfish API access at %s...", profile.Name, a.baseURL)
	_, err := a.apiGet("/redfish/v1/Systems/System.Embedded.1")
	if err != nil {
		return fmt.Errorf("iDRAC Redfish API verification failed: %w", err)
	}
	log.Printf("[idrac:%s] Connected", profile.Name)
	return nil
}

func (a *IdracAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	system, _ := a.apiGet("/redfish/v1/Systems/System.Embedded.1")
	power, _ := a.apiGet("/redfish/v1/Chassis/System.Embedded.1/Power")
	thermal, _ := a.apiGet("/redfish/v1/Chassis/System.Embedded.1/Thermal")
	processors, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/Processors")
	memory, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/Memory")
	storage, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/Storage")
	selEntries, _ := a.apiGetMembers("/redfish/v1/Systems/System.Embedded.1/LogServices/Sel/Entries")

	// Cap SEL entries to 50
	if len(selEntries) > 50 {
		selEntries = selEntries[:50]
	}

	snapshotData := map[string]interface{}{
		"system":     system,
		"power":      power,
		"thermal":    thermal,
		"processors": processors,
		"memory":     memory,
		"storage":    storage,
		"selEntries": selEntries,
	}

	alertList := extractIdracAlerts(system, selEntries)

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alertList,
		"collectedAt":  now,
	}, nil
}

func (a *IdracAdapter) Capabilities() []string {
	return []string{
		"idrac.read.system",
		"idrac.read.health",
		"idrac.read.power",
		"idrac.read.thermal",
		"idrac.read.inventory",
		"idrac.read.logs",
	}
}

func (a *IdracAdapter) HealthCheck() error {
	_, err := a.apiGet("/redfish/v1/Systems/System.Embedded.1")
	return err
}

func (a *IdracAdapter) Close() error {
	a.client = nil
	return nil
}

// apiGet fetches a single Redfish JSON object.
func (a *IdracAdapter) apiGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.authHeader)
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

// apiGetMembers fetches a Redfish collection and returns the Members array.
func (a *IdracAdapter) apiGetMembers(path string) ([]interface{}, error) {
	collection, err := a.apiGet(path)
	if err != nil {
		return nil, err
	}

	members, ok := collection["Members"].([]interface{})
	if !ok {
		// Some endpoints return data directly without Members wrapper
		return []interface{}{collection}, nil
	}
	return members, nil
}

func extractIdracAlerts(system map[string]interface{}, selEntries []interface{}) []map[string]interface{} {
	var alerts []map[string]interface{}

	// Check system health status
	if system != nil {
		if status, ok := system["Status"].(map[string]interface{}); ok {
			if health, ok := status["Health"].(string); ok && health != "OK" {
				alerts = append(alerts, map[string]interface{}{
					"severity": "warning",
					"source":   "dell-idrac",
					"message":  fmt.Sprintf("System health: %s", health),
				})
			}
		}
	}

	// Extract critical/error SEL entries
	for _, entry := range selEntries {
		e, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		severity, _ := e["Severity"].(string)
		if severity != "Critical" && severity != "Error" {
			continue
		}
		message, _ := e["Message"].(string)
		alertSev := "warning"
		if severity == "Critical" {
			alertSev = "error"
		}
		alerts = append(alerts, map[string]interface{}{
			"severity": alertSev,
			"source":   "dell-idrac",
			"message":  message,
		})
	}

	return alerts
}
