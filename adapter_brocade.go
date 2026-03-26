// ForgeAI Connector Host — Brocade FC Adapter (read-only)
//
// Collects switch chassis info, port status, media (SFP) diagnostics,
// and zoning configuration from Brocade FOS 8.2+ switches via the
// /rest/running/ REST API.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type BrocadeAdapter struct {
	profile *TargetProfile
	client  *http.Client
	baseURL string
	user    string
	pass    string
	token   string
}

func NewBrocadeAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &BrocadeAdapter{profile: profile}, nil
}

func (a *BrocadeAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = profile.Endpoint

	timeout := 15 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	a.client = NewHTTPClientFromProfile(profile, timeout)

	a.user = creds["username"]
	a.pass = creds["password"]
	if t := creds["token"]; t != "" {
		a.token = t
	} else if t := creds["api_token"]; t != "" {
		a.token = t
	}

	log.Printf("[brocade:%s] Verifying FOS REST API at %s...", profile.Name, a.baseURL)
	_, err := a.brocadeGet("/rest/running/brocade-chassis/chassis")
	if err != nil {
		return fmt.Errorf("Brocade FOS REST verification failed: %w", err)
	}
	log.Printf("[brocade:%s] Connected", profile.Name)
	return nil
}

func (a *BrocadeAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	chassis, _ := a.brocadeGet("/rest/running/brocade-chassis/chassis")
	switchInfo, _ := a.brocadeGet("/rest/running/brocade-fibrechannel-switch/fibrechannel-switch")
	ports, _ := a.brocadeGet("/rest/running/brocade-interface/fibrechannel")
	media, _ := a.brocadeGet("/rest/running/brocade-media/media-rdp")
	zoneConfig, _ := a.brocadeGet("/rest/running/brocade-zone/effective-configuration")
	fabricInfo, _ := a.brocadeGet("/rest/running/brocade-fabric/fabric-switch")

	// Extract port summary
	portItems := brocadeExtractArray(ports, "fibrechannel")
	portsOnline, portsOffline, portsFaulty := 0, 0, 0
	for _, p := range portItems {
		pm, _ := p.(map[string]interface{})
		if pm == nil {
			continue
		}
		// operational-status: 2=online, 3=offline, 5=faulty
		opSt, _ := pm["operational-status"].(float64)
		switch int(opSt) {
		case 2:
			portsOnline++
		case 3:
			portsOffline++
		case 5:
			portsFaulty++
		default:
			portsOffline++
		}
	}

	var alerts []map[string]interface{}
	if portsFaulty > 0 {
		alerts = append(alerts, map[string]interface{}{
			"severity": "critical",
			"source":   "brocade",
			"message":  fmt.Sprintf("%d port(s) in faulty state", portsFaulty),
		})
	}

	summary := map[string]interface{}{
		"portTotal":    len(portItems),
		"portsOnline":  portsOnline,
		"portsOffline": portsOffline,
		"portsFaulty":  portsFaulty,
	}

	// Extract chassis info
	if chassis != nil {
		if ch, ok := chassis["Response"].(map[string]interface{}); ok {
			if c, ok := ch["chassis"].(map[string]interface{}); ok {
				summary["chassisName"] = c["chassis-user-friendly-name"]
				summary["serialNumber"] = c["serial-number"]
				summary["productName"] = c["product-name"]
			}
		}
	}

	snapshotData := map[string]interface{}{
		"chassis":    chassis,
		"switchInfo": switchInfo,
		"ports":      ports,
		"media":      media,
		"zoneConfig": zoneConfig,
		"fabric":     fabricInfo,
		"summary":    summary,
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
	}, nil
}

func (a *BrocadeAdapter) Capabilities() []string {
	return []string{
		"brocade.read.chassis",
		"brocade.read.ports",
		"brocade.read.media",
		"brocade.read.zoning",
		"brocade.read.fabric",
	}
}

func (a *BrocadeAdapter) HealthCheck() error {
	_, err := a.brocadeGet("/rest/running/brocade-chassis/chassis")
	return err
}

func (a *BrocadeAdapter) Close() error {
	a.client = nil
	return nil
}

func (a *BrocadeAdapter) brocadeGet(path string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", a.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else if a.user != "" && a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	req.Header.Set("Accept", "application/yang-data+json")

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

// brocadeExtractArray extracts an array from Brocade's nested Response envelope.
func brocadeExtractArray(resp map[string]interface{}, key string) []interface{} {
	if resp == nil {
		return nil
	}
	// Try direct key
	if arr, ok := resp[key].([]interface{}); ok {
		return arr
	}
	// Try Response envelope
	if r, ok := resp["Response"].(map[string]interface{}); ok {
		if arr, ok := r[key].([]interface{}); ok {
			return arr
		}
	}
	return nil
}
