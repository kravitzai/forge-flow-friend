// ForgeAI Connector Host — Brocade FC Adapter (read-only)
//
// Collects switch chassis info, port status, media (SFP) diagnostics,
// and zoning configuration from Brocade FOS 8.2+ switches via the
// /rest/running/ REST API.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
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
		// If HTTPS fails with connection refused, try HTTP fallback
		if strings.HasPrefix(a.baseURL, "https://") && isConnRefused(err) {
			httpURL := "http://" + strings.TrimPrefix(a.baseURL, "https://")
			log.Printf("[brocade:%s] HTTPS connection refused, trying HTTP fallback at %s...", profile.Name, httpURL)
			a.baseURL = httpURL
			_, err2 := a.brocadeGet("/rest/running/brocade-chassis/chassis")
			if err2 != nil {
				return fmt.Errorf("Brocade FOS REST verification failed (tried HTTPS and HTTP): %w", err2)
			}
			log.Printf("[brocade:%s] Connected via HTTP (no TLS)", profile.Name)
			return nil
		}
		return fmt.Errorf("Brocade FOS REST verification failed: %w", err)
	}
	log.Printf("[brocade:%s] Connected via HTTPS", profile.Name)
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

	snapshotData := normalizeBrocadeSnapshot(chassis, switchInfo, ports, media, zoneConfig, fabricInfo)

	// Build alerts from normalized data
	var alerts []map[string]interface{}
	if pf, _ := snapshotData["portsFaulty"].(int); pf > 0 {
		alerts = append(alerts, map[string]interface{}{
			"severity": "critical",
			"source":   "brocade",
			"message":  fmt.Sprintf("%d port(s) in faulty state", pf),
		})
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
		"brocade.read.health",
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

// ── Normalization ──────────────────────────────────────────────────────

// normalizeBrocadeSnapshot flattens raw FOS REST responses into
// dashboard-ready fields expected by the frontend hook.
func normalizeBrocadeSnapshot(
	chassis, switchInfo, ports, media, zoneConfig, fabricInfo map[string]interface{},
) map[string]interface{} {
	out := map[string]interface{}{}

	// ── Switch identity ──
	if sw := brocadeExtractObject(switchInfo, "fibrechannel-switch"); sw != nil {
		out["switchName"] = sw["name"]
		out["switchWwn"] = sw["switch-wwn"]
		out["switchRole"] = sw["switch-role"]
		out["domainId"] = sw["domain-id"]
		out["firmwareVersion"] = sw["firmware-version"]
		out["model"] = sw["model"]
		// switch-state: 2=online, others not
		if st, ok := sw["switch-state"].(float64); ok {
			if int(st) == 2 {
				out["switchState"] = "Online"
			} else {
				out["switchState"] = fmt.Sprintf("state-%d", int(st))
			}
		}
	}

	// ── Chassis info ──
	if ch := brocadeExtractObject(chassis, "chassis"); ch != nil {
		if out["model"] == nil {
			out["model"] = ch["product-name"]
		}
		out["serialNumber"] = ch["serial-number"]
		out["chassisName"] = ch["chassis-user-friendly-name"]
		out["productName"] = ch["product-name"]
	}

	// ── Port summary ──
	portItems := brocadeExtractArray(ports, "fibrechannel")
	portsOnline, portsOffline, portsFaulty, portsDisabled := 0, 0, 0, 0
	fPort, ePort := 0, 0
	licensedPorts := 0
	for _, p := range portItems {
		pm, _ := p.(map[string]interface{})
		if pm == nil {
			continue
		}
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
		// is-enabled-state: 2=enabled, 6=disabled
		if en, ok := pm["is-enabled-state"].(float64); ok {
			if int(en) == 6 {
				portsDisabled++
			} else if int(en) == 2 {
				licensedPorts++
			}
		}
		// port-type: 7=E-Port, 10/17=F-Port
		if pt, ok := pm["port-type"].(float64); ok {
			switch int(pt) {
			case 7:
				ePort++
			case 10, 17:
				fPort++
			}
		}
	}

	// Count SFPs inserted from media endpoint
	mediaItems := brocadeExtractArray(media, "media-rdp")
	sfpInserted := len(mediaItems)

	out["ports"] = map[string]interface{}{
		"total":       len(portItems),
		"online":      portsOnline,
		"offline":     portsOffline,
		"faulty":      portsFaulty,
		"disabled":    portsDisabled,
		"fPort":       fPort,
		"ePort":       ePort,
		"licensed":    licensedPorts,
		"sfpInserted": sfpInserted,
	}
	// Top-level convenience fields for signal rules
	out["portTotal"] = len(portItems)
	out["portsOnline"] = portsOnline
	out["portsOffline"] = portsOffline
	out["portsFaulty"] = portsFaulty

	// ── SFP / Media warnings ──
	sfpWarnings := 0
	for _, m := range mediaItems {
		mm, _ := m.(map[string]interface{})
		if mm == nil {
			continue
		}
		// Check for power/temp alarm flags
		if hasBrocadeMediaWarning(mm) {
			sfpWarnings++
		}
	}
	out["sfpWarnings"] = sfpWarnings

	// ── Fabric ──
	fabricSwitches := brocadeExtractArray(fabricInfo, "fabric-switch")
	out["fabricSwitchCount"] = len(fabricSwitches)

	// ── Zoning ──
	if ec := brocadeExtractObject(zoneConfig, "effective-configuration"); ec != nil {
		out["zoningActiveCfg"] = ec["cfg-name"]
		if zones, ok := ec["zone"].([]interface{}); ok {
			out["zoneCount"] = len(zones)
		}
	} else {
		out["zoningActiveCfg"] = nil
	}

	// ── Raw data for investigation drill-down ──
	out["_raw"] = map[string]interface{}{
		"chassis":    chassis,
		"switchInfo": switchInfo,
		"ports":      ports,
		"media":      media,
		"zoneConfig": zoneConfig,
		"fabric":     fabricInfo,
	}

	return out
}

// hasBrocadeMediaWarning checks if a media-rdp entry has any warning/alarm flags set.
func hasBrocadeMediaWarning(m map[string]interface{}) bool {
	alarmKeys := []string{
		"remote-media-tx-power-alert-type",
		"remote-media-rx-power-alert-type",
		"remote-media-temperature-alert-type",
	}
	for _, k := range alarmKeys {
		if v, ok := m[k].(float64); ok && v != 0 {
			return true
		}
	}
	return false
}

// ── HTTP helpers ───────────────────────────────────────────────────────

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
	if arr, ok := resp[key].([]interface{}); ok {
		return arr
	}
	if r, ok := resp["Response"].(map[string]interface{}); ok {
		if arr, ok := r[key].([]interface{}); ok {
			return arr
		}
	}
	return nil
}

// brocadeExtractObject extracts a single object from Brocade's nested Response envelope.
func brocadeExtractObject(resp map[string]interface{}, key string) map[string]interface{} {
	if resp == nil {
		return nil
	}
	if obj, ok := resp[key].(map[string]interface{}); ok {
		return obj
	}
	if r, ok := resp["Response"].(map[string]interface{}); ok {
		if obj, ok := r[key].(map[string]interface{}); ok {
			return obj
		}
	}
	return nil
}

// isConnRefused checks if an error is a TCP connection refused.
func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "connection refused")
	}
	return strings.Contains(err.Error(), "connection refused")
}
