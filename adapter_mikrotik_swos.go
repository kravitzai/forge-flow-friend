// ForgeAI Connector Host — MikroTik SwOS Adapter (read-only)
//
// Collects system, port, switching, VLAN, LAG, RSTP, SFP, PoE,
// forwarding, and health data from MikroTik SwOS devices via
// authenticated HTTP page scraping. Optionally augments with SNMP.
//
// Supports: CSS/CRS switches running SwOS (not RouterOS).
// Does NOT support RouterOS devices — use adapter_mikrotik.go instead.
//
// SwOS has no REST/CLI API. Data is extracted by fetching internal
// JavaScript variable pages (e.g., /!dhost.b, /!stats.b, /!sfp.b).

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type MikroTikSwOSAdapter struct {
	profile    *TargetProfile
	client     *http.Client
	baseURL    string
	user       string
	pass       string
	sessionOK  bool
	snmpTarget string // optional SNMP augmentation target
}

func NewMikroTikSwOSAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &MikroTikSwOSAdapter{profile: profile}, nil
}

func (a *MikroTikSwOSAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	a.profile = profile
	a.baseURL = strings.TrimRight(profile.Endpoint, "/")
	a.user = creds["username"]
	a.pass = creds["password"]
	a.snmpTarget = creds["snmp_community"] // optional

	timeout := 20 * time.Second
	if profile.ResourceLimits.TimeoutSecs > 0 {
		timeout = time.Duration(profile.ResourceLimits.TimeoutSecs) * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	jar, _ := cookiejar.New(nil)
	a.client = &http.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: profile.TLS.InsecureSkipVerify,
			},
		},
	}

	// Authenticate via SwOS login
	log.Printf("[mikrotik-swos:%s] Authenticating to SwOS at %s...", profile.Name, a.baseURL)
	err := a.swosLogin()
	if err != nil {
		// Try HTTP fallback if HTTPS failed
		if strings.HasPrefix(a.baseURL, "https://") {
			httpURL := "http://" + strings.TrimPrefix(a.baseURL, "https://")
			log.Printf("[mikrotik-swos:%s] HTTPS failed, trying HTTP at %s...", profile.Name, httpURL)
			a.baseURL = httpURL
			jar2, _ := cookiejar.New(nil)
			a.client.Jar = jar2
			err2 := a.swosLogin()
			if err2 != nil {
				return fmt.Errorf("SwOS authentication failed (tried HTTPS and HTTP): %w", err2)
			}
		} else {
			return fmt.Errorf("SwOS authentication failed: %w", err)
		}
	}

	a.sessionOK = true
	log.Printf("[mikrotik-swos:%s] SwOS session established", profile.Name)
	return nil
}

// swosLogin authenticates to the SwOS web UI
func (a *MikroTikSwOSAdapter) swosLogin() error {
	loginURL := a.baseURL + "/"
	payload := fmt.Sprintf("usr=%s&pwd=%s", a.user, a.pass)
	resp, err := a.client.Post(loginURL, "application/x-www-form-urlencoded", strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// SwOS returns 200 with a session cookie on success
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		return fmt.Errorf("login returned HTTP %d", resp.StatusCode)
	}

	// Verify session by fetching system page
	_, verifyErr := a.swosGet("/!dhost.b")
	if verifyErr != nil {
		return fmt.Errorf("session verification failed: %w", verifyErr)
	}

	return nil
}

// swosGet fetches a SwOS internal page
func (a *MikroTikSwOSAdapter) swosGet(path string) ([]byte, error) {
	url := a.baseURL + path
	resp, err := a.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func (a *MikroTikSwOSAdapter) Collect() (map[string]interface{}, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Re-authenticate if session expired
	if !a.sessionOK {
		if err := a.swosLogin(); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		a.sessionOK = true
	}

	raw := make(map[string]interface{})

	// ── Fetch all available SwOS pages ──
	pageMap := map[string]string{
		"system":  "/!dhost.b",
		"link":    "/!link.b",
		"stats":   "/!stats.b",
		"sfp":     "/!sfp.b",
		"poe":     "/!poe.b",
		"vlan":    "/!vlan.b",
		"fwd":     "/!fwd.b",
		"lag":     "/!lag.b",
		"rstp":    "/!rstp.b",
		"hosts":   "/!host.b",
		"acl":     "/!acl.b",
		"snmp":    "/!snmp.b",
	}

	rawPages := make(map[string]string)
	capabilities := make(map[string]bool)

	for section, path := range pageMap {
		body, err := a.swosGet(path)
		if err != nil {
			log.Printf("[mikrotik-swos:%s] Page %s unavailable: %v", a.profile.Name, section, err)
			capabilities["has"+ucFirst(section)] = false
			continue
		}
		pageStr := string(body)
		if len(pageStr) < 10 || strings.Contains(pageStr, "\"error\"") {
			capabilities["has"+ucFirst(section)] = false
			continue
		}
		rawPages[section] = pageStr
		capabilities["has"+ucFirst(section)] = true
	}

	// ── Parse each available page ──
	identity := a.parseSystemPage(rawPages["system"])
	ports := a.parseLinkPage(rawPages["link"])
	stats := a.parseStatsPage(rawPages["stats"])
	sfp := a.parseSfpPage(rawPages["sfp"])
	poe := a.parsePoePage(rawPages["poe"])
	vlans := a.parseVlanPage(rawPages["vlan"])
	forwarding := a.parseFwdPage(rawPages["fwd"])
	lag := a.parseLagPage(rawPages["lag"])
	rstp := a.parseRstpPage(rawPages["rstp"])
	hosts := a.parseHostsPage(rawPages["hosts"])

	// Merge stats into ports
	if len(stats) > 0 && len(ports) > 0 {
		for i := range ports {
			if i < len(stats) {
				for k, v := range stats[i] {
					ports[i][k] = v
				}
			}
		}
	}

	// ── Derive health from port/system data ──
	health := a.deriveHealth(identity, ports, sfp, poe)

	// ── Build normalized snapshot ──
	snapshotData := map[string]interface{}{
		"identity":     identity,
		"system":       identity, // SwOS system is the identity page
		"ports":        ports,
		"switching":    map[string]interface{}{"portCount": len(ports)},
		"vlan":         vlans,
		"lag":          lag,
		"sfp":          sfp,
		"poe":          poe,
		"hosts":        forwarding,
		"hostTable":    hosts,
		"rstp":         rstp,
		"health":       health,
		"capabilities": capabilities,
		"_raw":         rawPages,
	}

	raw["snapshotData"] = snapshotData

	// Build alerts
	alerts := a.buildAlerts(snapshotData)

	// Extract signals
	signals := extractSwOSSignals(snapshotData)

	result := map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": snapshotData,
		"alerts":       alerts,
		"collectedAt":  now,
		"_signals":     signals,
	}

	if len(signals) > 0 {
		log.Printf("[mikrotik-swos:%s] Emitting %d signals", a.profile.Name, len(signals))
	}

	return result, nil
}

func (a *MikroTikSwOSAdapter) Capabilities() []string {
	return []string{
		"mikrotik-swos.read.system",
		"mikrotik-swos.read.ports",
		"mikrotik-swos.read.stats",
		"mikrotik-swos.read.vlan",
		"mikrotik-swos.read.forwarding",
		"mikrotik-swos.read.health",
	}
}

func (a *MikroTikSwOSAdapter) TargetType() string {
	return "mikrotik-swos"
}

// ── Page Parsers ──

var jsVarRe = regexp.MustCompile(`var\s+(\w+)\s*=\s*(\[.*?\]|{.*?}|\d+|'[^']*'|"[^"]*");`)

func (a *MikroTikSwOSAdapter) parseSystemPage(page string) map[string]interface{} {
	result := map[string]interface{}{}
	if page == "" {
		return result
	}

	// SwOS system page exports JS vars: nm, mac, brd, ver, bld, etc.
	kvPairs := extractJSVars(page)
	if v, ok := kvPairs["nm"]; ok {
		result["deviceName"] = v
	}
	if v, ok := kvPairs["mac"]; ok {
		result["macAddress"] = v
	}
	if v, ok := kvPairs["brd"]; ok {
		result["board"] = v
		result["model"] = v
	}
	if v, ok := kvPairs["ver"]; ok {
		result["version"] = v
	}
	if v, ok := kvPairs["bld"]; ok {
		result["build"] = v
	}
	if v, ok := kvPairs["upn"]; ok {
		result["uptime"] = v
	}

	return result
}

func (a *MikroTikSwOSAdapter) parseLinkPage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}

	// SwOS link page exports arrays for port properties
	ports := extractPortArrays(page, []string{"nm", "en", "lnk", "spd", "dpx", "fct", "mtu"})
	for i := range ports {
		ports[i]["index"] = i
		// Derive link state
		if lnk, ok := ports[i]["lnk"]; ok {
			switch fmt.Sprint(lnk) {
			case "1", "true":
				ports[i]["linkState"] = "up"
			default:
				ports[i]["linkState"] = "down"
			}
		}
		// Derive enabled state
		if en, ok := ports[i]["en"]; ok {
			switch fmt.Sprint(en) {
			case "0", "false":
				ports[i]["adminState"] = "disabled"
			default:
				ports[i]["adminState"] = "enabled"
			}
		}
	}
	return ports
}

func (a *MikroTikSwOSAdapter) parseStatsPage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}
	return extractPortArrays(page, []string{"rx", "tx", "rxb", "txb", "rxd", "txd", "rxe", "txe"})
}

func (a *MikroTikSwOSAdapter) parseSfpPage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}
	return extractPortArrays(page, []string{"tmp", "vlt", "cur", "txp", "rxp", "vnd", "prt"})
}

func (a *MikroTikSwOSAdapter) parsePoePage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}
	return extractPortArrays(page, []string{"en", "pwr", "cur", "vlt", "st"})
}

func (a *MikroTikSwOSAdapter) parseVlanPage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}
	// VLAN page typically has per-VLAN membership arrays
	kvPairs := extractJSVars(page)
	var vlans []map[string]interface{}
	// Parse VLAN entries from JS arrays
	if raw, ok := kvPairs["vlni"]; ok {
		ids := parseJSArray(raw)
		for _, id := range ids {
			vlans = append(vlans, map[string]interface{}{
				"vlanId": id,
			})
		}
	}
	return vlans
}

func (a *MikroTikSwOSAdapter) parseFwdPage(page string) map[string]interface{} {
	if page == "" {
		return nil
	}
	kvPairs := extractJSVars(page)
	return map[string]interface{}{
		"mode": kvPairs["fwt"],
		"raw":  kvPairs,
	}
}

func (a *MikroTikSwOSAdapter) parseLagPage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}
	return extractPortArrays(page, []string{"grp", "en", "lnk"})
}

func (a *MikroTikSwOSAdapter) parseRstpPage(page string) map[string]interface{} {
	if page == "" {
		return nil
	}
	kvPairs := extractJSVars(page)
	return map[string]interface{}{
		"enabled":    kvPairs["en"],
		"rootBridge": kvPairs["rb"],
		"priority":   kvPairs["prt"],
		"raw":        kvPairs,
	}
}

func (a *MikroTikSwOSAdapter) parseHostsPage(page string) []map[string]interface{} {
	if page == "" {
		return nil
	}
	return extractPortArrays(page, []string{"mac", "prt", "vid"})
}

// ── Health Derivation ──

func (a *MikroTikSwOSAdapter) deriveHealth(
	identity map[string]interface{},
	ports []map[string]interface{},
	sfp []map[string]interface{},
	poe []map[string]interface{},
) map[string]interface{} {
	health := map[string]interface{}{
		"overall": "healthy",
	}

	// Count port states
	totalPorts := len(ports)
	upPorts := 0
	downPorts := 0
	disabledPorts := 0
	for _, p := range ports {
		switch fmt.Sprint(p["linkState"]) {
		case "up":
			upPorts++
		case "down":
			if fmt.Sprint(p["adminState"]) == "disabled" {
				disabledPorts++
			} else {
				downPorts++
			}
		}
	}

	health["totalPorts"] = totalPorts
	health["upPorts"] = upPorts
	health["downPorts"] = downPorts
	health["disabledPorts"] = disabledPorts

	// SFP warnings
	sfpWarnings := 0
	for _, s := range sfp {
		if tmp, ok := s["tmp"]; ok {
			if t, err := strconv.ParseFloat(fmt.Sprint(tmp), 64); err == nil && t > 70 {
				sfpWarnings++
			}
		}
	}
	health["sfpWarnings"] = sfpWarnings

	if upPorts == 0 && totalPorts > 0 {
		health["overall"] = "critical"
	} else if sfpWarnings > 0 || (downPorts > totalPorts/2 && totalPorts > 4) {
		health["overall"] = "degraded"
	}

	return health
}

// ── Alert Builder ──

func (a *MikroTikSwOSAdapter) buildAlerts(snapshot map[string]interface{}) []map[string]interface{} {
	var alerts []map[string]interface{}

	health, _ := snapshot["health"].(map[string]interface{})
	if health != nil {
		if fmt.Sprint(health["overall"]) == "critical" {
			alerts = append(alerts, map[string]interface{}{
				"severity": "error",
				"title":    "All ports down",
				"message":  "No ports are currently linked up on this SwOS device.",
			})
		}
	}

	return alerts
}

// ── Signal Extraction ──

func extractSwOSSignals(snapshot map[string]interface{}) []SnapshotSignal {
	var signals []SnapshotSignal

	health, _ := snapshot["health"].(map[string]interface{})
	if health != nil {
		overall := fmt.Sprint(health["overall"])
		switch overall {
		case "critical":
			signals = append(signals, SnapshotSignal{Key: "switch.all_ports_down", Severity: "critical", Label: "All switch ports are down"})
		case "degraded":
			signals = append(signals, SnapshotSignal{Key: "switch.degraded", Severity: "warning", Label: "Switch health degraded"})
		}

		if sfpW, ok := health["sfpWarnings"]; ok {
			if w, err := strconv.Atoi(fmt.Sprint(sfpW)); err == nil && w > 0 {
				signals = append(signals, SnapshotSignal{Key: "sfp.temperature_warning", Severity: "warning", Label: fmt.Sprintf("%d SFP module(s) over temperature", w)})
			}
		}
	}

	// Port-level signals
	if ports, ok := snapshot["ports"].([]map[string]interface{}); ok {
		for _, p := range ports {
			if fmt.Sprint(p["linkState"]) == "down" && fmt.Sprint(p["adminState"]) != "disabled" {
				name := fmt.Sprint(p["nm"])
				if name == "" || name == "<nil>" {
					name = fmt.Sprintf("port%v", p["index"])
				}
				// Only signal for SFP ports as they are typically expected uplinks
				if strings.Contains(strings.ToLower(name), "sfp") {
					signals = append(signals, SnapshotSignal{
						Key:      "port.sfp_down",
						Severity: "warning",
						Label:    fmt.Sprintf("SFP port %s is down", name),
						Entity:   name,
					})
				}
			}
		}
	}

	// Fallback if no snapshot data at all
	if len(snapshot) == 0 {
		signals = append(signals, SnapshotSignal{Key: "switch.unknown", Severity: "warning", Label: "No SwOS data available"})
	}

	return signals
}

// ── JS Page Parsing Helpers ──

func extractJSVars(page string) map[string]string {
	result := make(map[string]string)
	matches := jsVarRe.FindAllStringSubmatch(page, -1)
	for _, m := range matches {
		if len(m) == 3 {
			val := strings.Trim(m[2], "'\"")
			result[m[1]] = val
		}
	}
	return result
}

func extractPortArrays(page string, fields []string) []map[string]interface{} {
	kvPairs := extractJSVars(page)
	maxLen := 0

	fieldArrays := make(map[string][]string)
	for _, f := range fields {
		if raw, ok := kvPairs[f]; ok {
			arr := parseJSArray(raw)
			fieldArrays[f] = arr
			if len(arr) > maxLen {
				maxLen = len(arr)
			}
		}
	}

	var result []map[string]interface{}
	for i := 0; i < maxLen; i++ {
		entry := map[string]interface{}{"index": i}
		for _, f := range fields {
			if arr, ok := fieldArrays[f]; ok && i < len(arr) {
				entry[f] = arr[i]
			}
		}
		result = append(result, entry)
	}
	return result
}

func parseJSArray(raw string) []string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") {
		return nil
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "'\"")
		result = append(result, p)
	}
	return result
}

func ucFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}




func (a *MikroTikSwOSAdapter) HealthCheck() error {
	if !a.sessionOK {
		return fmt.Errorf("SwOS session not established")
	}
	return nil
}

// Ensure adapter conforms to SNMP augmentation pattern
func (a *MikroTikSwOSAdapter) Close() error {
	a.sessionOK = false
	return nil
}
