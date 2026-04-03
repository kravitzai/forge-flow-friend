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
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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

var digestAuthParamRe = regexp.MustCompile(`(\w+)=("([^"]*)"|[^,]+)`)

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
	tlsCfg := &TLSConfig{
		InsecureSkipVerify: profile.TLS.InsecureSkipVerify,
	}
	a.client = NewHTTPClient(tlsCfg, nil, timeout)
	a.client.Jar = jar

	// Authenticate by probing a real SwOS data page.
	// SwOS models use HTTP auth (Digest on many versions, Basic on some),
	// not the old form POST flow.
	log.Printf("[mikrotik-swos:%s] Authenticating to SwOS at %s...", profile.Name, a.baseURL)
	err := a.swosLogin()
	if err != nil {
		// Try HTTP fallback if HTTPS failed
		if strings.HasPrefix(a.baseURL, "https://") {
			httpURL := "http://" + strings.TrimPrefix(a.baseURL, "https://")
			log.Printf("[mikrotik-swos:%s] HTTPS failed, trying HTTP at %s...", profile.Name, httpURL)
			a.baseURL = httpURL
			jar2, _ := cookiejar.New(nil)
			a.client = NewHTTPClient(tlsCfg, nil, timeout)
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

// swosLogin authenticates by probing a ranked list of SwOS data pages.
// Returns nil as soon as any page responds successfully.
// Different SwOS versions expose different pages.
func (a *MikroTikSwOSAdapter) swosLogin() error {
	candidates := []string{
		"/!link.b",  // present on all SwOS
		"/!dhost.b", // most CRS/CSS models
		"/sys.b",    // legacy SwOS
		"/!stats.b", // fallback
	}
	var lastErr error
	for _, path := range candidates {
		if _, err := a.swosGet(path); err == nil {
			log.Printf("[mikrotik-swos:%s] Auth probe succeeded via %s", a.profile.Name, path)
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("SwOS auth probe failed on all candidates: %w", lastErr)
}

// swosGet fetches a SwOS internal page using the device's native HTTP auth.
func (a *MikroTikSwOSAdapter) swosGet(path string) ([]byte, error) {
	return a.swosRequest(http.MethodGet, path, nil, "")
}

func (a *MikroTikSwOSAdapter) swosRequest(method, path string, body []byte, contentType string) ([]byte, error) {
	resp, err := a.doSwOSRequest(method, path, body, contentType, "")
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("Www-Authenticate")
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		authHeader, scheme, authErr := buildSwOSAuthHeader(challenge, method, path, a.user, a.pass)
		if authErr != nil {
			return nil, fmt.Errorf("%s %s: auth challenge unsupported: %w", method, path, authErr)
		}
		log.Printf("[mikrotik-swos:%s] Retrying %s with %s auth", a.profile.Name, path, scheme)

		resp, err = a.doSwOSRequest(method, path, body, contentType, authHeader)
		if err != nil {
			return nil, fmt.Errorf("%s %s retry: %w", method, path, err)
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return respBody, nil
}

func (a *MikroTikSwOSAdapter) doSwOSRequest(method, path string, body []byte, contentType, authHeader string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, a.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return a.client.Do(req)
}

func buildSwOSAuthHeader(challenge, method, uri, username, password string) (string, string, error) {
	lowerChallenge := strings.ToLower(challenge)
	if strings.Contains(lowerChallenge, "digest") {
		header, err := buildDigestAuthHeader(challenge, method, uri, username, password)
		return header, "digest", err
	}
	if strings.Contains(lowerChallenge, "basic") || challenge == "" {
		if username == "" {
			return "", "", fmt.Errorf("basic auth requested but username is empty")
		}
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		return "Basic " + token, "basic", nil
	}
	return "", "", fmt.Errorf("unsupported WWW-Authenticate challenge: %q", challenge)
}

func buildDigestAuthHeader(challenge, method, uri, username, password string) (string, error) {
	params := parseDigestAuthParams(challenge)
	realm := params["realm"]
	nonce := params["nonce"]
	if realm == "" || nonce == "" {
		return "", fmt.Errorf("missing realm/nonce in digest challenge")
	}

	cnonce, err := randomHex(8)
	if err != nil {
		return "", err
	}

	algorithm := strings.ToLower(params["algorithm"])
	ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", username, realm, password))
	if algorithm == "md5-sess" {
		ha1 = md5Hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, cnonce))
	} else if algorithm != "" && algorithm != "md5" {
		return "", fmt.Errorf("unsupported digest algorithm %q", params["algorithm"])
	}

	ha2 := md5Hex(fmt.Sprintf("%s:%s", method, uri))
	nc := "00000001"
	qop := ""
	if rawQop := params["qop"]; rawQop != "" {
		for _, option := range strings.Split(rawQop, ",") {
			candidate := strings.TrimSpace(strings.Trim(option, `"`))
			if candidate == "auth" {
				qop = candidate
				break
			}
			if qop == "" {
				qop = candidate
			}
		}
	}

	response := ""
	if qop != "" {
		response = md5Hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2))
	} else {
		response = md5Hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}

	parts := []string{
		fmt.Sprintf(`Digest username="%s"`, username),
		fmt.Sprintf(`realm="%s"`, realm),
		fmt.Sprintf(`nonce="%s"`, nonce),
		fmt.Sprintf(`uri="%s"`, uri),
		fmt.Sprintf(`response="%s"`, response),
	}
	if opaque := params["opaque"]; opaque != "" {
		parts = append(parts, fmt.Sprintf(`opaque="%s"`, opaque))
	}
	if params["algorithm"] != "" {
		parts = append(parts, fmt.Sprintf("algorithm=%s", params["algorithm"]))
	}
	if qop != "" {
		parts = append(parts,
			fmt.Sprintf("qop=%s", qop),
			fmt.Sprintf("nc=%s", nc),
			fmt.Sprintf(`cnonce="%s"`, cnonce),
		)
	}

	return strings.Join(parts, ", "), nil
}

func parseDigestAuthParams(challenge string) map[string]string {
	challenge = strings.TrimSpace(challenge)
	if strings.HasPrefix(strings.ToLower(challenge), "digest ") {
		challenge = challenge[len("Digest "):]
	}

	params := make(map[string]string)
	for _, match := range digestAuthParamRe.FindAllStringSubmatch(challenge, -1) {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[2])
		value = strings.Trim(value, `"`)
		params[strings.ToLower(match[1])] = value
	}
	return params
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
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

	log.Printf("[mikrotik-swos:%s] Pages fetched: %d of %d attempted", a.profile.Name, len(rawPages), len(pageMap))
	for section := range rawPages {
		log.Printf("[mikrotik-swos:%s]   page[%s] = %d bytes", a.profile.Name, section, len(rawPages[section]))
	}

	// Fallback: try legacy system page if /!dhost.b was unavailable
	if _, hasSystem := rawPages["system"]; !hasSystem {
		fallbacks := []string{"/sys.b", "/!link.b"}
		for _, fb := range fallbacks {
			if body, err := a.swosGet(fb); err == nil {
				rawPages["system"] = string(body)
				capabilities["hasSystem"] = true
				log.Printf("[mikrotik-swos:%s] System page fallback succeeded via %s", a.profile.Name, fb)
				break
			}
		}
	}

	// ── Parse each available page ──
	identity := a.parseSystemPage(rawPages["system"])

	// If identity is sparse (common when /!dhost.b is unavailable),
	// scan ALL fetched pages for scalar identity vars (brd, ver, mac)
	// that many SwOS pages include as header variables.
	if identity["model"] == nil || identity["version"] == nil {
		identityVars := []string{"brd", "ver", "mac", "bld"}
		for section, pageContent := range rawPages {
			if section == "system" {
				continue // already parsed
			}
			kvPairs := extractJSVars(pageContent)
			for _, varName := range identityVars {
				v, ok := kvPairs[varName]
				if !ok || strings.HasPrefix(v, "[") {
					continue // skip arrays
				}
				switch varName {
				case "brd":
					if identity["model"] == nil {
						identity["board"] = v
						identity["model"] = v
					}
				case "ver":
					if identity["version"] == nil {
						identity["version"] = v
					}
				case "mac":
					if identity["macAddress"] == nil {
						identity["macAddress"] = v
					}
				case "bld":
					if identity["build"] == nil {
						identity["build"] = v
					}
				}
			}
		}
		log.Printf("[mikrotik-swos:%s] Identity after cross-page scan: model=%v version=%v mac=%v",
			a.profile.Name, identity["model"], identity["version"], identity["macAddress"])
	}

	// Sanitize: if deviceName looks like a JS array, clear it
	if dn, ok := identity["deviceName"].(string); ok && strings.HasPrefix(dn, "[") {
		delete(identity, "deviceName")
	}
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

	log.Printf("[mikrotik-swos:%s] Emitting %d signals for cloud rollup", a.profile.Name, len(signals))
	for i, s := range signals {
		log.Printf("[mikrotik-swos:%s]   signal[%d] key=%s sev=%s label=%s", a.profile.Name, i, s.Key, s.Severity, s.Label)
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
