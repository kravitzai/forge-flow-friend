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
	// Preemptive auth — populated after first successful digest/basic
	// handshake so all subsequent requests skip the 401 round-trip.
	authScheme string // "digest", "basic", "form", ""
	authRealm  string // digest realm
	authNonce  string // last good nonce
	authOpaque string // digest opaque
	authQop    string // digest qop
	pathStyle  string // "bang" (/!x.b) or "lite" (/x)
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

// swosLogin probes a ranked list of SwOS data pages and validates that
// the response body actually contains JS variable data, not an auth
// redirect (which also returns HTTP 200 on some firmware versions).
func (a *MikroTikSwOSAdapter) swosLogin() error {
	// SwOS path families:
	// "bang" = CRS/CloudRouter: /!link.b /!dhost.b
	// "lite" = CSS/SwOS Lite:  /link /sys /stat
	type candidate struct {
		path      string
		pathStyle string
	}
	candidates := []candidate{
		// SwOS Lite (CSS326, CSS610 etc) — try first because these
		// devices also respond to bang paths with HTML catch-all
		// (false positive).
		{"/link", "lite"},
		{"/sys", "lite"},
		{"/stat", "lite"},
		// SwOS CRS/CloudRouter
		{"/!link.b", "bang"},
		{"/!dhost.b", "bang"},
		{"/!stats.b", "bang"},
	}
	for _, c := range candidates {
		body, err := a.swosGet(c.path)
		if err != nil {
			// 404 or network error — try next
			continue
		}
		if isSwOSDataPage(body) {
			log.Printf("[mikrotik-swos:%s] Auth confirmed via %s (%d bytes, style=%s)", a.profile.Name, c.path, len(body), c.pathStyle)
			a.pathStyle = c.pathStyle
			return nil
		}
		log.Printf("[mikrotik-swos:%s] %s returned 200 but no JS data, continuing", a.profile.Name, c.path)
	}
	// ── Fallback: form-based POST login ──
	// Used by SwOS 2.x on CRS series devices that do not use HTTP digest/basic auth.
	log.Printf("[mikrotik-swos:%s] HTTP auth failed, trying form-based login", a.profile.Name)
	if err := a.swosFormLogin(); err == nil {
		return nil
	}
	return fmt.Errorf("SwOS auth probe: no candidate page returned valid JS data — check credentials and device reachability")
}

// swosPageMap returns the correct URL path map based on the detected pathStyle.
func (a *MikroTikSwOSAdapter) swosPageMap() map[string]string {
	if a.pathStyle == "lite" {
		// CSS series SwOS Lite paths
		return map[string]string{
			"system": "/sys",
			"link":   "/link",
			"stats":  "/stat",
			"sfp":    "/sfp",
			"vlan":   "/vlan",
			"fwd":    "/fwd",
			"lag":    "/lag",
			"rstp":   "/rstp",
			"hosts":  "/host",
			"snmp":   "/snmp",
		}
	}
	// Default: CRS/CloudRouter bang paths
	return map[string]string{
		"system": "/!dhost.b",
		"link":   "/!link.b",
		"stats":  "/!stats.b",
		"sfp":    "/!sfp.b",
		"poe":    "/!poe.b",
		"vlan":   "/!vlan.b",
		"fwd":    "/!fwd.b",
		"lag":    "/!lag.b",
		"rstp":   "/!rstp.b",
		"hosts":  "/!host.b",
		"acl":    "/!acl.b",
		"snmp":   "/!snmp.b",
	}
}

// swosFormLogin attempts web-form-based login used by SwOS 2.x on CRS series
// devices. POSTs credentials to "/" with URL-encoded form body. On success the
// cookie jar stores the session cookie and subsequent data page GETs work
// without any Authorization header.
func (a *MikroTikSwOSAdapter) swosFormLogin() error {
	endpoints := []struct {
		path    string
		bodyFmt string
	}{
		{"/", "username=%s&password=%s"},
		{"/login", "username=%s&password=%s"},
		{"/!auth.b", "username=%s&password=%s"},
	}
	for _, ep := range endpoints {
		formBody := fmt.Sprintf(ep.bodyFmt, a.user, a.pass)

		// Allow redirect following — the session cookie is set on the
		// redirect target GET, not on the POST response itself.
		// The cookie jar captures every Set-Cookie in the full redirect
		// chain automatically.
		req, err := http.NewRequest(
			http.MethodPost,
			a.baseURL+ep.path,
			strings.NewReader(formBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Referer", a.baseURL+"/")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ForgeAI/1.0)")

		resp, err := a.client.Do(req)
		if err != nil {
			log.Printf("[mikrotik-swos:%s] Form POST %s failed: %v", a.profile.Name, ep.path, err)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		log.Printf("[mikrotik-swos:%s] Form POST %s completed (final HTTP %d)", a.profile.Name, ep.path, resp.StatusCode)

		// Verify: data page must return JS content
		type probeEntry struct {
			path      string
			pathStyle string
		}
		probes := []probeEntry{
			{"/link", "lite"}, {"/sys", "lite"},
			{"/!link.b", "bang"}, {"/!dhost.b", "bang"},
		}
		for _, probe := range probes {
			pbody, perr := a.swosGet(probe.path)
			if perr == nil && isSwOSDataPage(pbody) {
				log.Printf("[mikrotik-swos:%s] Form login via %s confirmed by %s (%d bytes)", a.profile.Name, ep.path, probe.path, len(pbody))
				a.authScheme = "form"
				a.pathStyle = probe.pathStyle
				return nil
			}
		}
		log.Printf("[mikrotik-swos:%s] Form POST %s completed but data pages still return no JS content", a.profile.Name, ep.path)
	}
	return fmt.Errorf("form login failed on all endpoints")
}

// swosGet fetches a SwOS internal page using the device's native HTTP auth.
func (a *MikroTikSwOSAdapter) swosGet(path string) ([]byte, error) {
	return a.swosRequest(http.MethodGet, path, nil, "")
}

// buildPreemptiveAuth constructs an Authorization header using stored auth
// parameters so the adapter can authenticate without a 401 round-trip.
// Returns "" if no auth has been established yet.
func (a *MikroTikSwOSAdapter) buildPreemptiveAuth(method, path string) string {
	switch a.authScheme {
	case "basic":
		token := base64.StdEncoding.EncodeToString([]byte(a.user + ":" + a.pass))
		return "Basic " + token
	case "digest":
		if a.authRealm == "" || a.authNonce == "" {
			return ""
		}
		cnonce, err := randomHex(8)
		if err != nil {
			return ""
		}
		ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", a.user, a.authRealm, a.pass))
		ha2 := md5Hex(fmt.Sprintf("%s:%s", method, path))
		nc := "00000001"
		var response string
		if a.authQop != "" {
			response = md5Hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, a.authNonce, nc, cnonce, a.authQop, ha2))
		} else {
			response = md5Hex(fmt.Sprintf("%s:%s:%s", ha1, a.authNonce, ha2))
		}
		parts := []string{
			fmt.Sprintf(`Digest username="%s"`, a.user),
			fmt.Sprintf(`realm="%s"`, a.authRealm),
			fmt.Sprintf(`nonce="%s"`, a.authNonce),
			fmt.Sprintf(`uri="%s"`, path),
			fmt.Sprintf(`response="%s"`, response),
		}
		if a.authOpaque != "" {
			parts = append(parts, fmt.Sprintf(`opaque="%s"`, a.authOpaque))
		}
		if a.authQop != "" {
			parts = append(parts,
				fmt.Sprintf("qop=%s", a.authQop),
				fmt.Sprintf("nc=%s", nc),
				fmt.Sprintf(`cnonce="%s"`, cnonce),
			)
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func (a *MikroTikSwOSAdapter) swosRequest(method, path string, body []byte, contentType string) ([]byte, error) {
	// ── Attempt 1: preemptive auth ──
	// If we have stored credentials, send them immediately to skip the 401 round-trip.
	preemptive := a.buildPreemptiveAuth(method, path)
	resp, err := a.doSwOSRequest(method, path, body, contentType, preemptive)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}

	// ── Handle 401: learn auth scheme ──
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("Www-Authenticate")
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		authHeader, scheme, authErr := buildSwOSAuthHeader(challenge, method, path, a.user, a.pass)
		if authErr != nil {
			return nil, fmt.Errorf("%s %s: auth unsupported: %w", method, path, authErr)
		}
		log.Printf("[mikrotik-swos:%s] Retrying %s with %s auth", a.profile.Name, path, scheme)

		resp, err = a.doSwOSRequest(method, path, body, contentType, authHeader)
		if err != nil {
			return nil, fmt.Errorf("%s %s retry: %w", method, path, err)
		}

		// Store auth params for future preemptive use
		if resp.StatusCode == http.StatusOK {
			params := parseDigestAuthParams(challenge)
			a.authScheme = scheme
			if scheme == "digest" {
				a.authRealm = params["realm"]
				a.authNonce = params["nonce"]
				a.authOpaque = params["opaque"]
				a.authQop = func() string {
					for _, opt := range strings.Split(params["qop"], ",") {
						if strings.TrimSpace(opt) == "auth" {
							return "auth"
						}
					}
					if params["qop"] != "" {
						return strings.TrimSpace(params["qop"])
					}
					return ""
				}()
				log.Printf("[mikrotik-swos:%s] Stored digest auth params (realm=%s)", a.profile.Name, a.authRealm)
			}
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
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Referer", a.baseURL+"/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ForgeAI/1.0)")
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
	pageMap := a.swosPageMap()

	rawPages := make(map[string]string)
	capabilities := make(map[string]bool)

	for section, path := range pageMap {
		body, err := a.swosGet(path)
		if err != nil {
			log.Printf("[mikrotik-swos:%s] Page %s unavailable: %v", a.profile.Name, section, err)
			capabilities["has"+ucFirst(section)] = false
			continue
		}
		if !isSwOSDataPage(body) {
			log.Printf("[mikrotik-swos:%s] Page %s returned non-data content (%d bytes), skipping", a.profile.Name, section, len(body))
			capabilities["has"+ucFirst(section)] = false
			continue
		}
		pageStr := string(body)
		rawPages[section] = pageStr
		capabilities["has"+ucFirst(section)] = true
	}

	log.Printf("[mikrotik-swos:%s] Fetched %d/%d pages: %v", a.profile.Name, len(rawPages), len(pageMap), func() []string {
		keys := make([]string, 0, len(rawPages))
		for k := range rawPages {
			keys = append(keys, k)
		}
		return keys
	}())

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

// jsVarRe matches SwOS JS variable assignments with "var" keyword.
// (?s) enables dot-matches-newline so arrays spanning multiple lines are captured.
var jsVarRe = regexp.MustCompile(`(?s)var\s+(\w+)\s*=\s*(\[.*?\]|\{.*?\}|\d+|'[^']*'|"[^"]*");`)

// jsBareRe matches bare JS assignments without "var" keyword (CSS326 SwOS-Lite).
// e.g. nm=['ether1','ether2']; or lnk=[1,0,1,0]; or brd='CSS326-24G-2S+';
var jsBareRe = regexp.MustCompile(`(?s)(?:^|[;\n])\s*(\w+)\s*=\s*(\[.*?\]|\{.*?\}|\d+|'[^']*'|"[^"]*");`)

func (a *MikroTikSwOSAdapter) parseSystemPage(page string) map[string]interface{} {
	result := map[string]interface{}{}
	if page == "" {
		return result
	}

	// SwOS system page exports JS vars: nm, mac, brd, ver, bld, etc.
	kvPairs := extractJSVars(page)

	// Primary keys (CRS /!dhost.b style)
	// Fallback keys (CSS /sys style)
	strOr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := kvPairs[k]; ok && v != "" {
				return v
			}
		}
		return ""
	}

	if v := strOr("nm", "id", "name"); v != "" {
		result["deviceName"] = v
	}
	if v := strOr("mac", "MAC"); v != "" {
		result["macAddress"] = v
	}
	if v := strOr("brd", "board", "type"); v != "" {
		result["board"] = v
		result["model"] = v
	}
	if v := strOr("ver", "version"); v != "" {
		result["version"] = v
	}
	if v := strOr("bld", "build"); v != "" {
		result["build"] = v
	}
	if v := strOr("upn", "uptime"); v != "" {
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
	// First pass: standard "var x = ...;" assignments
	matches := jsVarRe.FindAllStringSubmatch(page, -1)
	for _, m := range matches {
		if len(m) == 3 {
			val := strings.Trim(m[2], "'\"")
			result[m[1]] = val
		}
	}
	// Second pass: bare "x = ...;" assignments (CSS326 SwOS-Lite)
	bareMatches := jsBareRe.FindAllStringSubmatch(page, -1)
	for _, m := range bareMatches {
		if len(m) == 3 {
			key := m[1]
			if _, exists := result[key]; !exists {
				val := strings.Trim(m[2], "'\"")
				result[key] = val
			}
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

// isSwOSDataPage returns true if the response body looks like a real SwOS
// data page containing JS variable assignments (either "var x=..." or bare
// "x=...;" style used by CSS326 SwOS-Lite). Auth redirect pages return
// HTML — they pass HTTP 200 but contain no JS vars.
func isSwOSDataPage(body []byte) bool {
	s := string(body)
	// Must NOT look like an HTML login page
	lower := strings.ToLower(s)
	if strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<!doctype") ||
		strings.Contains(lower, "<form") ||
		strings.Contains(lower, "login") {
		return false
	}
	// Check for standard "var" assignments
	if strings.Contains(s, "var ") && (strings.Contains(s, "=[") || jsVarRe.MatchString(s)) {
		return true
	}
	// Check for bare assignments (CSS326 SwOS-Lite: nm=['...'];)
	if jsBareRe.MatchString(s) {
		return true
	}
	return false
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
