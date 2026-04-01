// ForgeAI Connector Host — Local API Server
//
// Lightweight read-only HTTP server that serves local snapshot data
// over the LAN in Hybrid Mode. Endpoints are authenticated via a
// pre-shared X-Local-Token header (except /v1/health).
//
// Endpoints:
//   GET /v1/health              — unauthenticated reachability probe
//   GET /v1/targets             — list all targets with status
//   GET /v1/targets/:id/snapshot — latest decrypted snapshot for a target

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultLocalAPIBind = "0.0.0.0:7070"
	localAPIVersion     = "v1"
)

// LocalAPIServer serves local snapshot data over the LAN.
// Only started when Hybrid Mode is enabled.
// All endpoints except /v1/health require X-Local-Token.
type LocalAPIServer struct {
	db         *LocalDB
	supervisor *Supervisor
	token      string
	bind       string
	server     *http.Server
	lanURL     string // e.g. "http://192.168.1.50:7070"
}

// NewLocalAPIServer creates and configures the server.
// token is the pre-shared auth token.
// bind is the listen address (e.g. "0.0.0.0:7070").
func NewLocalAPIServer(
	db *LocalDB,
	supervisor *Supervisor,
	token string,
	bind string,
) *LocalAPIServer {
	if bind == "" {
		bind = defaultLocalAPIBind
	}

	s := &LocalAPIServer{
		db:         db,
		supervisor: supervisor,
		token:      token,
		bind:       bind,
		lanURL:     detectLANURL(bind),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/targets", s.authMiddleware(s.handleTargets))
	mux.HandleFunc("/v1/targets/", s.authMiddleware(s.handleTargetRoute))

	s.server = &http.Server{
		Addr:         bind,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening. Non-blocking — runs in a goroutine.
func (s *LocalAPIServer) Start() {
	go func() {
		audit.Info("local_api.start", "Local API server listening",
			F("addr", s.bind),
			F("lan_url", s.lanURL))
		if err := s.server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			audit.Error("local_api.start",
				"Local API server error", Err(err))
		}
	}()
}

// Stop gracefully shuts down the server with a 5s timeout.
func (s *LocalAPIServer) Stop() {
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		audit.Warn("local_api.stop",
			"Local API shutdown error", Err(err))
	} else {
		audit.Info("local_api.stop", "Local API server stopped")
	}
}

// LANURL returns the advertised LAN address for this server.
func (s *LocalAPIServer) LANURL() string {
	return s.lanURL
}

// authMiddleware enforces X-Local-Token header.
func (s *LocalAPIServer) authMiddleware(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Local-Token")
		if tok != s.token {
			s.writeError(w, http.StatusUnauthorized,
				"invalid or missing X-Local-Token")
			return
		}
		next(w, r)
	}
}

// ── Handlers ──

// GET /v1/health — no auth required, used for reachability probe
func (s *LocalAPIServer) handleHealth(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}
	s.setCORS(w)

	state := s.supervisor.GetState()
	label := ""
	if state != nil {
		label = state.Identity.Label
	}

	var dbStats map[string]interface{}
	if s.db != nil {
		dbStats = s.db.Stats()
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"version":      HostVersion,
		"hybrid_mode":  true,
		"label":        label,
		"target_count": s.supervisor.TargetCount(),
		"db_stats":     dbStats,
	})
}

// GET /v1/targets — list all targets with status + summary
func (s *LocalAPIServer) handleTargets(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}
	s.setCORS(w)

	state := s.supervisor.GetState()
	if state == nil {
		s.writeJSON(w, http.StatusOK,
			map[string]interface{}{"targets": []interface{}{}})
		return
	}

	targets := make([]map[string]interface{}, 0,
		len(state.Targets))
	for _, t := range state.Targets {
		entry := map[string]interface{}{
			"target_id":   t.TargetID,
			"name":        t.Name,
			"target_type": t.TargetType,
			"enabled":     t.Enabled,
			"status":      string(t.Status),
			"endpoint":    t.Endpoint,
		}
		targets = append(targets, entry)
	}

	s.writeJSON(w, http.StatusOK,
		map[string]interface{}{"targets": targets})
}

// Routes /v1/targets/:id/snapshot and /v1/targets/:id/signals
func (s *LocalAPIServer) handleTargetRoute(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed,
			"method not allowed")
		return
	}
	s.setCORS(w)

	// Parse: /v1/targets/<id>/<action>
	parts := strings.Split(
		strings.TrimPrefix(r.URL.Path, "/v1/targets/"), "/")
	if len(parts) < 2 {
		s.writeError(w, http.StatusNotFound, "not found")
		return
	}

	targetID := parts[0]
	action := parts[1]

	switch action {
	case "snapshot":
		s.handleSnapshot(w, r, targetID)
	default:
		s.writeError(w, http.StatusNotFound,
			fmt.Sprintf("unknown action: %s", action))
	}
}

// GET /v1/targets/:id/snapshot
func (s *LocalAPIServer) handleSnapshot(
	w http.ResponseWriter, r *http.Request, targetID string,
) {
	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable,
			"local DB not available")
		return
	}

	payload, collectedAt, err := s.db.LatestSnapshot(targetID)
	if err != nil {
		audit.Warn("local_api.snapshot",
			"Failed to read snapshot", F("target_id", targetID),
			Err(err))
		s.writeError(w, http.StatusInternalServerError,
			"failed to read snapshot")
		return
	}

	if payload == nil {
		s.writeError(w, http.StatusNotFound,
			"no snapshot found for target")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"target_id":    targetID,
		"collected_at": collectedAt.UTC().Format(time.RFC3339),
		"snapshot":     payload,
	})
}

// ── Helpers ──

func (s *LocalAPIServer) writeJSON(
	w http.ResponseWriter, status int, v interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *LocalAPIServer) writeError(
	w http.ResponseWriter, status int, msg string,
) {
	s.writeJSON(w, status,
		map[string]interface{}{"ok": false, "error": msg})
}

func (s *LocalAPIServer) setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers",
		"X-Local-Token, Content-Type")
}

// detectLANURL finds the first non-loopback IPv4 address
// and builds the URL using the port from bind.
func detectLANURL(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		port = "7070"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Sprintf("http://127.0.0.1:%s", port)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil {
				return fmt.Sprintf("http://%s:%s", ip.String(), port)
			}
		}
	}

	return fmt.Sprintf("http://127.0.0.1:%s", port)
}
