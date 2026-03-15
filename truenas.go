// ForgeAI Local Connector — TrueNAS Adapter
//
// Read-only TrueNAS SCALE / CORE API client that collects ZFS pool health,
// datasets, snapshots, replication tasks, shares, and system alerts into
// a normalized snapshot matching the connector platform schema.
//
// Auth: Bearer token via API key (Settings → API Keys → Add in TrueNAS).

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ── TrueNAS snapshot data models ──

type TrueNASPoolSnapshot struct {
	Name         string  `json:"name"`
	Status       string  `json:"status"`        // ONLINE, DEGRADED, FAULTED, OFFLINE
	Healthy      bool    `json:"healthy"`
	Path         string  `json:"path"`
	Size         *int64  `json:"size"`
	Allocated    *int64  `json:"allocated"`
	Free         *int64  `json:"free"`
	Fragmentation *int64 `json:"fragmentation"` // percentage
	ReadOnly     bool    `json:"read_only"`
	ScanState    string  `json:"scan_state"`    // scrub/resilver status
	ScanErrors   *int64  `json:"scan_errors"`
	TopologyVdevs []TrueNASVdev `json:"topology_vdevs,omitempty"`
}

type TrueNASVdev struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // mirror, raidz1, raidz2, raidz3, stripe
	Status string `json:"status"`
	Disks  int    `json:"disks"`
}

type TrueNASDatasetSnapshot struct {
	Name              string  `json:"name"`
	Pool              string  `json:"pool"`
	Type              string  `json:"type"` // FILESYSTEM, VOLUME
	Used              *int64  `json:"used"`
	Available         *int64  `json:"available"`
	Quota             *int64  `json:"quota"`
	Reservation       *int64  `json:"reservation"`
	Compression       string  `json:"compression"`
	Deduplication     string  `json:"deduplication"`
	MountPoint        string  `json:"mountpoint"`
	RecordSize        *int64  `json:"record_size"`
	ATime             string  `json:"atime"`
	CompressRatio     string  `json:"compress_ratio"`
	ReadOnly          bool    `json:"read_only"`
	SnapshotCount     int     `json:"snapshot_count"`
}

type TrueNASZFSSnapshotSummary struct {
	Dataset       string `json:"dataset"`
	SnapshotCount int    `json:"snapshot_count"`
	OldestName    string `json:"oldest_name,omitempty"`
	NewestName    string `json:"newest_name,omitempty"`
	TotalBytes    *int64 `json:"total_bytes"`
}

type TrueNASReplicationTask struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Direction    string `json:"direction"` // PUSH, PULL
	Transport    string `json:"transport"` // SSH, LOCAL, LEGACY
	SourceDatasets []string `json:"source_datasets"`
	TargetDataset  string   `json:"target_dataset"`
	Enabled      bool   `json:"enabled"`
	State        string `json:"state"`  // RUNNING, WAITING, ERROR, FINISHED
	LastRun      string `json:"last_run,omitempty"`
	AutoSnap     bool   `json:"auto_snapshot"`
}

type TrueNASShareSnapshot struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Type    string `json:"type"` // smb, nfs
	Enabled bool   `json:"enabled"`
	Comment string `json:"comment,omitempty"`
}

type TrueNASSystemInfo struct {
	Version     string `json:"version"`
	Hostname    string `json:"hostname"`
	Uptime      *int64 `json:"uptime_seconds"`
	SystemType  string `json:"system_type"` // SCALE or CORE
}

type TrueNASSnapshotData struct {
	System       *TrueNASSystemInfo            `json:"system"`
	Pools        []TrueNASPoolSnapshot         `json:"pools"`
	Datasets     []TrueNASDatasetSnapshot      `json:"datasets"`
	Snapshots    []TrueNASZFSSnapshotSummary   `json:"snapshots"`
	Replication  []TrueNASReplicationTask       `json:"replication"`
	Shares       []TrueNASShareSnapshot         `json:"shares"`
	Alerts       []AlertEntry                   `json:"alerts"`
	CollectedAt  string                         `json:"collected_at"`
}

// ── TrueNAS client ──

type TrueNASClient struct {
	cfg        *Config
	httpClient *http.Client
}

func NewTrueNASClient(cfg *Config) *TrueNASClient {
	transport := &http.Transport{}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &TrueNASClient{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}
}

// apiGet makes an authenticated GET to the TrueNAS REST API
func (t *TrueNASClient) apiGet(path string) (json.RawMessage, error) {
	base := strings.TrimRight(t.cfg.TrueNASURL, "/")
	// Avoid double-prefixing if endpoint already includes /api/v2.0
	if !strings.Contains(base, "/api/v2.0") {
		base += "/api/v2.0"
	}
	url := base + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+t.cfg.TrueNASAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Detect HTML responses (wrong endpoint or missing API prefix)
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") || (len(body) > 0 && body[0] == '<') {
		return nil, fmt.Errorf("GET %s: received HTML instead of JSON — verify the endpoint URL points to the TrueNAS host (e.g. https://truenas-ip), not the API path", path)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s HTTP %d: %s", path, resp.StatusCode, string(body))
	}
	return json.RawMessage(body), nil
}

// CollectSnapshot gathers all TrueNAS data into a normalized snapshot
func (t *TrueNASClient) CollectSnapshot() (*TrueNASSnapshotData, error) {
	snap := &TrueNASSnapshotData{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Alerts:      []AlertEntry{},
	}

	// System info
	sysInfo, err := t.collectSystemInfo()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "warning", Source: "agent",
			Message: "Failed to collect system info: " + err.Error(),
		})
		log.Printf("[truenas] System info failed: %v", err)
	} else {
		snap.System = sysInfo
	}

	// Pools
	pools, err := t.collectPools()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "error", Source: "agent",
			Message: "Failed to collect pools: " + err.Error(),
		})
		log.Printf("[truenas] Pool collection failed: %v", err)
	} else {
		snap.Pools = pools
	}

	// Datasets
	datasets, err := t.collectDatasets()
	if err != nil {
		snap.Alerts = append(snap.Alerts, AlertEntry{
			Severity: "warning", Source: "agent",
			Message: "Failed to collect datasets: " + err.Error(),
		})
		log.Printf("[truenas] Dataset collection failed: %v", err)
	} else {
		snap.Datasets = datasets
	}

	// ZFS Snapshots (summary)
	snapshots, err := t.collectSnapshotSummary()
	if err != nil {
		log.Printf("[truenas] Snapshot summary failed: %v", err)
	} else {
		snap.Snapshots = snapshots
	}

	// Replication tasks
	repl, err := t.collectReplication()
	if err != nil {
		log.Printf("[truenas] Replication collection failed: %v", err)
	} else {
		snap.Replication = repl
	}

	// Shares (SMB + NFS)
	shares, err := t.collectShares()
	if err != nil {
		log.Printf("[truenas] Share collection failed: %v", err)
	} else {
		snap.Shares = shares
	}

	// System alerts from TrueNAS
	sysAlerts, err := t.collectAlerts()
	if err != nil {
		log.Printf("[truenas] Alert collection failed: %v", err)
	} else {
		snap.Alerts = append(snap.Alerts, sysAlerts...)
	}

	// Generate health alerts from collected data
	snap.Alerts = append(snap.Alerts, t.generateAlerts(snap)...)

	return snap, nil
}

// ── Collectors ──

func (t *TrueNASClient) collectSystemInfo() (*TrueNASSystemInfo, error) {
	raw, err := t.apiGet("/system/info")
	if err != nil {
		return nil, err
	}

	var info map[string]interface{}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}

	sys := &TrueNASSystemInfo{
		Version:  getString(info, "version"),
		Hostname: getString(info, "hostname"),
	}

	if v, ok := getInt(info, "uptime_seconds"); ok {
		sys.Uptime = &v
	}
	// Detect SCALE vs CORE
	if strings.Contains(strings.ToUpper(sys.Version), "SCALE") {
		sys.SystemType = "SCALE"
	} else {
		sys.SystemType = "CORE"
	}

	return sys, nil
}

func (t *TrueNASClient) collectPools() ([]TrueNASPoolSnapshot, error) {
	raw, err := t.apiGet("/pool")
	if err != nil {
		return nil, err
	}

	var poolsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &poolsRaw); err != nil {
		return nil, err
	}

	var pools []TrueNASPoolSnapshot
	for _, p := range poolsRaw {
		pool := TrueNASPoolSnapshot{
			Name:    getString(p, "name"),
			Status:  getString(p, "status"),
			Healthy: getBool(p, "healthy"),
			Path:    getString(p, "path"),
		}

		// Topology info
		if topo, ok := p["topology"].(map[string]interface{}); ok {
			if dataVdevs, ok := topo["data"].([]interface{}); ok {
				for _, dv := range dataVdevs {
					if vd, ok := dv.(map[string]interface{}); ok {
						vdev := TrueNASVdev{
							Name:   getString(vd, "name"),
							Type:   getString(vd, "type"),
							Status: getString(vd, "status"),
						}
						if children, ok := vd["children"].([]interface{}); ok {
							vdev.Disks = len(children)
						}
						pool.TopologyVdevs = append(pool.TopologyVdevs, vdev)
					}
				}
			}
		}

		// Scan info
		if scan, ok := p["scan"].(map[string]interface{}); ok {
			pool.ScanState = getString(scan, "state")
			if errs, ok := getInt(scan, "errors"); ok {
				pool.ScanErrors = &errs
			}
		}

		pool.ReadOnly = getBool(p, "is_decrypted") && getString(p, "status") == "ONLINE"

		// Size info — try parsing nested values
		if sizeVal, ok := p["size"]; ok {
			if size, ok := toInt64(sizeVal); ok {
				pool.Size = &size
			}
		}
		if allocVal, ok := p["allocated"]; ok {
			if alloc, ok := toInt64(allocVal); ok {
				pool.Allocated = &alloc
			}
		}
		if freeVal, ok := p["free"]; ok {
			if free, ok := toInt64(freeVal); ok {
				pool.Free = &free
			}
		}
		if fragVal, ok := p["fragmentation"]; ok {
			if frag, ok := toInt64(fragVal); ok {
				pool.Fragmentation = &frag
			}
		}

		pools = append(pools, pool)
	}

	return pools, nil
}

func (t *TrueNASClient) collectDatasets() ([]TrueNASDatasetSnapshot, error) {
	raw, err := t.apiGet("/pool/dataset")
	if err != nil {
		return nil, err
	}

	var dsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &dsRaw); err != nil {
		return nil, err
	}

	var datasets []TrueNASDatasetSnapshot
	for _, d := range dsRaw {
		ds := TrueNASDatasetSnapshot{
			Name:       getString(d, "name"),
			Pool:       getString(d, "pool"),
			Type:       getString(d, "type"),
			MountPoint: getString(d, "mountpoint"),
		}

		// TrueNAS returns nested property objects like {"value": "...", "rawvalue": "..."}
		ds.Used = getNestedInt(d, "used")
		ds.Available = getNestedInt(d, "available")
		ds.Quota = getNestedInt(d, "quota")
		ds.Reservation = getNestedInt(d, "reservation")
		ds.RecordSize = getNestedInt(d, "recordsize")

		ds.Compression = getNestedString(d, "compression")
		ds.Deduplication = getNestedString(d, "dedup")
		ds.ATime = getNestedString(d, "atime")
		ds.CompressRatio = getNestedString(d, "compressratio")

		if roVal := getNestedString(d, "readonly"); roVal == "ON" {
			ds.ReadOnly = true
		}

		datasets = append(datasets, ds)
	}

	return datasets, nil
}

func (t *TrueNASClient) collectSnapshotSummary() ([]TrueNASZFSSnapshotSummary, error) {
	raw, err := t.apiGet("/zfs/snapshot?limit=1000")
	if err != nil {
		return nil, err
	}

	var snapsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &snapsRaw); err != nil {
		return nil, err
	}

	// Group by dataset
	type snapInfo struct {
		names []string
		total int64
	}
	groups := map[string]*snapInfo{}

	for _, s := range snapsRaw {
		name := getString(s, "name") // dataset@snapname
		parts := strings.SplitN(name, "@", 2)
		if len(parts) != 2 {
			continue
		}
		dsName := parts[0]
		snapName := parts[1]

		if _, ok := groups[dsName]; !ok {
			groups[dsName] = &snapInfo{}
		}
		groups[dsName].names = append(groups[dsName].names, snapName)

		// Accumulate referenced bytes
		if props, ok := s["properties"].(map[string]interface{}); ok {
			if ref, ok := props["referenced"].(map[string]interface{}); ok {
				if rv, ok := ref["rawvalue"]; ok {
					if bytes, ok := toInt64(rv); ok {
						groups[dsName].total += bytes
					}
				}
			}
		}
	}

	var summaries []TrueNASZFSSnapshotSummary
	for ds, info := range groups {
		summary := TrueNASZFSSnapshotSummary{
			Dataset:       ds,
			SnapshotCount: len(info.names),
			TotalBytes:    &info.total,
		}
		if len(info.names) > 0 {
			summary.OldestName = info.names[0]
			summary.NewestName = info.names[len(info.names)-1]
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func (t *TrueNASClient) collectReplication() ([]TrueNASReplicationTask, error) {
	raw, err := t.apiGet("/replication")
	if err != nil {
		return nil, err
	}

	var replRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &replRaw); err != nil {
		return nil, err
	}

	var tasks []TrueNASReplicationTask
	for _, r := range replRaw {
		task := TrueNASReplicationTask{
			Name:      getString(r, "name"),
			Direction: getString(r, "direction"),
			Transport: getString(r, "transport"),
			Enabled:   getBool(r, "enabled"),
			AutoSnap:  getBool(r, "auto"),
		}

		if id, ok := getInt(r, "id"); ok {
			task.ID = int(id)
		}

		if srcDS, ok := r["source_datasets"].([]interface{}); ok {
			for _, ds := range srcDS {
				if s, ok := ds.(string); ok {
					task.SourceDatasets = append(task.SourceDatasets, s)
				}
			}
		}
		task.TargetDataset = getString(r, "target_dataset")

		// Job state
		if job, ok := r["job"].(map[string]interface{}); ok {
			task.State = getString(job, "state")
			if ts := getString(job, "time_finished"); ts != "" {
				task.LastRun = ts
			}
		} else {
			task.State = "IDLE"
		}

		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (t *TrueNASClient) collectShares() ([]TrueNASShareSnapshot, error) {
	var shares []TrueNASShareSnapshot

	// SMB shares
	smbRaw, err := t.apiGet("/sharing/smb")
	if err != nil {
		log.Printf("[truenas] SMB share collection failed: %v", err)
	} else {
		var smbShares []map[string]interface{}
		if err := json.Unmarshal(smbRaw, &smbShares); err == nil {
			for _, s := range smbShares {
				share := TrueNASShareSnapshot{
					Name:    getString(s, "name"),
					Path:    getString(s, "path"),
					Type:    "smb",
					Enabled: getBool(s, "enabled"),
					Comment: getString(s, "comment"),
				}
				if id, ok := getInt(s, "id"); ok {
					share.ID = int(id)
				}
				shares = append(shares, share)
			}
		}
	}

	// NFS shares
	nfsRaw, err := t.apiGet("/sharing/nfs")
	if err != nil {
		log.Printf("[truenas] NFS share collection failed: %v", err)
	} else {
		var nfsShares []map[string]interface{}
		if err := json.Unmarshal(nfsRaw, &nfsShares); err == nil {
			for _, s := range nfsShares {
				// NFS shares can have multiple paths
				paths := []string{}
				if pathList, ok := s["paths"].([]interface{}); ok {
					for _, p := range pathList {
						if ps, ok := p.(string); ok {
							paths = append(paths, ps)
						}
					}
				}
				path := getString(s, "path")
				if path == "" && len(paths) > 0 {
					path = paths[0]
				}

				share := TrueNASShareSnapshot{
					Path:    path,
					Type:    "nfs",
					Enabled: getBool(s, "enabled"),
					Comment: getString(s, "comment"),
				}
				if id, ok := getInt(s, "id"); ok {
					share.ID = int(id)
					share.Name = fmt.Sprintf("nfs-%d", id)
				}
				shares = append(shares, share)
			}
		}
	}

	return shares, nil
}

func (t *TrueNASClient) collectAlerts() ([]AlertEntry, error) {
	raw, err := t.apiGet("/alert/list")
	if err != nil {
		return nil, err
	}

	var alertsRaw []map[string]interface{}
	if err := json.Unmarshal(raw, &alertsRaw); err != nil {
		return nil, err
	}

	var alerts []AlertEntry
	for _, a := range alertsRaw {
		level := strings.ToLower(getString(a, "level"))
		severity := "info"
		switch level {
		case "critical", "error":
			severity = "error"
		case "warning":
			severity = "warning"
		case "notice", "info":
			severity = "info"
		}

		// Skip dismissed alerts
		if getBool(a, "dismissed") {
			continue
		}

		alerts = append(alerts, AlertEntry{
			Severity: severity,
			Source:   "truenas",
			Message:  getString(a, "formatted"),
			Field:    getString(a, "klass"),
		})
	}

	return alerts, nil
}

// generateAlerts produces operator-friendly alerts from collected data
func (t *TrueNASClient) generateAlerts(snap *TrueNASSnapshotData) []AlertEntry {
	var alerts []AlertEntry

	for _, pool := range snap.Pools {
		// Pool health
		if pool.Status != "ONLINE" {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "health",
				Message: fmt.Sprintf("Pool %s is %s", pool.Name, pool.Status),
				Field:   "pool.status",
			})
		}
		if !pool.Healthy {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "health",
				Message: fmt.Sprintf("Pool %s reported unhealthy", pool.Name),
				Field:   "pool.healthy",
			})
		}

		// Capacity thresholds
		if pool.Size != nil && pool.Allocated != nil && *pool.Size > 0 {
			pct := float64(*pool.Allocated) / float64(*pool.Size)
			if pct > 0.90 {
				alerts = append(alerts, AlertEntry{
					Severity: "error", Source: "storage",
					Message: fmt.Sprintf("Pool %s capacity critical: %.1f%%", pool.Name, pct*100),
					Field:   "pool.capacity",
				})
			} else if pct > 0.80 {
				alerts = append(alerts, AlertEntry{
					Severity: "warning", Source: "storage",
					Message: fmt.Sprintf("Pool %s capacity high: %.1f%%", pool.Name, pct*100),
					Field:   "pool.capacity",
				})
			}
		}

		// Fragmentation
		if pool.Fragmentation != nil && *pool.Fragmentation > 50 {
			sev := "warning"
			if *pool.Fragmentation > 75 {
				sev = "error"
			}
			alerts = append(alerts, AlertEntry{
				Severity: sev, Source: "storage",
				Message: fmt.Sprintf("Pool %s fragmentation: %d%%", pool.Name, *pool.Fragmentation),
				Field:   "pool.fragmentation",
			})
		}

		// Scan errors
		if pool.ScanErrors != nil && *pool.ScanErrors > 0 {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "storage",
				Message: fmt.Sprintf("Pool %s has %d scan errors", pool.Name, *pool.ScanErrors),
				Field:   "pool.scan_errors",
			})
		}
	}

	// Replication errors
	for _, task := range snap.Replication {
		if task.State == "ERROR" && task.Enabled {
			alerts = append(alerts, AlertEntry{
				Severity: "error", Source: "replication",
				Message: fmt.Sprintf("Replication task '%s' in error state", task.Name),
				Field:   "replication.state",
			})
		}
	}

	return alerts
}

// ── Helpers ──

// getNestedString extracts the "value" from TrueNAS nested property objects
// e.g. {"compression": {"value": "lz4", "rawvalue": "lz4", ...}}
func getNestedString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	// Try nested object first
	if obj, ok := v.(map[string]interface{}); ok {
		return getString(obj, "value")
	}
	// Fall back to plain string
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// getNestedInt extracts the "parsed" or "rawvalue" from TrueNAS nested property objects
func getNestedInt(m map[string]interface{}, key string) *int64 {
	v, ok := m[key]
	if !ok {
		return nil
	}
	// Try nested object
	if obj, ok := v.(map[string]interface{}); ok {
		if parsed, ok := obj["parsed"]; ok {
			if i, ok := toInt64(parsed); ok {
				return &i
			}
		}
		if raw, ok := obj["rawvalue"]; ok {
			if i, ok := toInt64(raw); ok {
				return &i
			}
		}
		if val, ok := obj["value"]; ok {
			if i, ok := toInt64(val); ok {
				return &i
			}
		}
	}
	// Try direct value
	if i, ok := toInt64(v); ok {
		return &i
	}
	return nil
}

// toInt64 converts various numeric types to int64
func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case string:
		// Try parsing numeric strings
		var i int64
		_, err := fmt.Sscanf(n, "%d", &i)
		return i, err == nil
	}
	return 0, false
}
