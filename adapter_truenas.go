// ForgeAI Connector Host — TrueNAS Adapter (bridge)
//
// Wraps the existing TrueNASClient to conform to the TargetAdapter interface.
// The actual TrueNAS API logic remains in truenas.go.

package main

import (
	"fmt"
	"log"
)

// TrueNASAdapter implements TargetAdapter for TrueNAS SCALE/CORE targets.
type TrueNASAdapter struct {
	client  *TrueNASClient
	profile *TargetProfile
	cfg     *Config
}

// NewTrueNASAdapter creates a TrueNASAdapter from a target profile.
func NewTrueNASAdapter(profile *TargetProfile) (TargetAdapter, error) {
	return &TrueNASAdapter{profile: profile}, nil
}

func (a *TrueNASAdapter) Init(profile *TargetProfile, creds map[string]string) error {
	cfg := &Config{
		TrueNASURL:         profile.Endpoint,
		InsecureSkipVerify: profile.TLS.InsecureSkipVerify,
		PollIntervalSecs:   profile.PollIntervalSecs,
	}

	// Extract credentials
	if v, ok := creds["api_key"]; ok {
		cfg.TrueNASAPIKey = v
	}

	a.cfg = cfg
	a.client = NewTrueNASClient(cfg)

	// Verify connectivity
	log.Printf("[truenas:%s] Verifying API access...", profile.Name)
	sysInfo, err := a.client.collectSystemInfo()
	if err != nil {
		return fmt.Errorf("API access verification failed: %w", err)
	}
	log.Printf("[truenas:%s] Connected to %s (%s) — %s",
		profile.Name, sysInfo.Hostname, sysInfo.SystemType, sysInfo.Version)

	return nil
}

func (a *TrueNASAdapter) Collect() (map[string]interface{}, error) {
	snapshot, err := a.client.CollectSnapshot()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"capabilities": a.Capabilities(),
		"snapshotData": map[string]interface{}{
			"system":      snapshot.System,
			"pools":       snapshot.Pools,
			"datasets":    snapshot.Datasets,
			"snapshots":   snapshot.Snapshots,
			"replication": snapshot.Replication,
			"shares":      snapshot.Shares,
		},
		"alerts":      snapshot.Alerts,
		"collectedAt": snapshot.CollectedAt,
	}, nil
}

func (a *TrueNASAdapter) Capabilities() []string {
	return []string{
		"truenas.read.health",
		"truenas.read.pools",
		"truenas.read.datasets",
		"truenas.read.snapshots",
		"truenas.read.replication",
		"truenas.read.shares",
		"truenas.read.alerts",
	}
}

func (a *TrueNASAdapter) HealthCheck() error {
	_, err := a.client.collectSystemInfo()
	return err
}

func (a *TrueNASAdapter) Close() error {
	a.client = nil
	return nil
}
