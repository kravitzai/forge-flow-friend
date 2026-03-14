// ForgeAI Connector Host — Supervisor & Reconciler
//
// The Supervisor is the long-running host process that manages
// per-target workers. It reconciles desired state (target profiles)
// against actual state (running workers) and handles the full lifecycle.

package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Supervisor manages the lifecycle of all target workers.
type Supervisor struct {
	mu       sync.RWMutex
	store    *Store
	state    *HostState
	workers  map[string]*Worker // targetID -> worker
	adapters map[string]AdapterFactory
	backend  *BackendClient
	policy   RetryPolicy
}

// NewSupervisor creates a new supervisor with the given store and backend.
func NewSupervisor(store *Store, backend *BackendClient) *Supervisor {
	return &Supervisor{
		store:    store,
		workers:  make(map[string]*Worker),
		adapters: make(map[string]AdapterFactory),
		backend:  backend,
		policy:   DefaultRetryPolicy(),
	}
}

// RegisterAdapter registers an adapter factory for a target type.
func (s *Supervisor) RegisterAdapter(targetType string, factory AdapterFactory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adapters[targetType] = factory
}

// Initialize loads or creates host state, handles legacy migration.
func (s *Supervisor) Initialize(legacyCfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try loading existing state
	state, err := s.store.LoadState()
	if err != nil {
		log.Printf("[supervisor] Failed to load state, starting fresh: %v", err)
	}

	if state != nil {
		s.state = state
		log.Printf("[supervisor] Loaded host state: %s (%d targets)",
			state.Identity.Label, len(state.Targets))
		return nil
	}

	// No existing state — check for legacy env config
	if legacyCfg != nil && legacyCfg.ConnectorToken != "" {
		log.Printf("[supervisor] Migrating legacy %s config to host model", legacyCfg.TargetType)
		state, creds := ImportLegacyEnvConfig(legacyCfg)
		s.state = state

		// Store credentials for the migrated target
		if len(state.Targets) > 0 {
			target := state.Targets[0]
			if err := s.store.SaveSecret(target.TargetID, creds); err != nil {
				return fmt.Errorf("save migrated credentials: %w", err)
			}
		}

		// Persist the new state
		if err := s.store.SaveState(state); err != nil {
			return fmt.Errorf("save initial state: %w", err)
		}

		log.Printf("[supervisor] Migration complete: host=%s, targets=%d",
			state.Identity.HostID[:12], len(state.Targets))
		return nil
	}

	// Fresh install with no config — will be enrolled via enrollment flow
	s.state = &HostState{
		Identity: HostIdentity{
			HostID: generateID(),
			Label:  "forgeai-host",
		},
		Config:  DefaultHostConfig(),
		Targets: []TargetProfile{},
		Version: 1,
	}

	return s.store.SaveState(s.state)
}

// InitializeWithState sets the supervisor state directly (used by enrollment).
func (s *Supervisor) InitializeWithState(state *HostState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// Reconcile compares desired target profiles against running workers
// and starts/stops/updates workers as needed.
func (s *Supervisor) Reconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		return fmt.Errorf("supervisor not initialized")
	}

	log.Printf("[supervisor] Reconciling %d target profiles against %d running workers",
		len(s.state.Targets), len(s.workers))

	desiredIDs := map[string]bool{}

	for i := range s.state.Targets {
		target := &s.state.Targets[i]
		desiredIDs[target.TargetID] = true

		existing, hasWorker := s.workers[target.TargetID]

		// Case 1: Target disabled or revoked — stop worker if running
		if !target.Enabled || target.Status == TargetStatusRevoked {
			if hasWorker {
				log.Printf("[reconcile] Stopping disabled/revoked target: %s", target.Name)
				existing.Stop()
				delete(s.workers, target.TargetID)
			}
			continue
		}

		// Case 2: Target paused — pause worker if running
		if target.Paused || target.Status == TargetStatusPaused {
			if hasWorker {
				ws := existing.State()
				if ws.Status == WorkerStatusRunning {
					log.Printf("[reconcile] Pausing target: %s", target.Name)
					existing.Pause()
				}
			}
			continue
		}

		// Case 3: Worker already running — check if config changed
		if hasWorker {
			continue
		}

		// Case 4: No worker — start one
		if err := s.startWorkerLocked(target); err != nil {
			log.Printf("[reconcile] Failed to start worker for %s: %v", target.Name, err)
			target.Status = TargetStatusError
		}
	}

	// Case 5: Workers running for targets no longer in desired state — stop them
	for targetID, worker := range s.workers {
		if !desiredIDs[targetID] {
			log.Printf("[reconcile] Stopping orphaned worker: %s", targetID)
			worker.Stop()
			delete(s.workers, targetID)
		}
	}

	// Persist state after reconciliation
	return s.store.SaveState(s.state)
}

// startWorkerLocked starts a worker for the given target. Caller must hold s.mu.
func (s *Supervisor) startWorkerLocked(target *TargetProfile) error {
	// Check max concurrent workers
	if s.state.Config.MaxConcurrentWorkers > 0 &&
		len(s.workers) >= s.state.Config.MaxConcurrentWorkers {
		return fmt.Errorf("max concurrent workers (%d) reached", s.state.Config.MaxConcurrentWorkers)
	}

	// Look up adapter factory
	factory, ok := s.adapters[target.TargetType]
	if !ok {
		return fmt.Errorf("no adapter registered for target type: %s", target.TargetType)
	}

	// Create adapter
	adapter, err := factory(target)
	if err != nil {
		return fmt.Errorf("create adapter for %s: %w", target.Name, err)
	}

	// Load credentials
	creds, err := s.store.LoadSecret(target.CredentialRef)
	if err != nil {
		adapter.Close()
		return fmt.Errorf("load credentials for %s: %w", target.Name, err)
	}
	if creds == nil {
		creds = map[string]string{}
	}

	// Create and start worker
	worker := NewWorker(WorkerConfig{
		Profile:   target,
		Adapter:   adapter,
		Creds:     creds,
		Policy:    s.policy,
		Backend:   s.backend,
		HostToken: s.state.Identity.ConnectorToken,
		OnStateChange: func(targetID string, status WorkerStatus) {
			s.onWorkerStateChange(targetID, status)
		},
	})

	if err := worker.Start(); err != nil {
		adapter.Close()
		return err
	}

	s.workers[target.TargetID] = worker
	target.Status = TargetStatusActive

	log.Printf("[supervisor] Started worker for %s (%s) — poll every %ds",
		target.Name, target.TargetType, target.PollIntervalSecs)

	return nil
}

// onWorkerStateChange handles worker status transitions.
func (s *Supervisor) onWorkerStateChange(targetID string, status WorkerStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.state.Targets {
		if s.state.Targets[i].TargetID == targetID {
			switch status {
			case WorkerStatusDegraded:
				s.state.Targets[i].Status = TargetStatusDegraded
			case WorkerStatusRunning:
				s.state.Targets[i].Status = TargetStatusActive
			case WorkerStatusStopped:
				s.state.Targets[i].Status = TargetStatusPaused
			case WorkerStatusFailed:
				s.state.Targets[i].Status = TargetStatusError
			}
			break
		}
	}
}

// AddTarget adds a new target profile and triggers reconciliation.
func (s *Supervisor) AddTarget(profile TargetProfile, creds map[string]string) error {
	s.mu.Lock()

	// Check for duplicate
	for _, t := range s.state.Targets {
		if t.TargetID == profile.TargetID {
			s.mu.Unlock()
			return fmt.Errorf("target %s already exists", profile.TargetID)
		}
	}

	// Store credentials
	if len(creds) > 0 {
		if err := s.store.SaveSecret(profile.CredentialRef, creds); err != nil {
			s.mu.Unlock()
			return fmt.Errorf("save credentials: %w", err)
		}
	}

	profile.UpdatedAt = time.Now()
	if profile.Status == "" {
		profile.Status = TargetStatusPending
	}
	s.state.Targets = append(s.state.Targets, profile)
	s.mu.Unlock()

	// Reconcile will start the worker
	return s.Reconcile()
}

// UpdateTarget updates an existing target profile in place and reconciles.
func (s *Supervisor) UpdateTarget(profile TargetProfile) error {
	s.mu.Lock()

	found := false
	for i := range s.state.Targets {
		if s.state.Targets[i].TargetID == profile.TargetID {
			// Stop existing worker if running
			if worker, ok := s.workers[profile.TargetID]; ok {
				worker.Stop()
				delete(s.workers, profile.TargetID)
			}

			// Preserve credential ref if not provided
			if profile.CredentialRef == "" {
				profile.CredentialRef = s.state.Targets[i].CredentialRef
			}

			profile.UpdatedAt = time.Now()
			s.state.Targets[i] = profile
			found = true
			break
		}
	}

	s.mu.Unlock()

	if !found {
		return fmt.Errorf("target %s not found for update", profile.TargetID)
	}

	return s.Reconcile()
}

// RemoveTarget stops and removes a target.
func (s *Supervisor) RemoveTarget(targetID string) error {
	s.mu.Lock()

	// Stop worker if running
	if worker, ok := s.workers[targetID]; ok {
		worker.Stop()
		delete(s.workers, targetID)
	}

	// Remove from state
	found := false
	var credRef string
	for i, t := range s.state.Targets {
		if t.TargetID == targetID {
			credRef = t.CredentialRef
			s.state.Targets = append(s.state.Targets[:i], s.state.Targets[i+1:]...)
			found = true
			break
		}
	}

	s.mu.Unlock()

	if !found {
		return fmt.Errorf("target %s not found", targetID)
	}

	// Clean up credentials
	if credRef != "" {
		s.store.DeleteSecret(credRef)
	}

	// Persist
	s.mu.RLock()
	err := s.store.SaveState(s.state)
	s.mu.RUnlock()
	return err
}

// GetConnectorToken returns the host's connector token for backend auth.
func (s *Supervisor) GetConnectorToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return ""
	}
	return s.state.Identity.ConnectorToken
}

// GetState returns the current host state (for sync manager).
func (s *Supervisor) GetState() *HostState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// GetTargets returns a copy of current target profiles.
func (s *Supervisor) GetTargets() []TargetProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return nil
	}
	targets := make([]TargetProfile, len(s.state.Targets))
	copy(targets, s.state.Targets)
	return targets
}

// Status returns a summary of all workers.
func (s *Supervisor) Status() []WorkerState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	states := make([]WorkerState, 0, len(s.workers))
	for _, w := range s.workers {
		states = append(states, w.State())
	}
	return states
}

// Shutdown gracefully stops all workers.
func (s *Supervisor) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[supervisor] Shutting down %d workers...", len(s.workers))
	var wg sync.WaitGroup
	for id, w := range s.workers {
		wg.Add(1)
		go func(id string, w *Worker) {
			defer wg.Done()
			w.Stop()
			log.Printf("[supervisor] Worker %s stopped", id)
		}(id, w)
	}
	wg.Wait()
	s.workers = make(map[string]*Worker)

	// Persist final state
	if s.state != nil {
		s.store.SaveState(s.state)
	}

	log.Printf("[supervisor] All workers stopped")
}

// TargetCount returns the number of configured targets.
func (s *Supervisor) TargetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state == nil {
		return 0
	}
	return len(s.state.Targets)
}

// WorkerCount returns the number of active workers.
func (s *Supervisor) WorkerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.workers)
}

// SupportedAdapterTypes returns the list of target types this host can run.
func (s *Supervisor) SupportedAdapterTypes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	types := make([]string, 0, len(s.adapters))
	for t := range s.adapters {
		types = append(types, t)
	}
	return types
}

// IsAdapterSupported checks if a target type has a registered adapter.
func (s *Supervisor) IsAdapterSupported(targetType string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.adapters[targetType]
	return ok
}

// BuildCapabilityManifest produces the runtime capability manifest for control-plane reporting.
func (s *Supervisor) BuildCapabilityManifest() HostCapabilityManifest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	adapters := make([]AdapterCapabilityInfo, 0, len(s.adapters))
	for targetType, factory := range s.adapters {
		// Create a temporary adapter to get capabilities
		dummyProfile := &TargetProfile{TargetType: targetType, Name: "probe"}
		adapter, err := factory(dummyProfile)
		var caps []string
		if err == nil {
			caps = adapter.Capabilities()
			adapter.Close()
		}
		adapters = append(adapters, AdapterCapabilityInfo{
			TargetType:   targetType,
			Capabilities: caps,
			OpsSupported: false, // Phase 6: all adapters are read-only
		})
	}

	updatePolicy := "none"
	if s.state != nil && s.state.Update.UpdatePolicy != "" {
		updatePolicy = s.state.Update.UpdatePolicy
	}

	return HostCapabilityManifest{
		AgentVersion:      HostVersion,
		SupportedAdapters: adapters,
		UpdatePolicy:      updatePolicy,
		OpsEnabledRuntime: false,
	}
}
