// ForgeAI Connector Host — Worker Lifecycle Manager
//
// Each target profile gets an independent worker goroutine.
// Workers are started, stopped, restarted, paused, and degraded
// independently. A single failing target never takes down the host.

package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// Worker represents a per-target collection worker.
type Worker struct {
	mu       sync.RWMutex
	profile  *TargetProfile
	adapter  TargetAdapter
	creds    map[string]string
	state    WorkerState
	policy   RetryPolicy
	cancel   context.CancelFunc
	ctx      context.Context
	done     chan struct{}
	backend  *BackendClient
	hostToken string

	// Callbacks
	onStateChange func(targetID string, status WorkerStatus)
}

// WorkerConfig bundles everything needed to create a worker.
type WorkerConfig struct {
	Profile   *TargetProfile
	Adapter   TargetAdapter
	Creds     map[string]string
	Policy    RetryPolicy
	Backend   *BackendClient
	HostToken string
	OnStateChange func(targetID string, status WorkerStatus)
}

// NewWorker creates a new worker for a target profile.
func NewWorker(cfg WorkerConfig) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Worker{
		profile:       cfg.Profile,
		adapter:       cfg.Adapter,
		creds:         cfg.Creds,
		policy:        cfg.Policy,
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		backend:       cfg.Backend,
		hostToken:     cfg.HostToken,
		onStateChange: cfg.OnStateChange,
		state: WorkerState{
			TargetID: cfg.Profile.TargetID,
			Status:   WorkerStatusIdle,
		},
	}
}

// Start begins the worker's collection loop.
// NOTE: Start must NOT call notifyStateChange synchronously — the caller
// (supervisor.startWorkerLocked) holds a mutex that the callback re-enters.
// The Running transition is emitted from the run() goroutine after init.
func (w *Worker) Start() error {
	w.mu.Lock()
	if w.state.Status == WorkerStatusRunning {
		w.mu.Unlock()
		return fmt.Errorf("worker %s already running", w.profile.TargetID)
	}
	// Mark as starting (not yet Running — that happens after init succeeds)
	w.state.Status = WorkerStatusStarting
	w.state.StartedAt = time.Now()
	w.state.ConsecutiveErrors = 0
	w.mu.Unlock()

	go w.run()
	return nil
}

// Stop gracefully stops the worker.
func (w *Worker) Stop() {
	w.cancel()
	<-w.done
	if w.adapter != nil {
		w.adapter.Close()
	}
	w.setStatus(WorkerStatusStopped)
}

// Pause marks the worker as paused (stops collection but keeps adapter alive).
func (w *Worker) Pause() {
	w.cancel()
	<-w.done
	w.setStatus(WorkerStatusPaused)
}

// Restart stops and restarts the worker with a fresh context.
func (w *Worker) Restart() error {
	w.Stop()

	// Reset context
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.done = make(chan struct{})

	return w.Start()
}

// State returns a copy of the current worker state.
func (w *Worker) State() WorkerState {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state
}

// run is the main collection loop. It initializes the adapter first,
// and only transitions to Running after init succeeds.
func (w *Worker) run() {
	defer close(w.done)

	// Initialize adapter inside the goroutine so the supervisor lock is
	// not held during this call (and its state-change callback).
	if err := w.adapter.Init(w.profile, w.creds); err != nil {
		log.Printf("[worker:%s] Adapter init failed: %v", w.profile.Name, err)
		w.setStatus(WorkerStatusFailed)
		return
	}

	// Adapter initialized — now we are truly Running.
	w.setStatus(WorkerStatusRunning)
	log.Printf("[worker:%s] Worker running", w.profile.Name)

	interval := time.Duration(w.profile.PollIntervalSecs) * time.Second
	if interval < 10*time.Second {
		interval = 30 * time.Second
	}

	// Send initial heartbeat
	w.sendHeartbeat()

	// Collect immediately
	w.collect()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if w.profile.Paused {
				continue
			}
			w.collect()
		}
	}
}

// collect performs one collection cycle with retry/backoff handling.
func (w *Worker) collect() {
	payload, err := w.adapter.Collect()
	if err != nil {
		w.handleError(err)
		// Send heartbeat instead of snapshot on error
		w.sendHeartbeat()
		return
	}

	// Reset error state on success
	w.mu.Lock()
	w.state.ConsecutiveErrors = 0
	w.state.LastCollectionAt = time.Now()
	w.state.TotalCollections++
	if w.state.Status == WorkerStatusDegraded {
		w.state.Status = WorkerStatusRunning
		w.mu.Unlock()
		w.notifyStateChange(WorkerStatusRunning)
		log.Printf("[worker:%s] Recovered from degraded state", w.profile.Name)
	} else {
		w.mu.Unlock()
	}

	// Enrich payload with common fields
	payload["type"] = "snapshot"
	payload["schemaVersion"] = 1
	payload["agentVersion"] = HostVersion
	payload["targetId"] = w.profile.TargetID
	payload["targetType"] = w.profile.TargetType

	if err := w.backend.Post(w.hostToken, payload); err != nil {
		log.Printf("[worker:%s] Snapshot delivery failed: %v", w.profile.Name, err)
	} else {
		log.Printf("[worker:%s] Snapshot delivered", w.profile.Name)
	}
}

// handleError records an error and applies backoff/degradation policy.
func (w *Worker) handleError(err error) {
	w.mu.Lock()
	w.state.ConsecutiveErrors++
	w.state.LastErrorAt = time.Now()
	w.state.LastError = err.Error()
	consecutive := w.state.ConsecutiveErrors
	w.mu.Unlock()

	log.Printf("[worker:%s] Collection error (%d/%d): %v",
		w.profile.Name, consecutive, w.policy.MaxConsecutiveErrors, err)

	if consecutive >= w.policy.MaxConsecutiveErrors {
		w.setStatus(WorkerStatusDegraded)
		log.Printf("[worker:%s] Marked DEGRADED after %d consecutive errors",
			w.profile.Name, consecutive)

		// Apply backoff sleep
		backoff := w.calculateBackoff(consecutive)
		log.Printf("[worker:%s] Backing off for %v", w.profile.Name, backoff)

		select {
		case <-time.After(backoff):
		case <-w.ctx.Done():
		}
	}
}

// calculateBackoff computes exponential backoff duration.
func (w *Worker) calculateBackoff(consecutive int) time.Duration {
	backoff := float64(w.policy.InitialBackoff) *
		math.Pow(w.policy.BackoffMultiplier, float64(consecutive-w.policy.MaxConsecutiveErrors))
	if backoff > float64(w.policy.MaxBackoff) {
		backoff = float64(w.policy.MaxBackoff)
	}
	return time.Duration(backoff)
}

// sendHeartbeat sends a heartbeat for this worker's target.
func (w *Worker) sendHeartbeat() {
	payload := map[string]interface{}{
		"type":         "heartbeat",
		"agentVersion": HostVersion,
		"targetId":     w.profile.TargetID,
		"targetType":   w.profile.TargetType,
		"capabilities": w.adapter.Capabilities(),
	}
	if err := w.backend.Post(w.hostToken, payload); err != nil {
		log.Printf("[worker:%s] Heartbeat failed: %v", w.profile.Name, err)
	}
}

func (w *Worker) setStatus(status WorkerStatus) {
	w.mu.Lock()
	w.state.Status = status
	w.mu.Unlock()
	w.notifyStateChange(status)
}

func (w *Worker) notifyStateChange(status WorkerStatus) {
	if w.onStateChange != nil {
		w.onStateChange(w.profile.TargetID, status)
	}
}
