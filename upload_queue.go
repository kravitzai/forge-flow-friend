// ForgeAI Connector Host — Snapshot Upload Queue
//
// Decouples collection from upload with a bounded in-memory queue,
// async uploader worker(s), retry with backoff, and priority-based
// eviction under pressure.

package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// UploadPriority determines eviction order under pressure.
type UploadPriority int

const (
	PriorityHigh   UploadPriority = 0 // health, alerts, posture
	PriorityMedium UploadPriority = 1 // interface/inventory summaries
	PriorityLow    UploadPriority = 2 // large detailed inventories
)

// QueuedSnapshot is a snapshot waiting to be uploaded.
type QueuedSnapshot struct {
	Token      string
	Payload    map[string]interface{}
	Priority   UploadPriority
	TargetID   string
	TargetType string
	EnqueuedAt time.Time
	Retries    int
	SizeBytes  int64
}

// UploadQueue is a bounded in-memory queue with priority-aware eviction.
type UploadQueue struct {
	mu       sync.Mutex
	items    []*QueuedSnapshot
	maxSize  int
	maxRetries int

	// Backend for uploads
	backend  *BackendClient

	// Lifecycle
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Upload worker config
	workerCount   int
	retryBackoff  time.Duration
	maxBackoff    time.Duration
}

// UploadQueueConfig configures the upload queue.
type UploadQueueConfig struct {
	MaxSize      int           // max queued snapshots (default 100)
	MaxRetries   int           // max retries per snapshot (default 3)
	WorkerCount  int           // concurrent upload workers (default 2)
	RetryBackoff time.Duration // initial retry backoff (default 5s)
	MaxBackoff   time.Duration // max retry backoff (default 60s)
}

func DefaultUploadQueueConfig() UploadQueueConfig {
	return UploadQueueConfig{
		MaxSize:      100,
		MaxRetries:   3,
		WorkerCount:  2,
		RetryBackoff: 5 * time.Second,
		MaxBackoff:   60 * time.Second,
	}
}

// NewUploadQueue creates and starts an upload queue.
func NewUploadQueue(backend *BackendClient, cfg UploadQueueConfig) *UploadQueue {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 5 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 60 * time.Second
	}

	q := &UploadQueue{
		items:        make([]*QueuedSnapshot, 0, cfg.MaxSize),
		maxSize:      cfg.MaxSize,
		maxRetries:   cfg.MaxRetries,
		backend:      backend,
		stopCh:       make(chan struct{}),
		workerCount:  cfg.WorkerCount,
		retryBackoff: cfg.RetryBackoff,
		maxBackoff:   cfg.MaxBackoff,
	}

	return q
}

// Start begins the upload worker goroutines.
func (q *UploadQueue) Start() {
	for i := 0; i < q.workerCount; i++ {
		q.wg.Add(1)
		go q.uploadWorker(i)
	}
	log.Printf("[upload-queue] Started %d upload workers (max_queue=%d, max_retries=%d)",
		q.workerCount, q.maxSize, q.maxRetries)
}

// Stop gracefully drains and stops the upload queue.
func (q *UploadQueue) Stop() {
	close(q.stopCh)
	q.wg.Wait()

	q.mu.Lock()
	remaining := len(q.items)
	q.mu.Unlock()

	if remaining > 0 {
		log.Printf("[upload-queue] Stopped with %d undelivered snapshots", remaining)
	} else {
		log.Printf("[upload-queue] Stopped cleanly")
	}
}

// Enqueue adds a snapshot to the upload queue.
// Returns true if enqueued, false if dropped due to capacity.
func (q *UploadQueue) Enqueue(token string, payload map[string]interface{}, priority UploadPriority) bool {
	payloadBytes, _ := json.Marshal(payload)
	sizeBytes := int64(len(payloadBytes))

	targetID, _ := payload["targetId"].(string)
	targetType, _ := payload["targetType"].(string)

	item := &QueuedSnapshot{
		Token:      token,
		Payload:    payload,
		Priority:   priority,
		TargetID:   targetID,
		TargetType: targetType,
		EnqueuedAt: time.Now(),
		SizeBytes:  sizeBytes,
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// If at capacity, try to evict lowest priority item
	if len(q.items) >= q.maxSize {
		evicted := q.evictLowestPriority(priority)
		if !evicted {
			agentMetrics.RecordUploadDropped()
			log.Printf("[upload-queue] DROPPED snapshot target=%s type=%s priority=%d (queue full, no lower priority to evict)",
				targetID, targetType, priority)
			return false
		}
	}

	q.items = append(q.items, item)
	agentMetrics.SetQueueDepth(len(q.items))

	return true
}

// evictLowestPriority removes the oldest lowest-priority item if it's lower
// priority than the incoming item. Caller must hold q.mu.
func (q *UploadQueue) evictLowestPriority(incomingPriority UploadPriority) bool {
	lowestIdx := -1
	lowestPri := incomingPriority // only evict if something is lower priority

	for i, item := range q.items {
		if item.Priority > lowestPri {
			lowestPri = item.Priority
			lowestIdx = i
		} else if item.Priority == lowestPri && lowestIdx >= 0 {
			// Same priority: evict older
			if item.EnqueuedAt.Before(q.items[lowestIdx].EnqueuedAt) {
				lowestIdx = i
			}
		}
	}

	if lowestIdx < 0 {
		return false
	}

	evicted := q.items[lowestIdx]
	q.items = append(q.items[:lowestIdx], q.items[lowestIdx+1:]...)
	agentMetrics.RecordUploadDropped()
	log.Printf("[upload-queue] Evicted snapshot target=%s priority=%d age=%v to make room",
		evicted.TargetID, evicted.Priority, time.Since(evicted.EnqueuedAt).Round(time.Second))

	return true
}

// uploadWorker is the goroutine that drains items from the queue and uploads.
func (q *UploadQueue) uploadWorker(workerID int) {
	defer q.wg.Done()

	for {
		select {
		case <-q.stopCh:
			return
		default:
		}

		item := q.dequeue()
		if item == nil {
			// No work — sleep briefly
			select {
			case <-q.stopCh:
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}

		err := q.backend.Post(item.Token, item.Payload)
		if err != nil {
			agentMetrics.RecordUploadFailure()
			item.Retries++

			if item.Retries >= q.maxRetries {
				agentMetrics.RecordUploadDropped()
				log.Printf("[upload-queue] worker=%d DROPPED snapshot target=%s after %d retries: %v",
					workerID, item.TargetID, item.Retries, err)
				continue
			}

			// Re-enqueue for retry
			backoff := q.calculateRetryBackoff(item.Retries)
			log.Printf("[upload-queue] worker=%d retry=%d/%d target=%s backoff=%v err=%v",
				workerID, item.Retries, q.maxRetries, item.TargetID, backoff, err)

			select {
			case <-q.stopCh:
				return
			case <-time.After(backoff):
			}

			q.mu.Lock()
			if len(q.items) < q.maxSize {
				q.items = append(q.items, item)
				agentMetrics.SetQueueDepth(len(q.items))
			} else {
				agentMetrics.RecordUploadDropped()
				log.Printf("[upload-queue] worker=%d DROPPED retry snapshot target=%s (queue full)",
					workerID, item.TargetID)
			}
			q.mu.Unlock()
		} else {
			agentMetrics.RecordUploadSuccess(item.SizeBytes)
		}
	}
}

// dequeue removes and returns the highest-priority (lowest number) oldest item.
func (q *UploadQueue) dequeue() *QueuedSnapshot {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	// Find highest priority (lowest value), oldest item
	bestIdx := 0
	for i := 1; i < len(q.items); i++ {
		if q.items[i].Priority < q.items[bestIdx].Priority {
			bestIdx = i
		} else if q.items[i].Priority == q.items[bestIdx].Priority &&
			q.items[i].EnqueuedAt.Before(q.items[bestIdx].EnqueuedAt) {
			bestIdx = i
		}
	}

	item := q.items[bestIdx]
	q.items = append(q.items[:bestIdx], q.items[bestIdx+1:]...)
	agentMetrics.SetQueueDepth(len(q.items))

	return item
}

func (q *UploadQueue) calculateRetryBackoff(retries int) time.Duration {
	backoff := q.retryBackoff
	for i := 1; i < retries; i++ {
		backoff *= 2
	}
	if backoff > q.maxBackoff {
		backoff = q.maxBackoff
	}
	return backoff
}

// Depth returns the current queue depth.
func (q *UploadQueue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// ── Priority Classification Helpers ──

// ClassifySnapshotPriority determines the upload priority for a snapshot payload.
func ClassifySnapshotPriority(payload map[string]interface{}) UploadPriority {
	// Heartbeats are always high priority
	if payloadType, _ := payload["type"].(string); payloadType == "heartbeat" {
		return PriorityHigh
	}

	// Check for alerts — presence of alerts bumps to high
	if alerts, ok := payload["alerts"]; ok {
		if alertList, ok := alerts.([]map[string]interface{}); ok && len(alertList) > 0 {
			return PriorityHigh
		}
		if alertList, ok := alerts.([]interface{}); ok && len(alertList) > 0 {
			return PriorityHigh
		}
	}

	// Check if snapshot has degraded marker
	if snapshotData, ok := payload["snapshotData"].(map[string]interface{}); ok {
		if _, hasDegraded := snapshotData["_collection_status"]; hasDegraded {
			return PriorityHigh
		}
	}

	// Large payloads are lower priority
	if data, err := json.Marshal(payload); err == nil {
		if len(data) > 500*1024 { // > 500KB
			return PriorityLow
		}
	}

	return PriorityMedium
}
