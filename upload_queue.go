// ForgeAI Connector Host — Snapshot Upload Queue
//
// Decouples collection from upload with a bounded in-memory queue,
// async uploader worker(s), retry with backoff, and priority-based
// eviction under pressure.

package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// UploadPriority determines eviction order under pressure.
type UploadPriority int

const (
	PriorityHigh   UploadPriority = 0
	PriorityMedium UploadPriority = 1
	PriorityLow    UploadPriority = 2
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

	backend  *BackendClient
	localDB  *LocalDB

	stopCh   chan struct{}
	notifyCh chan struct{}
	wg       sync.WaitGroup

	workerCount   int
	retryBackoff  time.Duration
	maxBackoff    time.Duration
}

// UploadQueueConfig configures the upload queue.
type UploadQueueConfig struct {
	MaxSize      int
	MaxRetries   int
	WorkerCount  int
	RetryBackoff time.Duration
	MaxBackoff   time.Duration
	LocalDB      *LocalDB
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

	return &UploadQueue{
		items:        make([]*QueuedSnapshot, 0, cfg.MaxSize),
		maxSize:      cfg.MaxSize,
		maxRetries:   cfg.MaxRetries,
		backend:      backend,
		localDB:      cfg.LocalDB,
		stopCh:       make(chan struct{}),
		notifyCh:     make(chan struct{}, 1),
		workerCount:  cfg.WorkerCount,
		retryBackoff: cfg.RetryBackoff,
		maxBackoff:   cfg.MaxBackoff,
	}
}

func (q *UploadQueue) Start() {
	for i := 0; i < q.workerCount; i++ {
		q.wg.Add(1)
		go q.uploadWorker(i)
	}
	audit.Info("upload.success", "Upload queue started",
		F("workers", q.workerCount), F("max_queue", q.maxSize), F("max_retries", q.maxRetries))
}

func (q *UploadQueue) Stop() {
	close(q.stopCh)
	q.wg.Wait()

	q.mu.Lock()
	remaining := len(q.items)
	q.mu.Unlock()

	if remaining > 0 {
		audit.Warn("upload.failed", "Upload queue stopped with undelivered snapshots",
			F("remaining", remaining))
	} else {
		audit.Info("upload.success", "Upload queue stopped cleanly")
	}
}

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

	if len(q.items) >= q.maxSize {
		evicted := q.evictLowestPriority(priority)
		if !evicted {
			agentMetrics.RecordUploadDropped()
			audit.Error("upload.dropped", "Snapshot dropped (queue full, no lower priority to evict)",
				F("target_id", targetID), F("target_type", targetType), F("priority", int(priority)))
			return false
		}
	}

	q.items = append(q.items, item)
	agentMetrics.SetQueueDepth(len(q.items))

	// Notify waiting workers
	select {
	case q.notifyCh <- struct{}{}:
	default:
	}

	return true
}

func (q *UploadQueue) evictLowestPriority(incomingPriority UploadPriority) bool {
	lowestIdx := -1
	lowestPri := incomingPriority

	for i, item := range q.items {
		if item.Priority > lowestPri {
			lowestPri = item.Priority
			lowestIdx = i
		} else if item.Priority == lowestPri && lowestIdx >= 0 {
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
	audit.Warn("upload.dropped", "Evicted snapshot to make room",
		F("target_id", evicted.TargetID), F("priority", int(evicted.Priority)),
		F("age", time.Since(evicted.EnqueuedAt).Round(time.Second).String()))

	return true
}

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
			select {
			case <-q.stopCh:
				return
			case <-q.notifyCh:
				continue
			}
		}

		err := q.backend.Post(item.Token, item.Payload)
		if err != nil {
			agentMetrics.RecordUploadFailure()
			item.Retries++

			if item.Retries >= q.maxRetries {
				agentMetrics.RecordUploadDropped()
				audit.Error("upload.dropped", fmt.Sprintf("Dropped snapshot after %d retries", item.Retries),
					F("target_id", item.TargetID), F("worker", workerID), Err(err))
				continue
			}

			backoff := q.calculateRetryBackoff(item.Retries)
			audit.Warn("upload.failed", "Upload retry scheduled",
				F("target_id", item.TargetID), F("worker", workerID),
				F("retry", item.Retries), F("max_retries", q.maxRetries),
				F("backoff", backoff.String()), Err(err))

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
				audit.Error("upload.dropped", "Dropped retry snapshot (queue full)",
					F("target_id", item.TargetID), F("worker", workerID))
			}
			q.mu.Unlock()
	} else {
			agentMetrics.RecordUploadSuccess(item.SizeBytes)
			// Mark synced in local DB if this was a
			// Hybrid Mode summary upload
			if q.localDB != nil {
				if id, ok := item.Payload["_localSnapshotId"]; ok {
					if snapshotID, ok := id.(string); ok && snapshotID != "" {
						if err := q.localDB.MarkSynced(snapshotID); err != nil {
							audit.Warn("local_db.sync",
								"Failed to mark snapshot synced",
								F("snapshot_id", snapshotID), Err(err))
						} else {
							audit.Debug("local_db.sync",
								"Snapshot marked synced",
								F("snapshot_id", snapshotID))
						}
					}
				}
			}
		}
	}
}

func (q *UploadQueue) dequeue() *QueuedSnapshot {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

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

func (q *UploadQueue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// ── Priority Classification Helpers ──

func ClassifySnapshotPriority(payload map[string]interface{}) UploadPriority {
	if payloadType, _ := payload["type"].(string); payloadType == "heartbeat" {
		return PriorityHigh
	}

	if alerts, ok := payload["alerts"]; ok {
		if alertList, ok := alerts.([]map[string]interface{}); ok && len(alertList) > 0 {
			return PriorityHigh
		}
		if alertList, ok := alerts.([]interface{}); ok && len(alertList) > 0 {
			return PriorityHigh
		}
	}

	if snapshotData, ok := payload["snapshotData"].(map[string]interface{}); ok {
		if _, hasDegraded := snapshotData["_collection_status"]; hasDegraded {
			return PriorityHigh
		}
	}

	if data, err := json.Marshal(payload); err == nil {
		if len(data) > 500*1024 {
			return PriorityLow
		}
	}

	return PriorityMedium
}
