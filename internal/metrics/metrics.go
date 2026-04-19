// Package metrics exposes the atomic counters Poolsmith increments on the
// hot path. The admin console and the /metrics HTTP endpoint both read
// snapshots from here.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds all cumulative counters. Safe for concurrent use.
type Registry struct {
	startTime time.Time

	// Client lifecycle
	TotalClients      atomic.Uint64 // cumulative clients ever accepted
	ActiveClients     atomic.Int64  // currently connected (post-startup)
	LoginsSucceeded   atomic.Uint64
	LoginsFailed      atomic.Uint64
	DisconnectedGrace atomic.Uint64

	// Server-side lifecycle
	TotalBackendConns atomic.Uint64
	ActiveBackends    atomic.Int64
	BackendErrors     atomic.Uint64

	// Query routing
	RoutedPrimary atomic.Uint64
	RoutedReplica atomic.Uint64
	RoutedDDL     atomic.Uint64
	Pinned        atomic.Uint64 // pin events (DDL/LISTEN/SET/PREPARE)

	// Query volume
	SQLCount        atomic.Uint64
	ParseMessages   atomic.Uint64
	BindMessages    atomic.Uint64
	ExecuteMessages atomic.Uint64

	// Per-database stats
	mu   sync.RWMutex
	dbs  map[string]*DBStats
}

// DBStats is an independent sub-counter group per database+user pool.
type DBStats struct {
	QueryCount    atomic.Uint64
	QueryDuration atomic.Uint64 // ns
	WaitCount     atomic.Uint64
	WaitDuration  atomic.Uint64 // ns
	BytesIn       atomic.Uint64
	BytesOut      atomic.Uint64
}

// New returns an empty Registry with StartTime=now.
func New() *Registry {
	return &Registry{
		startTime: time.Now(),
		dbs:       map[string]*DBStats{},
	}
}

// StartTime returns when the registry was created.
func (r *Registry) StartTime() time.Time { return r.startTime }

// DB returns (or creates) the per-db counters for key (usually "db/user").
func (r *Registry) DB(key string) *DBStats {
	r.mu.RLock()
	s, ok := r.dbs[key]
	r.mu.RUnlock()
	if ok {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.dbs[key]; ok {
		return s
	}
	s = &DBStats{}
	r.dbs[key] = s
	return s
}

// Snapshot returns a copy of the per-db stats map for admin queries.
func (r *Registry) Snapshot() map[string]DBStatsSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]DBStatsSnapshot, len(r.dbs))
	for k, v := range r.dbs {
		out[k] = DBStatsSnapshot{
			QueryCount:    v.QueryCount.Load(),
			QueryDuration: v.QueryDuration.Load(),
			WaitCount:     v.WaitCount.Load(),
			WaitDuration:  v.WaitDuration.Load(),
			BytesIn:       v.BytesIn.Load(),
			BytesOut:      v.BytesOut.Load(),
		}
	}
	return out
}

// DBStatsSnapshot is an immutable snapshot of DBStats.
type DBStatsSnapshot struct {
	QueryCount    uint64
	QueryDuration uint64
	WaitCount     uint64
	WaitDuration  uint64
	BytesIn       uint64
	BytesOut      uint64
}
