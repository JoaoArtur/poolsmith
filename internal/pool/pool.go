package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/logger"
	"github.com/JoaoArtur/poolsmith/internal/metrics"
)

// Key identifies a Pool uniquely: (server logical name, client-facing db, user).
// Backends are fungible within a Key but never across Keys — they were
// authenticated with specific credentials.
type Key struct {
	Server   string
	Database string
	User     string
}

// String returns a flat key for maps / logs.
func (k Key) String() string { return k.Server + "/" + k.Database + "/" + k.User }

// ConnectFunc is supplied by the caller (proxy/session) and encapsulates
// the dial + TLS + auth flow for one backend. This keeps the pool package
// free of auth/TLS dependencies.
type ConnectFunc func(ctx context.Context, k Key) (*Backend, error)

// Pool manages authenticated backends for one (server, db, user) triple.
// Safe for concurrent use.
type Pool struct {
	Key      Key
	MaxSize  int
	MinSize  int
	Reserve  int
	PoolMode config.PoolMode

	IdleTimeout    time.Duration
	MaxLifetime    time.Duration
	ConnectTimeout time.Duration

	connect ConnectFunc
	log     *logger.Logger
	m       *metrics.Registry

	mu        sync.Mutex
	idle      []*Backend // LIFO for temporal locality
	all       map[uint64]*Backend
	waiters   []chan *Backend
	nextID    atomic.Uint64
	closing   bool
	totalOpen atomic.Int64 // counts all non-dead backends
}

// Options bundles tunables passed to New.
type Options struct {
	Key            Key
	MaxSize        int
	MinSize        int
	Reserve        int
	PoolMode       config.PoolMode
	IdleTimeout    time.Duration
	MaxLifetime    time.Duration
	ConnectTimeout time.Duration
	Connect        ConnectFunc
	Logger         *logger.Logger
	Metrics        *metrics.Registry
}

// New returns a Pool with the given options.
func New(o Options) *Pool {
	if o.Logger == nil {
		o.Logger = logger.Nop()
	}
	if o.Metrics == nil {
		o.Metrics = metrics.New()
	}
	if o.MaxSize <= 0 {
		o.MaxSize = 20
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 15 * time.Second
	}
	return &Pool{
		Key:            o.Key,
		MaxSize:        o.MaxSize,
		MinSize:        o.MinSize,
		Reserve:        o.Reserve,
		PoolMode:       o.PoolMode,
		IdleTimeout:    o.IdleTimeout,
		MaxLifetime:    o.MaxLifetime,
		ConnectTimeout: o.ConnectTimeout,
		connect:        o.Connect,
		log:            o.Logger,
		m:              o.Metrics,
		all:            map[uint64]*Backend{},
	}
}

// Acquire returns an idle backend, opening one if under MaxSize and none is
// free. Respects ctx for deadlines.
func (p *Pool) Acquire(ctx context.Context) (*Backend, error) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}

	// 1. Try the idle list (LIFO).
	for len(p.idle) > 0 {
		n := len(p.idle) - 1
		b := p.idle[n]
		p.idle = p.idle[:n]
		if p.shouldReuse(b) {
			b.setState(StateAssigned)
			p.mu.Unlock()
			return b, nil
		}
		// Stale — close it and loop.
		p.discardLocked(b)
	}

	// 2. Room to open a new one?
	if p.totalOpen.Load() < int64(p.MaxSize) {
		p.totalOpen.Add(1)
		p.mu.Unlock()
		b, err := p.dial(ctx)
		if err != nil {
			p.totalOpen.Add(-1)
			return nil, err
		}
		p.mu.Lock()
		b.ID = p.nextID.Add(1)
		p.all[b.ID] = b
		b.setState(StateAssigned)
		p.mu.Unlock()
		return b, nil
	}

	// 3. Wait.
	ch := make(chan *Backend, 1)
	p.waiters = append(p.waiters, ch)
	p.mu.Unlock()

	select {
	case b := <-ch:
		if b == nil {
			return nil, ErrPoolClosed
		}
		b.setState(StateAssigned)
		return b, nil
	case <-ctx.Done():
		// Remove ourselves from waiters if we can (best-effort).
		p.mu.Lock()
		for i, w := range p.waiters {
			if w == ch {
				p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Release returns a backend to the pool. If the backend is pinned or dead
// (state indicates so), the pool closes it instead.
func (p *Pool) Release(b *Backend) {
	if b == nil {
		return
	}
	p.mu.Lock()
	if p.closing || b.State() == StateDead {
		p.discardLocked(b)
		p.mu.Unlock()
		return
	}
	if b.IsPinned() {
		// Pinned backends go to the dead pile on release — the client that
		// owned them is gone.
		p.discardLocked(b)
		p.mu.Unlock()
		return
	}

	// Hand off directly to a waiter if any.
	if len(p.waiters) > 0 {
		ch := p.waiters[0]
		p.waiters = p.waiters[1:]
		p.mu.Unlock()
		ch <- b
		return
	}

	b.setState(StateIdle)
	b.lastUsedAt.Store(time.Now().UnixNano())
	p.idle = append(p.idle, b)
	p.mu.Unlock()
}

// Close drains the pool and closes every backend.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closing = true
	waiters := p.waiters
	p.waiters = nil
	idle := p.idle
	p.idle = nil
	all := p.all
	p.all = map[uint64]*Backend{}
	p.mu.Unlock()

	for _, w := range waiters {
		close(w)
	}
	for _, b := range idle {
		_ = b.Close()
		p.totalOpen.Add(-1)
	}
	for _, b := range all {
		if b.State() != StateDead {
			_ = b.Close()
			p.totalOpen.Add(-1)
		}
	}
}

// Stats is a snapshot used by the admin console.
type Stats struct {
	Key        Key
	MaxSize    int
	TotalOpen  int64
	Idle       int
	Active     int
	Waiters    int
	PoolMode   config.PoolMode
}

// Stats returns a point-in-time snapshot.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	active := 0
	for _, b := range p.all {
		switch b.State() {
		case StateAssigned, StatePinned, StateInTx:
			active++
		}
	}
	return Stats{
		Key:       p.Key,
		MaxSize:   p.MaxSize,
		TotalOpen: p.totalOpen.Load(),
		Idle:      len(p.idle),
		Active:    active,
		Waiters:   len(p.waiters),
		PoolMode:  p.PoolMode,
	}
}

// EvictIdle closes backends that have been idle longer than IdleTimeout or
// open longer than MaxLifetime. Returns the number evicted. Call
// periodically from a janitor goroutine.
func (p *Pool) EvictIdle() int {
	if p.IdleTimeout == 0 && p.MaxLifetime == 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.idle[:0]
	closed := 0
	for _, b := range p.idle {
		if !p.shouldReuse(b) {
			_ = b.Close()
			delete(p.all, b.ID)
			p.totalOpen.Add(-1)
			closed++
			continue
		}
		kept = append(kept, b)
	}
	p.idle = kept
	return closed
}

// ---- internal ----

func (p *Pool) dial(ctx context.Context) (*Backend, error) {
	if p.connect == nil {
		return nil, errors.New("pool: no ConnectFunc configured")
	}
	ctx, cancel := context.WithTimeout(ctx, p.ConnectTimeout)
	defer cancel()
	b, err := p.connect(ctx, p.Key)
	if err != nil {
		return nil, fmt.Errorf("pool: connect %s: %w", p.Key, err)
	}
	p.m.TotalBackendConns.Add(1)
	p.m.ActiveBackends.Add(1)
	return b, nil
}

// shouldReuse returns false if the backend has exceeded max lifetime or idle
// timeout or appears broken.
func (p *Pool) shouldReuse(b *Backend) bool {
	if b.State() == StateDead {
		return false
	}
	if p.MaxLifetime > 0 && b.Age() > p.MaxLifetime {
		return false
	}
	if p.IdleTimeout > 0 && b.IdleFor() > p.IdleTimeout {
		return false
	}
	return true
}

// discardLocked MUST be called with p.mu held. It closes b and adjusts counters.
func (p *Pool) discardLocked(b *Backend) {
	delete(p.all, b.ID)
	_ = b.Close()
	p.m.ActiveBackends.Add(-1)
	p.totalOpen.Add(-1)
}

// ErrPoolClosed is returned by Acquire when the pool is shutting down.
var ErrPoolClosed = errors.New("pool: closed")
