// Package proxy ties everything together: accept TCP, negotiate TLS, drive
// the startup/auth handshake, and run the per-client session loop that
// shuttles messages between client and backend while classifying SQL and
// swapping backends according to the configured pool mode.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JoaoArtur/poolsmith/internal/admin"
	"github.com/JoaoArtur/poolsmith/internal/auth"
	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/logger"
	"github.com/JoaoArtur/poolsmith/internal/metrics"
	"github.com/JoaoArtur/poolsmith/internal/pool"
	"github.com/JoaoArtur/poolsmith/internal/tlsutil"
	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// Proxy is a running Poolsmith instance. Created by New; started by Serve.
type Proxy struct {
	cfg       *config.Config
	userlist  *config.Userlist
	log       *logger.Logger
	metrics   *metrics.Registry
	startedAt time.Time

	// TLS configs
	clientTLS *tls.Config

	// Authenticator — built once from cfg + userlist.
	auth *auth.Authenticator

	// Pools keyed by (server, database, user).
	mu    sync.RWMutex
	pools map[pool.Key]*pool.Pool

	// Control
	listener net.Listener
	paused   atomic.Bool
	closing  atomic.Bool
	done     chan struct{}

	shutdownFn func() // optional hook triggered by admin SHUTDOWN
}

// New constructs a Proxy.
func New(cfg *config.Config, users *config.Userlist, log *logger.Logger) (*Proxy, error) {
	if log == nil {
		log = logger.Nop()
	}
	tlsCfg, err := tlsutil.ServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		cfg:       cfg,
		userlist:  users,
		log:       log,
		metrics:   metrics.New(),
		startedAt: time.Now(),
		clientTLS: tlsCfg,
		auth:      &auth.Authenticator{Method: cfg.AuthType, Users: users},
		pools:     map[pool.Key]*pool.Pool{},
		done:      make(chan struct{}),
	}, nil
}

// SetShutdownHook installs a callback fired when the admin console issues
// SHUTDOWN. Typical implementations call Proxy.Close from a separate
// goroutine.
func (p *Proxy) SetShutdownHook(fn func()) { p.shutdownFn = fn }

// Serve starts the listener and blocks accepting clients until Close.
func (p *Proxy) Serve() error {
	addr := fmt.Sprintf("%s:%d", p.cfg.ListenAddr, p.cfg.ListenPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", addr, err)
	}
	p.listener = l
	p.log.Info("poolsmith: listening", "addr", addr)

	go p.janitor()

	for {
		conn, err := l.Accept()
		if err != nil {
			if p.closing.Load() {
				return nil
			}
			p.log.Warn("proxy: accept error", "err", err)
			continue
		}
		p.metrics.TotalClients.Add(1)
		p.metrics.ActiveClients.Add(1)
		go p.handleClient(conn)
	}
}

// Close stops accepting new clients and closes the listener.
func (p *Proxy) Close() {
	if !p.closing.CompareAndSwap(false, true) {
		return
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.mu.Lock()
	pools := p.pools
	p.pools = map[pool.Key]*pool.Pool{}
	p.mu.Unlock()
	for _, pl := range pools {
		pl.Close()
	}
	close(p.done)
}

// Done signals when Close has completed.
func (p *Proxy) Done() <-chan struct{} { return p.done }

// ---- Registry implementation for admin package ----

func (p *Proxy) ListPools() []pool.Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]pool.Stats, 0, len(p.pools))
	for _, pl := range p.pools {
		out = append(out, pl.Stats())
	}
	return out
}

func (p *Proxy) Pause() error {
	p.paused.Store(true)
	return nil
}

func (p *Proxy) Resume() error {
	p.paused.Store(false)
	return nil
}

func (p *Proxy) Reload() error {
	if p.cfg.Path == "" {
		return errors.New("proxy: no config path; cannot reload")
	}
	c, err := config.Load(p.cfg.Path)
	if err != nil {
		return err
	}
	// Replacing the pointer value requires care — the hot path reads
	// *p.cfg fields often. For v1 we just update the sub-fields that are
	// trivially mutable; topology changes require a full restart.
	p.cfg.DefaultPoolMode = c.DefaultPoolMode
	p.cfg.DefaultPoolSize = c.DefaultPoolSize
	p.cfg.MaxClientConn = c.MaxClientConn
	p.cfg.ServerIdleTimeout = c.ServerIdleTimeout
	p.cfg.ServerLifetime = c.ServerLifetime
	p.cfg.ClientIdleTimeout = c.ClientIdleTimeout
	if p.userlist != nil && p.cfg.AuthFile != "" {
		_ = p.userlist.Reload()
	}
	p.log.Info("proxy: config reloaded")
	return nil
}

func (p *Proxy) Shutdown() {
	if p.shutdownFn != nil {
		go p.shutdownFn()
	} else {
		go p.Close()
	}
}

func (p *Proxy) Config() *config.Config         { return p.cfg }
func (p *Proxy) Metrics() *metrics.Registry     { return p.metrics }
func (p *Proxy) StartTime() time.Time           { return p.startedAt }

// Ensure interface satisfaction at compile time.
var _ admin.Registry = (*Proxy)(nil)

// ---- client handler is in client.go ----

// poolFor returns (or creates) the pool for (server, database, user).
func (p *Proxy) poolFor(k pool.Key, db *config.Database) (*pool.Pool, error) {
	p.mu.RLock()
	pl, ok := p.pools[k]
	p.mu.RUnlock()
	if ok {
		return pl, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if pl, ok = p.pools[k]; ok {
		return pl, nil
	}
	srv, ok := p.cfg.Servers[k.Server]
	if !ok {
		return nil, fmt.Errorf("proxy: unknown server %q", k.Server)
	}
	mode := db.PoolMode
	size := db.PoolSize
	if size == 0 {
		size = p.cfg.DefaultPoolSize
	}
	pl = pool.New(pool.Options{
		Key:            k,
		MaxSize:        size,
		MinSize:        db.MinPoolSize,
		Reserve:        db.ReservePool,
		PoolMode:       mode,
		IdleTimeout:    p.cfg.ServerIdleTimeout,
		MaxLifetime:    p.cfg.ServerLifetime,
		ConnectTimeout: p.cfg.ServerConnectTimeout,
		Connect:        p.connectBackend(srv, db),
		Logger:         p.log,
		Metrics:        p.metrics,
	})
	p.pools[k] = pl
	return pl, nil
}

// connectBackend returns a ConnectFunc bound to the given server+database.
func (p *Proxy) connectBackend(srv *config.Server, db *config.Database) pool.ConnectFunc {
	return func(ctx context.Context, k pool.Key) (*pool.Backend, error) {
		b, err := pool.NewBackend(ctx, srv, db.UpstreamName, k.User, p.cfg.ServerConnectTimeout)
		if err != nil {
			return nil, err
		}
		// Upstream TLS
		tcfg, wantTLS, err := tlsutil.UpstreamConfig(srv)
		if err != nil {
			_ = b.Close()
			return nil, err
		}
		if wantTLS {
			if err := b.UpgradeTLS(tcfg); err != nil {
				if !errors.Is(err, pool.ErrTLSRefused) || srv.TLSMode == "require" || srv.TLSMode == "verify-ca" || srv.TLSMode == "verify-full" {
					_ = b.Close()
					return nil, err
				}
				// prefer/allow: server refused; proceed without TLS.
			}
		}

		// Startup
		if err := b.SendStartup(map[string]string{
			"application_name": "poolsmith",
		}); err != nil {
			_ = b.Close()
			return nil, err
		}

		// Authenticate to the upstream as the client's user. We need the
		// password from the userlist.
		pw, ok := p.userlist.Lookup(k.User)
		if !ok {
			_ = b.Close()
			return nil, fmt.Errorf("proxy: no userlist entry for %q", k.User)
		}
		if err := runUpstreamAuth(b.Reader, b.Writer, k.User, pw); err != nil {
			_ = b.Close()
			return nil, err
		}
		if err := b.CompleteStartup(); err != nil {
			_ = b.Close()
			return nil, err
		}
		return b, nil
	}
}

// janitor runs background housekeeping: evict idle backends, close stale
// pools.
func (p *Proxy) janitor() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-t.C:
			p.mu.RLock()
			for _, pl := range p.pools {
				pl.EvictIdle()
			}
			p.mu.RUnlock()
		}
	}
}

// runUpstreamAuth drives the client side of auth against an upstream server.
// It reads AuthenticationXxx messages from the backend and responds with the
// appropriate MD5/SCRAM/cleartext flow, stopping when AuthenticationOk
// arrives.
func runUpstreamAuth(r *wire.Reader, w *wire.Writer, user, password string) error {
	m, err := r.ReadMessage()
	if err != nil {
		return fmt.Errorf("upstream auth: read: %w", err)
	}
	switch m.Type {
	case wire.BeAuthentication:
		a, err := wire.ParseAuth(m.Body)
		if err != nil {
			return err
		}
		switch a.Sub {
		case uint32(wire.AuthOK):
			return nil
		case uint32(wire.AuthMD5Password):
			if err := auth.ClientAuthMD5(r, w, a, user, password); err != nil {
				return err
			}
		case uint32(wire.AuthCleartextPassword):
			if err := w.WriteMessage(wire.FePasswordMessage, append([]byte(password), 0)); err != nil {
				return err
			}
			if err := w.Flush(); err != nil {
				return err
			}
		case uint32(wire.AuthSASL):
			if err := auth.ClientAuthSCRAM(r, w, user, password); err != nil {
				return err
			}
		default:
			return fmt.Errorf("upstream auth: unsupported method %d", a.Sub)
		}
		// Consume remaining Auth* messages until AuthOK.
		for {
			m, err := r.ReadMessage()
			if err != nil {
				return err
			}
			if m.Type == wire.BeErrorResponse {
				return fmt.Errorf("upstream rejected auth: %s", wire.FormatError(wire.ParseErrorFields(m.Body)))
			}
			if m.Type != wire.BeAuthentication {
				return fmt.Errorf("upstream auth: unexpected msg %q", m.Type)
			}
			a2, err := wire.ParseAuth(m.Body)
			if err != nil {
				return err
			}
			if a2.Sub == uint32(wire.AuthOK) {
				return nil
			}
			// SASLContinue / SASLFinal already consumed by ClientAuthSCRAM.
			return fmt.Errorf("upstream auth: unexpected sub-code %d", a2.Sub)
		}
	case wire.BeErrorResponse:
		return fmt.Errorf("upstream error: %s", wire.FormatError(wire.ParseErrorFields(m.Body)))
	}
	return fmt.Errorf("upstream auth: unexpected message %q", m.Type)
}

// writeErrorToClient sends an ErrorResponse + ReadyForQuery(Idle) and flushes.
func writeErrorToClient(w *wire.Writer, sqlstate, msg string) error {
	if err := w.WriteMessage(wire.BeErrorResponse, wire.BuildError("ERROR", sqlstate, msg)); err != nil {
		return err
	}
	if err := w.WriteMessage(wire.BeReadyForQuery, wire.BuildReadyForQuery(wire.TxIdle)); err != nil {
		return err
	}
	return w.Flush()
}

// fatalToClient sends a FATAL error and flushes (no ReadyForQuery).
func fatalToClient(w *wire.Writer, sqlstate, msg string) error {
	if err := w.WriteMessage(wire.BeErrorResponse, wire.BuildError("FATAL", sqlstate, msg)); err != nil {
		return err
	}
	return w.Flush()
}
