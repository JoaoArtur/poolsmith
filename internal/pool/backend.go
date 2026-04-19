// Package pool manages pools of authenticated backend connections to
// upstream Postgres servers. A Backend wraps one net.Conn talking the
// Postgres v3 wire protocol; a Pool holds many Backends keyed by
// (server, database, user).
package pool

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// BackendState tracks the lifecycle of a server connection.
type BackendState int32

const (
	StateNew       BackendState = iota // not yet authenticated
	StateIdle                          // authenticated, not assigned
	StateAssigned                      // currently bound to a client
	StatePinned                        // assigned AND pinned until client disconnect
	StateInTx                          // inside a transaction
	StateClosing                       // draining
	StateDead                          // must be discarded
)

func (s BackendState) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateIdle:
		return "idle"
	case StateAssigned:
		return "assigned"
	case StatePinned:
		return "pinned"
	case StateInTx:
		return "in_tx"
	case StateClosing:
		return "closing"
	case StateDead:
		return "dead"
	}
	return "unknown"
}

// Backend is an authenticated TCP connection to a Postgres server.
//
// Concurrency: a Backend is used by at most one goroutine at a time — the
// client session that currently owns it. The owner reads and writes through
// Reader/Writer directly.
type Backend struct {
	Server   *config.Server
	Database string
	User     string

	Conn   net.Conn
	Reader *wire.Reader
	Writer *wire.Writer

	// Backend key returned by the server; used to cancel queries later.
	Key wire.BackendKey

	// ParameterStatus values received during startup (and kept in sync through
	// ParameterStatus messages later). Forwarded to clients on check-out so
	// SET is transparent across backend swaps.
	Params map[string]string

	// Unique ID for logs / admin console.
	ID uint64

	// Mutable state — guarded by Pool.mu when the Pool owns this backend, or
	// owned exclusively by the session when checked out.
	state        atomic.Int32 // BackendState as int32
	createdAt    time.Time
	lastUsedAt   atomic.Int64 // unix nanos
	queriesRun   atomic.Uint64
	txNestDepth  int // SAVEPOINT tracking; 0 = not in a transaction block
	pinnedByUser string
	pinReason    string
}

// NewBackend dials the server but does NOT authenticate. Call Authenticate
// separately (usually via auth.ClientAuth*).
func NewBackend(ctx context.Context, srv *config.Server, dbName, user string, timeout time.Duration) (*Backend, error) {
	addr := net.JoinHostPort(srv.Host, fmt.Sprintf("%d", srv.Port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("pool: dial %s: %w", addr, err)
	}
	// TLS negotiation happens as part of startup — the caller drives it.
	b := &Backend{
		Server:    srv,
		Database:  dbName,
		User:      user,
		Conn:      conn,
		Reader:    wire.NewReader(conn),
		Writer:    wire.NewWriter(conn),
		Params:    map[string]string{},
		createdAt: time.Now(),
	}
	b.lastUsedAt.Store(time.Now().UnixNano())
	return b, nil
}

// UpgradeTLS sends SSLRequest and, if the server accepts, wraps the conn.
func (b *Backend) UpgradeTLS(cfg *tls.Config) error {
	// SSLRequest: 8 bytes: [len:4=8][code:4=80877103]
	req := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := b.Conn.Write(req); err != nil {
		return fmt.Errorf("pool: ssl request: %w", err)
	}
	var resp [1]byte
	if _, err := b.Conn.Read(resp[:]); err != nil {
		return fmt.Errorf("pool: ssl response: %w", err)
	}
	switch resp[0] {
	case 'S':
		tconn := tls.Client(b.Conn, cfg)
		if err := tconn.Handshake(); err != nil {
			return fmt.Errorf("pool: tls handshake: %w", err)
		}
		b.Conn = tconn
		b.Reader = wire.NewReader(tconn)
		b.Writer = wire.NewWriter(tconn)
		return nil
	case 'N':
		return ErrTLSRefused
	default:
		return fmt.Errorf("pool: unexpected SSLRequest response byte %q", resp[0])
	}
}

// SendStartup sends the StartupMessage to the upstream. Caller must then
// drive the auth flow with the auth package.
func (b *Backend) SendStartup(extraParams map[string]string) error {
	params := map[string]string{
		"user":     b.User,
		"database": b.Database,
	}
	for k, v := range extraParams {
		params[k] = v
	}
	if err := b.Writer.WriteStartup(wire.BuildStartup(params)); err != nil {
		return err
	}
	return b.Writer.Flush()
}

// CompleteStartup reads BackendKeyData + ParameterStatus + ReadyForQuery
// after a successful auth.
func (b *Backend) CompleteStartup() error {
	for {
		m, err := b.Reader.ReadMessage()
		if err != nil {
			return fmt.Errorf("pool: read startup: %w", err)
		}
		switch m.Type {
		case wire.BeParameterStatus:
			name, val, err := wire.ParseParameterStatus(m.Body)
			if err != nil {
				return err
			}
			b.Params[name] = val
		case wire.BeBackendKeyData:
			k, err := wire.ParseBackendKeyData(m.Body)
			if err != nil {
				return err
			}
			b.Key = k
		case wire.BeReadyForQuery:
			b.setState(StateIdle)
			return nil
		case wire.BeErrorResponse:
			return fmt.Errorf("server error: %s", wire.FormatError(wire.ParseErrorFields(m.Body)))
		case wire.BeNoticeResponse:
			// ignore notices
		default:
			return fmt.Errorf("pool: unexpected post-auth message %q", m.Type)
		}
	}
}

// Close terminates the backend gracefully (sends Terminate then closes conn).
func (b *Backend) Close() error {
	b.setState(StateDead)
	_ = b.Writer.WriteMessage(wire.FeTerminate, nil)
	_ = b.Writer.Flush()
	return b.Conn.Close()
}

// State returns the current lifecycle state.
func (b *Backend) State() BackendState { return BackendState(b.state.Load()) }

func (b *Backend) setState(s BackendState) { b.state.Store(int32(s)) }

// TouchUse bumps lastUsedAt and queriesRun.
func (b *Backend) TouchUse() {
	b.lastUsedAt.Store(time.Now().UnixNano())
	b.queriesRun.Add(1)
}

// Age returns how long the backend has been open.
func (b *Backend) Age() time.Duration { return time.Since(b.createdAt) }

// IdleFor returns time since last use.
func (b *Backend) IdleFor() time.Duration {
	return time.Since(time.Unix(0, b.lastUsedAt.Load()))
}

// QueryCount returns cumulative queries served by this backend.
func (b *Backend) QueryCount() uint64 { return b.queriesRun.Load() }

// TxDepth returns the nested transaction depth (0 = not in tx).
func (b *Backend) TxDepth() int { return b.txNestDepth }

// SetTxDepth is called by the session loop as it tracks BEGIN/COMMIT/SAVEPOINT.
func (b *Backend) SetTxDepth(d int) { b.txNestDepth = d }

// Pin marks this backend as pinned to the current owning client.
func (b *Backend) Pin(user, reason string) {
	b.pinnedByUser = user
	b.pinReason = reason
	b.setState(StatePinned)
}

// IsPinned reports whether the backend is pinned.
func (b *Backend) IsPinned() bool { return b.State() == StatePinned }

// PinReason returns the reason string captured when Pin was called.
func (b *Backend) PinReason() string { return b.pinReason }

// ErrTLSRefused is returned by UpgradeTLS when the server declines TLS.
var ErrTLSRefused = errors.New("pool: server refused TLS")
