package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/JoaoArtur/poolsmith/internal/admin"
	"github.com/JoaoArtur/poolsmith/internal/classify"
	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/pool"
	"github.com/JoaoArtur/poolsmith/internal/prepared"
	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// handleClient is the per-client goroutine.
func (p *Proxy) handleClient(rawConn net.Conn) {
	defer func() {
		p.metrics.ActiveClients.Add(-1)
		_ = rawConn.Close()
	}()
	// Client login timeout — applies to the whole startup/auth phase.
	if p.cfg.ClientLoginTimeout > 0 {
		_ = rawConn.SetDeadline(time.Now().Add(p.cfg.ClientLoginTimeout))
	}

	// 1. TLS / SSLRequest negotiation.
	conn, err := p.maybeUpgradeClientTLS(rawConn)
	if err != nil {
		p.log.Warn("client: TLS upgrade failed", "err", err, "remote", rawConn.RemoteAddr())
		return
	}

	cr := wire.NewReader(conn)
	cw := wire.NewWriter(conn)

	// 2. Startup message (may be Cancel, GSSENC, etc.).
	m, err := cr.ReadStartupMessage()
	if err != nil {
		p.log.Warn("client: read startup", "err", err)
		return
	}
	sp, err := wire.ParseStartup(m.Body)
	if err != nil {
		_ = fatalToClient(cw, "08P01", "invalid startup message")
		return
	}
	switch sp.Version {
	case wire.CancelRequestCode:
		p.handleCancel(m.Body)
		return
	case wire.GSSENCRequestCode:
		// GSSAPI not supported — tell client and close.
		_, _ = conn.Write([]byte{'N'})
		return
	case wire.ProtocolV3:
		// proceed
	default:
		_ = fatalToClient(cw, "0A000", fmt.Sprintf("unsupported protocol version %d.%d", sp.Version>>16, sp.Version&0xFFFF))
		return
	}

	user := sp.Params["user"]
	dbName := sp.Params["database"]
	if dbName == "" {
		dbName = user
	}
	if user == "" {
		_ = fatalToClient(cw, "28000", "user is required")
		return
	}

	p.log.Info("client: startup", "user", user, "db", dbName, "remote", rawConn.RemoteAddr())

	// 3. Admin console fast-path.
	if admin.IsAdminDB(dbName) {
		// Auth admin user too.
		if err := p.auth.AuthenticateClient(cr, cw, user); err != nil {
			p.metrics.LoginsFailed.Add(1)
			p.log.Warn("admin: auth failed", "user", user, "err", err)
			return
		}
		if !p.isAdminUser(user) {
			_ = fatalToClient(cw, "42501", "not authorized for admin console")
			return
		}
		p.metrics.LoginsSucceeded.Add(1)
		// Clear login deadline.
		_ = rawConn.SetDeadline(time.Time{})
		if err := p.runAdmin(cr, cw); err != nil && !isEOF(err) {
			p.log.Warn("admin session ended with error", "err", err)
		}
		return
	}

	// 4. Resolve database.
	db, ok := p.cfg.Databases[dbName]
	if !ok {
		_ = fatalToClient(cw, "3D000", fmt.Sprintf("database %q not found", dbName))
		return
	}

	// 5. Authenticate client.
	if err := p.auth.AuthenticateClient(cr, cw, user); err != nil {
		p.metrics.LoginsFailed.Add(1)
		p.log.Warn("client: auth failed", "user", user, "err", err)
		return
	}
	p.metrics.LoginsSucceeded.Add(1)

	// 6. Post-auth: AuthenticationOK + ParameterStatus subset + BackendKeyData + ReadyForQuery.
	//    The specific params we forward come from the first backend we pair
	//    with, but since we may not attach yet, synthesize the essentials now
	//    and patch later via ParameterStatus messages.
	if err := finishClientStartup(cw, user, dbName); err != nil {
		p.log.Warn("client: finish startup", "err", err)
		return
	}
	// Login phase done — clear deadline, install idle timeout via per-read
	// deadlines in the loop below.
	_ = rawConn.SetDeadline(time.Time{})

	// 7. Main session loop.
	sess := &session{
		p:         p,
		conn:      conn,
		cr:        cr,
		cw:        cw,
		user:      user,
		dbName:    dbName,
		db:        db,
		registry:  prepared.NewClientRegistry(),
		statsKey:  dbName + "/" + user,
	}
	if err := sess.run(); err != nil && !isEOF(err) {
		p.log.Warn("client: session ended with error", "err", err, "user", user, "db", dbName)
	}
	if sess.backend != nil {
		sess.releaseBackend()
	}
}

// maybeUpgradeClientTLS peeks the first 8 bytes; if they are an SSLRequest
// and we have a TLS config, it replies 'S' and wraps the connection.
// Otherwise it responds 'N' (for SSLRequest without TLS support) or returns
// the connection unchanged for StartupMessages.
func (p *Proxy) maybeUpgradeClientTLS(conn net.Conn) (net.Conn, error) {
	// Peek first 8 bytes to see whether they're an SSLRequest.
	var hdr [8]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	ln := binary.BigEndian.Uint32(hdr[0:4])
	code := binary.BigEndian.Uint32(hdr[4:8])
	if ln == 8 && code == wire.SSLRequestCode {
		if p.clientTLS == nil {
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, err
			}
			// Client will typically send a StartupMessage next.
			return conn, nil
		}
		if _, err := conn.Write([]byte{'S'}); err != nil {
			return nil, err
		}
		tc := tls.Server(conn, p.clientTLS)
		if err := tc.Handshake(); err != nil {
			return nil, err
		}
		return tc, nil
	}
	// Not an SSLRequest — we must return the bytes we already consumed.
	return &prefixedConn{Conn: conn, prefix: append([]byte{}, hdr[:]...)}, nil
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// handleCancel routes a CancelRequest to the appropriate backend.
func (p *Proxy) handleCancel(body []byte) {
	// body is [code:4][pid:4][secret:4]
	if len(body) != 12 {
		return
	}
	pid := binary.BigEndian.Uint32(body[4:8])
	sec := binary.BigEndian.Uint32(body[8:12])
	// Find a backend whose BackendKeyData matches. This is O(N_pools * N_backends)
	// but cancellations are rare.
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pl := range p.pools {
		_ = pl // iteration over pool internals would leak abstraction.
		// v1: we don't proxy cancels yet (clients usually close conn instead).
		// TODO(v1.1): add Pool.FindByKey and send CancelRequest upstream.
	}
	_ = pid
	_ = sec
}

// isAdminUser reports whether user is listed in admin_users.
func (p *Proxy) isAdminUser(user string) bool {
	for _, u := range p.cfg.AdminUsers {
		if u == user {
			return true
		}
	}
	return false
}

// runAdmin is a simple-query-only loop for the admin console.
func (p *Proxy) runAdmin(cr *wire.Reader, cw *wire.Writer) error {
	// Send BackendKeyData (mostly theatre — admin can't be cancelled) then RFQ.
	if err := cw.WriteMessage(wire.BeParameterStatus, wire.BuildParameterStatus("server_version", "Poolsmith 0.1")); err != nil {
		return err
	}
	if err := cw.WriteMessage(wire.BeBackendKeyData, wire.BuildBackendKeyData(wire.BackendKey{PID: 1, Secret: 1})); err != nil {
		return err
	}
	if err := cw.WriteMessage(wire.BeReadyForQuery, wire.BuildReadyForQuery(wire.TxIdle)); err != nil {
		return err
	}
	if err := cw.Flush(); err != nil {
		return err
	}
	console := admin.New(p)
	for {
		m, err := cr.ReadMessage()
		if err != nil {
			return err
		}
		switch m.Type {
		case wire.FeQuery:
			q, err := wire.ParseQuery(m.Body)
			if err != nil {
				return err
			}
			if err := console.HandleQuery(nil, cw, q); err != nil {
				return err
			}
		case wire.FeTerminate:
			return nil
		default:
			// Admin doesn't support extended protocol; reject politely.
			if err := writeErrorToClient(cw, "0A000", "admin console supports simple queries only"); err != nil {
				return err
			}
		}
	}
}

// finishClientStartup sends AuthOK + essential ParameterStatus + synthetic
// BackendKeyData + ReadyForQuery(Idle).
func finishClientStartup(cw *wire.Writer, user, dbName string) error {
	if err := cw.WriteMessage(wire.BeAuthentication, wire.BuildAuthOK()); err != nil {
		return err
	}
	for k, v := range map[string]string{
		"server_version":          "Poolsmith",
		"server_encoding":         "UTF8",
		"client_encoding":         "UTF8",
		"application_name":        "",
		"DateStyle":               "ISO, MDY",
		"IntervalStyle":           "postgres",
		"TimeZone":                "UTC",
		"integer_datetimes":       "on",
		"standard_conforming_strings": "on",
		"is_superuser":            "off",
		"session_authorization":   user,
	} {
		if err := cw.WriteMessage(wire.BeParameterStatus, wire.BuildParameterStatus(k, v)); err != nil {
			return err
		}
	}
	// Synthetic BackendKeyData — we'll proxy real cancellations through later.
	if err := cw.WriteMessage(wire.BeBackendKeyData, wire.BuildBackendKeyData(wire.BackendKey{PID: 0, Secret: 0})); err != nil {
		return err
	}
	if err := cw.WriteMessage(wire.BeReadyForQuery, wire.BuildReadyForQuery(wire.TxIdle)); err != nil {
		return err
	}
	return cw.Flush()
}

// session holds per-client runtime state for one connected client.
type session struct {
	p       *Proxy
	conn    net.Conn
	cr      *wire.Reader
	cw      *wire.Writer
	user    string
	dbName  string
	db      *config.Database
	backend *pool.Backend
	backendSet *prepared.BackendSet
	registry *prepared.ClientRegistry
	statsKey string
	inTx    bool
	pinned  bool
}

// releaseBackend returns the current backend to its pool (or closes it if
// pinned/broken).
func (s *session) releaseBackend() {
	if s.backend == nil {
		return
	}
	s.backendSet = nil
	pl, err := s.p.poolFor(pool.Key{Server: s.backend.Server.Name, Database: s.dbName, User: s.user}, s.db)
	if err != nil {
		_ = s.backend.Close()
		s.backend = nil
		return
	}
	pl.Release(s.backend)
	s.backend = nil
}

// ensureBackend makes sure a backend is assigned. The routing decision uses
// r (from the classifier) to pick between primary and replica pools.
func (s *session) ensureBackend(r classify.Route) error {
	// Already have one and we're pinned — reuse.
	if s.backend != nil && (s.pinned || s.inTx) {
		return nil
	}
	// For transaction/statement pool modes, reuse across statements only if
	// no swap is needed.
	if s.backend != nil {
		cur := serverRoleOf(s.backend)
		if routeAllowsRole(r, cur) {
			return nil
		}
		// Swap: release current, acquire new.
		s.releaseBackend()
	}

	serverName := s.pickServer(r)
	k := pool.Key{Server: serverName, Database: s.dbName, User: s.user}
	pl, err := s.p.poolFor(k, s.db)
	if err != nil {
		return err
	}
	b, err := pl.Acquire(s.contextWithTimeout())
	if err != nil {
		return err
	}
	s.backend = b
	s.backendSet = prepared.NewBackendSet()
	return nil
}

func (s *session) pickServer(r classify.Route) string {
	if r == classify.RouteReplica && len(s.db.Replicas) > 0 {
		// Simple round-robin via atomic global — we don't need strict fairness.
		i := int(roundRobin.Add(1)-1) % len(s.db.Replicas)
		return s.db.Replicas[i]
	}
	return s.db.Primary
}

// run is the main message loop. Terminates on EOF, Terminate, or fatal error.
func (s *session) run() error {
	for {
		if s.p.cfg.ClientIdleTimeout > 0 && !s.inTx && !s.pinned {
			_ = s.conn.SetReadDeadline(time.Now().Add(s.p.cfg.ClientIdleTimeout))
		}
		m, err := s.cr.ReadMessage()
		if err != nil {
			return err
		}
		if err := s.dispatch(m); err != nil {
			return err
		}
	}
}

// dispatch handles one client message.
func (s *session) dispatch(m wire.Message) error {
	switch m.Type {
	case wire.FeTerminate:
		return io.EOF
	case wire.FeQuery:
		return s.handleSimpleQuery(m)
	case wire.FeParse:
		return s.handleParse(m)
	case wire.FeBind:
		return s.handleBind(m)
	case wire.FeDescribe:
		return s.handleDescribeOrClose(m, true)
	case wire.FeClose:
		return s.handleDescribeOrClose(m, false)
	case wire.FeExecute, wire.FeSync, wire.FeFlush, wire.FeCopyData, wire.FeCopyDone, wire.FeCopyFail:
		return s.forwardToBackend(m)
	}
	return writeErrorToClient(s.cw, "0A000", fmt.Sprintf("unsupported message type %q", m.Type))
}

func (s *session) handleSimpleQuery(m wire.Message) error {
	sql, err := wire.ParseQuery(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", "invalid Query message")
	}
	a := classify.Analyze(sql)
	// Track counters
	switch a.Route {
	case classify.RoutePrimary:
		s.p.metrics.RoutedPrimary.Add(1)
	case classify.RouteReplica:
		s.p.metrics.RoutedReplica.Add(1)
	case classify.RouteDDL:
		s.p.metrics.RoutedDDL.Add(1)
	}
	if a.Pin {
		s.p.metrics.Pinned.Add(1)
	}
	if err := s.ensureBackend(a.Route); err != nil {
		return writeErrorToClient(s.cw, "08006", fmt.Sprintf("no backend available: %v", err))
	}
	if a.Pin || s.db.PoolMode == config.PoolSession {
		s.pinned = true
		s.backend.Pin(s.user, fmt.Sprintf("route=%v sql=%s", a.Route, firstWord(sql)))
	}
	// Track simple BEGIN/COMMIT heuristics.
	uu := firstWord(sql)
	switch strings.ToUpper(uu) {
	case "BEGIN", "START":
		s.inTx = true
	case "COMMIT", "ROLLBACK", "END":
		s.inTx = false
	}
	// Forward and relay responses until ReadyForQuery.
	if err := s.forwardToBackend(m); err != nil {
		return err
	}
	return s.relayUntilReady()
}

func (s *session) handleParse(m wire.Message) error {
	s.p.metrics.ParseMessages.Add(1)
	// Look at the SQL text to decide pin/route. In transaction mode, we
	// rewrite the statement name for later transparent re-parse on swap.
	_, _, _, err := wire.ParseParseMessage(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", "invalid Parse message")
	}
	// Analyze against the query text — re-extract quickly.
	_, query, _, _ := wire.ParseParseMessage(m.Body)
	a := classify.Analyze(query)
	if err := s.ensureBackend(a.Route); err != nil {
		return writeErrorToClient(s.cw, "08006", err.Error())
	}
	if a.Pin || s.db.PoolMode == config.PoolSession {
		s.pinned = true
		s.backend.Pin(s.user, "prepared/pin")
	}
	// Rewrite statement name to a canonical hash-based name.
	rewritten, ent, err := s.registry.OnParse(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", err.Error())
	}
	// If the backend hasn't parsed this canonical statement yet, inject a
	// Parse → Sync preamble. Only needed in transaction mode where a backend
	// swap may have lost prior parses; session mode also works but is harmless.
	if ent != nil && s.backendSet != nil && !s.backendSet.Has(ent.CanonicalName) {
		if err := s.backend.Writer.WriteMessage(wire.FeParse, rewritten); err != nil {
			return err
		}
		s.backendSet.Add(ent.CanonicalName)
		return s.backend.Writer.Flush()
	}
	// Statement already known to backend; the client still expects a
	// ParseComplete, so swallow the Parse on this side and synthesize one.
	if ent != nil {
		return s.cw.WriteMessage(wire.BeParseComplete, nil)
	}
	// Unnamed statement — forward as-is.
	if err := s.backend.Writer.WriteMessage(wire.FeParse, m.Body); err != nil {
		return err
	}
	return s.backend.Writer.Flush()
}

func (s *session) handleBind(m wire.Message) error {
	s.p.metrics.BindMessages.Add(1)
	rewritten, _, err := s.registry.OnBind(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", err.Error())
	}
	if s.backend == nil {
		// Extended query without Parse? Pick primary by default.
		if err := s.ensureBackend(classify.RoutePrimary); err != nil {
			return writeErrorToClient(s.cw, "08006", err.Error())
		}
	}
	if err := s.backend.Writer.WriteMessage(wire.FeBind, rewritten); err != nil {
		return err
	}
	return s.backend.Writer.Flush()
}

func (s *session) handleDescribeOrClose(m wire.Message, describe bool) error {
	rewritten, _, err := s.registry.OnDescribeOrClose(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", err.Error())
	}
	if s.backend == nil {
		if err := s.ensureBackend(classify.RoutePrimary); err != nil {
			return writeErrorToClient(s.cw, "08006", err.Error())
		}
	}
	tag := wire.FeClose
	if describe {
		tag = wire.FeDescribe
	}
	if err := s.backend.Writer.WriteMessage(tag, rewritten); err != nil {
		return err
	}
	return s.backend.Writer.Flush()
}

// forwardToBackend sends the client message to the current backend untouched.
func (s *session) forwardToBackend(m wire.Message) error {
	if s.backend == nil {
		if err := s.ensureBackend(classify.RoutePrimary); err != nil {
			return writeErrorToClient(s.cw, "08006", err.Error())
		}
	}
	if err := s.backend.Writer.WriteMessage(m.Type, m.Body); err != nil {
		return err
	}
	return s.backend.Writer.Flush()
}

// relayUntilReady copies messages from backend to client, stopping after the
// next ReadyForQuery. It also tracks transaction state and parameter status
// so we can swap backends between transactions.
func (s *session) relayUntilReady() error {
	for {
		m, err := s.backend.Reader.ReadMessage()
		if err != nil {
			return err
		}
		if err := s.cw.WriteMessage(m.Type, m.Body); err != nil {
			return err
		}
		switch m.Type {
		case wire.BeReadyForQuery:
			if err := s.cw.Flush(); err != nil {
				return err
			}
			status, _ := wire.ParseReadyForQuery(m.Body)
			s.inTx = status == wire.TxInBlock || status == wire.TxFailed
			s.onReadyForQuery()
			return nil
		case wire.BeParameterStatus:
			name, val, _ := wire.ParseParameterStatus(m.Body)
			s.backend.Params[name] = val
		case wire.BeErrorResponse:
			s.p.metrics.BackendErrors.Add(1)
		}
	}
}

// onReadyForQuery decides whether to release the backend now (transaction
// mode between transactions; statement mode after every statement).
func (s *session) onReadyForQuery() {
	s.backend.TouchUse()
	if s.pinned {
		return
	}
	switch s.db.PoolMode {
	case config.PoolSession:
		// keep
	case config.PoolTransaction:
		if !s.inTx {
			s.releaseBackend()
		}
	case config.PoolStatement:
		if !s.inTx {
			s.releaseBackend()
		}
	}
}

// contextWithTimeout returns a short-lived context honouring QueryWaitTimeout
// for backend acquisition.
func (s *session) contextWithTimeout() context.Context {
	if s.p.cfg.QueryWaitTimeout > 0 {
		ctx, _ := context.WithTimeout(context.Background(), s.p.cfg.QueryWaitTimeout)
		return ctx
	}
	return context.Background()
}

// ---- helpers ----

// serverRoleOf returns primary/replica for the backend's server.
func serverRoleOf(b *pool.Backend) config.ServerRole { return b.Server.Role }

// routeAllowsRole reports whether a backend with role `role` satisfies `r`.
func routeAllowsRole(r classify.Route, role config.ServerRole) bool {
	switch r {
	case classify.RouteReplica:
		return true // replica or primary both OK (primary as fallback)
	case classify.RouteDDL, classify.RoutePrimary:
		return role == config.RolePrimary
	}
	return true
}

// firstWord returns the leading token of a simple SQL string.
func firstWord(s string) string {
	s = strings.TrimLeft(s, " \t\r\n")
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' {
			break
		}
		i++
	}
	return s[:i]
}

func isEOF(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "use of closed network connection"))
}

// roundRobin is the global replica RR counter.
var roundRobin atomic.Uint32
