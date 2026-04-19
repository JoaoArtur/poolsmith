package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"sort"
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
		// TCP/TLS probes (kube-proxy, GLB health checks) open and close
		// without completing TLS — demote to debug to avoid log spam.
		p.log.Debug("client: TLS upgrade failed", "err", err, "remote", rawConn.RemoteAddr())
		return
	}

	cr := wire.NewReader(conn)
	cw := wire.NewWriter(conn)

	// 2. Startup message (may be Cancel, GSSENC, etc.).
	m, err := cr.ReadStartupMessage()
	if err != nil {
		// Same reason as above — most of these are half-open probes.
		p.log.Debug("client: read startup", "err", err)
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
	if err := finishClientStartup(cw, user, dbName, p.cfg.AuthType != config.AuthSCRAM); err != nil {
		p.log.Warn("client: finish startup", "err", err)
		return
	}
	// Login phase done — clear deadline, install idle timeout via per-read
	// deadlines in the loop below.
	_ = rawConn.SetDeadline(time.Time{})

	// 7. Main session loop.
	sess := &session{
		p:             p,
		conn:          conn,
		cr:            cr,
		cw:            cw,
		user:          user,
		dbName:        dbName,
		db:            db,
		registry:      prepared.NewClientRegistry(),
		statsKey:      dbName + "/" + user,
		startupParams: filterStartupParams(sp.Params),
	}
	sess.startupSig = startupParamsSig(sess.startupParams)
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
	// SCRAM's server side already sends AuthenticationOk; MD5/trust/plain
	// don't — we do it here for those.
	if p.cfg.AuthType != config.AuthSCRAM {
		if err := cw.WriteMessage(wire.BeAuthentication, wire.BuildAuthOK()); err != nil {
			return err
		}
	}
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

// finishClientStartup sends AuthOK (if sendAuthOk is true) + essential
// ParameterStatus + synthetic BackendKeyData + ReadyForQuery(Idle).
func finishClientStartup(cw *wire.Writer, user, dbName string, sendAuthOk bool) error {
	if sendAuthOk {
		if err := cw.WriteMessage(wire.BeAuthentication, wire.BuildAuthOK()); err != nil {
			return err
		}
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
	registry *prepared.ClientRegistry
	statsKey string
	inTx    bool
	pinned  bool

	// extAdmin holds an admin SHOW query the client Parse'd via extended
	// protocol. When set, handleBind/handleDescribeOrClose/handleExecute
	// synthesize local responses instead of forwarding.
	extAdmin string

	// Client-supplied startup parameters (search_path, options, TimeZone,
	// …) forwarded verbatim to upstream backends. startupSig is the stable
	// hash used as the Params component of pool.Key so clients with
	// different startup state don't share backends.
	startupParams map[string]string
	startupSig    string
}

// releaseBackend returns the current backend to its pool (or closes it if
// pinned/broken).
func (s *session) releaseBackend() {
	if s.backend == nil {
		return
	}
	pl, err := s.p.poolFor(pool.Key{Server: s.backend.Server.Name, Database: s.dbName, User: s.user, Params: s.startupSig}, s.db, s.startupParams)
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
	k := pool.Key{Server: serverName, Database: s.dbName, User: s.user, Params: s.startupSig}
	pl, err := s.p.poolFor(k, s.db, s.startupParams)
	if err != nil {
		return err
	}
	b, err := pl.Acquire(s.contextWithTimeout())
	if err != nil {
		return err
	}
	s.backend = b
	if err := s.syncBackendParams(); err != nil {
		// Failed to re-sync — the backend is in a weird state. Close it so
		// it gets replaced, and surface the error to the client.
		b.Close()
		s.backend = nil
		return err
	}
	return nil
}

// syncBackendParams makes the newly-acquired backend match the session's
// desired tracked parameter values. It issues one SET per mismatching
// parameter and drains responses up to ReadyForQuery. This is how one
// shared pool serves many tenants with distinct search_paths.
func (s *session) syncBackendParams() error {
	if s.backend == nil || len(s.startupParams) == 0 {
		return nil
	}
	for _, name := range trackedParamNames {
		want := lookupCI(s.startupParams, name)
		if want == "" {
			continue
		}
		have := lookupCI(s.backend.Params, name)
		if have == want {
			continue
		}
		if err := s.setBackendParam(name, want); err != nil {
			return fmt.Errorf("sync %s=%q: %w", name, want, err)
		}
	}
	return nil
}

// setBackendParam runs `SET <name> TO <literal>` on the backend and drains
// the response until ReadyForQuery. Values are quoted as single-quoted
// string literals with '' escaping — safe for every GUC value Postgres
// accepts.
func (s *session) setBackendParam(name, value string) error {
	quoted := "'" + strings.ReplaceAll(value, "'", "''") + "'"
	sql := "SET " + name + " TO " + quoted
	if err := s.backend.Writer.WriteMessage(wire.FeQuery, wire.BuildQuery(sql)); err != nil {
		return err
	}
	if err := s.backend.Writer.Flush(); err != nil {
		return err
	}
	for {
		m, err := s.backend.Reader.ReadMessage()
		if err != nil {
			return err
		}
		switch m.Type {
		case wire.BeReadyForQuery:
			s.backend.Params[name] = value
			return nil
		case wire.BeErrorResponse:
			// Drain until RFQ anyway so the backend stays in a usable state.
			errMsg := wire.FormatError(wire.ParseErrorFields(m.Body))
			for {
				m2, err := s.backend.Reader.ReadMessage()
				if err != nil {
					return err
				}
				if m2.Type == wire.BeReadyForQuery {
					break
				}
			}
			return errors.New(errMsg)
		case wire.BeParameterStatus:
			n, v, _ := wire.ParseParameterStatus(m.Body)
			s.backend.Params[n] = v
		}
	}
}

// lookupCI returns m[k] for any case-insensitive match of k in m.
func lookupCI(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	kl := strings.ToLower(k)
	for mk, mv := range m {
		if strings.ToLower(mk) == kl {
			return mv
		}
	}
	return ""
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
	case wire.FeSync:
		if s.extAdmin != "" {
			// Emit ReadyForQuery ourselves; admin query already emitted
			// RowDescription/DataRow/CommandComplete during Execute.
			if err := s.cw.WriteMessage(wire.BeReadyForQuery, wire.BuildReadyForQuery(wire.TxIdle)); err != nil {
				return err
			}
			s.extAdmin = ""
			return s.cw.Flush()
		}
		// Sync flushes pending extended-query responses and ends the
		// implicit transaction. We forward it AND pump responses back to
		// the client until ReadyForQuery.
		if err := s.forwardToBackend(m); err != nil {
			return err
		}
		return s.relayUntilReady()
	case wire.FeExecute:
		if s.extAdmin != "" {
			console := admin.New(s.p)
			if err := console.HandleExtendedExecute(s.cw, s.extAdmin); err != nil {
				return err
			}
			return nil
		}
		if err := s.forwardToBackend(m); err != nil {
			return err
		}
		return nil
	case wire.FeFlush, wire.FeCopyData, wire.FeCopyDone, wire.FeCopyFail:
		if err := s.forwardToBackend(m); err != nil {
			return err
		}
		// Flush causes the server to send any pending responses but does NOT
		// include ReadyForQuery. Execute alone before Sync behaves similarly.
		// We pump whatever bytes the backend is willing to produce right
		// now, bounded by a short read deadline, so GUIs that interleave
		// Flush with small reads still make progress.
		if m.Type == wire.FeFlush {
			return s.relayPending()
		}
		return nil
	}
	return writeErrorToClient(s.cw, "0A000", fmt.Sprintf("unsupported message type %q", m.Type))
}

func (s *session) handleSimpleQuery(m wire.Message) error {
	sql, err := wire.ParseQuery(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", "invalid Query message")
	}
	// Intercept read-only admin SHOW commands so they work from any database
	// and any user without having to connect to the admin console.
	if isReadOnlyAdminQuery(sql) {
		console := admin.New(s.p)
		return console.HandleQuery(nil, s.cw, sql)
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
	stmtName, query, oids, err := wire.ParseParseMessage(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", "invalid Parse message")
	}
	_ = stmtName
	_ = oids
	// Intercept admin SHOW queries even when issued via extended protocol —
	// we need to remember the statement so the ensuing Bind/Describe/Execute
	// return our local answer instead of being forwarded to Postgres.
	if isReadOnlyAdminQuery(query) {
		s.extAdmin = query
		return s.cw.WriteMessage(wire.BeParseComplete, nil)
	}
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
	if ent != nil && s.backend.PreparedSet != nil && !s.backend.PreparedSet.Has(ent.CanonicalName) {
		if err := s.backend.Writer.WriteMessage(wire.FeParse, rewritten); err != nil {
			return err
		}
		s.backend.PreparedSet.Add(ent.CanonicalName)
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
	if s.extAdmin != "" {
		return s.cw.WriteMessage(wire.BeBindComplete, nil)
	}
	rewritten, ent, err := s.registry.OnBind(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", err.Error())
	}
	if s.backend == nil {
		if err := s.ensureBackend(classify.RoutePrimary); err != nil {
			return writeErrorToClient(s.cw, "08006", err.Error())
		}
	}
	// If this bind targets a named prepared statement AND the current
	// backend hasn't parsed the canonical name (likely because the pool
	// swapped backends after a previous Sync), inject Parse first.
	if err := s.ensureCanonicalParsed(ent); err != nil {
		return writeErrorToClient(s.cw, "08006", err.Error())
	}
	if err := s.backend.Writer.WriteMessage(wire.FeBind, rewritten); err != nil {
		return err
	}
	return s.backend.Writer.Flush()
}

// ensureCanonicalParsed makes sure the current backend has already parsed
// the given prepared-statement Entry. If not (common in transaction-mode
// pooling after a backend swap), it injects a Parse ahead of whatever the
// caller is about to send. Safe to call with ent==nil (no-op).
func (s *session) ensureCanonicalParsed(ent *prepared.Entry) error {
	if ent == nil || s.backend == nil {
		return nil
	}
	if s.backend.PreparedSet != nil && s.backend.PreparedSet.Has(ent.CanonicalName) {
		return nil
	}
	body := wire.BuildParseMessage(ent.CanonicalName, ent.Query, ent.ParamOIDs)
	if err := s.backend.Writer.WriteMessage(wire.FeParse, body); err != nil {
		return err
	}
	if s.backend.PreparedSet != nil {
		s.backend.PreparedSet.Add(ent.CanonicalName)
	}
	return nil
}

func (s *session) handleDescribeOrClose(m wire.Message, describe bool) error {
	if s.extAdmin != "" {
		if describe {
			return s.cw.WriteMessage(wire.BeNoData, nil)
		}
		return s.cw.WriteMessage(wire.BeCloseComplete, nil)
	}
	// Look up the statement (if named) so we can re-Parse it on the current
	// backend if the pool swapped it out from under us.
	var ent *prepared.Entry
	if len(m.Body) >= 1 && m.Body[0] == 'S' {
		if name, _, err := readCStringFromBody(m.Body[1:]); err == nil && name != "" {
			ent = s.registry.Lookup(name)
		}
	}
	rewritten, _, err := s.registry.OnDescribeOrClose(m.Body)
	if err != nil {
		return writeErrorToClient(s.cw, "08P01", err.Error())
	}
	if s.backend == nil {
		if err := s.ensureBackend(classify.RoutePrimary); err != nil {
			return writeErrorToClient(s.cw, "08006", err.Error())
		}
	}
	if err := s.ensureCanonicalParsed(ent); err != nil {
		return writeErrorToClient(s.cw, "08006", err.Error())
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

// readCStringFromBody reads a NUL-terminated C-string from body.
func readCStringFromBody(b []byte) (string, []byte, error) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], nil
		}
	}
	return "", nil, wire.ErrShortRead
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

// relayPending pumps whatever messages the backend has buffered with a
// short read deadline, stopping when the backend would block. Used after
// a Flush where ReadyForQuery is not expected.
func (s *session) relayPending() error {
	if s.backend == nil {
		return nil
	}
	for {
		if tcp, ok := s.backend.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = tcp.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		}
		m, err := s.backend.Reader.ReadMessage()
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				// Reset deadline and return control to the session loop.
				if tcp, ok := s.backend.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
					_ = tcp.SetReadDeadline(time.Time{})
				}
				return s.cw.Flush()
			}
			return err
		}
		if err := s.cw.WriteMessage(m.Type, m.Body); err != nil {
			return err
		}
		if m.Type == wire.BeReadyForQuery {
			status, _ := wire.ParseReadyForQuery(m.Body)
			s.inTx = status == wire.TxInBlock || status == wire.TxFailed
			s.onReadyForQuery()
			if tcp, ok := s.backend.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
				_ = tcp.SetReadDeadline(time.Time{})
			}
			return s.cw.Flush()
		}
	}
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

// isReadOnlyAdminQuery reports whether sql is one of the SHOW commands
// Poolsmith exposes via the admin console. These are safe to answer from
// any client session — they only read internal state.
func isReadOnlyAdminQuery(sql string) bool {
	s := strings.ToUpper(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sql), ";")))
	switch s {
	case "SHOW POOLS", "SHOW DATABASES", "SHOW SERVERS",
		"SHOW STATS", "SHOW TOTALS", "SHOW CLIENTS",
		"SHOW CONFIG", "SHOW VERSION":
		return true
	}
	// Accept trailing whitespace/variants like "SHOW POOLS ".
	for _, p := range []string{"SHOW POOLS", "SHOW DATABASES", "SHOW SERVERS",
		"SHOW STATS", "SHOW TOTALS", "SHOW CLIENTS", "SHOW CONFIG", "SHOW VERSION"} {
		if s == p || strings.HasPrefix(s, p+" ") {
			return true
		}
	}
	return false
}

// filterStartupParams keeps only parameters that are safe to forward to the
// upstream server. user and database are fixed by the pool Key; replication
// is never supported through Poolsmith.
func filterStartupParams(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if lk == "user" || lk == "database" || lk == "replication" {
			continue
		}
		out[k] = v
	}
	return out
}

// stickyParamNames are startup parameters whose value MUST force a separate
// pool — there's currently no such parameter because everything we care
// about (search_path, client_encoding, bytea_output, …) can be re-SET on
// the backend cheaply at checkout via trackedParamNames.
//
// Intentionally empty: in multi-tenant apps each client often sends a
// unique search_path, and partitioning the pool by that would collapse
// multiplexing back to one backend per tenant.
var stickyParamNames = map[string]struct{}{}

// trackedParamNames are startup parameters whose value is (a) important
// for query correctness and (b) settable via SET at runtime. When a
// session checks out a backend whose current value differs from the
// session's desired value, Poolsmith issues a SET before handing the
// backend over. This is how many tenants share one small pool without
// getting each other's search_path.
var trackedParamNames = []string{
	"search_path",
	"client_encoding",
	"bytea_output",
	"standard_conforming_strings",
	"timezone",
	"datestyle",
	"intervalstyle",
	"extra_float_digits",
}

// startupParamsSig returns a stable 16-hex-digit signature for the subset of
// startup parameters that matter for pool sharing. Empty when every param in
// the input is volatile (application_name etc.).
func startupParamsSig(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if _, ok := stickyParamNames[strings.ToLower(k)]; ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	h := fnv.New64a()
	for _, k := range keys {
		_, _ = h.Write([]byte(strings.ToLower(k)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(m[k]))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%016x", h.Sum64())
}

func isEOF(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "use of closed network connection"))
}

// roundRobin is the global replica RR counter.
var roundRobin atomic.Uint32
