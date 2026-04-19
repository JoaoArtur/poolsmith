// Package admin implements Poolsmith's admin console — a pseudo database
// named "poolsmith" that accepts SQL commands like SHOW POOLS, SHOW STATS,
// PAUSE, RESUME, RELOAD, SHUTDOWN.
//
// Clients connect with psql, select the admin database, and run commands as
// plain text via the simple-query protocol. Responses are synthesized
// row-by-row and never touch a real Postgres backend.
package admin

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/metrics"
	"github.com/JoaoArtur/poolsmith/internal/pool"
	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// Registry is the external surface the admin console queries against. The
// proxy package provides a concrete implementation.
type Registry interface {
	ListPools() []pool.Stats
	Pause() error
	Resume() error
	Reload() error
	Shutdown()
	Config() *config.Config
	Metrics() *metrics.Registry
	StartTime() time.Time
}

// Console is an admin session handler bound to one client.
type Console struct {
	reg Registry
	// suppressReady skips the trailing ReadyForQuery frame in finish().
	// Used by HandleExtendedExecute where the caller emits RFQ on Sync.
	suppressReady bool
}

// New returns a Console reading from reg.
func New(reg Registry) *Console { return &Console{reg: reg} }

// IsAdminDB reports whether dbName targets the admin console.
func IsAdminDB(dbName string) bool {
	return strings.ToLower(dbName) == "poolsmith"
}

// HandleExtendedExecute runs an admin query during an extended-protocol
// Execute: it emits RowDescription + DataRow(s) + CommandComplete but NOT
// ReadyForQuery (the session loop will emit RFQ when Sync arrives).
func (c *Console) HandleExtendedExecute(w *wire.Writer, sql string) error {
	c.suppressReady = true
	defer func() { c.suppressReady = false }()
	return c.HandleQuery(nil, w, sql)
}

// HandleQuery processes one simple-query and writes the response to w.
// Returns error only on I/O failure — SQL errors are sent as ErrorResponse.
func (c *Console) HandleQuery(ctx context.Context, w *wire.Writer, sql string) error {
	sql = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sql), ";"))
	if sql == "" {
		return c.finishMethod(w, "")
	}
	upper := strings.ToUpper(sql)
	switch {
	case strings.HasPrefix(upper, "SHOW POOLS"):
		return c.showPools(w)
	case strings.HasPrefix(upper, "SHOW DATABASES"):
		return c.showDatabases(w)
	case strings.HasPrefix(upper, "SHOW SERVERS"):
		return c.showServers(w)
	case strings.HasPrefix(upper, "SHOW STATS"), strings.HasPrefix(upper, "SHOW TOTALS"):
		return c.showStats(w)
	case strings.HasPrefix(upper, "SHOW CLIENTS"):
		return c.showClients(w)
	case strings.HasPrefix(upper, "SHOW CONFIG"):
		return c.showConfig(w)
	case strings.HasPrefix(upper, "SHOW VERSION"):
		return c.showVersion(w)
	case upper == "PAUSE":
		if err := c.reg.Pause(); err != nil {
			return c.writeErr(w, "0A000", err.Error())
		}
		return c.finishMethod(w, "PAUSE")
	case upper == "RESUME":
		if err := c.reg.Resume(); err != nil {
			return c.writeErr(w, "0A000", err.Error())
		}
		return c.finishMethod(w, "RESUME")
	case upper == "RELOAD":
		if err := c.reg.Reload(); err != nil {
			return c.writeErr(w, "0A000", err.Error())
		}
		return c.finishMethod(w, "RELOAD")
	case upper == "SHUTDOWN":
		c.reg.Shutdown()
		return c.finishMethod(w, "SHUTDOWN")
	}
	return c.writeErr(w, "42601", fmt.Sprintf("unknown admin command: %s", sql))
}

// ---- SHOW implementations ----

func (c *Console) showPools(w *wire.Writer) error {
	cols := []string{"database", "user", "server", "cl_active", "cl_waiting", "sv_active", "sv_idle", "sv_total", "pool_mode"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	for _, s := range c.reg.ListPools() {
		row := []string{
			s.Key.Database, s.Key.User, s.Key.Server,
			itoa(s.Active), itoa(s.Waiters), itoa(s.Active), itoa(s.Idle),
			i64toa(s.TotalOpen), s.PoolMode.String(),
		}
		if err := writeDataRow(w, row); err != nil {
			return err
		}
	}
	return c.finishMethod(w, "SHOW")
}

func (c *Console) showDatabases(w *wire.Writer) error {
	cols := []string{"name", "host", "port", "database", "pool_size", "pool_mode"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	cfg := c.reg.Config()
	for _, db := range cfg.Databases {
		srv := cfg.Servers[db.Primary]
		host, port := "", "0"
		if srv != nil {
			host = srv.Host
			port = itoa(srv.Port)
		}
		row := []string{db.Name, host, port, db.UpstreamName, itoa(db.PoolSize), db.PoolMode.String()}
		if err := writeDataRow(w, row); err != nil {
			return err
		}
	}
	return c.finishMethod(w, "SHOW")
}

func (c *Console) showServers(w *wire.Writer) error {
	cols := []string{"name", "host", "port", "role", "tls"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	cfg := c.reg.Config()
	for _, s := range cfg.Servers {
		role := "primary"
		if s.Role == config.RoleReplica {
			role = "replica"
		}
		tls := "off"
		if s.TLS {
			tls = "on"
		}
		row := []string{s.Name, s.Host, itoa(s.Port), role, tls}
		if err := writeDataRow(w, row); err != nil {
			return err
		}
	}
	return c.finishMethod(w, "SHOW")
}

func (c *Console) showStats(w *wire.Writer) error {
	cols := []string{"database", "total_xact_count", "total_query_count", "total_received", "total_sent", "total_query_time"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	for k, s := range c.reg.Metrics().Snapshot() {
		row := []string{k, "0", u64toa(s.QueryCount), u64toa(s.BytesIn), u64toa(s.BytesOut), u64toa(s.QueryDuration)}
		if err := writeDataRow(w, row); err != nil {
			return err
		}
	}
	return c.finishMethod(w, "SHOW")
}

func (c *Console) showClients(w *wire.Writer) error {
	cols := []string{"active_clients"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	row := []string{i64toa(c.reg.Metrics().ActiveClients.Load())}
	if err := writeDataRow(w, row); err != nil {
		return err
	}
	return c.finishMethod(w, "SHOW")
}

func (c *Console) showConfig(w *wire.Writer) error {
	cols := []string{"key", "value"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	cfg := c.reg.Config()
	entries := [][2]string{
		{"listen_addr", cfg.ListenAddr},
		{"listen_port", itoa(cfg.ListenPort)},
		{"pool_mode", cfg.DefaultPoolMode.String()},
		{"default_pool_size", itoa(cfg.DefaultPoolSize)},
		{"max_client_conn", itoa(cfg.MaxClientConn)},
		{"auth_type", authName(cfg.AuthType)},
		{"server_idle_timeout", cfg.ServerIdleTimeout.String()},
		{"server_lifetime", cfg.ServerLifetime.String()},
	}
	for _, e := range entries {
		if err := writeDataRow(w, []string{e[0], e[1]}); err != nil {
			return err
		}
	}
	return c.finishMethod(w, "SHOW")
}

func (c *Console) showVersion(w *wire.Writer) error {
	cols := []string{"version"}
	if err := writeRowDesc(w, cols); err != nil {
		return err
	}
	if err := writeDataRow(w, []string{"Poolsmith 0.1 (postgres-wire v3)"}); err != nil {
		return err
	}
	return c.finishMethod(w, "SHOW")
}

// ---- helpers ----

func writeRowDesc(w *wire.Writer, cols []string) error {
	// RowDescription: Int16(n) then n times { name C-string, tableOID Int32,
	// colAttrNum Int16, typeOID Int32, typeSize Int16, typeMod Int32,
	// format Int16 }
	var b []byte
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(cols)))
	b = append(b, n[:]...)
	for _, c := range cols {
		b = append(b, c...)
		b = append(b, 0)
		var buf [18]byte
		// tableOID=0, colAttrNum=0
		// typeOID=25 (text), typeSize=-1, typeMod=-1, format=0 (text)
		binary.BigEndian.PutUint32(buf[0:4], 0)
		binary.BigEndian.PutUint16(buf[4:6], 0)
		binary.BigEndian.PutUint32(buf[6:10], 25)
		binary.BigEndian.PutUint16(buf[10:12], uint16(0xFFFF)) // -1
		binary.BigEndian.PutUint32(buf[12:16], uint32(0xFFFFFFFF))
		binary.BigEndian.PutUint16(buf[16:18], 0)
		b = append(b, buf[:]...)
	}
	return w.WriteMessage(wire.BeRowDescription, b)
}

func writeDataRow(w *wire.Writer, values []string) error {
	var b []byte
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(values)))
	b = append(b, n[:]...)
	for _, v := range values {
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(v)))
		b = append(b, ln[:]...)
		b = append(b, v...)
	}
	return w.WriteMessage(wire.BeDataRow, b)
}

func writeCommandComplete(w *wire.Writer, tag string) error {
	body := make([]byte, 0, len(tag)+1)
	body = append(body, tag...)
	body = append(body, 0)
	return w.WriteMessage(wire.BeCommandComplete, body)
}

func writeReadyForQuery(w *wire.Writer) error {
	return w.WriteMessage(wire.BeReadyForQuery, wire.BuildReadyForQuery(wire.TxIdle))
}

func finish(w *wire.Writer, tag string) error {
	if tag != "" {
		if err := writeCommandComplete(w, tag); err != nil {
			return err
		}
	}
	if err := writeReadyForQuery(w); err != nil {
		return err
	}
	return w.Flush()
}

// finishMethod is like finish but honours Console.suppressReady so extended
// query paths can skip the trailing ReadyForQuery.
func (c *Console) finishMethod(w *wire.Writer, tag string) error {
	if tag != "" {
		if err := writeCommandComplete(w, tag); err != nil {
			return err
		}
	}
	if !c.suppressReady {
		if err := writeReadyForQuery(w); err != nil {
			return err
		}
	}
	return w.Flush()
}

func (c *Console) writeErr(w *wire.Writer, code, msg string) error {
	if err := w.WriteMessage(wire.BeErrorResponse, wire.BuildError("ERROR", code, msg)); err != nil {
		return err
	}
	return c.finishMethod(w, "")
}

func itoa(n int) string    { return fmt.Sprintf("%d", n) }
func i64toa(n int64) string  { return fmt.Sprintf("%d", n) }
func u64toa(n uint64) string { return fmt.Sprintf("%d", n) }

func authName(a config.AuthMethod) string {
	switch a {
	case config.AuthTrust:
		return "trust"
	case config.AuthPlain:
		return "plain"
	case config.AuthMD5:
		return "md5"
	case config.AuthSCRAM:
		return "scram-sha-256"
	}
	return "unknown"
}
