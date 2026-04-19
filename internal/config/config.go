package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PoolMode mirrors PgBouncer: session/transaction/statement.
type PoolMode int

const (
	PoolSession PoolMode = iota
	PoolTransaction
	PoolStatement
)

func (m PoolMode) String() string {
	switch m {
	case PoolSession:
		return "session"
	case PoolTransaction:
		return "transaction"
	case PoolStatement:
		return "statement"
	}
	return "unknown"
}

// ParsePoolMode accepts "session", "transaction", "statement"
// (case-insensitive).
func ParsePoolMode(s string) (PoolMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "session":
		return PoolSession, nil
	case "transaction":
		return PoolTransaction, nil
	case "statement":
		return PoolStatement, nil
	}
	return 0, fmt.Errorf("unknown pool_mode %q", s)
}

// AuthMethod describes how Poolsmith authenticates the client.
type AuthMethod int

const (
	AuthTrust AuthMethod = iota
	AuthPlain
	AuthMD5
	AuthSCRAM
)

func ParseAuthMethod(s string) (AuthMethod, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trust":
		return AuthTrust, nil
	case "plain", "password":
		return AuthPlain, nil
	case "md5":
		return AuthMD5, nil
	case "scram-sha-256", "scram":
		return AuthSCRAM, nil
	}
	return 0, fmt.Errorf("unknown auth_type %q", s)
}

// Server identifies an upstream Postgres. It can be a primary or a replica.
type Server struct {
	Name    string // logical name, e.g. "primary" or "replica_a"
	Host    string
	Port    int
	Role    ServerRole
	TLS     bool
	TLSMode string // "disable", "prefer", "require", "verify-ca", "verify-full"
}

// ServerRole indicates whether a server accepts writes or only reads.
type ServerRole int

const (
	RolePrimary ServerRole = iota
	RoleReplica
)

// Database maps a client-visible DB name to an upstream logical DB.
type Database struct {
	Name         string     // virtual name clients connect to
	UpstreamName string     // real dbname sent to Postgres (defaults to Name)
	Primary      string     // server name accepting writes
	Replicas     []string   // server names accepting reads (optional)
	PoolSize     int        // max server conns for this db (per user)
	ReservePool  int
	MinPoolSize  int
	PoolMode     PoolMode
	User         string     // optional forced auth user; if empty the client-provided user is used
}

// Config is the fully-parsed Poolsmith configuration.
type Config struct {
	// Listen / admin
	ListenAddr      string
	ListenPort      int
	AdminUsers      []string
	StatsUsers      []string

	// TLS (client-facing)
	ClientTLS     bool
	ClientTLSCert string
	ClientTLSKey  string
	ClientTLSCA   string
	ClientTLSMode string // "disable","allow","require","verify-ca","verify-full"

	// Upstream TLS defaults (can be overridden per-server)
	ServerTLSMode string

	// Auth
	AuthType    AuthMethod
	AuthFile    string // path to userlist.txt
	AuthUser    string // user with permission to look up others via auth_query
	AuthQuery   string // optional query to fetch password from DB

	// Pool defaults
	DefaultPoolMode     PoolMode
	DefaultPoolSize     int
	DefaultReservePool  int
	DefaultMinPoolSize  int

	ServerIdleTimeout   time.Duration
	ServerLifetime      time.Duration
	ServerConnectTimeout time.Duration
	ServerLoginRetry    time.Duration
	QueryTimeout        time.Duration
	QueryWaitTimeout    time.Duration
	ClientIdleTimeout   time.Duration
	ClientLoginTimeout  time.Duration

	MaxClientConn int
	MaxDbConn     int
	MaxUserConn   int

	// Application layer
	ApplicationNameAddHost bool
	TrackExtraParameters   []string

	// Logical topology
	Servers   map[string]*Server
	Databases map[string]*Database

	// Source-of-truth path for Reload
	Path string
}

// Load parses a full config file (Poolsmith INI). Unknown keys are ignored
// with a warning slot (callers may inspect Unknown via future API).
func Load(path string) (*Config, error) {
	ini, err := ParseIniFile(path)
	if err != nil {
		return nil, err
	}
	c := defaults()
	c.Path = path

	p := ini.Section("poolsmith")
	if p == nil {
		// Accept [pgbouncer] for drop-in compatibility.
		p = ini.Section("pgbouncer")
	}
	if p == nil {
		return nil, fmt.Errorf("config: missing [poolsmith] (or [pgbouncer]) section")
	}

	// Listen / admin
	c.ListenAddr = getStr(p, "listen_addr", c.ListenAddr)
	c.ListenPort = getInt(p, "listen_port", c.ListenPort)
	c.AdminUsers = splitCSV(getStr(p, "admin_users", "postgres"))
	c.StatsUsers = splitCSV(getStr(p, "stats_users", ""))

	// TLS
	c.ClientTLSMode = getStr(p, "client_tls_sslmode", c.ClientTLSMode)
	c.ClientTLSCert = getStr(p, "client_tls_cert_file", "")
	c.ClientTLSKey = getStr(p, "client_tls_key_file", "")
	c.ClientTLSCA = getStr(p, "client_tls_ca_file", "")
	c.ClientTLS = c.ClientTLSMode != "disable" && c.ClientTLSCert != ""
	c.ServerTLSMode = getStr(p, "server_tls_sslmode", c.ServerTLSMode)

	// Auth
	if v := getStr(p, "auth_type", "md5"); v != "" {
		am, err := ParseAuthMethod(v)
		if err != nil {
			return nil, err
		}
		c.AuthType = am
	}
	c.AuthFile = getStr(p, "auth_file", "")
	c.AuthUser = getStr(p, "auth_user", "")
	c.AuthQuery = getStr(p, "auth_query", "")

	// Pool defaults
	if v := getStr(p, "pool_mode", "transaction"); v != "" {
		m, err := ParsePoolMode(v)
		if err != nil {
			return nil, err
		}
		c.DefaultPoolMode = m
	}
	c.DefaultPoolSize = getInt(p, "default_pool_size", c.DefaultPoolSize)
	c.DefaultReservePool = getInt(p, "reserve_pool_size", c.DefaultReservePool)
	c.DefaultMinPoolSize = getInt(p, "min_pool_size", c.DefaultMinPoolSize)

	// Timeouts (PgBouncer uses seconds; we accept bare ints OR durations)
	c.ServerIdleTimeout = getDur(p, "server_idle_timeout", c.ServerIdleTimeout)
	c.ServerLifetime = getDur(p, "server_lifetime", c.ServerLifetime)
	c.ServerConnectTimeout = getDur(p, "server_connect_timeout", c.ServerConnectTimeout)
	c.ServerLoginRetry = getDur(p, "server_login_retry", c.ServerLoginRetry)
	c.QueryTimeout = getDur(p, "query_timeout", c.QueryTimeout)
	c.QueryWaitTimeout = getDur(p, "query_wait_timeout", c.QueryWaitTimeout)
	c.ClientIdleTimeout = getDur(p, "client_idle_timeout", c.ClientIdleTimeout)
	c.ClientLoginTimeout = getDur(p, "client_login_timeout", c.ClientLoginTimeout)

	c.MaxClientConn = getInt(p, "max_client_conn", c.MaxClientConn)
	c.MaxDbConn = getInt(p, "max_db_connections", c.MaxDbConn)
	c.MaxUserConn = getInt(p, "max_user_connections", c.MaxUserConn)

	// [servers] — map name to host:port[:role][:tls]
	if ss := ini.Section("servers"); ss != nil {
		for name, spec := range ss {
			srv, err := parseServerSpec(name, spec)
			if err != nil {
				return nil, err
			}
			c.Servers[name] = srv
		}
	}

	// [databases] — PgBouncer-style k = host=... port=... dbname=... ; extended
	// with server= and replicas= for multi-upstream topologies.
	if ds := ini.Section("databases"); ds != nil {
		for name, spec := range ds {
			db, err := parseDatabaseSpec(name, spec, c)
			if err != nil {
				return nil, err
			}
			c.Databases[name] = db
		}
	}

	if len(c.Databases) == 0 {
		return nil, fmt.Errorf("config: at least one database is required")
	}
	return c, nil
}

func defaults() *Config {
	return &Config{
		ListenAddr:           "0.0.0.0",
		ListenPort:           6432,
		ClientTLSMode:        "disable",
		ServerTLSMode:        "prefer",
		AuthType:             AuthMD5,
		DefaultPoolMode:      PoolTransaction,
		DefaultPoolSize:      20,
		DefaultReservePool:   0,
		DefaultMinPoolSize:   0,
		ServerIdleTimeout:    600 * time.Second,
		ServerLifetime:       3600 * time.Second,
		ServerConnectTimeout: 15 * time.Second,
		ServerLoginRetry:     15 * time.Second,
		QueryTimeout:         0,
		QueryWaitTimeout:     120 * time.Second,
		ClientIdleTimeout:    0,
		ClientLoginTimeout:   60 * time.Second,
		MaxClientConn:        100,
		MaxDbConn:            0,
		MaxUserConn:          0,
		Servers:              map[string]*Server{},
		Databases:            map[string]*Database{},
	}
}

func parseServerSpec(name, spec string) (*Server, error) {
	s := &Server{Name: name, Role: RolePrimary, Port: 5432, TLSMode: "prefer"}
	fields := kvList(spec)
	for k, v := range fields {
		switch k {
		case "host":
			s.Host = v
		case "port":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("server %s: port %q: %w", name, v, err)
			}
			s.Port = n
		case "role":
			switch strings.ToLower(v) {
			case "primary":
				s.Role = RolePrimary
			case "replica", "standby", "secondary":
				s.Role = RoleReplica
			default:
				return nil, fmt.Errorf("server %s: unknown role %q", name, v)
			}
		case "sslmode", "tls":
			s.TLSMode = v
			s.TLS = v != "disable"
		}
	}
	if s.Host == "" {
		// Allow shorthand "host:port"
		if strings.Contains(spec, ":") && !strings.Contains(spec, "=") {
			hp := strings.SplitN(spec, ":", 2)
			s.Host = hp[0]
			if len(hp) == 2 {
				n, err := strconv.Atoi(hp[1])
				if err != nil {
					return nil, fmt.Errorf("server %s: %w", name, err)
				}
				s.Port = n
			}
		} else {
			return nil, fmt.Errorf("server %s: host is required", name)
		}
	}
	return s, nil
}

func parseDatabaseSpec(name, spec string, c *Config) (*Database, error) {
	db := &Database{
		Name:         name,
		UpstreamName: name,
		PoolSize:     c.DefaultPoolSize,
		ReservePool:  c.DefaultReservePool,
		MinPoolSize:  c.DefaultMinPoolSize,
		PoolMode:     c.DefaultPoolMode,
	}
	fields := kvList(spec)
	// Legacy PgBouncer style: host/port/dbname inline → synthesize a Server.
	host := fields["host"]
	port := fields["port"]
	inlineServerNeeded := host != ""
	for k, v := range fields {
		switch k {
		case "server":
			db.Primary = v
		case "replicas":
			db.Replicas = splitCSV(v)
		case "dbname":
			db.UpstreamName = v
		case "user":
			db.User = v
		case "pool_mode":
			pm, err := ParsePoolMode(v)
			if err != nil {
				return nil, fmt.Errorf("database %s: %w", name, err)
			}
			db.PoolMode = pm
		case "pool_size":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("database %s: pool_size %q: %w", name, v, err)
			}
			db.PoolSize = n
		case "reserve_pool":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("database %s: reserve_pool %q: %w", name, v, err)
			}
			db.ReservePool = n
		case "min_pool_size":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("database %s: min_pool_size %q: %w", name, v, err)
			}
			db.MinPoolSize = n
		}
	}
	if inlineServerNeeded {
		// Create an implicit server named after the database.
		srvName := "_db_" + name
		p := 5432
		if port != "" {
			if n, err := strconv.Atoi(port); err == nil {
				p = n
			}
		}
		c.Servers[srvName] = &Server{Name: srvName, Host: host, Port: p, TLSMode: "prefer"}
		db.Primary = srvName
	}
	if db.Primary == "" {
		return nil, fmt.Errorf("database %s: server= is required (or inline host=)", name)
	}
	if _, ok := c.Servers[db.Primary]; !ok {
		return nil, fmt.Errorf("database %s: unknown primary server %q", name, db.Primary)
	}
	for _, r := range db.Replicas {
		if _, ok := c.Servers[r]; !ok {
			return nil, fmt.Errorf("database %s: unknown replica server %q", name, r)
		}
	}
	return db, nil
}

// kvList parses a "k=v k=v" list (whitespace-separated).
func kvList(spec string) map[string]string {
	out := map[string]string{}
	fields := strings.Fields(spec)
	for _, f := range fields {
		eq := strings.IndexByte(f, '=')
		if eq < 0 {
			continue
		}
		out[strings.ToLower(f[:eq])] = f[eq+1:]
	}
	return out
}

func getStr(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func getInt(m map[string]string, k string, def int) int {
	if v, ok := m[k]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getDur(m map[string]string, k string, def time.Duration) time.Duration {
	v, ok := m[k]
	if !ok {
		return def
	}
	// Bare int = seconds (PgBouncer convention).
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
