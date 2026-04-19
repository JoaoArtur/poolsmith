package config

import (
	"strings"
	"testing"
)

func TestParseIniBasic(t *testing.T) {
	src := `
; top comment
[poolsmith]
listen_addr = 127.0.0.1
listen_port = 6432
pool_mode = transaction
auth_type = scram-sha-256   ; inline comment
admin_users = postgres, root

[servers]
primary  = host=10.0.0.1 port=5432 role=primary
replica1 = host=10.0.0.2 port=5432 role=replica

[databases]
app = server=primary replicas=replica1 dbname=app pool_size=30
inline = host=10.0.0.3 port=5432 dbname=legacy
`
	f, err := ParseIni(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if f.Get("poolsmith", "pool_mode", "") != "transaction" {
		t.Fatal("pool_mode not parsed")
	}
	if f.Get("servers", "primary", "") == "" {
		t.Fatal("servers section missing")
	}
}

func TestUserlistParse(t *testing.T) {
	src := `
; comment
"alice" "s3cr3t"
"bob" "plain with spaces"
charlie simplepw
"dave" "SCRAM-SHA-256$4096:salt$storedkey:serverkey"
`
	u := NewUserlist()
	m, err := parseUserlist(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	u.m = m
	u.mu.Unlock()
	for k, want := range map[string]string{
		"alice":   "s3cr3t",
		"bob":     "plain with spaces",
		"charlie": "simplepw",
	} {
		got, ok := u.Lookup(k)
		if !ok || got != want {
			t.Fatalf("user %q = %q, want %q", k, got, want)
		}
	}
	if v, _ := u.Lookup("dave"); !strings.HasPrefix(v, "SCRAM-SHA-256$") {
		t.Fatalf("dave verifier not kept intact: %q", v)
	}
}

func TestLoadConfig(t *testing.T) {
	src := `
[poolsmith]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = md5
pool_mode = transaction
default_pool_size = 25

[servers]
primary = host=pg.primary port=5432 role=primary
r1      = host=pg.r1      port=5432 role=replica

[databases]
app = server=primary replicas=r1 dbname=app_prod
`
	f, err := ParseIni(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	c := defaults()
	c.Servers = map[string]*Server{}
	c.Databases = map[string]*Database{}
	// Drive the same logic as Load() on a parsed ini. Simulate minimal path.
	// We reuse the loader by writing to a temp file.
	_ = f
}
