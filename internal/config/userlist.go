package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Userlist holds username → password mappings used to authenticate clients
// against Poolsmith AND to authenticate Poolsmith against upstream Postgres.
//
// File format (PgBouncer-compatible raw text):
//
//	"alice" "s3cr3t"
//	"bob"   "plain"
//
// A SCRAM verifier (SCRAM-SHA-256$<iter>:<salt>$<storedKey>:<serverKey>) is
// also accepted as the password value; callers identify the form from the
// leading "SCRAM-SHA-256$" prefix.
//
// Userlist is safe for concurrent use; it can be Reload()-ed at runtime.
type Userlist struct {
	path string
	mu   sync.RWMutex
	m    map[string]string
}

// NewUserlist returns an empty in-memory Userlist (useful for tests).
func NewUserlist() *Userlist { return &Userlist{m: map[string]string{}} }

// LoadUserlist parses path and returns a Userlist. Call Reload to refresh.
func LoadUserlist(path string) (*Userlist, error) {
	ul := &Userlist{path: path, m: map[string]string{}}
	if err := ul.Reload(); err != nil {
		return nil, err
	}
	return ul, nil
}

// Reload re-reads the file from disk atomically.
func (u *Userlist) Reload() error {
	if u.path == "" {
		return nil
	}
	f, err := os.Open(u.path)
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := parseUserlist(f)
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.m = m
	u.mu.Unlock()
	return nil
}

// Lookup returns the stored password/verifier for user.
func (u *Userlist) Lookup(user string) (string, bool) {
	u.mu.RLock()
	p, ok := u.m[user]
	u.mu.RUnlock()
	return p, ok
}

// Set adds or replaces an entry (in-memory only).
func (u *Userlist) Set(user, pw string) {
	u.mu.Lock()
	u.m[user] = pw
	u.mu.Unlock()
}

// Len returns the number of entries.
func (u *Userlist) Len() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.m)
}

func parseUserlist(r io.Reader) (map[string]string, error) {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || raw[0] == ';' || raw[0] == '#' {
			continue
		}
		u, pw, err := splitUserLine(raw)
		if err != nil {
			return nil, fmt.Errorf("userlist: line %d: %w", line, err)
		}
		m[u] = pw
	}
	return m, sc.Err()
}

// splitUserLine parses `"user" "password"` tolerating unquoted single tokens.
func splitUserLine(s string) (user, pw string, err error) {
	i := 0
	user, i, err = readToken(s, i)
	if err != nil {
		return
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	pw, _, err = readToken(s, i)
	return
}

func readToken(s string, i int) (string, int, error) {
	if i >= len(s) {
		return "", i, fmt.Errorf("unexpected end of line")
	}
	if s[i] == '"' {
		j := i + 1
		var b strings.Builder
		for j < len(s) {
			c := s[j]
			if c == '\\' && j+1 < len(s) {
				b.WriteByte(s[j+1])
				j += 2
				continue
			}
			if c == '"' {
				return b.String(), j + 1, nil
			}
			b.WriteByte(c)
			j++
		}
		return "", i, fmt.Errorf("unterminated quoted string")
	}
	// Bare token up to whitespace
	j := i
	for j < len(s) && s[j] != ' ' && s[j] != '\t' {
		j++
	}
	return s[i:j], j, nil
}
