// Package prepared implements transparent prepared-statement translation for
// transaction-mode pooling.
//
// Problem: a client may send Parse("stmt1", "SELECT …") and later
// Bind("", "stmt1", …) on a backend it borrowed for just one transaction.
// In transaction-mode pooling the next transaction may land on a different
// backend that never saw stmt1 → execution fails.
//
// Poolsmith solves this the way PgBouncer 1.21+ does: it keeps a per-client
// map of {client stmt name → hash(query text)} and a per-backend set of
// hashes the backend has actually parsed. When forwarding a Bind/Execute/
// Describe/Close for a client statement, the translator:
//
//  1. Rewrites the statement name to a canonical hash-based name.
//  2. If the target backend has not parsed that canonical name yet, injects
//     a Parse(canonical, text) ahead of the user's Bind.
//  3. If the client Close('S', "stmt1") would orphan a canonical name on the
//     backend, defer the backend-side Close until the client disconnects.
//
// Bytes on the wire look like normal extended-query traffic; the client
// never knows the name was rewritten.
package prepared

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// ClientRegistry tracks prepared statements named by a single client.
// Safe for concurrent use by the one session goroutine.
type ClientRegistry struct {
	mu sync.Mutex
	// clientName → entry
	byName map[string]*Entry
}

// Entry is the metadata kept for a client-named prepared statement.
type Entry struct {
	ClientName    string
	CanonicalName string // "_pm_" + hex(fnv64a(query||oids))
	Query         string
	ParamOIDs     []uint32
}

// NewClientRegistry returns an empty registry.
func NewClientRegistry() *ClientRegistry {
	return &ClientRegistry{byName: map[string]*Entry{}}
}

// OnParse records a Parse the client just sent and returns a rewritten Parse
// message body targeting the canonical name. The caller forwards this
// rewritten body instead of the original.
//
// If stmt name is "" (unnamed), OnParse returns the original body unchanged —
// unnamed statements do not need rewriting because the backend forgets them
// at Sync.
func (r *ClientRegistry) OnParse(body []byte) (rewritten []byte, e *Entry, err error) {
	name, query, oids, err := wire.ParseParseMessage(body)
	if err != nil {
		return nil, nil, err
	}
	if name == "" {
		return body, nil, nil
	}
	canon := canonicalName(query, oids)
	ent := &Entry{ClientName: name, CanonicalName: canon, Query: query, ParamOIDs: oids}
	r.mu.Lock()
	r.byName[name] = ent
	r.mu.Unlock()
	return wire.BuildParseMessage(canon, query, oids), ent, nil
}

// OnBind rewrites a Bind body's source-statement field to the canonical
// name. Returns (nil, nil) if the statement name is unknown — the caller
// should forward untouched and let Postgres error.
func (r *ClientRegistry) OnBind(body []byte) ([]byte, *Entry, error) {
	portal, stmt, err := wire.ParseBindStmt(body)
	if err != nil {
		return nil, nil, err
	}
	if stmt == "" {
		return body, nil, nil
	}
	r.mu.Lock()
	ent := r.byName[stmt]
	r.mu.Unlock()
	if ent == nil {
		return body, nil, nil
	}
	return rewriteBindSourceName(body, portal, ent.CanonicalName), ent, nil
}

// OnDescribeOrClose rewrites Describe('S', name) / Close('S', name) bodies
// to refer to the canonical name. For Close('S', …) the caller should NOT
// forward the message to the backend (the canonical name stays cached);
// the registry returns remove=true so the caller knows to drop the client
// entry and synthesize a CloseComplete back to the client.
func (r *ClientRegistry) OnDescribeOrClose(body []byte) (rewritten []byte, remove bool, err error) {
	if len(body) < 1 {
		return nil, false, wire.ErrShortRead
	}
	kind := body[0]
	name, _, err := readCString(body[1:])
	if err != nil {
		return nil, false, err
	}
	if kind != 'S' || name == "" {
		return body, false, nil
	}
	r.mu.Lock()
	ent := r.byName[name]
	r.mu.Unlock()
	if ent == nil {
		return body, false, nil
	}
	return buildNamedDC(kind, ent.CanonicalName), false, nil
}

// Lookup returns the Entry for a client statement name, or nil.
func (r *ClientRegistry) Lookup(clientName string) *Entry {
	if clientName == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byName[clientName]
}

// ForgetClient frees the registry (called on client disconnect).
func (r *ClientRegistry) ForgetClient() {
	r.mu.Lock()
	r.byName = map[string]*Entry{}
	r.mu.Unlock()
}

// BackendSet tracks which canonical names have been Parse'd on one backend.
// Shared between proxy and pool — protected internally.
type BackendSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

// NewBackendSet returns an empty set.
func NewBackendSet() *BackendSet {
	return &BackendSet{m: map[string]struct{}{}}
}

// Has reports whether the canonical name has already been Parse'd on this
// backend.
func (s *BackendSet) Has(canon string) bool {
	s.mu.Lock()
	_, ok := s.m[canon]
	s.mu.Unlock()
	return ok
}

// Add records that canonical name was Parse'd.
func (s *BackendSet) Add(canon string) {
	s.mu.Lock()
	s.m[canon] = struct{}{}
	s.mu.Unlock()
}

// Clear resets the set (e.g. when the backend resets).
func (s *BackendSet) Clear() {
	s.mu.Lock()
	s.m = map[string]struct{}{}
	s.mu.Unlock()
}

// ---- helpers ----

// canonicalName derives a stable, server-valid name from the query text.
func canonicalName(query string, oids []uint32) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(query))
	var buf [4]byte
	for _, o := range oids {
		binary.BigEndian.PutUint32(buf[:], o)
		_, _ = h.Write(buf[:])
	}
	return fmt.Sprintf("_pm_%016x", h.Sum64())
}

// rewriteBindSourceName replaces the statement name field in a Bind body.
// Bind layout: [portal C-string][stmt C-string][rest …]
func rewriteBindSourceName(body []byte, portal, newStmt string) []byte {
	// Find the end of the two leading C-strings.
	pEnd := indexNul(body, 0)
	if pEnd < 0 {
		return body
	}
	sEnd := indexNul(body, pEnd+1)
	if sEnd < 0 {
		return body
	}
	rest := body[sEnd+1:]
	out := make([]byte, 0, len(portal)+1+len(newStmt)+1+len(rest))
	out = append(out, portal...)
	out = append(out, 0)
	out = append(out, newStmt...)
	out = append(out, 0)
	out = append(out, rest...)
	return out
}

// buildNamedDC builds the body of a Describe or Close targeting a named
// statement.
func buildNamedDC(kind byte, name string) []byte {
	out := make([]byte, 0, 2+len(name))
	out = append(out, kind)
	out = append(out, name...)
	out = append(out, 0)
	return out
}

func indexNul(b []byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == 0 {
			return i
		}
	}
	return -1
}

func readCString(b []byte) (string, []byte, error) {
	i := indexNul(b, 0)
	if i < 0 {
		return "", nil, wire.ErrShortRead
	}
	return string(b[:i]), b[i+1:], nil
}
