// Package config parses Poolsmith configuration files.
//
// The INI dialect is intentionally a superset of PgBouncer's config so that
// operators migrating from PgBouncer can drop their pgbouncer.ini in with
// minimal changes. Supported syntax:
//
//   [section]
//   key = value
//   ; comments start with semicolon or #
//   key = value with spaces   ; inline comments stripped
//   key = "quoted value with spaces = ok"
//
// Section names and keys are case-insensitive and stored lowercase.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// IniFile is a parsed INI document: map[section]map[key]value.
type IniFile map[string]map[string]string

// ParseIniFile reads and parses the file at path.
func ParseIniFile(path string) (IniFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIni(f)
}

// ParseIni parses an INI document from r.
func ParseIni(r io.Reader) (IniFile, error) {
	out := IniFile{}
	section := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		s := stripInlineComment(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if s[0] == '[' {
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, fmt.Errorf("config: line %d: unterminated section header", line)
			}
			section = strings.ToLower(strings.TrimSpace(s[1:end]))
			if _, ok := out[section]; !ok {
				out[section] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return nil, fmt.Errorf("config: line %d: expected key = value", line)
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		val := unquote(strings.TrimSpace(s[eq+1:]))
		if section == "" {
			return nil, fmt.Errorf("config: line %d: key outside of section", line)
		}
		out[section][key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// stripInlineComment removes trailing ;/# comments while honouring quoted
// strings.
func stripInlineComment(s string) string {
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQ = !inQ
			continue
		}
		if !inQ && (c == ';' || c == '#') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// Section returns the named section, or nil if absent.
func (f IniFile) Section(name string) map[string]string {
	return f[strings.ToLower(name)]
}

// Get returns section[key] or def if not present.
func (f IniFile) Get(section, key, def string) string {
	s := f.Section(section)
	if s == nil {
		return def
	}
	v, ok := s[strings.ToLower(key)]
	if !ok {
		return def
	}
	return v
}

// ErrMissing indicates a required section or key is missing.
var ErrMissing = errors.New("config: missing required setting")
