// Package classify inspects SQL text to decide how Poolsmith should route
// and handle a statement.
//
// Two facets are returned by Analyze:
//
//  1. Route — primary / replica / ddl
//  2. Pinning hint — whether this statement MUST pin the current client to
//     its backend for the rest of the session (DDL, LISTEN, SET, PREPARE,
//     temp tables, …)
//
// The scanner is zero-allocation, byte-level, and intentionally tolerant.
package classify

// Scanner walks an input []byte skipping comments and string/dollar-quoted
// literals. Not safe for concurrent use.
type Scanner struct {
	s   []byte
	pos int
}

func newScanner(b []byte) *Scanner { return &Scanner{s: b} }

func (z *Scanner) eof() bool          { return z.pos >= len(z.s) }
func (z *Scanner) peek() byte         { if z.pos >= len(z.s) { return 0 }; return z.s[z.pos] }
func (z *Scanner) peekAt(i int) byte  { if i < 0 || i >= len(z.s) { return 0 }; return z.s[i] }
func (z *Scanner) advance(n int)      { z.pos += n; if z.pos > len(z.s) { z.pos = len(z.s) } }

func (z *Scanner) skipSpaces() {
	for z.pos < len(z.s) {
		c := z.s[z.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			z.pos++
			continue
		}
		return
	}
}

// skipIrrelevant advances over whitespace and comments (nested blocks OK).
func (z *Scanner) skipIrrelevant() bool {
	start := z.pos
	for {
		z.skipSpaces()
		if z.eof() {
			break
		}
		c := z.s[z.pos]
		if c == '-' && z.peekAt(z.pos+1) == '-' {
			z.pos += 2
			for z.pos < len(z.s) && z.s[z.pos] != '\n' {
				z.pos++
			}
			if z.pos < len(z.s) {
				z.pos++
			}
			continue
		}
		if c == '/' && z.peekAt(z.pos+1) == '*' {
			z.pos += 2
			depth := 1
			for z.pos < len(z.s) && depth > 0 {
				if z.pos+1 < len(z.s) && z.s[z.pos] == '/' && z.s[z.pos+1] == '*' {
					z.pos += 2
					depth++
					continue
				}
				if z.pos+1 < len(z.s) && z.s[z.pos] == '*' && z.s[z.pos+1] == '/' {
					z.pos += 2
					depth--
					continue
				}
				z.pos++
			}
			continue
		}
		break
	}
	return z.pos != start
}

func (z *Scanner) atLiteralStart() bool {
	if z.eof() {
		return false
	}
	c := z.s[z.pos]
	switch c {
	case '\'', '"':
		return true
	case '$':
		_, ok := z.findDollarOpen(z.pos)
		return ok
	}
	return false
}

func (z *Scanner) skipLiteral() {
	if z.eof() {
		return
	}
	switch z.s[z.pos] {
	case '\'':
		z.pos++
		for z.pos < len(z.s) {
			c := z.s[z.pos]
			if c == '\'' {
				if z.peekAt(z.pos+1) == '\'' {
					z.pos += 2
					continue
				}
				z.pos++
				return
			}
			if c == '\\' && z.pos+1 < len(z.s) {
				z.pos += 2
				continue
			}
			z.pos++
		}
	case '"':
		z.pos++
		for z.pos < len(z.s) {
			c := z.s[z.pos]
			if c == '"' {
				if z.peekAt(z.pos+1) == '"' {
					z.pos += 2
					continue
				}
				z.pos++
				return
			}
			z.pos++
		}
	case '$':
		start := z.pos
		afterOpen, ok := z.findDollarOpen(z.pos)
		if !ok {
			z.pos++
			return
		}
		tag := z.s[start:afterOpen]
		z.pos = afterOpen
		for z.pos < len(z.s) {
			if z.s[z.pos] == '$' && z.pos+len(tag) <= len(z.s) && bytesEqual(z.s[z.pos:z.pos+len(tag)], tag) {
				z.pos += len(tag)
				return
			}
			z.pos++
		}
	}
}

func (z *Scanner) findDollarOpen(i int) (int, bool) {
	if i >= len(z.s) || z.s[i] != '$' {
		return 0, false
	}
	j := i + 1
	for j < len(z.s) {
		c := z.s[j]
		if c == '$' {
			if j == i+1 {
				return j + 1, true
			}
			if isIdentStart(z.s[i+1]) {
				ok := true
				for k := i + 2; k < j; k++ {
					if !isIdentCont(z.s[k]) {
						ok = false
						break
					}
				}
				if ok {
					return j + 1, true
				}
			}
			return 0, false
		}
		if !isIdentStart(c) && !isIdentCont(c) {
			return 0, false
		}
		j++
	}
	return 0, false
}

func (z *Scanner) readKeyword(out []byte) []byte {
	n := 0
	for z.pos < len(z.s) && n < cap(out) {
		c := z.s[z.pos]
		if !isIdentStart(c) && !isIdentCont(c) {
			break
		}
		out = append(out, asciiUpper(c))
		z.pos++
		n++
	}
	// Advance past any remaining identifier bytes beyond cap(out).
	for z.pos < len(z.s) {
		c := z.s[z.pos]
		if !isIdentStart(c) && !isIdentCont(c) {
			break
		}
		z.pos++
	}
	return out
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80
}

func isIdentCont(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

func asciiUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 32
	}
	return c
}

func kwEquals(got []byte, upper string) bool {
	if len(got) != len(upper) {
		return false
	}
	for i := 0; i < len(got); i++ {
		if asciiUpper(got[i]) != upper[i] {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
