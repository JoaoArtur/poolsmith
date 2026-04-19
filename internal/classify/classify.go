package classify

import "unsafe"

// Route is the destination a statement must be dispatched to.
type Route int

const (
	RoutePrimary Route = iota
	RouteReplica
	RouteDDL
)

// Analysis is the result of classifying one or more SQL statements.
// Pin=true means the client session MUST stick to a single backend for the
// remainder of the session (DDL, LISTEN, SET, PREPARE, temp table, etc.).
type Analysis struct {
	Route Route
	Pin   bool
}

// Analyze inspects sql and returns a routing + pinning decision.
//
// It is stateless, allocation-free on the hot path, and intentionally
// tolerant: anything it cannot classify falls back to {RoutePrimary, false}.
func Analyze(sql string) Analysis {
	if len(sql) == 0 {
		return Analysis{RoutePrimary, false}
	}
	b := stringToBytes(sql)
	var s Scanner
	s.s = b

	hintRoute, hintRouteSet, hintPin := parseHints(&s)

	result := Analysis{RoutePrimary, false}
	started := false

	for {
		s.skipIrrelevant()
		if s.eof() {
			break
		}
		if s.peek() == ';' {
			s.advance(1)
			continue
		}
		a := analyzeStatement(&s)
		// scanner is now at ';' or EOF
		if !started {
			result = a
			started = true
		} else {
			result = combine(result, a)
		}
		if !s.eof() && s.peek() == ';' {
			s.advance(1)
		}
	}

	if hintRouteSet {
		result.Route = hintRoute
	}
	if hintPin {
		result.Pin = true
	}
	return result
}

func combine(a, b Analysis) Analysis {
	r := a
	if routeStrength(b.Route) > routeStrength(a.Route) {
		r.Route = b.Route
	}
	if b.Pin {
		r.Pin = true
	}
	return r
}

func routeStrength(r Route) int {
	switch r {
	case RouteDDL:
		return 2
	case RoutePrimary:
		return 1
	default:
		return 0
	}
}

// analyzeStatement reads one statement (until ';' or EOF) and classifies it.
func analyzeStatement(s *Scanner) Analysis {
	var buf [24]byte
	verb := nextKeyword(s, buf[:0])
	if verb == nil {
		drainStatement(s)
		return Analysis{RoutePrimary, false}
	}
	return dispatch(s, verb)
}

func dispatch(s *Scanner, verb []byte) Analysis {
	switch {
	case kwEquals(verb, "SELECT"):
		return analyzeSelect(s)
	case kwEquals(verb, "TABLE"), kwEquals(verb, "VALUES"):
		drainStatement(s)
		return Analysis{RouteReplica, false}
	case kwEquals(verb, "SHOW"):
		drainStatement(s)
		return Analysis{RouteReplica, false}
	case kwEquals(verb, "WITH"):
		return analyzeWith(s)
	case kwEquals(verb, "EXPLAIN"):
		return analyzeExplain(s)
	case kwEquals(verb, "INSERT"),
		kwEquals(verb, "UPDATE"),
		kwEquals(verb, "DELETE"),
		kwEquals(verb, "MERGE"):
		drainStatement(s)
		return Analysis{RoutePrimary, false}
	case kwEquals(verb, "COPY"):
		return analyzeCopy(s)
	case kwEquals(verb, "BEGIN"),
		kwEquals(verb, "START"),
		kwEquals(verb, "COMMIT"),
		kwEquals(verb, "END"),
		kwEquals(verb, "ROLLBACK"),
		kwEquals(verb, "SAVEPOINT"),
		kwEquals(verb, "RELEASE"),
		kwEquals(verb, "ABORT"):
		drainStatement(s)
		return Analysis{RoutePrimary, false}
	case kwEquals(verb, "SET"):
		return analyzeSet(s)
	case kwEquals(verb, "LISTEN"),
		kwEquals(verb, "UNLISTEN"),
		kwEquals(verb, "NOTIFY"):
		drainStatement(s)
		return Analysis{RoutePrimary, true}
	case kwEquals(verb, "RESET"),
		kwEquals(verb, "LOCK"),
		kwEquals(verb, "PREPARE"),
		kwEquals(verb, "DEALLOCATE"),
		kwEquals(verb, "DISCARD"),
		kwEquals(verb, "DECLARE"),
		kwEquals(verb, "FETCH"),
		kwEquals(verb, "MOVE"),
		kwEquals(verb, "CLOSE"):
		drainStatement(s)
		return Analysis{RoutePrimary, true}
	case kwEquals(verb, "CREATE"):
		return analyzeCreate(s)
	case kwEquals(verb, "ALTER"),
		kwEquals(verb, "DROP"),
		kwEquals(verb, "TRUNCATE"),
		kwEquals(verb, "GRANT"),
		kwEquals(verb, "REVOKE"),
		kwEquals(verb, "CLUSTER"),
		kwEquals(verb, "REINDEX"),
		kwEquals(verb, "VACUUM"),
		kwEquals(verb, "COMMENT"),
		kwEquals(verb, "REFRESH"),
		kwEquals(verb, "IMPORT"),
		kwEquals(verb, "SECURITY"),
		kwEquals(verb, "ANALYZE"),
		kwEquals(verb, "DO"):
		drainStatement(s)
		return Analysis{RouteDDL, true}
	}
	drainStatement(s)
	return Analysis{RoutePrimary, false}
}

func analyzeSelect(s *Scanner) Analysis {
	var buf [24]byte
	route := RouteReplica
	prevIsFor := false
	sawFrom := false
	for {
		kw := nextKeyword(s, buf[:0])
		if kw == nil {
			break
		}
		if prevIsFor && (kwEquals(kw, "UPDATE") ||
			kwEquals(kw, "SHARE") ||
			kwEquals(kw, "NO") ||
			kwEquals(kw, "KEY")) {
			route = RoutePrimary
		}
		if !sawFrom && kwEquals(kw, "INTO") {
			route = RoutePrimary
		}
		if kwEquals(kw, "FROM") {
			sawFrom = true
		}
		prevIsFor = kwEquals(kw, "FOR")
	}
	return Analysis{route, false}
}

func analyzeWith(s *Scanner) Analysis {
	var buf [24]byte
	route := RouteReplica
	prevIsFor := false
	for {
		kw := nextKeyword(s, buf[:0])
		if kw == nil {
			break
		}
		if kwEquals(kw, "INSERT") ||
			kwEquals(kw, "UPDATE") ||
			kwEquals(kw, "DELETE") ||
			kwEquals(kw, "MERGE") {
			route = RoutePrimary
		}
		if prevIsFor && (kwEquals(kw, "UPDATE") ||
			kwEquals(kw, "SHARE") ||
			kwEquals(kw, "NO") ||
			kwEquals(kw, "KEY")) {
			route = RoutePrimary
		}
		prevIsFor = kwEquals(kw, "FOR")
	}
	return Analysis{route, false}
}

func analyzeExplain(s *Scanner) Analysis {
	var buf [24]byte
	var innerBuf [24]byte
	hasAnalyze := false
	var innerVerb []byte
	for {
		kw := nextKeyword(s, buf[:0])
		if kw == nil {
			break
		}
		if kwEquals(kw, "ANALYZE") {
			hasAnalyze = true
			continue
		}
		if isExplainOption(kw) {
			continue
		}
		// inner statement verb encountered
		innerVerb = append(innerBuf[:0], kw...)
		break
	}
	if !hasAnalyze {
		drainStatement(s)
		return Analysis{RouteReplica, false}
	}
	if innerVerb == nil {
		return Analysis{RouteReplica, false}
	}
	return dispatch(s, innerVerb)
}

func isExplainOption(kw []byte) bool {
	return kwEquals(kw, "VERBOSE") ||
		kwEquals(kw, "BUFFERS") ||
		kwEquals(kw, "COSTS") ||
		kwEquals(kw, "SETTINGS") ||
		kwEquals(kw, "WAL") ||
		kwEquals(kw, "TIMING") ||
		kwEquals(kw, "SUMMARY") ||
		kwEquals(kw, "FORMAT") ||
		kwEquals(kw, "GENERIC_PLAN") ||
		kwEquals(kw, "ON") ||
		kwEquals(kw, "OFF") ||
		kwEquals(kw, "TRUE") ||
		kwEquals(kw, "FALSE") ||
		kwEquals(kw, "TEXT") ||
		kwEquals(kw, "JSON") ||
		kwEquals(kw, "XML") ||
		kwEquals(kw, "YAML")
}

func analyzeCopy(s *Scanner) Analysis {
	var buf [24]byte
	for {
		kw := nextKeyword(s, buf[:0])
		if kw == nil {
			break
		}
		if kwEquals(kw, "FROM") {
			drainStatement(s)
			return Analysis{RoutePrimary, false}
		}
		if kwEquals(kw, "TO") {
			drainStatement(s)
			return Analysis{RouteReplica, false}
		}
	}
	return Analysis{RoutePrimary, false}
}

func analyzeSet(s *Scanner) Analysis {
	var buf [24]byte
	kw := nextKeyword(s, buf[:0])
	drainStatement(s)
	if kw != nil && kwEquals(kw, "LOCAL") {
		return Analysis{RoutePrimary, false}
	}
	return Analysis{RoutePrimary, true}
}

func analyzeCreate(s *Scanner) Analysis {
	var buf [24]byte
	sawTemp := false
	for {
		kw := nextKeyword(s, buf[:0])
		if kw == nil {
			break
		}
		if kwEquals(kw, "GLOBAL") || kwEquals(kw, "LOCAL") {
			continue
		}
		if kwEquals(kw, "TEMP") || kwEquals(kw, "TEMPORARY") {
			sawTemp = true
			continue
		}
		if kwEquals(kw, "TABLE") && sawTemp {
			drainStatement(s)
			return Analysis{RoutePrimary, true}
		}
		drainStatement(s)
		return Analysis{RouteDDL, true}
	}
	return Analysis{RouteDDL, true}
}

// nextKeyword advances until the next identifier keyword inside the current
// statement. Returns nil at ';' or EOF. Non-ident bytes (operators, numbers,
// punctuation) and literals are skipped. Writes the keyword (uppercased,
// truncated to cap(buf)) into buf's backing array.
func nextKeyword(s *Scanner, buf []byte) []byte {
	for {
		s.skipIrrelevant()
		if s.eof() {
			return nil
		}
		c := s.peek()
		if c == ';' {
			return nil
		}
		if c == '\'' || c == '"' {
			s.skipLiteral()
			continue
		}
		if c == '$' {
			if _, ok := s.findDollarOpen(s.pos); ok {
				s.skipLiteral()
				continue
			}
			s.advance(1)
			continue
		}
		if isIdentStart(c) {
			return s.readKeyword(buf)
		}
		s.advance(1)
	}
}

// drainStatement moves the scanner to the next ';' or EOF, honoring literals
// and comments.
func drainStatement(s *Scanner) {
	for {
		s.skipIrrelevant()
		if s.eof() {
			return
		}
		c := s.peek()
		if c == ';' {
			return
		}
		if c == '\'' || c == '"' {
			s.skipLiteral()
			continue
		}
		if c == '$' {
			if _, ok := s.findDollarOpen(s.pos); ok {
				s.skipLiteral()
				continue
			}
			s.advance(1)
			continue
		}
		if isIdentStart(c) {
			for !s.eof() && (isIdentStart(s.s[s.pos]) || isIdentCont(s.s[s.pos])) {
				s.pos++
			}
			continue
		}
		s.advance(1)
	}
}

// parseHints parses /*+ ... */ block comments (and -- line comments) that
// precede the first statement token. Returns the last route hint seen and
// whether a pin hint was present.
func parseHints(s *Scanner) (route Route, routeSet bool, pin bool) {
	for {
		s.skipSpaces()
		if s.eof() {
			return
		}
		c := s.peek()
		if c == '-' && s.peekAt(s.pos+1) == '-' {
			s.pos += 2
			for s.pos < len(s.s) && s.s[s.pos] != '\n' {
				s.pos++
			}
			if s.pos < len(s.s) {
				s.pos++
			}
			continue
		}
		if c != '/' || s.peekAt(s.pos+1) != '*' {
			return
		}
		bodyStart := s.pos + 2
		isHint := bodyStart < len(s.s) && s.s[bodyStart] == '+'
		if isHint {
			bodyStart++
		}
		s.pos += 2
		depth := 1
		for s.pos < len(s.s) && depth > 0 {
			if s.pos+1 < len(s.s) && s.s[s.pos] == '/' && s.s[s.pos+1] == '*' {
				s.pos += 2
				depth++
				continue
			}
			if s.pos+1 < len(s.s) && s.s[s.pos] == '*' && s.s[s.pos+1] == '/' {
				s.pos += 2
				depth--
				if depth == 0 {
					break
				}
				continue
			}
			s.pos++
		}
		if isHint {
			bodyEnd := s.pos - 2
			if bodyEnd < bodyStart {
				bodyEnd = bodyStart
			}
			r, rSet, p := parseHintBody(s.s[bodyStart:bodyEnd])
			if rSet {
				route = r
				routeSet = true
			}
			if p {
				pin = true
			}
		}
	}
}

func parseHintBody(content []byte) (route Route, routeSet bool, pin bool) {
	i := 0
	for i < len(content) {
		c := content[i]
		if isHintSep(c) {
			i++
			continue
		}
		j := i
		for j < len(content) && !isHintSep(content[j]) {
			j++
		}
		word := content[i:j]
		switch {
		case asciiEqFold(word, "primary"):
			route, routeSet = RoutePrimary, true
		case asciiEqFold(word, "replica"):
			route, routeSet = RouteReplica, true
		case asciiEqFold(word, "ddl"):
			route, routeSet = RouteDDL, true
		case asciiEqFold(word, "pin"):
			pin = true
		}
		i = j
	}
	return
}

func isHintSep(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' || c == '\f' || c == '\v'
}

func asciiEqFold(a []byte, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x := a[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if x != b[i] {
			return false
		}
	}
	return true
}

// stringToBytes aliases a string as a []byte without allocation.
// The returned slice must not be mutated.
func stringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
