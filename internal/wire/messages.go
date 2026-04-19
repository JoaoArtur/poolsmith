package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// ----------------------------------------------------------------------------
// Startup messages (untyped)
// ----------------------------------------------------------------------------

// StartupParams is the key/value list sent by a client after the protocol
// version in a StartupMessage.
type StartupParams struct {
	Version uint32
	Params  map[string]string
}

// ParseStartup decodes the body of an untyped startup message (body starts
// at the version int32). It dispatches on the version code.
//
// Returns the decoded params if Version == ProtocolV3; otherwise returns a
// StartupParams with Version set and Params nil so the caller can react to
// SSLRequest / CancelRequest / GSSENCRequest specially.
func ParseStartup(body []byte) (StartupParams, error) {
	if len(body) < 4 {
		return StartupParams{}, ErrShortRead
	}
	v := binary.BigEndian.Uint32(body[:4])
	sp := StartupParams{Version: v}
	if v != ProtocolV3 {
		// SSLRequest, CancelRequest, GSSENCRequest, or a future protocol.
		return sp, nil
	}
	sp.Params = map[string]string{}
	rest := body[4:]
	for len(rest) > 0 && rest[0] != 0 {
		k, r, err := readCString(rest)
		if err != nil {
			return sp, err
		}
		if len(r) == 0 {
			return sp, fmt.Errorf("wire: startup param %q has no value", k)
		}
		v, r2, err := readCString(r)
		if err != nil {
			return sp, err
		}
		sp.Params[k] = v
		rest = r2
	}
	return sp, nil
}

// BuildStartup encodes a StartupMessage body for an upstream connection.
// Callers pass it to Writer.WriteStartup.
func BuildStartup(params map[string]string) []byte {
	var b bytes.Buffer
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], ProtocolV3)
	b.Write(ver[:])
	for k, v := range params {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(v)
		b.WriteByte(0)
	}
	b.WriteByte(0) // terminating null
	return b.Bytes()
}

// CancelRequest body.
func BuildCancelRequest(pid, secret uint32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[0:], CancelRequestCode)
	binary.BigEndian.PutUint32(b[4:], pid)
	binary.BigEndian.PutUint32(b[8:], secret)
	return b
}

// ----------------------------------------------------------------------------
// Authentication ('R')
// ----------------------------------------------------------------------------

// AuthMessage is a parsed AuthenticationXxx backend message.
type AuthMessage struct {
	Sub  uint32 // AuthOK, AuthMD5Password, AuthSASL, …
	Data []byte // sub-specific payload (salt, SASL mechanisms, SCRAM blobs, …)
}

// ParseAuth parses a Message whose Type == 'R'.
func ParseAuth(body []byte) (AuthMessage, error) {
	if len(body) < 4 {
		return AuthMessage{}, ErrShortRead
	}
	return AuthMessage{
		Sub:  binary.BigEndian.Uint32(body[:4]),
		Data: body[4:],
	}, nil
}

// BuildAuthOK returns the body of an AuthenticationOk message.
func BuildAuthOK() []byte {
	b := make([]byte, 4)
	// all zeros = AuthOK
	return b
}

// BuildAuthMD5 returns the body of an AuthenticationMD5Password message with
// the given 4-byte salt.
func BuildAuthMD5(salt [4]byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], 5)
	copy(b[4:], salt[:])
	return b
}

// BuildAuthCleartext returns the body of AuthenticationCleartextPassword.
func BuildAuthCleartext() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 3)
	return b
}

// BuildAuthSASL returns the body of AuthenticationSASL with the given list
// of mechanism names.
func BuildAuthSASL(mechs ...string) []byte {
	var b bytes.Buffer
	var code [4]byte
	binary.BigEndian.PutUint32(code[:], 10)
	b.Write(code[:])
	for _, m := range mechs {
		b.WriteString(m)
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return b.Bytes()
}

// BuildAuthSASLContinue returns the body of AuthenticationSASLContinue.
func BuildAuthSASLContinue(data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(b[:4], 11)
	copy(b[4:], data)
	return b
}

// BuildAuthSASLFinal returns the body of AuthenticationSASLFinal.
func BuildAuthSASLFinal(data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(b[:4], 12)
	copy(b[4:], data)
	return b
}

// ----------------------------------------------------------------------------
// Password / SASL response (frontend, tag 'p')
// ----------------------------------------------------------------------------

// ParsePasswordMessage treats the body as a NUL-terminated C string
// (used for plain and MD5 passwords).
func ParsePasswordMessage(body []byte) (string, error) {
	if len(body) == 0 {
		return "", ErrShortRead
	}
	s, _, err := readCString(body)
	return s, err
}

// ParseSASLInitialResponse decodes a frontend SASLInitialResponse body:
// [mechanism name C-string][len int32][response bytes].
func ParseSASLInitialResponse(body []byte) (mech string, response []byte, err error) {
	mech, rest, err := readCString(body)
	if err != nil {
		return "", nil, err
	}
	if len(rest) < 4 {
		return "", nil, ErrShortRead
	}
	ln := int32(binary.BigEndian.Uint32(rest[:4]))
	rest = rest[4:]
	if ln < 0 {
		return mech, nil, nil
	}
	if int(ln) > len(rest) {
		return "", nil, ErrShortRead
	}
	return mech, rest[:ln], nil
}

// BuildSASLInitialResponse encodes the frontend body.
func BuildSASLInitialResponse(mech string, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString(mech)
	b.WriteByte(0)
	var ln [4]byte
	if data == nil {
		binary.BigEndian.PutUint32(ln[:], ^uint32(0)) // -1
	} else {
		binary.BigEndian.PutUint32(ln[:], uint32(len(data)))
	}
	b.Write(ln[:])
	b.Write(data)
	return b.Bytes()
}

// BuildSASLResponse encodes a subsequent SASL response (just raw bytes in
// the body).
func BuildSASLResponse(data []byte) []byte { return append([]byte(nil), data...) }

// ----------------------------------------------------------------------------
// ErrorResponse / NoticeResponse ('E'/'N')
// ----------------------------------------------------------------------------

// ErrorField represents a single typed field inside ErrorResponse.
type ErrorField struct {
	Code  byte
	Value string
}

// Fatal / Error codes commonly used by Poolsmith internally.
const (
	EFSeverity     = 'S' // localized severity
	EFSeverityV    = 'V' // machine-readable severity (PG ≥ 9.6)
	EFCode         = 'C' // SQLSTATE
	EFMessage      = 'M'
	EFDetail       = 'D'
	EFHint         = 'H'
	EFPosition     = 'P'
	EFInternalPos  = 'p'
	EFInternalQ    = 'q'
	EFWhere        = 'W'
	EFSchemaName   = 's'
	EFTableName    = 't'
	EFColumnName   = 'c'
	EFDataTypeName = 'd'
	EFConstraint   = 'n'
	EFFile         = 'F'
	EFLine         = 'L'
	EFRoutine      = 'R'
)

// BuildError returns the body of an ErrorResponse. Use WriteMessage with
// type 'E'.
func BuildError(severity, code, msg string, extra ...ErrorField) []byte {
	var b bytes.Buffer
	for _, f := range []ErrorField{
		{Code: EFSeverity, Value: severity},
		{Code: EFSeverityV, Value: severity},
		{Code: EFCode, Value: code},
		{Code: EFMessage, Value: msg},
	} {
		if f.Value == "" {
			continue
		}
		b.WriteByte(f.Code)
		b.WriteString(f.Value)
		b.WriteByte(0)
	}
	for _, f := range extra {
		if f.Value == "" {
			continue
		}
		b.WriteByte(f.Code)
		b.WriteString(f.Value)
		b.WriteByte(0)
	}
	b.WriteByte(0) // terminating null
	return b.Bytes()
}

// ParseErrorFields parses the body of 'E' or 'N' into a slice of fields.
// It is tolerant of missing trailing NUL bytes.
func ParseErrorFields(body []byte) []ErrorField {
	out := make([]ErrorField, 0, 4)
	for len(body) > 0 && body[0] != 0 {
		code := body[0]
		body = body[1:]
		v, rest, err := readCString(body)
		if err != nil {
			break
		}
		out = append(out, ErrorField{Code: code, Value: v})
		body = rest
	}
	return out
}

// ----------------------------------------------------------------------------
// ReadyForQuery ('Z')
// ----------------------------------------------------------------------------

// ParseReadyForQuery returns the transaction status byte.
func ParseReadyForQuery(body []byte) (byte, error) {
	if len(body) < 1 {
		return 0, ErrShortRead
	}
	return body[0], nil
}

// BuildReadyForQuery returns a 1-byte body for ReadyForQuery.
func BuildReadyForQuery(status byte) []byte { return []byte{status} }

// ----------------------------------------------------------------------------
// ParameterStatus ('S') / BackendKeyData ('K')
// ----------------------------------------------------------------------------

// ParseParameterStatus decodes a ParameterStatus message body.
func ParseParameterStatus(body []byte) (name, value string, err error) {
	name, rest, err := readCString(body)
	if err != nil {
		return "", "", err
	}
	value, _, err = readCString(rest)
	return
}

// BuildParameterStatus encodes a ParameterStatus body.
func BuildParameterStatus(name, value string) []byte {
	var b bytes.Buffer
	b.WriteString(name)
	b.WriteByte(0)
	b.WriteString(value)
	b.WriteByte(0)
	return b.Bytes()
}

// BackendKey is the (pid, secret) pair used for query cancellation.
type BackendKey struct {
	PID    uint32
	Secret uint32
}

// ParseBackendKeyData decodes a 'K' message body.
func ParseBackendKeyData(body []byte) (BackendKey, error) {
	if len(body) < 8 {
		return BackendKey{}, ErrShortRead
	}
	return BackendKey{
		PID:    binary.BigEndian.Uint32(body[0:4]),
		Secret: binary.BigEndian.Uint32(body[4:8]),
	}, nil
}

// BuildBackendKeyData encodes a 'K' body.
func BuildBackendKeyData(k BackendKey) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], k.PID)
	binary.BigEndian.PutUint32(b[4:8], k.Secret)
	return b
}

// ----------------------------------------------------------------------------
// Simple Query ('Q')
// ----------------------------------------------------------------------------

// ParseQuery reads the SQL text of a Query message (NUL-terminated).
func ParseQuery(body []byte) (string, error) {
	s, _, err := readCString(body)
	return s, err
}

// BuildQuery encodes a Query body.
func BuildQuery(sql string) []byte {
	b := make([]byte, 0, len(sql)+1)
	b = append(b, sql...)
	b = append(b, 0)
	return b
}

// ----------------------------------------------------------------------------
// Extended Query: Parse/Bind/Describe/Execute/Close
// ----------------------------------------------------------------------------

// ParseParseMessage decodes a 'P' Parse body.
// Layout: [stmt C-string][query C-string][n int16][n * oid int32]
func ParseParseMessage(body []byte) (stmtName, query string, paramOIDs []uint32, err error) {
	stmtName, rest, err := readCString(body)
	if err != nil {
		return
	}
	query, rest, err = readCString(rest)
	if err != nil {
		return
	}
	if len(rest) < 2 {
		err = ErrShortRead
		return
	}
	n := binary.BigEndian.Uint16(rest[:2])
	rest = rest[2:]
	if len(rest) < 4*int(n) {
		err = ErrShortRead
		return
	}
	paramOIDs = make([]uint32, n)
	for i := 0; i < int(n); i++ {
		paramOIDs[i] = binary.BigEndian.Uint32(rest[i*4 : i*4+4])
	}
	return
}

// BuildParseMessage encodes a 'P' body.
func BuildParseMessage(stmtName, query string, paramOIDs []uint32) []byte {
	var b bytes.Buffer
	b.WriteString(stmtName)
	b.WriteByte(0)
	b.WriteString(query)
	b.WriteByte(0)
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(paramOIDs)))
	b.Write(n[:])
	var ob [4]byte
	for _, o := range paramOIDs {
		binary.BigEndian.PutUint32(ob[:], o)
		b.Write(ob[:])
	}
	return b.Bytes()
}

// ParseCloseMessage decodes a Close ('C') body: [kind byte]['S'|'P'][name C-string].
func ParseCloseMessage(body []byte) (kind byte, name string, err error) {
	if len(body) < 1 {
		return 0, "", ErrShortRead
	}
	kind = body[0]
	name, _, err = readCString(body[1:])
	return
}

// ParseDescribeMessage decodes Describe ('D'). Same layout as Close.
func ParseDescribeMessage(body []byte) (kind byte, name string, err error) {
	return ParseCloseMessage(body)
}

// ParseBindStmt extracts the destination portal and source statement names
// from a Bind ('B') message body. Full Bind parsing is not needed by the
// proxy — only these two fields matter for prepared-statement routing.
func ParseBindStmt(body []byte) (portal, stmt string, err error) {
	portal, rest, err := readCString(body)
	if err != nil {
		return
	}
	stmt, _, err = readCString(rest)
	return
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func readCString(b []byte) (string, []byte, error) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, ErrShortRead
	}
	return string(b[:i]), b[i+1:], nil
}

// FormatError formats a parsed ErrorResponse for log output.
func FormatError(fields []ErrorField) string {
	var sev, code, msg string
	for _, f := range fields {
		switch f.Code {
		case EFSeverityV, EFSeverity:
			if sev == "" {
				sev = f.Value
			}
		case EFCode:
			code = f.Value
		case EFMessage:
			msg = f.Value
		}
	}
	if code == "" && msg == "" {
		return fmt.Sprintf("error fields: %+v", fields)
	}
	return fmt.Sprintf("%s %s: %s", sev, code, msg)
}

// ErrProtocolViolation indicates the peer sent something unexpected.
var ErrProtocolViolation = errors.New("wire: protocol violation")
