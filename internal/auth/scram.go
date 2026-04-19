package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/poolsmith/poolsmith/internal/wire"
)

const (
	scramMechanism = "SCRAM-SHA-256"
	scramIterCount = 4096
	// base64("n,,") — the channel-binding header echoed by the client in
	// the client-final-message when no channel binding is in use.
	scramCBindFlagB64 = "biws"
)

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

// pbkdf2HMACSHA256 implements RFC 2898 PBKDF2 with HMAC-SHA-256 and a fixed
// 32-byte output. Using the single-block form keeps the implementation small.
func pbkdf2HMACSHA256(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := make([]byte, len(u))
	copy(out, u)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func sha256Sum(msg []byte) []byte {
	s := sha256.Sum256(msg)
	return s[:]
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor length mismatch")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// scramKeys derives the SCRAM key material from a plain password plus salt.
func scramKeys(password string, salt []byte, iter int) (saltedPassword, clientKey, storedKey, serverKey []byte) {
	saltedPassword = pbkdf2HMACSHA256([]byte(password), salt, iter)
	clientKey = hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey = sha256Sum(clientKey)
	serverKey = hmacSHA256(saltedPassword, []byte("Server Key"))
	return
}

// ---------------------------------------------------------------------------
// Message parsing
// ---------------------------------------------------------------------------

// parseAttrList splits "a=v,b=v,..." and returns a map of single-letter keys.
// Duplicates keep the first occurrence.
func parseAttrList(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if len(part) < 2 || part[1] != '=' {
			continue
		}
		k := string(part[0])
		if _, ok := out[k]; !ok {
			out[k] = part[2:]
		}
	}
	return out
}

// parseClientFirst decodes a client-first-message.
// Returns the bare (attribute) portion and the attribute map.
func parseClientFirst(s string) (bare string, attrs map[string]string, err error) {
	// gs2-header: gs2-cbind-flag "," [authzid] ","
	if len(s) < 3 {
		return "", nil, fmt.Errorf("scram: client-first too short")
	}
	if s[0] != 'n' && s[0] != 'y' && s[0] != 'p' {
		return "", nil, fmt.Errorf("scram: invalid gs2 cbind flag %q", s[0])
	}
	// Expect "<flag>,<authzid>," prefix.
	i := strings.Index(s, ",")
	if i < 0 {
		return "", nil, fmt.Errorf("scram: malformed gs2 header")
	}
	rest := s[i+1:]
	j := strings.Index(rest, ",")
	if j < 0 {
		return "", nil, fmt.Errorf("scram: malformed gs2 header")
	}
	bare = rest[j+1:]
	attrs = parseAttrList(bare)
	if _, ok := attrs["n"]; !ok {
		return "", nil, fmt.Errorf("scram: missing username (n=)")
	}
	if _, ok := attrs["r"]; !ok {
		return "", nil, fmt.Errorf("scram: missing nonce (r=)")
	}
	return bare, attrs, nil
}

// parseClientFinal returns (withoutProof, attrs).
func parseClientFinal(s string) (withoutProof string, attrs map[string]string, err error) {
	attrs = parseAttrList(s)
	if _, ok := attrs["c"]; !ok {
		return "", nil, fmt.Errorf("scram: missing channel binding (c=)")
	}
	if _, ok := attrs["r"]; !ok {
		return "", nil, fmt.Errorf("scram: missing nonce (r=)")
	}
	if _, ok := attrs["p"]; !ok {
		return "", nil, fmt.Errorf("scram: missing proof (p=)")
	}
	idx := strings.LastIndex(s, ",p=")
	if idx < 0 {
		return "", nil, fmt.Errorf("scram: malformed client-final")
	}
	withoutProof = s[:idx]
	return withoutProof, attrs, nil
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// ServerAuthSCRAM runs a SCRAM-SHA-256 exchange as the authenticator against
// a PostgreSQL client. storedPassword is the plain-text secret.
func ServerAuthSCRAM(r *wire.Reader, w *wire.Writer, user, storedPassword string) error {
	// Advertise the mechanism.
	if err := w.WriteMessage(wire.BeAuthentication, wire.BuildAuthSASL(scramMechanism)); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Read SASLInitialResponse (frontend 'p').
	msg, err := r.ReadMessage()
	if err != nil {
		return err
	}
	if msg.Type != wire.FeSASLInitial {
		sendAuthError(w, "expected SASLInitialResponse")
		return fmt.Errorf("scram: expected SASLInitialResponse, got %q", msg.Type)
	}
	mech, initial, err := wire.ParseSASLInitialResponse(msg.Body)
	if err != nil {
		return err
	}
	if mech != scramMechanism {
		sendAuthError(w, "unsupported SASL mechanism")
		return fmt.Errorf("scram: unsupported mechanism %q", mech)
	}
	clientFirst := string(initial)
	clientFirstBare, cfAttrs, err := parseClientFirst(clientFirst)
	if err != nil {
		sendAuthError(w, "invalid client-first-message")
		return err
	}
	clientNonce := cfAttrs["r"]

	// Generate server nonce + salt.
	var srvRaw [18]byte
	if _, err := rand.Read(srvRaw[:]); err != nil {
		return err
	}
	serverNonce := base64.StdEncoding.EncodeToString(srvRaw[:])
	combinedNonce := clientNonce + serverNonce

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	serverFirst := "r=" + combinedNonce + ",s=" + saltB64 + ",i=" + strconv.Itoa(scramIterCount)
	if err := w.WriteMessage(wire.BeAuthentication, wire.BuildAuthSASLContinue([]byte(serverFirst))); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Read client-final ('p').
	msg, err = r.ReadMessage()
	if err != nil {
		return err
	}
	if msg.Type != wire.FeSASLResponse {
		sendAuthError(w, "expected SASLResponse")
		return fmt.Errorf("scram: expected SASLResponse, got %q", msg.Type)
	}
	clientFinal := string(msg.Body)
	cfwp, fAttrs, err := parseClientFinal(clientFinal)
	if err != nil {
		sendAuthError(w, "invalid client-final-message")
		return err
	}
	if fAttrs["c"] != scramCBindFlagB64 {
		sendAuthError(w, "channel binding mismatch")
		return fmt.Errorf("scram: unexpected channel-binding %q", fAttrs["c"])
	}
	if fAttrs["r"] != combinedNonce {
		sendAuthError(w, "nonce mismatch")
		return fmt.Errorf("scram: nonce mismatch")
	}
	proof, err := base64.StdEncoding.DecodeString(fAttrs["p"])
	if err != nil || len(proof) != sha256.Size {
		sendAuthError(w, "invalid client proof")
		return fmt.Errorf("scram: invalid proof")
	}

	_, _, storedKey, serverKey := scramKeys(storedPassword, salt, scramIterCount)
	authMessage := clientFirstBare + "," + serverFirst + "," + cfwp
	clientSignature := hmacSHA256(storedKey, []byte(authMessage))
	candidateClientKey := xorBytes(proof, clientSignature)
	candidateStored := sha256Sum(candidateClientKey)

	if subtle.ConstantTimeCompare(candidateStored, storedKey) != 1 {
		sendAuthError(w, "password authentication failed")
		return fmt.Errorf("scram: password mismatch for user %q", user)
	}

	serverSig := hmacSHA256(serverKey, []byte(authMessage))
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSig)
	if err := w.WriteMessage(wire.BeAuthentication, wire.BuildAuthSASLFinal([]byte(serverFinal))); err != nil {
		return err
	}
	if err := w.WriteMessage(wire.BeAuthentication, wire.BuildAuthOK()); err != nil {
		return err
	}
	return w.Flush()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// ClientAuthSCRAM runs a SCRAM-SHA-256 exchange as the client against an
// upstream PostgreSQL server. The caller has already received an
// AuthenticationSASL ('R'/10) message; this function sends the initial
// response, completes the exchange, and returns after validating the server
// signature in AuthenticationSASLFinal. It does NOT consume the trailing
// AuthenticationOk — the caller does.
func ClientAuthSCRAM(r *wire.Reader, w *wire.Writer, user, password string) error {
	// Client nonce: 18 random bytes base64-encoded.
	var nonceRaw [18]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return err
	}
	clientNonce := base64.StdEncoding.EncodeToString(nonceRaw[:])
	clientFirstBare := "n=" + saslPrepUser(user) + ",r=" + clientNonce
	clientFirst := "n,," + clientFirstBare

	if err := w.WriteMessage(wire.FeSASLInitial, wire.BuildSASLInitialResponse(scramMechanism, []byte(clientFirst))); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Read server-first (AuthenticationSASLContinue).
	msg, err := r.ReadMessage()
	if err != nil {
		return err
	}
	if msg.Type != wire.BeAuthentication {
		return fmt.Errorf("scram: expected Authentication, got %q", msg.Type)
	}
	am, err := wire.ParseAuth(msg.Body)
	if err != nil {
		return err
	}
	if am.Sub != uint32(wire.AuthSASLContinue) {
		return fmt.Errorf("scram: expected SASLContinue, got sub %d", am.Sub)
	}
	serverFirst := string(am.Data)
	sfAttrs := parseAttrList(serverFirst)
	combinedNonce, ok := sfAttrs["r"]
	if !ok || !strings.HasPrefix(combinedNonce, clientNonce) {
		return fmt.Errorf("scram: server nonce does not extend client nonce")
	}
	saltB64, ok := sfAttrs["s"]
	if !ok {
		return fmt.Errorf("scram: missing salt in server-first")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("scram: invalid salt: %w", err)
	}
	iterStr, ok := sfAttrs["i"]
	if !ok {
		return fmt.Errorf("scram: missing iteration count")
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter < 1 {
		return fmt.Errorf("scram: invalid iteration count %q", iterStr)
	}

	_, clientKey, storedKey, serverKey := scramKeys(password, salt, iter)
	clientFinalWithoutProof := "c=" + scramCBindFlagB64 + ",r=" + combinedNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	clientSignature := hmacSHA256(storedKey, []byte(authMessage))
	proof := xorBytes(clientKey, clientSignature)
	clientFinal := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)

	if err := w.WriteMessage(wire.FeSASLResponse, wire.BuildSASLResponse([]byte(clientFinal))); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Read server-final (AuthenticationSASLFinal).
	msg, err = r.ReadMessage()
	if err != nil {
		return err
	}
	if msg.Type != wire.BeAuthentication {
		return fmt.Errorf("scram: expected Authentication, got %q", msg.Type)
	}
	am, err = wire.ParseAuth(msg.Body)
	if err != nil {
		return err
	}
	if am.Sub != uint32(wire.AuthSASLFinal) {
		return fmt.Errorf("scram: expected SASLFinal, got sub %d", am.Sub)
	}
	serverFinal := string(am.Data)
	sfFinal := parseAttrList(serverFinal)
	vb64, ok := sfFinal["v"]
	if !ok {
		return fmt.Errorf("scram: missing server signature")
	}
	gotSig, err := base64.StdEncoding.DecodeString(vb64)
	if err != nil {
		return fmt.Errorf("scram: invalid server signature: %w", err)
	}
	wantSig := hmacSHA256(serverKey, []byte(authMessage))
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return fmt.Errorf("scram: server signature mismatch")
	}
	return nil
}

// saslPrepUser applies a minimal SASLprep escaping for the SCRAM username
// attribute: '=' → "=3D", ',' → "=2C". Full SASLprep (RFC 4013) is not
// required because PostgreSQL ignores this field and uses the startup user.
func saslPrepUser(u string) string {
	if !strings.ContainsAny(u, "=,") {
		return u
	}
	var b strings.Builder
	for i := 0; i < len(u); i++ {
		switch u[i] {
		case '=':
			b.WriteString("=3D")
		case ',':
			b.WriteString("=2C")
		default:
			b.WriteByte(u[i])
		}
	}
	return b.String()
}
