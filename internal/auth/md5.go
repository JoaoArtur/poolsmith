package auth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// md5Hex returns hex(md5(a || b)).
func md5Hex(a, b []byte) string {
	h := md5.New()
	h.Write(a)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// md5Token returns the PostgreSQL MD5 password token:
//
//	"md5" + md5hex( md5hex(password+user) + salt )
func md5Token(user, password string, salt [4]byte) string {
	inner := md5Hex([]byte(password), []byte(user))
	outer := md5Hex([]byte(inner), salt[:])
	return "md5" + outer
}

// ServerAuthMD5 performs PostgreSQL MD5 authentication against a client.
// storedPassword is the plain-text password from the userlist.
func ServerAuthMD5(r *wire.Reader, w *wire.Writer, user, storedPassword string) error {
	var salt [4]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return fmt.Errorf("md5 auth: salt: %w", err)
	}
	if err := w.WriteMessage(wire.BeAuthentication, wire.BuildAuthMD5(salt)); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	msg, err := r.ReadMessage()
	if err != nil {
		return err
	}
	if msg.Type != wire.FePasswordMessage {
		sendAuthError(w, "expected PasswordMessage")
		return fmt.Errorf("md5 auth: expected PasswordMessage, got %q", msg.Type)
	}
	got, err := wire.ParsePasswordMessage(msg.Body)
	if err != nil {
		return err
	}
	want := md5Token(user, storedPassword, salt)
	if !constantTimeEqualString(got, want) {
		sendAuthError(w, "password authentication failed")
		return fmt.Errorf("md5 auth: password mismatch for user %q", user)
	}
	return nil
}

// ClientAuthMD5 replies to an AuthenticationMD5Password received from the
// upstream server. authMsg.Data must carry the 4-byte salt.
func ClientAuthMD5(r *wire.Reader, w *wire.Writer, authMsg wire.AuthMessage, user, password string) error {
	if authMsg.Sub != uint32(wire.AuthMD5Password) {
		return fmt.Errorf("md5 auth: unexpected sub-code %d", authMsg.Sub)
	}
	if len(authMsg.Data) < 4 {
		return fmt.Errorf("md5 auth: salt too short")
	}
	var salt [4]byte
	copy(salt[:], authMsg.Data[:4])
	token := md5Token(user, password, salt)
	body := make([]byte, 0, len(token)+1)
	body = append(body, token...)
	body = append(body, 0)
	if err := w.WriteMessage(wire.FePasswordMessage, body); err != nil {
		return err
	}
	return w.Flush()
}
