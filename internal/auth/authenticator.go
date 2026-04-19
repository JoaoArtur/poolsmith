package auth

import (
	"fmt"

	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// Authenticator dispatches client-side authentication based on the configured
// method and the userlist-provided secret.
type Authenticator struct {
	Method config.AuthMethod
	Users  *config.Userlist
}

// AuthenticateClient runs the handshake that the client expects, completing
// either with a nil error (caller must still send AuthenticationOk for non-
// SCRAM methods) or a non-nil error after the client has been informed with
// an ErrorResponse.
//
// For AuthTrust no bytes are exchanged. For AuthPlain/AuthMD5 the caller is
// responsible for writing the final AuthenticationOk; ServerAuthSCRAM already
// writes it as part of the SASL exchange.
func (a *Authenticator) AuthenticateClient(r *wire.Reader, w *wire.Writer, user string) error {
	switch a.Method {
	case config.AuthTrust:
		return nil
	case config.AuthPlain:
		return a.serverAuthPlain(r, w, user)
	case config.AuthMD5:
		pw, ok := a.lookup(user)
		if !ok {
			sendAuthError(w, "password authentication failed")
			return fmt.Errorf("auth: user %q not in userlist", user)
		}
		return ServerAuthMD5(r, w, user, pw)
	case config.AuthSCRAM:
		pw, ok := a.lookup(user)
		if !ok {
			sendAuthError(w, "password authentication failed")
			return fmt.Errorf("auth: user %q not in userlist", user)
		}
		return ServerAuthSCRAM(r, w, user, pw)
	default:
		return fmt.Errorf("auth: unsupported method %d", a.Method)
	}
}

func (a *Authenticator) lookup(user string) (string, bool) {
	if a.Users == nil {
		return "", false
	}
	return a.Users.Lookup(user)
}

func (a *Authenticator) serverAuthPlain(r *wire.Reader, w *wire.Writer, user string) error {
	if err := w.WriteMessage(wire.BeAuthentication, wire.BuildAuthCleartext()); err != nil {
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
		return fmt.Errorf("plain auth: expected PasswordMessage, got %q", msg.Type)
	}
	got, err := wire.ParsePasswordMessage(msg.Body)
	if err != nil {
		return err
	}
	want, ok := a.lookup(user)
	if !ok || !constantTimeEqualString(got, want) {
		sendAuthError(w, "password authentication failed")
		return fmt.Errorf("plain auth: password mismatch for user %q", user)
	}
	return nil
}
