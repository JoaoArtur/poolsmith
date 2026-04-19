package auth

import (
	"net"
	"testing"
	"time"

	"github.com/poolsmith/poolsmith/internal/wire"
)

func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = a.SetDeadline(deadline)
	_ = b.SetDeadline(deadline)
	return a, b
}

func TestMD5RoundTripSuccess(t *testing.T) {
	serverConn, clientConn := pipePair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	const user = "alice"
	const password = "s3cr3t"

	errCh := make(chan error, 1)
	go func() {
		r := wire.NewReader(serverConn)
		w := wire.NewWriter(serverConn)
		errCh <- ServerAuthMD5(r, w, user, password)
	}()

	cr := wire.NewReader(clientConn)
	cw := wire.NewWriter(clientConn)

	// Client reads the AuthenticationMD5Password.
	msg, err := cr.ReadMessage()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if msg.Type != wire.BeAuthentication {
		t.Fatalf("want 'R', got %q", msg.Type)
	}
	am, err := wire.ParseAuth(msg.Body)
	if err != nil {
		t.Fatalf("parse auth: %v", err)
	}
	if err := ClientAuthMD5(cr, cw, am, user, password); err != nil {
		t.Fatalf("ClientAuthMD5: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestMD5RoundTripWrongPassword(t *testing.T) {
	serverConn, clientConn := pipePair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	const user = "alice"

	errCh := make(chan error, 1)
	go func() {
		r := wire.NewReader(serverConn)
		w := wire.NewWriter(serverConn)
		errCh <- ServerAuthMD5(r, w, user, "right-password")
	}()

	cr := wire.NewReader(clientConn)
	cw := wire.NewWriter(clientConn)
	msg, err := cr.ReadMessage()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	am, err := wire.ParseAuth(msg.Body)
	if err != nil {
		t.Fatalf("parse auth: %v", err)
	}
	if err := ClientAuthMD5(cr, cw, am, user, "wrong-password"); err != nil {
		t.Fatalf("ClientAuthMD5: %v", err)
	}
	// Server should return an error; also sends an ErrorResponse which the
	// client would read but we don't care here.
	if err := <-errCh; err == nil {
		t.Fatalf("expected server error on wrong password")
	}
}
