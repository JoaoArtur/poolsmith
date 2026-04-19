package auth

import (
	"encoding/base64"
	"testing"

	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// RFC 7677 Section 3 test vector.
func TestSCRAMRFC7677Vector(t *testing.T) {
	const (
		password               = "pencil"
		clientFirstBare        = "n=user,r=rOprNGfwEbeRWgbNEkqO"
		serverFirst            = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
		clientFinalNoProof     = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
		saltB64                = "W22ZaJ0SNY7soEsUEjb6gQ=="
		iter                   = 4096
		wantClientProofB64     = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
		wantServerSignatureB64 = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
	)

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatalf("salt decode: %v", err)
	}
	_, clientKey, storedKey, serverKey := scramKeys(password, salt, iter)

	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalNoProof
	clientSig := hmacSHA256(storedKey, []byte(authMessage))
	proof := xorBytes(clientKey, clientSig)
	gotProof := base64.StdEncoding.EncodeToString(proof)
	if gotProof != wantClientProofB64 {
		t.Fatalf("client proof mismatch:\n got  %s\n want %s", gotProof, wantClientProofB64)
	}

	gotSrvSig := base64.StdEncoding.EncodeToString(hmacSHA256(serverKey, []byte(authMessage)))
	if gotSrvSig != wantServerSignatureB64 {
		t.Fatalf("server signature mismatch:\n got  %s\n want %s", gotSrvSig, wantServerSignatureB64)
	}
}

func TestSCRAMRoundTrip(t *testing.T) {
	serverConn, clientConn := pipePair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	const user = "alice"
	const password = "correcthorsebatterystaple"

	errCh := make(chan error, 1)
	go func() {
		r := wire.NewReader(serverConn)
		w := wire.NewWriter(serverConn)
		errCh <- ServerAuthSCRAM(r, w, user, password)
	}()

	cr := wire.NewReader(clientConn)
	cw := wire.NewWriter(clientConn)

	// Client reads AuthenticationSASL (10) sent by the server.
	msg, err := cr.ReadMessage()
	if err != nil {
		t.Fatalf("client read SASL: %v", err)
	}
	if msg.Type != wire.BeAuthentication {
		t.Fatalf("want 'R', got %q", msg.Type)
	}
	am, err := wire.ParseAuth(msg.Body)
	if err != nil {
		t.Fatalf("parse auth: %v", err)
	}
	if am.Sub != uint32(wire.AuthSASL) {
		t.Fatalf("want AuthSASL, got %d", am.Sub)
	}

	if err := ClientAuthSCRAM(cr, cw, user, password); err != nil {
		t.Fatalf("ClientAuthSCRAM: %v", err)
	}

	// Drain the AuthenticationOk that the server writes after SASLFinal so
	// the goroutine's Flush completes on the pipe.
	msg, err = cr.ReadMessage()
	if err != nil {
		t.Fatalf("client read AuthOK: %v", err)
	}
	if msg.Type != wire.BeAuthentication {
		t.Fatalf("want 'R', got %q", msg.Type)
	}
	am, err = wire.ParseAuth(msg.Body)
	if err != nil {
		t.Fatalf("parse auth ok: %v", err)
	}
	if am.Sub != uint32(wire.AuthOK) {
		t.Fatalf("want AuthOK, got sub %d", am.Sub)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestSCRAMWrongPassword(t *testing.T) {
	serverConn, clientConn := pipePair(t)
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		r := wire.NewReader(serverConn)
		w := wire.NewWriter(serverConn)
		errCh <- ServerAuthSCRAM(r, w, "alice", "real-password")
	}()

	cr := wire.NewReader(clientConn)
	cw := wire.NewWriter(clientConn)
	// Read AuthenticationSASL challenge.
	if _, err := cr.ReadMessage(); err != nil {
		t.Fatalf("client read: %v", err)
	}
	_ = ClientAuthSCRAM(cr, cw, "alice", "wrong-password")

	if err := <-errCh; err == nil {
		t.Fatalf("expected server error on wrong password")
	}
}
