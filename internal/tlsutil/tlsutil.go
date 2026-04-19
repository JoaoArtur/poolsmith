// Package tlsutil builds *tls.Config values for the client-facing listener
// and for upstream backend connections.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/JoaoArtur/poolsmith/internal/config"
)

// ServerConfig builds the TLS config the listener hands to incoming clients.
// Returns (nil, nil) when TLS is disabled.
func ServerConfig(c *config.Config) (*tls.Config, error) {
	if !c.ClientTLS {
		return nil, nil
	}
	if c.ClientTLSCert == "" || c.ClientTLSKey == "" {
		return nil, errors.New("tlsutil: client_tls_cert_file and client_tls_key_file are required")
	}
	cert, err := tls.LoadX509KeyPair(c.ClientTLSCert, c.ClientTLSKey)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: load client cert/key: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if c.ClientTLSMode == "verify-ca" || c.ClientTLSMode == "verify-full" {
		if c.ClientTLSCA == "" {
			return nil, errors.New("tlsutil: client_tls_ca_file is required when client_tls_sslmode is verify-*")
		}
		pem, err := os.ReadFile(c.ClientTLSCA)
		if err != nil {
			return nil, fmt.Errorf("tlsutil: read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tlsutil: failed to parse CA certificate")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// UpstreamConfig builds the TLS config used when dialling upstream servers.
// Returns (nil, false, err) when upstream TLS is disabled for this server.
func UpstreamConfig(srv *config.Server) (*tls.Config, bool, error) {
	mode := srv.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	switch mode {
	case "disable":
		return nil, false, nil
	case "allow", "prefer", "require":
		return &tls.Config{
			ServerName:         srv.Host,
			InsecureSkipVerify: true, //nolint:gosec // verify-ca/verify-full should be used for real verification
			MinVersion:         tls.VersionTLS12,
		}, true, nil
	case "verify-ca", "verify-full":
		return &tls.Config{
			ServerName: srv.Host,
			MinVersion: tls.VersionTLS12,
			// Callers may inject root CAs via a higher-level hook if needed;
			// without it we use the system pool which is usually what you
			// want for managed Postgres (RDS, Cloud SQL, …).
		}, true, nil
	}
	return nil, false, fmt.Errorf("tlsutil: unknown upstream TLS mode %q", mode)
}
