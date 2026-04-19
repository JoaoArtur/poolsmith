// Package wire implements the PostgreSQL frontend/backend message protocol
// (v3.0) used by Poolsmith to talk to clients and upstream servers.
//
// Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
//
// Design constraints:
//   - Zero-copy where possible: message bodies are handed out as slices into
//     an internal reusable buffer when the caller is about to forward them,
//     copied only when the payload needs to outlive the read.
//   - No reflection. No allocations on the hot path (per-message) beyond the
//     buffer grow, which is amortised.
//   - Byte-order is always big-endian (PG protocol).
package wire

// Frontend message type bytes (client → server).
const (
	FeBind            byte = 'B'
	FeClose           byte = 'C'
	FeCopyData        byte = 'd'
	FeCopyDone        byte = 'c'
	FeCopyFail        byte = 'f'
	FeDescribe        byte = 'D'
	FeExecute         byte = 'E'
	FeFlush           byte = 'H'
	FeFunctionCall    byte = 'F'
	FeGSSResponse     byte = 'p'
	FeParse           byte = 'P'
	FePasswordMessage byte = 'p'
	FeQuery           byte = 'Q'
	FeSASLInitial     byte = 'p'
	FeSASLResponse    byte = 'p'
	FeSync            byte = 'S'
	FeTerminate       byte = 'X'
)

// Backend message type bytes (server → client).
const (
	BeAuthentication       byte = 'R'
	BeBackendKeyData       byte = 'K'
	BeBindComplete         byte = '2'
	BeCloseComplete        byte = '3'
	BeCommandComplete      byte = 'C'
	BeCopyData             byte = 'd'
	BeCopyDone             byte = 'c'
	BeCopyInResponse       byte = 'G'
	BeCopyOutResponse      byte = 'H'
	BeCopyBothResponse     byte = 'W'
	BeDataRow              byte = 'D'
	BeEmptyQueryResponse   byte = 'I'
	BeErrorResponse        byte = 'E'
	BeFunctionCallResponse byte = 'V'
	BeNegotiateProtocol    byte = 'v'
	BeNoData               byte = 'n'
	BeNoticeResponse       byte = 'N'
	BeNotificationResponse byte = 'A'
	BeParameterDescription byte = 't'
	BeParameterStatus      byte = 'S'
	BeParseComplete        byte = '1'
	BePortalSuspended      byte = 's'
	BeReadyForQuery        byte = 'Z'
	BeRowDescription       byte = 'T'
)

// Authentication sub-codes (first int32 of an AuthenticationMessage body).
const (
	AuthOK                byte = 0
	AuthKerberosV5        byte = 2
	AuthCleartextPassword byte = 3
	AuthMD5Password       byte = 5
	AuthSCMCredential     byte = 6
	AuthGSS               byte = 7
	AuthGSSContinue       byte = 8
	AuthSSPI              byte = 9
	AuthSASL              byte = 10
	AuthSASLContinue      byte = 11
	AuthSASLFinal         byte = 12
)

// Transaction status flags from ReadyForQuery ('Z').
const (
	TxIdle    byte = 'I' // not in a transaction
	TxInBlock byte = 'T' // in a transaction block
	TxFailed  byte = 'E' // in a failed transaction block
)

// Protocol version constants used in the startup message.
const (
	ProtocolV3Major   = 3
	ProtocolV3Minor   = 0
	ProtocolV3        = ProtocolV3Major<<16 | ProtocolV3Minor
	SSLRequestCode    = 80877103 // 1234.5679
	GSSENCRequestCode = 80877104 // 1234.5680
	CancelRequestCode = 80877102 // 1234.5678
)
