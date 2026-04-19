package auth

import (
	"crypto/subtle"

	"github.com/JoaoArtur/poolsmith/internal/wire"
)

// SQLSTATE 28P01: invalid_password.
const sqlstateInvalidPassword = "28P01"

// sendAuthError writes a FATAL ErrorResponse (28P01) and flushes.
func sendAuthError(w *wire.Writer, msg string) {
	_ = w.WriteMessage(wire.BeErrorResponse, wire.BuildError("FATAL", sqlstateInvalidPassword, msg))
	_ = w.Flush()
}

func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
