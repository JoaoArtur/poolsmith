package wire

import (
	"bufio"
	"encoding/binary"
	"io"
)

// Writer writes PostgreSQL wire messages to an io.Writer. It is a thin
// helper: callers build the body with BodyBuf methods and call Flush when
// they want the bytes to hit the wire.
type Writer struct {
	bw *bufio.Writer
}

// NewWriter wraps w with an 8KiB bufio.Writer. If w is already *bufio.Writer
// it is reused.
func NewWriter(w io.Writer) *Writer {
	if bw, ok := w.(*bufio.Writer); ok {
		return &Writer{bw: bw}
	}
	return &Writer{bw: bufio.NewWriterSize(w, 8<<10)}
}

// WriteMessage writes a typed message with a type byte. Body is the payload
// without the 4-byte length prefix.
func (w *Writer) WriteMessage(t byte, body []byte) error {
	var hdr [5]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)+4))
	if _, err := w.bw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.bw.Write(body)
	return err
}

// WriteRaw writes an arbitrary byte slice as-is. Callers use this to forward
// messages they have already framed (e.g. during transparent proxying).
func (w *Writer) WriteRaw(p []byte) error {
	_, err := w.bw.Write(p)
	return err
}

// WriteStartup writes an untyped startup-style message (no type byte, just
// [Len:4][Body]). Used for StartupMessage, SSLRequest, CancelRequest upstream.
func (w *Writer) WriteStartup(body []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)+4))
	if _, err := w.bw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.bw.Write(body)
	return err
}

// Flush pushes buffered bytes to the underlying writer.
func (w *Writer) Flush() error { return w.bw.Flush() }

// Available returns the number of bytes that can be written without flushing.
func (w *Writer) Available() int { return w.bw.Available() }

// Buffered returns the number of bytes currently buffered.
func (w *Writer) Buffered() int { return w.bw.Buffered() }
