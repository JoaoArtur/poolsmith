package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxMessageSize caps a single message body to prevent a malicious peer from
// forcing Poolsmith to allocate gigabytes. PgBouncer uses 64MB as a sensible
// upper bound; we follow the same convention.
const MaxMessageSize = 1 << 26 // 64 MiB

// Message is one PostgreSQL wire-protocol message.
//
// Type is the one-byte type tag (0 for an untyped startup/SSL/cancel message).
// Body contains the payload WITHOUT the 4-byte length prefix and WITHOUT the
// type tag. Body aliases a buffer owned by the Reader and is valid until the
// NEXT ReadMessage call on that Reader. Call Clone() if you need to keep it.
type Message struct {
	Type byte
	Body []byte
}

// Clone returns a deep copy of m that does not alias the reader's buffer.
func (m Message) Clone() Message {
	b := make([]byte, len(m.Body))
	copy(b, m.Body)
	return Message{Type: m.Type, Body: b}
}

// Raw returns the fully-framed bytes (type + length + body) for forwarding.
// Only valid for typed messages (Type != 0).
func (m Message) Raw(scratch []byte) []byte {
	scratch = append(scratch[:0], m.Type)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(m.Body)+4))
	scratch = append(scratch, hdr[:]...)
	scratch = append(scratch, m.Body...)
	return scratch
}

// Reader reads PostgreSQL wire messages from an io.Reader using a single
// reusable buffer.
//
// Concurrency: NOT safe for concurrent use. Each connection gets its own
// Reader.
type Reader struct {
	r    io.Reader
	buf  []byte // grows on demand; never shrinks below high-water mark
	head int    // offset of first unread byte (bytes before head are consumed)
	tail int    // offset of first unused byte in buf; len = tail-head
}

// NewReader returns a Reader backed by r with an 8KiB initial buffer.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, buf: make([]byte, 8<<10)}
}

// ReadMessage reads one typed message (frontend or backend).
// Invalidates any Body slice returned by a previous ReadMessage call.
func (r *Reader) ReadMessage() (Message, error) {
	if err := r.fill(5); err != nil {
		return Message{}, err
	}
	t := r.buf[r.head]
	ln := binary.BigEndian.Uint32(r.buf[r.head+1 : r.head+5])
	if ln < 4 {
		return Message{}, fmt.Errorf("wire: invalid message length %d for type %q", ln, t)
	}
	if ln > MaxMessageSize {
		return Message{}, fmt.Errorf("wire: message of type %q too large: %d bytes", t, ln)
	}
	total := 1 + int(ln)
	if err := r.fill(total); err != nil {
		return Message{}, err
	}
	bodyStart := r.head + 5
	bodyEnd := r.head + total
	m := Message{Type: t, Body: r.buf[bodyStart:bodyEnd]}
	r.head = bodyEnd
	return m, nil
}

// ReadStartupMessage reads the untyped first message: [Len:4][Body:Len-4].
// Body starts at the protocol version int32.
func (r *Reader) ReadStartupMessage() (Message, error) {
	if err := r.fill(4); err != nil {
		return Message{}, err
	}
	ln := binary.BigEndian.Uint32(r.buf[r.head : r.head+4])
	if ln < 4 {
		return Message{}, fmt.Errorf("wire: invalid startup length %d", ln)
	}
	if ln > MaxMessageSize {
		return Message{}, fmt.Errorf("wire: startup message too large: %d bytes", ln)
	}
	total := int(ln)
	if err := r.fill(total); err != nil {
		return Message{}, err
	}
	m := Message{Type: 0, Body: r.buf[r.head+4 : r.head+total]}
	r.head += total
	return m, nil
}

// Buffered returns bytes currently buffered but not yet consumed.
func (r *Reader) Buffered() int { return r.tail - r.head }

// fill ensures that at least n bytes are available starting at r.head.
func (r *Reader) fill(n int) error {
	if n > MaxMessageSize+5 {
		return fmt.Errorf("wire: fill request too large (%d)", n)
	}
	// Compact if head > 0 and we need more room at the tail.
	if r.tail+n-r.Buffered() > cap(r.buf) {
		if r.head > 0 {
			copy(r.buf, r.buf[r.head:r.tail])
			r.tail -= r.head
			r.head = 0
		}
		if cap(r.buf) < n {
			nb := make([]byte, n)
			copy(nb, r.buf[:r.tail])
			r.buf = nb
		} else {
			r.buf = r.buf[:cap(r.buf)]
		}
	}
	for r.Buffered() < n {
		if r.tail == cap(r.buf) {
			// Shouldn't happen after the compact above, but just in case.
			if r.head > 0 {
				copy(r.buf, r.buf[r.head:r.tail])
				r.tail -= r.head
				r.head = 0
			} else {
				return errors.New("wire: buffer full")
			}
		}
		nr, err := r.r.Read(r.buf[r.tail:cap(r.buf)])
		if nr > 0 {
			r.tail += nr
		}
		if err != nil {
			if err == io.EOF && r.Buffered() >= n {
				return nil
			}
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

// ErrShortRead is returned when a typed-message body parser runs out of bytes.
var ErrShortRead = errors.New("wire: short read in message body")
