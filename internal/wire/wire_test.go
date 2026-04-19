package wire

import (
	"bytes"
	"testing"
)

func TestStartupRoundTrip(t *testing.T) {
	params := map[string]string{
		"user":             "app",
		"database":         "app",
		"application_name": "poolsmith-test",
	}
	body := BuildStartup(params)

	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteStartup(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(&buf)
	m, err := r.ReadStartupMessage()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ParseStartup(m.Body)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Version != ProtocolV3 {
		t.Fatalf("version=%x want v3", sp.Version)
	}
	for k, v := range params {
		if got := sp.Params[k]; got != v {
			t.Fatalf("param %q = %q, want %q", k, got, v)
		}
	}
}

func TestMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteMessage(FeQuery, BuildQuery("SELECT 1")); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteMessage(BeReadyForQuery, BuildReadyForQuery(TxIdle)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(&buf)

	m1, err := r.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if m1.Type != FeQuery {
		t.Fatalf("type=%q", m1.Type)
	}
	q, err := ParseQuery(m1.Body)
	if err != nil {
		t.Fatal(err)
	}
	if q != "SELECT 1" {
		t.Fatalf("q=%q", q)
	}

	m2, err := r.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if m2.Type != BeReadyForQuery {
		t.Fatalf("type=%q", m2.Type)
	}
	s, err := ParseReadyForQuery(m2.Body)
	if err != nil {
		t.Fatal(err)
	}
	if s != TxIdle {
		t.Fatalf("status=%q", s)
	}
}

func TestErrorFieldsRoundTrip(t *testing.T) {
	body := BuildError("ERROR", "28P01", "password authentication failed")
	fields := ParseErrorFields(body)
	if len(fields) < 3 {
		t.Fatalf("got %d fields", len(fields))
	}
	got := FormatError(fields)
	want := "ERROR 28P01: password authentication failed"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseMessageRoundTrip(t *testing.T) {
	body := BuildParseMessage("stmt1", "SELECT $1::int + $2::int", []uint32{23, 23})
	name, query, oids, err := ParseParseMessage(body)
	if err != nil {
		t.Fatal(err)
	}
	if name != "stmt1" {
		t.Fatalf("name=%q", name)
	}
	if query != "SELECT $1::int + $2::int" {
		t.Fatalf("query=%q", query)
	}
	if len(oids) != 2 || oids[0] != 23 || oids[1] != 23 {
		t.Fatalf("oids=%v", oids)
	}
}

func TestBackendKeyDataRoundTrip(t *testing.T) {
	k := BackendKey{PID: 12345, Secret: 0xdeadbeef}
	body := BuildBackendKeyData(k)
	got, err := ParseBackendKeyData(body)
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatalf("got %+v want %+v", got, k)
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	buf := make([]byte, 5)
	buf[0] = FeQuery
	// claim 100 MiB
	buf[1] = 0x06
	buf[2] = 0x40
	buf[3] = 0x00
	buf[4] = 0x00
	r := NewReader(bytes.NewReader(buf))
	_, err := r.ReadMessage()
	if err == nil {
		t.Fatal("expected error for oversize message")
	}
}
