package pcap

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestReader(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	buf.Write(hdr)

	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:4], 7)
	binary.LittleEndian.PutUint32(rec[4:8], 900000)
	binary.LittleEndian.PutUint32(rec[8:12], 4)
	binary.LittleEndian.PutUint32(rec[12:16], 4)
	buf.Write(rec)
	buf.Write([]byte{1, 2, 3, 4})

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.TimeNs != 7_900_000_000 {
		t.Fatalf("time = %d", got.TimeNs)
	}
	if !bytes.Equal(got.Data, []byte{1, 2, 3, 4}) {
		t.Fatalf("data = %v", got.Data)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
