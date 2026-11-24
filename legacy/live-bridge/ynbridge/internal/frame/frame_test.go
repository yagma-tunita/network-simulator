package frame

import (
	"bytes"
	"io"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := []byte{1, 2, 3, 4, 5}
	if err := Write(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if _, err := Read(&buf); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
