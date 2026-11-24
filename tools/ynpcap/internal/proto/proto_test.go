package proto

import (
	"encoding/binary"
	"testing"
)

func TestParseIPv4TCPOptions(t *testing.T) {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 20)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})

	opts := []byte{
		2, 4, 0x05, 0xb4,
		3, 3, 7,
		4, 2,
		8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		1, 0,
	}
	tcp := make([]byte, 20+len(opts))
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = byte((20+len(opts))/4) << 4
	tcp[13] = TCPSyn
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], opts)

	parsedIP, err := ParseIPv4(ip)
	if err != nil {
		t.Fatal(err)
	}
	if parsedIP.ChecksumOK {
		t.Fatal("expected invalid ipv4 checksum in synthetic packet")
	}

	tc, err := ParseTCP(tcp, parsedIP.Src, parsedIP.Dst)
	if err != nil {
		t.Fatal(err)
	}
	if mss, ok := tc.MSS(); !ok || mss != 1460 {
		t.Fatalf("mss = %d, %v", mss, ok)
	}
	if ws, ok := tc.WindowScale(); !ok || ws != 7 {
		t.Fatalf("ws = %d, %v", ws, ok)
	}
	if !tc.SACKPermitted() {
		t.Fatal("sack not permitted")
	}
	if ts, ecr, ok := tc.Timestamps(); !ok || ts != 1 || ecr != 0 {
		t.Fatalf("ts = %d/%d, %v", ts, ecr, ok)
	}
}
