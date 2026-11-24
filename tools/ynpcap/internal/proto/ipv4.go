package proto

import (
	"encoding/binary"
	"errors"
	"net"
)

type IPv4 struct {
	Src        [4]byte
	Dst        [4]byte
	Protocol   uint8
	TTL        uint8
	Payload    []byte
	ChecksumOK bool
}

func (p IPv4) SrcIP() string { return net.IP(p.Src[:]).String() }
func (p IPv4) DstIP() string { return net.IP(p.Dst[:]).String() }

func ParseIPv4(b []byte) (IPv4, error) {
	var p IPv4
	if len(b) < 20 || b[0]>>4 != 4 {
		return p, errors.New("bad ipv4 header")
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return p, errors.New("bad ipv4 ihl")
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		return p, errors.New("bad ipv4 length")
	}
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return p, errors.New("fragmented ipv4")
	}
	copy(p.Src[:], b[12:16])
	copy(p.Dst[:], b[16:20])
	p.Protocol = b[9]
	p.TTL = b[8]
	p.ChecksumOK = Checksum(b[:ihl]) == 0
	p.Payload = b[ihl:total]
	return p, nil
}
