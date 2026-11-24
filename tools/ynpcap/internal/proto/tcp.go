package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type TCPOption struct {
	Kind uint8
	Data []byte
}

const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
)

type SackBlock struct {
	Left  uint32
	Right uint32
}

type TCP struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Flags      uint8
	Window     uint16
	Options    []TCPOption
	Payload    []byte
	ChecksumOK bool
}

func ParseTCP(b []byte, src, dst [4]byte) (TCP, error) {
	var t TCP
	if len(b) < 20 {
		return t, errors.New("short tcp header")
	}
	t.SrcPort = binary.BigEndian.Uint16(b[0:2])
	t.DstPort = binary.BigEndian.Uint16(b[2:4])
	t.Seq = binary.BigEndian.Uint32(b[4:8])
	t.Ack = binary.BigEndian.Uint32(b[8:12])
	off := int(b[12]>>4) * 4
	if off < 20 || off > len(b) {
		return t, errors.New("bad tcp offset")
	}
	t.Flags = b[13]
	t.Window = binary.BigEndian.Uint16(b[14:16])
	t.Payload = b[off:]

	for i := 20; i < off; {
		kind := b[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			t.Options = append(t.Options, TCPOption{Kind: kind})
			i++
			continue
		}
		if i+1 >= off {
			return t, errors.New("truncated tcp option")
		}
		l := int(b[i+1])
		if l < 2 || i+l > off {
			return t, errors.New("bad tcp option length")
		}
		t.Options = append(t.Options, TCPOption{Kind: kind, Data: b[i+2 : i+l]})
		i += l
	}

	t.ChecksumOK = tcpChecksum(b[:off], t.Payload, src, dst)
	return t, nil
}

func tcpChecksum(header, payload []byte, src, dst [4]byte) bool {
	buf := make([]byte, 0, 12+len(header)+len(payload))
	buf = append(buf, src[:]...)
	buf = append(buf, dst[:]...)
	buf = append(buf, 0, 6)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(header)+len(payload)))
	buf = append(buf, l[:]...)
	buf = append(buf, header...)
	buf = append(buf, payload...)
	return Checksum(buf) == 0
}

func (t TCP) Has(kind uint8) bool {
	for _, o := range t.Options {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

func (t TCP) MSS() (uint16, bool) {
	for _, o := range t.Options {
		if o.Kind == 2 && len(o.Data) == 2 {
			return binary.BigEndian.Uint16(o.Data), true
		}
	}
	return 0, false
}

func (t TCP) WindowScale() (uint8, bool) {
	for _, o := range t.Options {
		if o.Kind == 3 && len(o.Data) == 1 {
			return o.Data[0], true
		}
	}
	return 0, false
}

func (t TCP) SACKPermitted() bool { return t.Has(4) }

func (t TCP) SACKBlocks() []SackBlock {
	var out []SackBlock
	for _, o := range t.Options {
		if o.Kind != 5 || len(o.Data)%8 != 0 {
			continue
		}
		for i := 0; i < len(o.Data); i += 8 {
			out = append(out, SackBlock{
				Left:  binary.BigEndian.Uint32(o.Data[i : i+4]),
				Right: binary.BigEndian.Uint32(o.Data[i+4 : i+8]),
			})
		}
	}
	return out
}

func (t TCP) Timestamps() (uint32, uint32, bool) {
	for _, o := range t.Options {
		if o.Kind == 8 && len(o.Data) == 8 {
			return binary.BigEndian.Uint32(o.Data[0:4]),
				binary.BigEndian.Uint32(o.Data[4:8]), true
		}
	}
	return 0, 0, false
}

func (t TCP) String(src, dst [4]byte) string {
	return fmt.Sprintf("%s:%d -> %s:%d", net.IP(src[:]), t.SrcPort, net.IP(dst[:]), t.DstPort)
}
