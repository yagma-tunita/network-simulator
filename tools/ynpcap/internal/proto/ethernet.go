package proto

import (
	"encoding/binary"
	"errors"
	"net"
)

type Ethernet struct {
	Src       [6]byte
	Dst       [6]byte
	EtherType uint16
	Payload   []byte
}

func ParseEthernet(b []byte) (Ethernet, error) {
	var e Ethernet
	if len(b) < 14 {
		return e, errors.New("short ethernet frame")
	}
	copy(e.Dst[:], b[0:6])
	copy(e.Src[:], b[6:12])
	typ := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for typ == 0x8100 || typ == 0x88a8 {
		if len(b) < off+4 {
			return e, errors.New("short vlan tag")
		}
		typ = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	e.EtherType = typ
	e.Payload = b[off:]
	return e, nil
}

func (e Ethernet) SrcMAC() string { return net.HardwareAddr(e.Src[:]).String() }
func (e Ethernet) DstMAC() string { return net.HardwareAddr(e.Dst[:]).String() }
