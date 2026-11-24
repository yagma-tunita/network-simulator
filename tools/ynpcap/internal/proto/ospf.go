package proto

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"
)

type LSA struct {
	Age        uint16
	Type       uint8
	ID         [4]byte
	AdvRouter  [4]byte
	Seq        uint32
	Checksum   uint16
	Length     uint16
	ChecksumOK bool
}

type OSPF struct {
	Version     uint8
	Type        uint8
	Length      uint16
	RouterID    [4]byte
	Area        [4]byte
	ChecksumOK  bool
	AuthType    uint16
	AuthDataLen uint8
	KeyID       uint8
	CryptoSeq   uint32
	Digest      []byte
	LSAs        []LSA
}

func (o OSPF) RouterIDString() string { return net.IP(o.RouterID[:]).String() }

func VerifyOSPFMD5(b []byte, key []byte) bool {
	if len(b) < 24 || len(key) != 16 {
		return false
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if binary.BigEndian.Uint16(b[14:16]) != 2 || length < 24 || len(b) < length+16 {
		return false
	}
	h := md5.New()
	h.Write(b[:length])
	h.Write(key)
	sum := h.Sum(nil)
	for i := 0; i < 16; i++ {
		if sum[i] != b[length+i] {
			return false
		}
	}
	return true
}

func ParseOSPF(b []byte) (OSPF, error) {
	var o OSPF
	if len(b) < 24 {
		return o, errors.New("short ospf header")
	}
	o.Version = b[0]
	o.Type = b[1]
	o.Length = binary.BigEndian.Uint16(b[2:4])
	if int(o.Length) < 24 || int(o.Length) > len(b) {
		return o, errors.New("bad ospf length")
	}
	pkt := b[:o.Length]
	copy(o.RouterID[:], pkt[4:8])
	copy(o.Area[:], pkt[8:12])
	stored := binary.BigEndian.Uint16(pkt[12:14])
	o.AuthType = binary.BigEndian.Uint16(pkt[14:16])
	if o.AuthType == 2 {
		dlen := int(pkt[19])
		if dlen != 16 && dlen != 20 && dlen != 32 {
			return o, errors.New("bad ospf crypto digest length")
		}
		if len(b) < int(o.Length)+dlen {
			return o, errors.New("short ospf crypto digest")
		}
		o.AuthDataLen = uint8(dlen)
		o.KeyID = pkt[18]
		o.CryptoSeq = binary.BigEndian.Uint32(pkt[20:24])
		o.Digest = append([]byte(nil), b[o.Length:o.Length+uint16(dlen)]...)
		o.ChecksumOK = true
	} else {
		o.ChecksumOK = ospfChecksum(pkt) == stored
	}

	if o.Type == 4 && len(pkt) >= 28 {
		count := binary.BigEndian.Uint32(pkt[24:28])
		if count > 4096 {
			return o, errors.New("too many ospf lsas")
		}
		off := 28
		for i := uint32(0); i < count; i++ {
			lsa, next, err := parseLSA(pkt, off)
			if err != nil {
				return o, err
			}
			o.LSAs = append(o.LSAs, lsa)
			off = next
		}
	}
	return o, nil
}

func ospfChecksum(pkt []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(pkt); i += 2 {
		if i == 12 || (i >= 16 && i < 24) {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if len(pkt)%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func parseLSA(pkt []byte, off int) (LSA, int, error) {
	var l LSA
	if off+20 > len(pkt) {
		return l, 0, errors.New("short lsa header")
	}
	l.Age = binary.BigEndian.Uint16(pkt[off : off+2])
	l.Type = pkt[off+3]
	copy(l.ID[:], pkt[off+4:off+8])
	copy(l.AdvRouter[:], pkt[off+8:off+12])
	l.Seq = binary.BigEndian.Uint32(pkt[off+12 : off+16])
	l.Checksum = binary.BigEndian.Uint16(pkt[off+16 : off+18])
	l.Length = binary.BigEndian.Uint16(pkt[off+18 : off+20])
	if l.Length < 20 || off+int(l.Length) > len(pkt) {
		return l, 0, errors.New("bad lsa length")
	}
	body := make([]byte, l.Length)
	copy(body, pkt[off:off+int(l.Length)])
	body[16], body[17] = 0, 0
	l.ChecksumOK = fletcher(body) == l.Checksum
	return l, off + int(l.Length), nil
}

func fletcher(lsa []byte) uint16 {
	var c0, c1 int
	for i := 2; i < len(lsa); i++ {
		c0 = (c0 + int(lsa[i])) % 255
		c1 = (c1 + c0) % 255
	}
	x := ((len(lsa)-17)*c0 - c1) % 255
	if x <= 0 {
		x += 255
	}
	y := 510 - c0 - x
	for y > 255 {
		y -= 255
	}
	return uint16((x << 8) | y)
}
